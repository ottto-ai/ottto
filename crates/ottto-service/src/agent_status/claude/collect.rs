//! Claude status collect operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::append_claude_desktop_plan_observations;
use crate::agent_status::append_current_plan_observation;
use crate::agent_status::base_snapshot;
use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::claude_account_from_local_metadata;
use crate::agent_status::claude_account_identifier_hashes_from_observations;
use crate::agent_status::claude_account_session_not_offered_capability;
use crate::agent_status::claude_account_weekly_not_offered_capability;
use crate::agent_status::claude_credentials_in_keychain;
use crate::agent_status::claude_credit_pools;
use crate::agent_status::claude_desktop_metadata_present;
use crate::agent_status::claude_desktop_scan_from_root;
use crate::agent_status::claude_desktop_support_dir;
use crate::agent_status::claude_local_plan_facts_contradict;
use crate::agent_status::claude_oauth_end_caller_run;
use crate::agent_status::claude_oauth_usage_network_disabled;
use crate::agent_status::claude_owner_call_allowed;
use crate::agent_status::claude_plan_name;
use crate::agent_status::claude_quota_check_diagnostic;
use crate::agent_status::claude_relogin_warning;
use crate::agent_status::claude_strong_oauth_identity_hashes;
use crate::agent_status::claude_token_owner;
use crate::agent_status::claude_version_detected;
use crate::agent_status::collect_claude_oauth_usage_with_credential;
use crate::agent_status::collect_claude_statusline_context_status;
use crate::agent_status::collect_claude_statusline_quota_windows;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::default_claude_identity_diagnostic;
use crate::agent_status::default_support_dir;
use crate::agent_status::effective_user_account_name;
use crate::agent_status::fs;
use crate::agent_status::home_dir;
use crate::agent_status::home_path;
use crate::agent_status::not_installed_snapshot;
use crate::agent_status::parse_claude_auth_json;
use crate::agent_status::prefer_newer_exact_claude_statusline_windows;
use crate::agent_status::read_claude_slot_locally;
use crate::agent_status::refine_claude_local_plan_metadata;
use crate::agent_status::require_claude_auth_identity_agreement;
use crate::agent_status::run_command_capture;
use crate::agent_status::stable_claude_slot_credential;
use crate::agent_status::stamp_claude_cli_account_identity;
use crate::agent_status::supported_capability;
use crate::agent_status::unsupported_account;
use crate::agent_status::unsupported_capability;
use crate::agent_status::unsupported_quota_window;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentCapabilityGap;
use crate::agent_status::AgentContextCompleteness;
use crate::agent_status::AgentContextState;
use crate::agent_status::AgentContextStatus;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentModelStatus;
use crate::agent_status::AgentRuntimeDefaults;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountsStatusV1;
use crate::agent_status::ClaudeCliOauthAccount;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeCredentialRead;
use crate::agent_status::ClaudeDesktopMetadataCache;
use crate::agent_status::ClaudeDesktopPairs;
use crate::agent_status::ClaudeDesktopScan;
use crate::agent_status::ClaudeLiveLogin;
use crate::agent_status::ClaudeLocalLoginState;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeOAuthUsageOutcome;
use crate::agent_status::ClaudeSlotAccountBinding;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::ClaudeStatusLineQuota;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::Duration;
use crate::agent_status::FileClaudeConfigSlotSettingsStore;
use crate::agent_status::Instant;
use crate::agent_status::Mutex;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::OnceLock;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::SourceKind;
use crate::agent_status::StableClaudeSlotCredential;
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_DEFAULT_HOME_SPLIT_LOGIN_CODE;
use crate::agent_status::CLAUDE_RELOGIN_APPROACHING_CODE;
use crate::agent_status::CLAUDE_SETTINGS_FAILURE_BOUND;
use crate::agent_status::COMMAND_TIMEOUT;

/// macOS enterprise/MDM policy settings for Claude Code. Highest precedence in
/// Claude Code's own chain and not overridable by a developer, so it is applied
/// last.
pub(in crate::agent_status) const CLAUDE_MANAGED_SETTINGS_PATH: &str =
    "/Library/Application Support/ClaudeCode/managed-settings.json";

/// Claude Code settings files, lowest precedence first.
///
/// Claude Code's own order is user settings, then project settings, then local
/// project settings, then managed settings on top. Project-scoped
/// `.claude/settings*.json` files are intentionally out of scope here: the daemon
/// has no single project cwd, and a checked-out repository's settings are not a
/// machine default. `~/.claude/settings.local.json` is included because the
/// local MCP inventory already treats it as an override of `~/.claude/settings.json`.
pub(in crate::agent_status) fn claude_settings_paths() -> Vec<(String, PathBuf)> {
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
pub(in crate::agent_status) struct ClaudeRuntimeDefaultsCapture {
    pub(in crate::agent_status) defaults: Option<AgentRuntimeDefaults>,
    pub(in crate::agent_status) capability: AgentCapabilityGap,
    pub(in crate::agent_status) diagnostic: Option<AgentStatusDiagnostic>,
}

/// Assemble display-safe Claude Code runtime defaults from the local settings
/// chain for the agent-status upload. The backend overwrites `machine_id` from
/// the stored snapshot, so it is left unset here.
pub(in crate::agent_status) fn build_claude_runtime_defaults(
    captured_at: &str,
) -> ClaudeRuntimeDefaultsCapture {
    claude_runtime_defaults_from_paths(captured_at, &claude_settings_paths())
}

pub(in crate::agent_status) fn claude_runtime_defaults_from_paths(
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
                    // The saved model's `/effort` (or the legacy top-level
                    // `effortLevel`), plus every model's saved effort. Reported
                    // exactly as configured; absent means absent.
                    reasoning_effort: defaults.reasoning_effort,
                    reasoning_effort_by_model: defaults.reasoning_effort_by_model,
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

pub(in crate::agent_status) fn apply_claude_statusline_context_provenance(
    snapshot: &mut AgentStatusSnapshot,
    full_oauth_quota_collected: bool,
) {
    // Context is an augmentation, not quota provenance. Keep the strong
    // full-meter proof when OAuth usage already supplied quota; otherwise
    // statusLine remains the honest partial source marker.
    if !full_oauth_quota_collected {
        snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
    }
}

/// A signed-in default login whose `.claude.json` identity could not be
/// trusted: keep the plan stored with the credential, claim no identity.
pub(in crate::agent_status) fn claude_signed_in_account_without_identity(
    credential_plan: Option<String>,
) -> AgentAccountStatus {
    let mut auth = serde_json::Map::new();
    auth.insert("loggedIn".to_string(), Value::Bool(true));
    auth.insert("authMethod".to_string(), Value::from("claude.ai"));
    auth.insert("apiProvider".to_string(), Value::from("firstParty"));
    if let Some(plan) = credential_plan {
        auth.insert("subscriptionType".to_string(), Value::from(plan));
    }
    parse_claude_auth_json(&Value::Object(auth))
}

/// A non-OAuth way the default Claude Code login authenticates. Claude Code
/// gives these precedence over the stored OAuth login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeAlternativeAuth {
    Bedrock,
    Vertex,
    ApiKey,
}

impl ClaudeAlternativeAuth {
    pub(in crate::agent_status) fn auth_method(self) -> &'static str {
        match self {
            Self::Bedrock => "bedrock",
            Self::Vertex => "vertex",
            Self::ApiKey => "api_key",
        }
    }

    pub(in crate::agent_status) fn api_provider(self) -> &'static str {
        match self {
            Self::Bedrock => "bedrock",
            Self::Vertex => "vertex",
            Self::ApiKey => "anthropic",
        }
    }

    /// How Claude Code usage is billed on this route.
    pub(in crate::agent_status) fn billing_channel(self) -> &'static str {
        match self {
            Self::Bedrock => "amazon_bedrock",
            Self::Vertex => "google_vertex",
            Self::ApiKey => "direct_api",
        }
    }
}

/// Whether a Claude login authenticates without OAuth, following Claude
/// Code 2.1.288's own rules (read statically from its source):
///
/// - Settings layers are applied low to high (`user`, `project`, `local`,
///   `flag`, `policy`); the highest layer that defines a value wins, and the
///   settings `env` overrides the process environment. `paths` must be ordered
///   lowest precedence first. `ambient` is the daemon's own environment,
///   consulted last.
/// - `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` route all inference.
/// - `ANTHROPIC_AUTH_TOKEN` and `apiKeyHelper` are used ahead of OAuth.
/// - `ANTHROPIC_API_KEY` is used in an interactive session only once the user
///   approved it (its last 20 characters are in `.claude.json`
///   `customApiKeyResponses.approved`); otherwise only when no OAuth login is
///   usable. A Max user who declined the key stays on the subscription.
///
/// Only presence (and, for the API key, the approval suffix compared in
/// memory) is read; no value is kept.
pub(in crate::agent_status) fn claude_alternative_auth(
    paths: &[(String, PathBuf)],
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    approved_api_key_suffixes: &[String],
    stored_console_key: bool,
) -> Option<ClaudeAlternativeAuth> {
    let layers = claude_settings_layers(paths);
    claude_alternative_auth_layers(
        &layers,
        ambient,
        oauth_usable,
        approved_api_key_suffixes,
        stored_console_key,
    )
}

/// Readable settings layers, highest precedence first. `paths` are ordered
/// lowest precedence first.
pub(in crate::agent_status) fn claude_settings_layers(paths: &[(String, PathBuf)]) -> Vec<Value> {
    paths
        .iter()
        .rev()
        .filter_map(|(_, path)| {
            fs::read_to_string(path)
                .ok()
                .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        })
        .collect()
}

/// A settings `env` value from the highest layer that defines it, else the
/// ambient environment (layers highest precedence first).
pub(in crate::agent_status) fn claude_visible_env(
    layers: &[Value],
    ambient: &dyn Fn(&str) -> Option<String>,
    key: &str,
) -> Option<String> {
    layers
        .iter()
        .find_map(|layer| {
            layer
                .get("env")
                .and_then(|env| env.get(key))
                .map(|value| match value {
                    Value::String(text) => text.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                })
        })
        .or_else(|| ambient(key))
}

pub(in crate::agent_status) fn claude_env_truthy(value: Option<String>) -> bool {
    value.is_some_and(|text| {
        let text = text.trim().to_ascii_lowercase();
        !text.is_empty() && text != "0" && text != "false"
    })
}

/// The same precedence evaluator for a caller that has already read and
/// validated all layers (highest precedence first).
pub(crate) fn claude_alternative_auth_layers(
    layers: &[Value],
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    approved_api_key_suffixes: &[String],
    stored_console_key: bool,
) -> Option<ClaudeAlternativeAuth> {
    let present = |value: &Value| match value {
        Value::String(text) => !text.trim().is_empty(),
        Value::Null => false,
        _ => true,
    };
    let truthy = claude_env_truthy;
    let env_value = |key: &str| claude_visible_env(layers, ambient, key);
    if truthy(env_value("CLAUDE_CODE_USE_BEDROCK")) {
        return Some(ClaudeAlternativeAuth::Bedrock);
    }
    if truthy(env_value("CLAUDE_CODE_USE_VERTEX")) {
        return Some(ClaudeAlternativeAuth::Vertex);
    }
    let auth_token =
        env_value("ANTHROPIC_AUTH_TOKEN").is_some_and(|value| !value.trim().is_empty());
    let api_key_helper = layers
        .iter()
        .find_map(|layer| layer.get("apiKeyHelper"))
        .is_some_and(present);
    if auth_token || api_key_helper {
        return Some(ClaudeAlternativeAuth::ApiKey);
    }
    let api_key_active = env_value("ANTHROPIC_API_KEY").is_some_and(|key| {
        let key = key.trim();
        !key.is_empty()
            && (!oauth_usable || {
                let suffix = key
                    .char_indices()
                    .rev()
                    .nth(19)
                    .map_or(key, |(index, _)| &key[index..]);
                approved_api_key_suffixes
                    .iter()
                    .any(|approved| approved == suffix)
            })
    });
    // A Console API key saved by `/login` ("/login managed key": the
    // `Claude Code` keychain item or `.claude.json` `primaryApiKey`). Counted
    // only when no OAuth login is usable, so a subscription stays one.
    (api_key_active || (stored_console_key && !oauth_usable))
        .then_some(ClaudeAlternativeAuth::ApiKey)
}

/// Whether a Console API key saved by `/login` is present for this login:
/// `.claude.json` `primaryApiKey` or, on macOS, its `Claude Code` keychain
/// item (`Claude Code-<hash>` for a registered config dir, the same suffix as
/// the OAuth item; presence only, read without `-w`). No key value is kept.
pub(in crate::agent_status) fn claude_stored_console_key_present(
    slot: &ClaudeConfigDirSlot,
) -> bool {
    let in_config = fs::read_to_string(slot.identity_path(&home_dir()))
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .and_then(|value| {
            value
                .get("primaryApiKey")
                .and_then(Value::as_str)
                .map(|key| !key.trim().is_empty())
        })
        .unwrap_or(false);
    if in_config {
        return true;
    }
    if !claude_credentials_in_keychain()
        || crate::command_env::executable_path("security").is_none()
    {
        return false;
    }
    let Some(account) = effective_user_account_name() else {
        return false;
    };
    run_command_capture(
        "security",
        &[
            "find-generic-password",
            "-a",
            &account,
            "-s",
            &slot
                .service_name()
                .replacen("Claude Code-credentials", "Claude Code", 1),
        ],
        COMMAND_TIMEOUT,
    )
    .success
}

/// `.claude.json` `customApiKeyResponses.approved`: suffixes of API keys the
/// user accepted in Claude Code.
pub(in crate::agent_status) fn claude_approved_api_key_suffixes(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .and_then(|value| {
            value
                .get("customApiKeyResponses")?
                .get("approved")?
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
        })
        .unwrap_or_default()
}

pub(in crate::agent_status) fn claude_default_alternative_auth_now(
    oauth_usable: bool,
) -> Option<ClaudeAlternativeAuth> {
    claude_alternative_auth_for_slot(
        &ClaudeConfigDirSlot::Default,
        &|key| std::env::var(key).ok(),
        oauth_usable,
        false,
    )
}

/// [`claude_alternative_auth`] for one login, read from that login's own
/// settings, `.claude.json` approvals and stored Console key. `ambient` is the
/// environment the Claude Code process for this login runs with.
///
/// `print_mode`: a `claude -p` run. Claude Code 2.1.288 (`Rb`: when the
/// session is non-interactive, `ANTHROPIC_API_KEY` is returned before the
/// `customApiKeyResponses` approval check) then uses any `ANTHROPIC_API_KEY`,
/// approved or not.
pub(in crate::agent_status) fn claude_alternative_auth_for_slot(
    slot: &ClaudeConfigDirSlot,
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    print_mode: bool,
) -> Option<ClaudeAlternativeAuth> {
    claude_alternative_auth(
        &claude_settings_paths_for_slot(slot),
        ambient,
        // The approval rule applies only while an OAuth login is usable.
        oauth_usable && !print_mode,
        &claude_approved_api_key_suffixes(&slot.identity_path(&home_dir())),
        !oauth_usable && claude_stored_console_key_present(slot),
    )
}

/// Claude Code's settings files for one login, lowest precedence first.
pub(in crate::agent_status) fn claude_settings_paths_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Vec<(String, PathBuf)> {
    match slot.config_dir() {
        None => claude_settings_paths(),
        Some(config_dir) => vec![
            (
                "claude_code.settings".to_string(),
                PathBuf::from(config_dir).join("settings.json"),
            ),
            (
                "claude_code.settings_local".to_string(),
                PathBuf::from(config_dir).join("settings.local.json"),
            ),
            (
                "claude_code.managed_settings".to_string(),
                PathBuf::from(CLAUDE_MANAGED_SETTINGS_PATH),
            ),
        ],
    }
}

/// A plan-usage snapshot younger than this is reused by `/usage`, which then
/// refreshes nothing.
pub(in crate::agent_status) const CLAUDE_USAGE_CACHE_REUSE_MS: i64 = 60_000;

/// Why the background refresher must not run `claude -p /usage` for this
/// login now. Claude Code 2.1.288's `/usage` returns without awaiting a token
/// refresh when:
///
/// - the stored scopes lack `user:profile`;
/// - `.claude.json` `oauthAccount.billingType` is `usage_based`;
/// - another credential takes precedence over the OAuth login (Bedrock,
///   Vertex, an auth token, `apiKeyHelper`, or an approved API key). Judged by
///   the same helper the status uses, with the refresher's own environment
///   (it starts Claude Code with a cleared environment, so only the login's
///   settings files count) and print-mode precedence: any `ANTHROPIC_API_KEY`
///   in those settings counts, approved or not;
/// - its plan-usage snapshot is under 60 seconds old (a later pass runs).
pub(crate) fn claude_refresher_skip_reason(
    slot: &ClaudeConfigDirSlot,
    live: &ClaudeLiveLogin,
    now: OffsetDateTime,
) -> Option<&'static str> {
    if !live
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.has_profile_scope)
    {
        return Some("no_profile_scope");
    }
    let config = fs::read_to_string(slot.identity_path(&home_dir()))
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok());
    let config = config.as_ref();
    if config.and_then(|value| value.get("oauthAccount")?.get("billingType")?.as_str())
        == Some("usage_based")
    {
        return Some("usage_billing");
    }
    if claude_alternative_auth_for_slot(slot, &|_| None, true, true).is_some() {
        return Some("other_auth");
    }
    let fetched_at_ms = config
        .and_then(|value| {
            claude_credit_pools::claude_cached_usage_fetched_at_ms(
                value.get("cachedUsageUtilization")?,
            )
        })
        .and_then(|ms| i64::try_from(ms).ok());
    let now_ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if fetched_at_ms.is_some_and(|fetched| {
        let age = now_ms - fetched;
        (0..CLAUDE_USAGE_CACHE_REUSE_MS).contains(&age)
    }) {
        return Some("usage_cached");
    }
    None
}

/// A Claude home's owner check (the default home or a registered slot): the
/// binding `.claude.json` names, and the stored token's owner once proven.
pub(in crate::agent_status) struct ClaudeTokenOwner {
    pub(in crate::agent_status) cached: Option<(String, String)>,
    pub(in crate::agent_status) proven: Option<claude_token_owner::ProvenOwner>,
}

impl ClaudeTokenOwner {
    pub(in crate::agent_status) fn proven_binding(&self) -> Option<(String, String)> {
        self.proven
            .as_ref()
            .map(|owner| (owner.account_hash.clone(), owner.organization_hash.clone()))
    }

    /// Proven to be exactly `expected`, account and organization.
    pub(in crate::agent_status) fn proves(&self, expected: &ClaudeSlotAccountBinding) -> bool {
        self.proven.as_ref().is_some_and(|owner| {
            owner.account_hash == expected.account_identifier_hash
                && owner.organization_hash == expected.organization_identifier_hash
        })
    }

    /// Proven and known, but not the account `.claude.json` names.
    pub(in crate::agent_status) fn split_login(&self) -> bool {
        self.proven.is_some() && self.proven_binding() != self.cached
    }

    /// Information only: the default home counts as the token owner's account.
    pub(in crate::agent_status) fn split_login_diagnostic(&self) -> Option<AgentStatusDiagnostic> {
        self.split_login().then(|| AgentStatusDiagnostic::source(
            CLAUDE_DEFAULT_HOME_SPLIT_LOGIN_CODE,
            AgentDiagnosticSeverity::Warning,
            "Claude Desktop and the terminal use different accounts in the default Claude folder; it counts as the terminal login's account.",
        ))
    }

    /// The binding the default slot is verified against when it is not the
    /// one `.claude.json` names: none while unproven, the owner's on a split.
    pub(in crate::agent_status) fn binding_override(&self) -> Option<Option<(String, String)>> {
        match &self.proven {
            None => Some(None),
            Some(_) if self.split_login() => Some(self.proven_binding()),
            Some(_) => None,
        }
    }
}

/// The proven owner of a home's stored token (`home` is `"default"` or the
/// slot id). A valid token may be sent when `calls_allowed` (the background
/// gates of `claude_owner_call_allowed`, or false for remembered verdicts
/// only). A lapsed token waiting for Claude Code's refresh is never sent: it
/// keeps the verdict remembered for that same token. Any other login state
/// has nothing to prove.
pub(in crate::agent_status) fn prove_claude_token_owner(
    home: &str,
    login_state: &ClaudeLocalLoginState,
    access_token: Option<&str>,
    calls_allowed: bool,
) -> Option<claude_token_owner::ProvenOwner> {
    let may_call = match login_state {
        ClaudeLocalLoginState::AccessValid => calls_allowed,
        ClaudeLocalLoginState::RefreshPending => false,
        _ => return None,
    };
    claude_token_owner::proven_owner(home, access_token?, may_call)
}

/// Prove the default home's token owner, only where the local files disagree:
/// a locally valid token whose plan contradicts `.claude.json`. A lapsed token
/// waiting for Claude Code's refresh is never sent; it keeps the verdict
/// remembered for that same token. Elsewhere (`None`) the default home keeps
/// its usual path. The owner is the cached account: the credential's plan is
/// stale and is dropped. The owner is another known account (a registered
/// slot with the same hashes): `stable` takes that account's own
/// `.claude.json`, so labels and plan facts come only from an account Ottto
/// knows. Anything else stays unproven and the caller fails closed.
pub(in crate::agent_status) fn resolve_claude_default_home_owner(
    login_state: &ClaudeLocalLoginState,
    stable: &mut StableClaudeSlotCredential,
    known_identities: &[ClaudeCliOauthAccount],
) -> Option<ClaudeTokenOwner> {
    let refresh_pending = *login_state == ClaudeLocalLoginState::RefreshPending;
    if !matches!(
        login_state,
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending
    ) || !claude_local_plan_facts_contradict(
        stable.credential.subscription_type.as_deref(),
        stable.oauth_account.organization_type.as_deref(),
    ) {
        return None;
    }
    let cached = claude_strong_oauth_identity_hashes(&stable.oauth_account);
    let owner = prove_claude_token_owner(
        "default",
        login_state,
        stable.credential.access_token.as_deref(),
        claude_owner_call_allowed(),
    );
    if refresh_pending && owner.is_none() {
        return None;
    }
    let mut resolved = ClaudeTokenOwner {
        cached,
        proven: owner,
    };
    if resolved.split_login() {
        let owner = resolved.proven_binding();
        match known_identities
            .iter()
            .find(|known| claude_strong_oauth_identity_hashes(known) == owner)
        {
            Some(known) => stable.oauth_account = known.clone(),
            None => resolved.proven = None,
        }
    } else if resolved.proven.is_some() {
        stable.credential.subscription_type = None;
    }
    Some(resolved)
}

/// The owner check's hashes on a home's local status.
pub(in crate::agent_status) fn apply_claude_token_owner(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    owner: Option<&ClaudeTokenOwner>,
) {
    let Some(owner) = owner else {
        return;
    };
    (status.cached_account_hash, status.cached_organization_hash) = owner.cached.clone().unzip();
    (
        status.token_owner_account_hash,
        status.token_owner_organization_hash,
    ) = owner.proven_binding().unzip();
    status.owner_proven_at = owner.proven.as_ref().map(|owner| owner.proven_at.clone());
}

/// Also returns this pass's exact Claude Desktop folder pairs, read in the same
/// single scan as the default snapshot's Desktop readings, and the default
/// home's owner check.
pub(in crate::agent_status) fn collect_claude_status(
    captured_at: String,
    expires_at: String,
    slot_owned_bindings: &BTreeSet<ClaudeStrongBinding>,
    keep_signed_in: bool,
    known_identities: &[ClaudeCliOauthAccount],
    desktop_metadata: &mut ClaudeDesktopMetadataCache,
) -> (
    AgentStatusSnapshot,
    ClaudeDesktopPairs,
    Option<ClaudeTokenOwner>,
) {
    // Presence is decided by the canonical detector, which requires the `claude`
    // binary. A lone `~/.claude/settings.json` — which Ottto's own relay-base
    // patch writes during onboarding — must NOT read as "installed", or a Mac
    // that never had Claude reports it as present and then fails verification
    // with "claude is not installed or not executable".
    let claude_desktop_root = claude_desktop_support_dir();
    let claude_cli_present =
        crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode);
    if !claude_cli_present && !claude_desktop_metadata_present(&claude_desktop_root) {
        return (
            not_installed_snapshot(SourceKind::ClaudeCode, "claude", captured_at, expires_at),
            ClaudeDesktopPairs::default(),
            None,
        );
    }
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    // Login state comes from local metadata only: `.claude.json` (before),
    // the stored credential, `.claude.json` (after). `claude auth status`
    // printed exactly these fields but could refresh, and so sign out, the
    // default login on every pass.
    let local = read_claude_slot_locally(&ClaudeConfigDirSlot::Default);
    let mut login_state = local.state;
    let default_live = local.live_login();
    // "Keep my Claude accounts signed in": the default login gets the same
    // single waiting background refresh as registered slots.
    let refresh = if claude_oauth_usage_network_disabled() {
        crate::claude_refresher::RefreshDecision::NotNeeded
    } else {
        crate::claude_refresher::maybe_refresh(
            "default",
            &ClaudeConfigDirSlot::Default,
            &default_live,
            keep_signed_in,
        )
    };
    if login_state == ClaudeLocalLoginState::RefreshPending
        && refresh == crate::claude_refresher::RefreshDecision::FailedWaitingForSignIn
    {
        // The background refresh could not advance this credential: ask for
        // sign-in (the app's "Sign in again" gate), no retry until it changes.
        login_state = ClaudeLocalLoginState::NeedsLogin;
    }
    if let Some(warning) = claude_relogin_warning(
        default_live
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.refresh_token_expires_at.as_deref()),
        OffsetDateTime::now_utc(),
    ) {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            CLAUDE_RELOGIN_APPROACHING_CODE,
            AgentDiagnosticSeverity::Warning,
            warning,
        ));
    }
    let credential_plan = match &local.credential {
        ClaudeCredentialRead::Present(credential) => credential.subscription_type.clone(),
        ClaudeCredentialRead::Absent | ClaudeCredentialRead::Unreadable => None,
    };
    let mut stable_default_credential = stable_claude_slot_credential(
        local.initial_oauth_account,
        local.credential.into_credential(),
        local.final_oauth_account,
    );
    // `.claude.json` is only a display cache here: another writer (a Claude
    // Desktop session) may have written it for a different account than the
    // stored token's. Where the two disagree, the token's proven owner decides.
    let default_owner = stable_default_credential.as_mut().ok().and_then(|stable| {
        resolve_claude_default_home_owner(&login_state, stable, known_identities)
    });
    if let Some(owner) = &default_owner {
        snapshot.diagnostics.extend(owner.split_login_diagnostic());
        if owner.proven.is_none() {
            stable_default_credential = Err(ClaudeSlotProbeFailure::OwnerUnproven);
        }
    }
    // Claude Code uses a configured Bedrock/Vertex route or API key ahead of
    // the stored OAuth login, so it is evaluated first.
    let oauth_usable = matches!(
        login_state,
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending
    );
    let alternative = claude_default_alternative_auth_now(oauth_usable);
    match login_state {
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            let mut refined_seat_plan = None;
            let mut refined_max_plan = None;
            let account = match stable_default_credential.as_ref() {
                Ok(stable) => {
                    match claude_account_from_local_metadata(
                        &stable.oauth_account,
                        &stable.credential,
                    ) {
                        Ok(mut account) => {
                            match require_claude_auth_identity_agreement(
                                &account,
                                &stable.oauth_account,
                            ) {
                                Ok(()) => {
                                    let refined = refine_claude_local_plan_metadata(
                                        &mut account,
                                        &stable.oauth_account,
                                    );
                                    refined_seat_plan = refined.seat_plan;
                                    refined_max_plan = refined.max_plan;
                                    // Positive account + organization identity is
                                    // required before local metadata can stamp
                                    // full-meter identity.
                                    stamp_claude_cli_account_identity(
                                        &mut account,
                                        &stable.oauth_account,
                                    );
                                }
                                Err(failure) => snapshot
                                    .diagnostics
                                    .push(default_claude_identity_diagnostic(failure)),
                            }
                            account
                        }
                        Err(failure) => {
                            snapshot
                                .diagnostics
                                .push(default_claude_identity_diagnostic(failure));
                            claude_signed_in_account_without_identity(
                                (failure != ClaudeSlotProbeFailure::OwnerUnproven)
                                    .then(|| credential_plan.clone())
                                    .flatten(),
                            )
                        }
                    }
                }
                Err(failure) => {
                    snapshot
                        .diagnostics
                        .push(default_claude_identity_diagnostic(*failure));
                    // An unproven owner gets no plan either: the stored plan
                    // may be another account's.
                    claude_signed_in_account_without_identity(
                        (*failure != ClaudeSlotProbeFailure::OwnerUnproven)
                            .then(|| credential_plan.clone())
                            .flatten(),
                    )
                }
            };
            let mut account = account;
            if let Some(alternative) = alternative {
                // The OAuth login still supplies identity, plan and
                // subscription usage; Claude Code itself authenticates, and
                // bills its own usage, the other way.
                account.auth_method = Some(alternative.auth_method().to_string());
                account.billing_channel = Some(alternative.billing_channel().to_string());
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
            if let Some(max_plan) = refined_max_plan.and_then(|plan| claude_plan_name(Some(plan))) {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_max_rate_limit_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude plan tier resolved to {max_plan} from local Claude Code account metadata."
                    ),
                ));
            }
        }
        _ if alternative.is_some() => {
            // No usable OAuth login, but Claude Code authenticates another way:
            // signed in, with no subscription identity or usage.
            let alternative = alternative.expect("checked");
            let mut auth = serde_json::Map::new();
            auth.insert("loggedIn".to_string(), Value::Bool(true));
            auth.insert(
                "authMethod".to_string(),
                Value::from(alternative.auth_method()),
            );
            auth.insert(
                "apiProvider".to_string(),
                Value::from(alternative.api_provider()),
            );
            snapshot.account = Some(parse_claude_auth_json(&Value::Object(auth)));
            snapshot.status = AgentStatusState::Available;
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::IdentityUnknown,
                ));
        }
        ClaudeLocalLoginState::Unreadable => {
            // Fail closed: a failed or malformed read is not "signed out".
            snapshot.account = Some(unsupported_account("anthropic"));
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::ProbeFailed,
                ));
        }
        ClaudeLocalLoginState::NotSignedIn
        | ClaudeLocalLoginState::NeedsLogin
        | ClaudeLocalLoginState::SignedOutByCli => {
            let mut account = unsupported_account("anthropic");
            if login_state == ClaudeLocalLoginState::NotSignedIn {
                account.login_state = AgentLoginState::SignedOut;
            }
            snapshot.account = Some(account);
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::CredentialUnavailable,
                ));
        }
    }
    let version_detected = claude_version_detected();
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
    let strong_oauth_identity = match (
        stable_default_credential.as_ref().ok(),
        snapshot.account.as_ref(),
    ) {
        (Some(stable), Some(account))
            if require_claude_auth_identity_agreement(account, &stable.oauth_account).is_ok() =>
        {
            claude_strong_oauth_identity_hashes(&stable.oauth_account)
        }
        _ => None,
    };
    let claude_account_identifier_hash = strong_oauth_identity
        .as_ref()
        .map(|(account_hash, _)| account_hash.clone())
        .unwrap_or_default();
    let ClaudeDesktopScan {
        observations: desktop_plan_observations,
        pairs: desktop_pairs,
    } = claude_desktop_scan_from_root(
        &claude_desktop_root,
        &snapshot.captured_at,
        desktop_metadata,
    );
    let observable_account_identifier_hashes =
        claude_account_identifier_hashes_from_observations(&desktop_plan_observations);
    let apply_statusline_quota = |snapshot: &mut AgentStatusSnapshot,
                                  quota_capability: &mut AgentCapabilityGap|
     -> bool {
        match collect_claude_statusline_quota_windows(
            &claude_account_identifier_hash,
            &observable_account_identifier_hashes,
        ) {
            Ok(ClaudeStatusLineQuota::Windows(windows)) if !windows.is_empty() => {
                snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                snapshot.diagnostics.push(claude_quota_check_diagnostic(
                        "claude_statusline_read_succeeded",
                        "The supported local statusLine cache was read successfully; its quota windows retain their original observation times.",
                        current_unix_seconds(),
                    ).with_quota_binding(windows[0].account_identifier_hash.clone(), windows[0].organization_identifier_hash.clone()));
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
    if let (Some(stable), Some((account_hash, organization_hash)), Some(account)) = (
        stable_default_credential.as_ref().ok(),
        strong_oauth_identity.as_ref(),
        snapshot.account.as_mut(),
    ) {
        account.account_identifier_hash = Some(account_hash.clone());
        account.organization_identifier_hash = Some(organization_hash.clone());
        if account.account_id.is_none() {
            account.account_id = stable.oauth_account.account_uuid.clone();
        }
        if account.organization_id.is_none() {
            account.organization_id = stable.oauth_account.organization_uuid.clone();
        }
        account.billing_identity_evidence = billing_identity_evidence_for(
            &account.account_identifier_hash,
            &account.organization_identifier_hash,
            &account.credential_fingerprint_hash,
        );
    }
    let oauth_outcome = match (
        strong_oauth_identity.as_ref(),
        stable_default_credential.as_ref().ok(),
    ) {
        (Some((account_hash, organization_hash)), Some(stable)) => {
            let caller = if ClaudeStrongBinding::new(account_hash, organization_hash)
                .is_some_and(|binding| slot_owned_bindings.contains(&binding))
            {
                ClaudeOAuthUsageCaller::DefaultDeferredToSlot
            } else {
                ClaudeOAuthUsageCaller::Default
            };
            collect_claude_oauth_usage_with_credential(
                account_hash,
                organization_hash,
                stable.credential.access_token.clone(),
                stable.credential.access_expires_at.clone(),
                &caller,
                current_unix_seconds,
            )
        }
        _ => {
            claude_oauth_end_caller_run(&ClaudeOAuthUsageCaller::Default);
            ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage requires strong matching local account and organization identity."
                    .to_string(),
            ))
        }
    };
    // Pushed before the quota branch below so the reason the endpoint was or
    // was not called rides the snapshot regardless of which source ends up
    // serving quota. These diagnostics are the alert channel for the circuit
    // breaker: they travel to the backend with the agent-status upload.
    snapshot.diagnostics.extend(oauth_outcome.diagnostics);
    let mut full_oauth_quota_collected = false;
    let mut account_weekly_not_offered = false;
    let mut account_session_not_offered = false;
    match oauth_outcome.result {
        Ok(usage) if !usage.windows.is_empty() => {
            full_oauth_quota_collected = true;
            account_weekly_not_offered = usage.account_weekly_not_offered;
            account_session_not_offered = usage.account_session_not_offered;
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            snapshot.quota_windows = usage.windows;
            snapshot.credit_balances = usage.credit_balances;
            // StatusLine may be newer than the locally cached OAuth answer.
            // Only a source-proven exact account/workspace pair can replace
            // that pair's meter; scoped windows/credits stay independently dated.
            if let Ok(ClaudeStatusLineQuota::Windows(windows)) =
                collect_claude_statusline_quota_windows(
                    &claude_account_identifier_hash,
                    &observable_account_identifier_hashes,
                )
            {
                if prefer_newer_exact_claude_statusline_windows(
                    &mut snapshot.quota_windows,
                    windows,
                ) {
                    snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                    snapshot.diagnostics.push(claude_quota_check_diagnostic(
                        "claude_statusline_newer_exact_binding_selected",
                        "Newer local statusLine readings replaced the matching account/workspace OAuth meters; other meters retain their own observation times.",
                        current_unix_seconds(),
                    ).with_quota_binding(Some(claude_account_identifier_hash.clone()), strong_oauth_identity.as_ref().map(|(_, organization)| organization.clone())));
                }
            }
            quota_capability = supported_capability(
                "quota_windows",
                "Collected from Claude Code's local OAuth usage endpoint.",
            );
        }
        Ok(_) => {
            apply_statusline_quota(&mut snapshot, &mut quota_capability);
        }
        Err(_message) => {
            if !apply_statusline_quota(&mut snapshot, &mut quota_capability) {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_oauth_usage_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    "Couldn't read your Claude limits",
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
                apply_claude_statusline_context_provenance(
                    &mut snapshot,
                    full_oauth_quota_collected,
                );
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
            "Read from local Claude Code login metadata (stored credential deadlines and .claude.json); no Claude command runs.",
        ),
        quota_capability,
        context_capability,
        runtime_defaults.capability,
    ];
    if account_weekly_not_offered {
        snapshot
            .capabilities
            .push(claude_account_weekly_not_offered_capability());
    }
    if account_session_not_offered {
        snapshot
            .capabilities
            .push(claude_account_session_not_offered_capability());
    }
    if let Some(diagnostic) = runtime_defaults.diagnostic {
        snapshot.diagnostics.push(diagnostic);
    }
    if version_detected {
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
    }
    (snapshot, desktop_pairs, default_owner)
}

/// The registered-slot settings for one collection pass. A failed read is
/// retried once (a reader can land between a writer's two atomic renames of
/// the settings file and its sidecar) and then logged: such a pass must not
/// look like a machine without registered slots.
pub(in crate::agent_status) fn load_claude_slot_settings_for_pass(
) -> Result<ClaudeAccountsStatusV1, ottto_core::ClaudeConfigSlotSettingsError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .load()
        .or_else(|_| {
            std::thread::sleep(Duration::from_millis(100));
            store.load()
        })
        .inspect_err(|_| eprintln!("claude_status registered_slots=unavailable"))
}

pub(in crate::agent_status) const CLAUDE_SETTINGS_FAILURE_BOUND_PASSES: u32 = 6;

/// Whether a run of failed settings reads (first failure at `since`, `passes`
/// consecutive failed passes) has outlasted the bound. Pure.
pub(in crate::agent_status) fn claude_settings_failure_outlasted(
    since: Instant,
    passes: u32,
    now: Instant,
) -> bool {
    now.saturating_duration_since(since) >= CLAUDE_SETTINGS_FAILURE_BOUND
        || passes >= CLAUDE_SETTINGS_FAILURE_BOUND_PASSES
}

/// Record this pass's settings read and say whether the failure run has
/// outlasted the bound. A successful read resets it.
pub(in crate::agent_status) fn claude_settings_failure_bound_exceeded(failed: bool) -> bool {
    static RUN: OnceLock<Mutex<Option<(Instant, u32)>>> = OnceLock::new();
    let mut run = RUN
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !failed {
        *run = None;
        return false;
    }
    let (since, passes) = run.get_or_insert((Instant::now(), 0));
    *passes += 1;
    claude_settings_failure_outlasted(*since, *passes, Instant::now())
}
