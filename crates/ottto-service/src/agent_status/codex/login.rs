//! Codex status login operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::billing_identity_hash;
use crate::agent_status::codex_app_server_rate_limit_snapshots;
use crate::agent_status::codex_credit_grants;
use crate::agent_status::codex_home_slots;
use crate::agent_status::codex_saved_quota;
use crate::agent_status::default_codex_home;
use crate::agent_status::effective_user_identity;
use crate::agent_status::extract_email;
use crate::agent_status::extract_plan_type;
use crate::agent_status::first_json_string;
use crate::agent_status::json_timestamp_rfc3339;
use crate::agent_status::looks_like_model_name;
use crate::agent_status::safe_display_label;
use crate::agent_status::unsupported_account;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::CodexAuthCredentials;
use crate::agent_status::CodexCredentialReadError;
use crate::agent_status::CodexHomeTrust;
use crate::agent_status::CodexStrongIdentity;
use crate::agent_status::CodexWorkspaceTargetEvidence;
use crate::agent_status::Command;
use crate::agent_status::Deserialize;
use crate::agent_status::FileCodexAccountSlotSettingsStore;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::Rfc3339;
use crate::agent_status::UtcOffset;
use crate::agent_status::Value;
use crate::agent_status::URL_SAFE_NO_PAD;
use base64::Engine as _;

pub(in crate::agent_status) fn parse_codex_account_text(text: &str) -> Option<AgentAccountStatus> {
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
            confidence: AgentStatusConfidence::Medium,
            ..unsupported_account("openai")
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
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(|plan| format!("chatgpt_{plan}")),
        billing_channel: Some("subscription".to_string()),
        confidence: AgentStatusConfidence::Medium,
        ..unsupported_account("openai")
    })
}

pub(in crate::agent_status) fn read_codex_auth_account_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<Option<AgentAccountStatus>, CodexCredentialReadError> {
    let Some(credentials) = read_codex_auth_credentials_at(codex_home, home_trust)? else {
        return Ok(None);
    };
    let Some(token) = credentials.id_token.as_deref() else {
        return Ok(None);
    };
    Ok(parse_codex_id_token_account(token))
}

pub(in crate::agent_status) fn read_codex_auth_credentials_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<Option<CodexAuthCredentials>, CodexCredentialReadError> {
    let Some(body) = ottto_core::read_codex_auth_file_secure(codex_home, home_trust)
        .map_err(|_| CodexCredentialReadError)?
    else {
        return Ok(None);
    };
    let json: Value = serde_json::from_slice(&body).map_err(|_| CodexCredentialReadError)?;
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
        return Ok(None);
    }
    Ok(Some(CodexAuthCredentials {
        access_token,
        id_token,
        account_id,
    }))
}

pub(in crate::agent_status) fn codex_account_id_from_id_token(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id", "chatgpt_user_id"]))
}

pub(in crate::agent_status) fn parse_codex_id_token_account(
    token: &str,
) -> Option<AgentAccountStatus> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    let plan_type = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_plan_type"]))
        .map(normalize_plan_type)
        .filter(|value| !value.is_empty());
    // `chatgpt_user_id` is the stable user. `chatgpt_account_id` is the
    // currently selected ChatGPT workspace/account and is the value Codex's
    // supported `forced_chatgpt_workspace_id` restriction consumes. Treating
    // the latter as the user collapses two workspaces into two fake users.
    let account_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(&claims, &["sub"]));
    let workspace_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id"]));
    let email = first_json_string(&claims, &["email"]);
    // The same claim object that carries `chatgpt_plan_type` also carries the
    // real subscription period and the time that period evidence was checked.
    // Read them here rather than deriving anything: the backend contract is
    // "reported or absent".
    let subscription_period_start = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_start")
    });
    let subscription_period_end = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_until")
    });
    let subscription_period_last_checked_at = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_last_checked")
    });
    // Deliberately unchanged: a period with no plan, account, email, or
    // organization is not a useful account row, so it does not by itself
    // resurrect one.
    if plan_type.is_none() && account_id.is_none() && email.is_none() && workspace_id.is_none() {
        return None;
    }
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email,
        account_id,
        organization_id: workspace_id,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start,
        subscription_period_end,
        subscription_period_last_checked_at,
        billing_identity_confidence: AgentStatusConfidence::Low,
        confidence: AgentStatusConfidence::Low,
        ..unsupported_account("openai")
    })
}

/// The user and workspace ids a local Codex credential claims: the access
/// token's (live, when `live_access`), agreeing with the stored account id
/// and, when present, the id token at any age. Codex refreshes its login only
/// when due, so the id token may be past its expiry while the access token
/// lives. Decoding a JWT never authenticates it; this names what the
/// credential says, nothing more.
pub(in crate::agent_status) fn codex_credential_claimed_ids(
    credentials: &CodexAuthCredentials,
    live_access: bool,
) -> Option<(String, String)> {
    let access_token = credentials.access_token.as_deref()?;
    let ids = codex_jwt_claimed_ids(&if live_access {
        structurally_valid_live_codex_jwt_claims(access_token)?
    } else {
        structurally_valid_codex_jwt_claims(access_token)?
    })?;
    if credentials.account_id.as_deref() != Some(ids.1.as_str()) {
        return None;
    }
    if let Some(id_token) = credentials.id_token.as_deref() {
        if codex_jwt_claimed_ids(&structurally_valid_codex_jwt_claims(id_token)?)? != ids {
            return None;
        }
    }
    Some(ids)
}

/// The user and workspace ids a decoded Codex JWT names: the auth claim's
/// user id (else `sub`) and its workspace (ChatGPT account) id.
pub(crate) fn codex_jwt_claimed_ids(claims: &Value) -> Option<(String, String)> {
    let auth_claim = claims.get("https://api.openai.com/auth");
    let account_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(claims, &["sub"]))?;
    let workspace_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
        .or_else(|| first_json_string(claims, &["chatgpt_account_id"]))?;
    Some((account_id, workspace_id))
}

/// When the live binding a credential claims
/// ([`codex_credential_claimed_binding`]) lapses: its access token's expiry
/// (the id token is checked at any age). `None` when it cannot be read.
pub(in crate::agent_status) fn codex_credential_claim_lapses_at(
    credentials: &CodexAuthCredentials,
) -> Option<u64> {
    structurally_valid_live_codex_jwt_claims(credentials.access_token.as_deref()?)?
        .get("exp")?
        .as_i64()
        .and_then(|expires_at| u64::try_from(expires_at).ok())
}

/// The account identifier hash the credential claims (not validated), for
/// the provider-call log.
pub(in crate::agent_status) fn codex_credential_claimed_account_hash(
    credentials: &CodexAuthCredentials,
) -> Option<String> {
    let (account_id, _) = codex_credential_claimed_ids(credentials, true)?;
    billing_identity_hash("openai", "account", &account_id)
}

/// The account identifier hash a home's credential claims, for the
/// provider-call log. `None` when it names none or cannot be read (and, in
/// unit tests, for any home outside the scratch dir).
pub(crate) fn codex_home_claimed_account_hash(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Option<String> {
    if !crate::provider_calls::readable_for_account(codex_home) {
        return None;
    }
    let credentials = read_codex_auth_credentials_at(codex_home, home_trust).ok()??;
    codex_credential_claimed_account_hash(&credentials)
}

/// The Codex home a Codex CLI run started with the daemon's environment uses:
/// its `CODEX_HOME`, else `~/.codex`.
pub(crate) fn codex_cli_home() -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .filter(|home| !home.is_empty())
        .map_or_else(default_codex_home, PathBuf::from)
}

/// The account a Codex CLI run started with the daemon's environment signs
/// in as ([`codex_cli_home`]), for the provider-call log.
pub(crate) fn codex_cli_home_claimed_account_hash() -> Option<String> {
    codex_home_claimed_account_hash(&codex_cli_home(), CodexHomeTrust::ProviderDefault)
}

/// The user a Codex access token claims (not validated), hashed like
/// [`codex_credential_claimed_account_hash`], for the provider-call log of a
/// request made with exactly that token.
pub(crate) fn codex_access_token_claimed_account_hash(access_token: &str) -> Option<String> {
    let claims = structurally_valid_live_codex_jwt_claims(access_token)?;
    let account_id = claims
        .get("https://api.openai.com/auth")
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(&claims, &["sub"]))?;
    billing_identity_hash("openai", "account", &account_id)
}

/// The binding key ([`codex_credit_grants::binding_key`]) a local Codex
/// credential claims ([`codex_credential_claimed_ids`]). Only a key to compare
/// with an earlier provider-validated binding; it is never an identity and
/// grants no authority.
pub(in crate::agent_status) fn codex_credential_claimed_binding(
    credentials: &CodexAuthCredentials,
    live_access: bool,
) -> Option<String> {
    let (account_id, raw_workspace_id) = codex_credential_claimed_ids(credentials, live_access)?;
    let (account, workspace) =
        codex_identity_hashes(Some(account_id.as_str()), Some(raw_workspace_id.as_str()));
    Some(codex_credit_grants::binding_key(&account?, &workspace?))
}

/// The canonical hashes of a Codex user id and workspace id, each on its own:
/// the user (`chatgpt_user_id`, else `user_id`, else `sub`) in the "account"
/// role and the selected ChatGPT workspace (`chatgpt_account_id`) in the
/// "workspace" role. Shared so a claimed binding and a raw-only status row
/// cannot spell the same login two ways.
pub(in crate::agent_status) fn codex_identity_hashes(
    account_id: Option<&str>,
    workspace_id: Option<&str>,
) -> (Option<String>, Option<String>) {
    (
        account_id.and_then(|id| billing_identity_hash("openai", "account", id)),
        workspace_id.and_then(|id| billing_identity_hash("openai", "workspace", id)),
    )
}

pub(in crate::agent_status) fn validated_codex_identity(
    credentials: &CodexAuthCredentials,
    provider_account: Option<&Value>,
    rate_limits: Option<&Value>,
    provider_authenticated_active_credential: bool,
) -> Option<CodexStrongIdentity> {
    // Decoding a JWT never authenticates it. This flag is supplied only after
    // the provider has successfully used the active access token for the same
    // quota response. App-server does that after account/read refreshes the
    // credential; the default-only legacy fallback does it when the provider
    // accepts the access token and workspace header for its quota response.
    if !provider_authenticated_active_credential {
        return None;
    }
    let (account_id, raw_workspace_id) = codex_credential_claimed_ids(credentials, true)?;
    let claims = structurally_valid_live_codex_jwt_claims(credentials.access_token.as_deref()?)?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    if let Some(provider_account) = provider_account {
        let active = provider_account.get("account")?;
        if active.get("type").and_then(Value::as_str) != Some("chatgpt") {
            return None;
        }
        let claim_email = codex_access_token_email(&claims)?;
        let active_email = first_json_string(active, &["email"])?;
        if claim_email != active_email {
            return None;
        }
        let claim_plan = auth_claim
            .and_then(|value| first_json_string(value, &["chatgpt_plan_type"]))
            .map(normalize_plan_type)?;
        let active_plan =
            first_json_string(active, &["planType", "plan_type"]).map(normalize_plan_type)?;
        if claim_plan != active_plan {
            return None;
        }
        if rate_limits
            .into_iter()
            .flat_map(codex_app_server_rate_limit_snapshots)
            .filter_map(|(_, snapshot)| first_json_string(snapshot, &["planType", "plan_type"]))
            .map(normalize_plan_type)
            .any(|plan| plan != active_plan)
        {
            return None;
        }
    }
    let superseded_account_identifier_hash =
        billing_identity_hash("openai", "account", &raw_workspace_id);
    // A historical alias read at any id-token age, never current membership.
    let superseded_organization_identifier_hash = credentials
        .id_token
        .as_deref()
        .and_then(structurally_valid_codex_jwt_claims)
        .as_ref()
        .and_then(|id_claims| id_claims.get("https://api.openai.com/auth"))
        .map(codex_organizations)
        .and_then(|organizations| {
            organizations
                .into_iter()
                .find(|organization| organization.is_default)
                .and_then(|organization| organization.id)
        })
        .and_then(|organization_id| {
            billing_identity_hash("openai", "organization", &organization_id)
        });
    Some(CodexStrongIdentity {
        account_identifier_hash: billing_identity_hash("openai", "account", &account_id)?,
        workspace_identifier_hash: billing_identity_hash("openai", "workspace", &raw_workspace_id)?,
        raw_workspace_id,
        superseded_account_identifier_hash,
        superseded_organization_identifier_hash,
    })
}

pub(in crate::agent_status) fn codex_access_token_email(claims: &Value) -> Option<String> {
    claims
        .get("email")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            claims
                .get("https://api.openai.com/profile")
                .and_then(|profile| profile.get("email"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .map(|value| value.trim().to_string())
}

pub(in crate::agent_status) fn structurally_valid_live_codex_jwt_claims(
    token: &str,
) -> Option<Value> {
    let claims = structurally_valid_codex_jwt_claims(token)?;
    let expires_at = claims.get("exp").and_then(Value::as_i64)?;
    (expires_at > OffsetDateTime::now_utc().unix_timestamp()).then_some(claims)
}

/// The claims of a Codex JWT whose shape, algorithm, issuer and audience are
/// plausible. Expiry is not checked here. Decoding never authenticates a
/// token; it only names what the token says.
pub(crate) fn structurally_valid_codex_jwt_claims(token: &str) -> Option<Value> {
    let mut segments = token.split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if segments.next().is_some() || signature.is_empty() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header
        .get("alg")
        .and_then(Value::as_str)
        .map_or(true, |alg| alg == "none")
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    if first_json_string(&claims, &["iss"]).as_deref() != Some("https://auth.openai.com") {
        return None;
    }
    let has_audience = claims.get("aud").is_some_and(|audience| match audience {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str().is_some_and(|value| !value.trim().is_empty())),
        _ => false,
    });
    if !has_audience {
        return None;
    }
    Some(claims)
}

pub(in crate::agent_status) fn codex_app_server_account(
    value: &Value,
) -> Option<AgentAccountStatus> {
    let account = value.get("account")?;
    if account.get("type").and_then(Value::as_str) != Some("chatgpt") {
        return None;
    }
    let plan_type = first_json_string(account, &["planType", "plan_type"])
        .map(normalize_plan_type)
        .filter(|value| !value.is_empty());
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email: first_json_string(account, &["email"]),
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("openai")
    })
}

/// An `account/read` result that names no account (`account: null`) and does
/// not say the provider needs no OpenAI sign-in. A missing field is not this.
pub(in crate::agent_status) fn codex_app_server_account_absent(value: &Value) -> bool {
    value.get("account").is_some_and(Value::is_null)
        && value.get("requiresOpenaiAuth").and_then(Value::as_bool) != Some(false)
}

/// Sanity window for a reported subscription-period boundary, in Unix seconds.
///
/// The claim's wire type is not guaranteed, so a millisecond-encoded value is a
/// real possibility. It lands far outside this window and therefore reads as
/// "not reported" rather than as a year-57000 renewal date.
pub(in crate::agent_status) const SUBSCRIPTION_PERIOD_MIN_UNIX_SECONDS: i64 = 1_420_070_400; // 2015-01-01T00:00:00Z

pub(in crate::agent_status) const SUBSCRIPTION_PERIOD_MAX_UNIX_SECONDS: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

/// Read one subscription-period boundary from a provider auth claim.
///
/// Format-tolerant by design: epoch seconds (number or numeric string) and
/// RFC3339 strings are both accepted and normalized to an offset-bearing UTC
/// RFC3339 timestamp. Anything unparseable, or outside the sanity window,
/// returns `None`. No failure path substitutes `now`.
pub(in crate::agent_status) fn subscription_period_timestamp(
    value: &Value,
    key: &str,
) -> Option<String> {
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

#[derive(Debug, Clone)]
pub(in crate::agent_status) struct CodexOrganization {
    pub(in crate::agent_status) id: Option<String>,
    pub(in crate::agent_status) label: Option<String>,
    pub(in crate::agent_status) is_default: bool,
    pub(in crate::agent_status) plan_type: Option<String>,
}

pub(in crate::agent_status) fn codex_workspace_target_evidence_from_id_token(
    token: &str,
    observed_at: &str,
) -> Option<Vec<CodexWorkspaceTargetEvidence>> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth")?;
    let account_identifier_hash = first_json_string(auth_claim, &["chatgpt_user_id", "user_id"])
        .or_else(|| first_json_string(&claims, &["sub"]))
        .as_deref()
        .and_then(|value| billing_identity_hash("openai", "account", value));
    let account_label = safe_display_label(first_json_string(&claims, &["email"]).as_deref());
    let claimed_plan_type = safe_display_label(
        first_json_string(auth_claim, &["chatgpt_plan_type", "plan_type"]).as_deref(),
    );
    Some(
        codex_organizations(auth_claim)
            .into_iter()
            .map(|organization| CodexWorkspaceTargetEvidence {
                account_identifier_hash: account_identifier_hash.clone(),
                workspace_identifier_hash: organization
                    .id
                    .as_deref()
                    .and_then(|value| billing_identity_hash("openai", "workspace", value)),
                workspace_label: safe_display_label(organization.label.as_deref()),
                account_label: account_label.clone(),
                plan_type: organization
                    .plan_type
                    .clone()
                    .and_then(|plan| safe_display_label(Some(plan.as_str())))
                    .or_else(|| {
                        organization
                            .is_default
                            .then(|| claimed_plan_type.clone())
                            .flatten()
                    }),
                is_default: organization.is_default,
                observed_at: observed_at.to_string(),
            })
            .collect(),
    )
}

pub(in crate::agent_status) fn codex_organizations(value: &Value) -> Vec<CodexOrganization> {
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

pub(in crate::agent_status) fn merge_codex_accounts(
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
        subscription_period_last_checked_at: auth_account
            .subscription_period_last_checked_at
            .or(existing.subscription_period_last_checked_at),
        account_identifier_hash: auth_account
            .account_identifier_hash
            .or(existing.account_identifier_hash),
        organization_identifier_hash: auth_account
            .organization_identifier_hash
            .or(existing.organization_identifier_hash),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: auth_account
            .credential_fingerprint_hash
            .or(existing.credential_fingerprint_hash),
        billing_identity_evidence: auth_account
            .billing_identity_evidence
            .or(existing.billing_identity_evidence),
        claude_quota_access_state: auth_account
            .claude_quota_access_state
            .or(existing.claude_quota_access_state),
        claude_anchor_durability: auth_account
            .claude_anchor_durability
            .or(existing.claude_anchor_durability),
        claude_anchor_health: auth_account
            .claude_anchor_health
            .or(existing.claude_anchor_health),
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

pub(in crate::agent_status) fn normalize_plan_type(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(|c: char| c.is_whitespace() || c == '-' || c == '/', "_")
}

pub(in crate::agent_status) fn chatgpt_subscription_product(plan_type: String) -> String {
    if plan_type.starts_with("chatgpt_") {
        plan_type
    } else {
        format!("chatgpt_{plan_type}")
    }
}

/// Match Codex's explicit-mode precedence. ChatGPT login can retain an
/// exchanged API key; explicit API/unknown modes cannot inherit stale OAuth.
pub(crate) fn session_launch_codex_api_key_route(home: &Path, trust: CodexHomeTrust) -> bool {
    let Some(value) = ottto_core::read_codex_auth_file_secure(home, trust)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return false;
    };
    if let Some(mode) = value.get("auth_mode").filter(|mode| !mode.is_null()) {
        return mode.as_str() != Some("chatgpt");
    }
    // Legacy inference is used only without an explicit mode.
    [
        "OPENAI_API_KEY",
        "personal_access_token",
        "bedrock_api_key",
        "bedrock_access_keys",
    ]
    .iter()
    .any(|key| value.get(key).is_some_and(|value| !value.is_null()))
}

/// Accepted registered Codex slots (never a process-only home), login cause.
pub(crate) fn registered_codex_creator_slots() -> Vec<(String, String, usize)> {
    let Ok(status) = FileCodexAccountSlotSettingsStore::default().load() else {
        return Vec::new();
    };
    let env_api_key = ["OPENAI_API_KEY", "CODEX_API_KEY"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()));
    let slots = codex_home_slots(&status).into_iter();
    slots
        .filter_map(|slot| {
            let (account, workspace) = slot.registered_binding?;
            let cause = codex_slot_login_cause(&slot.home, env_api_key);
            Some((account, workspace, cause))
        })
        .collect()
}

/// Named only with forced ChatGPT config, `chatgpt` auth mode and no API key
/// there or in the env; unreadable refuses. Only these fields are decoded.
pub(crate) fn codex_slot_login_cause(home: &Path, env_api_key: bool) -> usize {
    use crate::codex_scan_diagnostics::*;
    #[derive(Deserialize)]
    struct SavedLogin {
        auth_mode: Option<String>,
        #[serde(rename = "OPENAI_API_KEY", default)]
        api_key: Option<serde::de::IgnoredAny>,
    }
    let config = ottto_core::read_codex_config_file_secure(home, CodexHomeTrust::Managed);
    let forced = config.ok().flatten().and_then(|body| {
        let config: toml_edit::DocumentMut = String::from_utf8(body).ok()?.parse().ok()?;
        Some(config.get("forced_login_method")?.as_str()? == "chatgpt")
    });
    let auth = ottto_core::read_codex_auth_file_secure(home, CodexHomeTrust::Managed);
    let saved = auth.ok().flatten();
    let saved = saved.and_then(|auth| serde_json::from_slice::<SavedLogin>(&auth).ok());
    match saved.filter(|saved| saved.auth_mode.as_deref() == Some("chatgpt")) {
        _ if forced != Some(true) => CREATOR_NOT_FORCED_CHATGPT,
        None => CREATOR_MODE_UNREADABLE,
        Some(saved) if saved.api_key.is_some() || env_api_key => CREATOR_API_KEY,
        Some(_) => CREATOR_NAMED,
    }
}

pub(crate) fn session_launch_codex_identity(
    home: &Path,
    trust: CodexHomeTrust,
) -> Option<(String, String)> {
    if session_launch_codex_api_key_route(home, trust) {
        return None;
    }
    let binding = codex_saved_quota::held_launch_binding(home, trust)?;
    let (account, workspace) = binding.split_once(':')?;
    Some((account.to_string(), workspace.to_string()))
}

pub(in crate::agent_status) fn read_codex_config_model_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Option<String> {
    let body = ottto_core::read_codex_config_file_secure(codex_home, home_trust).ok()??;
    let body = std::str::from_utf8(&body).ok()?;
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

/// `codex login` for one managed home, with the same binary, PATH and clean
/// environment as the home's quota reads. `None` when Codex is not found.
pub(crate) fn codex_login_command(codex_home: &Path) -> Option<Command> {
    resolved_codex_home_command(codex_home, &["login"], false)
}

/// Resolve Codex once and run it with one exact credential home. Ambient
/// provider credentials are deliberately excluded so a managed slot cannot
/// silently fall back to the default account or an API key.
pub(in crate::agent_status) fn resolved_codex_home_command(
    codex_home: &Path,
    args: &[&str],
    _allow_ambient_environment: bool,
) -> Option<Command> {
    let identity = effective_user_identity()?;
    let program_path = crate::command_env::executable_path("codex")?;
    let mut command = Command::new(program_path);
    command.args(args).env_clear();
    command
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name)
        .env("CODEX_HOME", codex_home)
        .env("CODEX_SQLITE_HOME", codex_home);
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    Some(command)
}
