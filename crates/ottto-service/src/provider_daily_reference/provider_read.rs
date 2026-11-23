//! The one provider read: its credential and login shapes, the single route it
//! may contact, and why a read did not produce a payload.

use super::state::ProviderFailure;
use super::wire::AccountIdentityHashes;
use super::{logins, PROVIDER_ENDPOINT, PROVIDER_TIMEOUT};
use anyhow::Result;
use serde_json::Value;
use std::fmt;

/// Why a provider read did not produce a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderReadError {
    /// 401/403 - the credential no longer authorizes this read.
    AuthRejected(u16),
    /// The answer is not the shape we normalize: unreadable body, no day rows,
    /// or a status that says the route moved (400/404/410).
    ResponseShape(String),
    /// 429 beyond ordinary politeness.
    RateLimited,
    /// A `users` count above one: the answer covers more than the signed-in
    /// user. Counted as a shape failure.
    WorkspaceWide,
    /// 5xx and transport failures. Never counted against the breaker.
    Transient(String),
}

impl ProviderReadError {
    pub(super) fn failure_class(&self) -> Option<ProviderFailure> {
        match self {
            ProviderReadError::AuthRejected(_) => Some(ProviderFailure::AuthRejected),
            ProviderReadError::ResponseShape(_) => Some(ProviderFailure::ResponseShape),
            ProviderReadError::RateLimited => Some(ProviderFailure::RateLimited),
            ProviderReadError::WorkspaceWide => Some(ProviderFailure::ResponseShape),
            ProviderReadError::Transient(_) => None,
        }
    }

    pub(super) fn category(&self) -> &'static str {
        match self {
            ProviderReadError::AuthRejected(_) => "provider_auth_rejected",
            ProviderReadError::ResponseShape(_) => "provider_response_shape",
            ProviderReadError::RateLimited => "provider_rate_limited",
            ProviderReadError::WorkspaceWide => "workspace_wide_answer",
            ProviderReadError::Transient(_) => "provider_unavailable",
        }
    }

    /// The HTTP status, where one alone classifies the failure. Free-form
    /// detail strings are never logged: they can echo provider output.
    pub(super) fn http_status(&self) -> Option<u16> {
        match self {
            ProviderReadError::AuthRejected(status) => Some(*status),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Provider read
// ---------------------------------------------------------------------------

/// Read one bounded day window from the provider.
pub trait ProviderDailyUsageReader {
    fn fetch_window(
        &self,
        credential: &CodexCredential,
        start_date: &str,
        end_date: &str,
    ) -> Result<Value, ProviderReadError>;
}

/// The Codex credential this read uses. The daemon reads the customer's own
/// already-issued token from their own `~/.codex/auth.json`; it never mints,
/// refreshes, or stores one.
#[derive(Clone, PartialEq, Eq)]
pub struct CodexCredential {
    pub access_token: String,
    pub account_id: Option<String>,
    /// Stable provider account scope used only to derive row attribution.
    /// Disclosure v2 authorization never gates on this value.
    pub account_scope: String,
}

/// Presence only: the token, header and scope never reach formatted output.
impl fmt::Debug for CodexCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCredential")
            .field("account_id_present", &self.account_id.is_some())
            .finish_non_exhaustive()
    }
}

/// One Codex login a cycle reads with: its credential, the account identity
/// its live access token proves (if any), and when that token lapses. Built
/// only by [`logins::read_home`] from one secure read and one parse.
#[derive(Clone)]
pub(crate) struct CodexLogin {
    pub(super) home_kind: logins::LoginHomeKind,
    pub(super) credential: CodexCredential,
    pub(super) identity: Option<AccountIdentityHashes>,
    pub(super) lapses_at: u64,
}

impl fmt::Debug for CodexLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexLogin")
            .field("home_kind", &self.home_kind.label())
            .field("identified", &self.identity.is_some())
            .finish_non_exhaustive()
    }
}

/// The one provider route this capability may contact.
pub struct ChatGptDailyUsageReader;

impl ProviderDailyUsageReader for ChatGptDailyUsageReader {
    fn fetch_window(
        &self,
        credential: &CodexCredential,
        start_date: &str,
        end_date: &str,
    ) -> Result<Value, ProviderReadError> {
        // `workspace_user=true` scopes the answer to the signed-in user's own
        // usage. Without it a workspace member could be handed workspace-wide
        // numbers, which would be compared against one user's Ottto totals.
        let url = format!(
            "{PROVIDER_ENDPOINT}?start_date={start_date}&end_date={end_date}&group_by=day&workspace_user=true"
        );
        let mut request = crate::retry_tls::agent()
            .get(&url)
            .timeout(PROVIDER_TIMEOUT)
            .set("Accept", "application/json")
            // Be trivially identifiable and trivially benign. Never a
            // provider-client User-Agent.
            .set("User-Agent", &crate::agent_status::ottto_user_agent())
            .set(
                "Authorization",
                &format!("Bearer {}", credential.access_token),
            );
        if let Some(account_id) = credential.account_id.as_deref() {
            request = request.set("ChatGPT-Account-Id", account_id);
        }
        // The user the request's own token names, as every other Codex line
        // does (`account_id` is the workspace).
        let account =
            crate::agent_status::codex_access_token_claimed_account_hash(&credential.access_token);
        let started = std::time::Instant::now();
        let response = request.call();
        crate::provider_calls::record(crate::provider_calls::ProviderCall::observed(
            crate::provider_calls::Provider::Openai,
            crate::provider_calls::CallKind::CodexDailyWorkspaceUsage,
            crate::provider_calls::trigger_or(crate::provider_calls::Trigger::Schedule),
            account.as_deref(),
            crate::provider_calls::http_result(&response),
            started.elapsed(),
        ));
        match response {
            Ok(response) => response
                .into_json::<Value>()
                .map_err(|error| ProviderReadError::ResponseShape(format!("unreadable: {error}"))),
            Err(ureq::Error::Status(status @ (401 | 403), _response)) => {
                Err(ProviderReadError::AuthRejected(status))
            }
            Err(ureq::Error::Status(429, _response)) => Err(ProviderReadError::RateLimited),
            Err(ureq::Error::Status(status @ (400 | 404 | 410), _response)) => Err(
                ProviderReadError::ResponseShape(format!("unexpected status {status}")),
            ),
            Err(ureq::Error::Status(status, _response)) => Err(ProviderReadError::Transient(
                format!("provider status {status}"),
            )),
            Err(_) => Err(ProviderReadError::Transient("transport error".to_string())),
        }
    }
}

pub(super) fn codex_credential_from_auth(json: &Value) -> Option<CodexCredential> {
    let access_token = json
        .pointer("/tokens/access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let account_id = ["account_id", "chatgpt_account_id"]
        .iter()
        .find_map(|key| {
            json.get(*key).and_then(Value::as_str).or_else(|| {
                json.pointer(&format!("/tokens/{key}"))
                    .and_then(Value::as_str)
            })
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    // The account scope must identify the provider account, not the token: a
    // token rotation must not read as a different account and invalidate the
    // customer's consent.
    let account_scope = account_id.clone().or_else(|| {
        json.pointer("/tokens/id_token")
            .and_then(Value::as_str)
            .and_then(id_token_account_scope)
    })?;
    Some(CodexCredential {
        access_token: access_token.to_string(),
        account_id,
        account_scope,
    })
}

/// Pull the ChatGPT account claim out of an id token, without verifying it: it
/// is used only as a local, stable account scope that is immediately hashed.
fn id_token_account_scope(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let decoded = base64_url_decode(payload)?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    let auth = json.get("https://api.openai.com/auth")?;
    ["chatgpt_account_id", "chatgpt_user_id"]
        .iter()
        .find_map(|key| auth.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let index = ALPHABET.iter().position(|candidate| *candidate == byte)? as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}
