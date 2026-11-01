//! Which account owns the default Claude home's token.
//!
//! The default `~/.claude` has more than one writer: a Claude Desktop Code
//! session writes `.claude.json` `oauthAccount` for Desktop's account, while
//! a terminal `claude` keeps its own login in the default keychain item. The
//! token's owner is the account that is billed, so it is proven with that
//! token (`GET /api/oauth/profile`) and `.claude.json` is only a display cache.
//!
//! Only the account and organization uuids are read; they are hashed with the
//! existing identity scheme and the body is dropped. The verdict lives in
//! memory, keyed by a fingerprint of the token itself: one call per token,
//! with back-off after a failure.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

const CLAUDE_OAUTH_PROFILE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/profile";
const FIRST_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(60 * 60);

/// The account and organization hashes a token was proven to belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProvenOwner {
    pub(super) account_hash: String,
    pub(super) organization_hash: String,
    pub(super) proven_at: String,
}

enum Verdict {
    Proven(ProvenOwner),
    Failed { retry_at: Instant, failures: u32 },
}

/// The latest default-home token and its verdict. One entry: the default home
/// holds one token at a time.
static LAST: Mutex<Option<(String, Verdict)>> = Mutex::new(None);

/// A content fingerprint of the stored token (never a file time).
fn credential_fingerprint(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-credential-fingerprint:v1\0");
    hasher.update(access_token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The proven owner of `access_token`, or `None` while unproven. The provider
/// is asked at most once per token, and again after a failure only once its
/// back-off has passed; `may_call` false serves the remembered verdict only.
/// `cached` is the `.claude.json` binding, read only by tests.
pub(super) fn proven_owner(
    access_token: &str,
    may_call: bool,
    cached: Option<&(String, String)>,
) -> Option<ProvenOwner> {
    // Tests that install no profile responder keep today's pairing: the token
    // belongs to the cached account, and nothing is remembered.
    #[cfg(test)]
    if PROFILE_TEST_RESPONSE.with(std::cell::Cell::get).is_none() {
        return cached.map(|(account_hash, organization_hash)| ProvenOwner {
            account_hash: account_hash.clone(),
            organization_hash: organization_hash.clone(),
            proven_at: crate::current_rfc3339_timestamp(),
        });
    }
    #[cfg(not(test))]
    let _ = cached;
    let fingerprint = credential_fingerprint(access_token);
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let failures = match last.as_ref() {
        Some((known, verdict)) if *known == fingerprint => match verdict {
            Verdict::Proven(owner) => return Some(owner.clone()),
            Verdict::Failed { retry_at, .. } if Instant::now() < *retry_at => return None,
            Verdict::Failed { failures, .. } => *failures,
        },
        _ => 0,
    };
    if !may_call {
        return None;
    }
    let verdict = match fetch_owner(access_token) {
        Some(owner) => Verdict::Proven(owner),
        None => {
            let failures = failures.saturating_add(1);
            let retry = FIRST_RETRY
                .saturating_mul(1 << failures.saturating_sub(1).min(6))
                .min(MAX_RETRY);
            Verdict::Failed {
                retry_at: Instant::now() + retry,
                failures,
            }
        }
    };
    let owner = match &verdict {
        Verdict::Proven(owner) => Some(owner.clone()),
        Verdict::Failed { .. } => None,
    };
    *last = Some((fingerprint, verdict));
    owner
}

fn fetch_owner(access_token: &str) -> Option<ProvenOwner> {
    #[cfg(test)]
    let injected = PROFILE_TEST_RESPONSE
        .with(std::cell::Cell::get)
        .map(|respond| respond());
    #[cfg(not(test))]
    let injected: Option<Result<Value, u16>> = None;
    let started = Instant::now();
    let response = match injected {
        Some(Ok(body)) => Ok(body),
        Some(Err(status)) => Err(crate::provider_calls::CallResult::Http(status)),
        None => {
            let response = crate::retry_tls::agent()
                .get(CLAUDE_OAUTH_PROFILE_ENDPOINT)
                .set("Accept", "application/json")
                .set("Authorization", &format!("Bearer {access_token}"))
                .set("anthropic-beta", super::CLAUDE_OAUTH_BETA_HEADER)
                .set("User-Agent", &super::ottto_user_agent())
                .timeout(super::COMMAND_TIMEOUT)
                .call();
            match crate::provider_calls::http_result(&response) {
                crate::provider_calls::CallResult::Ok => response
                    .ok()
                    .and_then(|response| response.into_json::<Value>().ok())
                    .ok_or(crate::provider_calls::CallResult::Error("invalid_body")),
                failed => Err(failed),
            }
        }
    };
    let owner = response.as_ref().ok().and_then(owner_from_profile);
    let result = match (&response, &owner) {
        (Err(failed), _) => *failed,
        (Ok(_), None) => crate::provider_calls::CallResult::Error("no_owner"),
        (Ok(_), Some(_)) => crate::provider_calls::CallResult::Ok,
    };
    {
        use crate::provider_calls::{CallKind, Provider, ProviderCall, Trigger};
        crate::provider_calls::record(ProviderCall::observed(
            Provider::Anthropic,
            CallKind::ClaudeOauthProfile,
            crate::provider_calls::trigger_or(Trigger::Schedule),
            owner.as_ref().map(|owner| owner.account_hash.as_str()),
            result,
            started.elapsed(),
        ));
    }
    owner
}

/// Hash the two uuids; everything else in the body is dropped with it.
fn owner_from_profile(body: &Value) -> Option<ProvenOwner> {
    let uuid = |pointer: &str| body.pointer(pointer).and_then(Value::as_str);
    Some(ProvenOwner {
        account_hash: super::billing_identity_hash("anthropic", "account", uuid("/account/uuid")?)?,
        organization_hash: super::billing_identity_hash(
            "anthropic",
            "organization",
            uuid("/organization/uuid")?,
        )?,
        proven_at: crate::current_rfc3339_timestamp(),
    })
}

#[cfg(test)]
thread_local! {
    /// Test-only stand-in for the profile endpoint on this test's thread: a
    /// 200 body (`Ok`) or an HTTP status (`Err`).
    pub(super) static PROFILE_TEST_RESPONSE: std::cell::Cell<Option<fn() -> Result<Value, u16>>> =
        const { std::cell::Cell::new(None) };
}
