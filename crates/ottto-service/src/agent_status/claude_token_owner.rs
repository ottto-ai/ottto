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

use std::collections::BTreeMap;
#[cfg(not(test))]
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

/// Each slot's latest token and its verdict: one entry per slot, since a slot
/// holds one token at a time. Tests keep one map per test thread.
type Memo = BTreeMap<String, (String, Verdict)>;
/// Past this many slots the memo restarts, costing at most repeated calls.
const MAX_MEMOIZED_SLOTS: usize = 32;

#[cfg(not(test))]
static LAST: Mutex<Memo> = Mutex::new(BTreeMap::new());

#[cfg(not(test))]
fn with_last<R>(use_last: impl FnOnce(&mut Memo) -> R) -> R {
    use_last(
        &mut LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

#[cfg(test)]
thread_local! {
    static LAST: std::cell::RefCell<Memo> = const { std::cell::RefCell::new(BTreeMap::new()) };
}

#[cfg(test)]
fn with_last<R>(use_last: impl FnOnce(&mut Memo) -> R) -> R {
    LAST.with(|last| use_last(&mut last.borrow_mut()))
}

/// A content fingerprint of the stored token (never a file time).
pub(super) fn credential_fingerprint(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-credential-fingerprint:v1\0");
    hasher.update(access_token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The proven owner of `access_token`, or `None` while unproven. The provider
/// is asked at most once per token, and again after a failure only once its
/// back-off has passed; `may_call` false serves the remembered verdict only.
/// No lock is held during the call.
pub(super) fn proven_owner(access_token: &str, may_call: bool) -> Option<ProvenOwner> {
    proven_slot_owner("default", access_token, may_call)
}

/// `proven_owner` for one slot's token.
pub(super) fn proven_slot_owner(
    slot_id: &str,
    access_token: &str,
    may_call: bool,
) -> Option<ProvenOwner> {
    let fingerprint = credential_fingerprint(access_token);
    let failures = with_last(|last| match last.get(slot_id) {
        Some((known, verdict)) if *known == fingerprint => match verdict {
            Verdict::Proven(owner) => Err(Some(owner.clone())),
            Verdict::Failed { retry_at, .. } if Instant::now() < *retry_at => Err(None),
            Verdict::Failed { failures, .. } => Ok(*failures),
        },
        _ => Ok(0),
    });
    let failures = match failures {
        Ok(failures) if may_call => failures,
        Ok(_) => return None,
        Err(remembered) => return remembered,
    };
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
    with_last(|last| {
        if last.len() >= MAX_MEMOIZED_SLOTS && !last.contains_key(slot_id) {
            last.clear();
        }
        last.insert(slot_id.to_owned(), (fingerprint, verdict));
    });
    owner
}

fn fetch_owner(access_token: &str) -> Option<ProvenOwner> {
    #[cfg(test)]
    let injected = Some(PROFILE_TEST_RESPONSE
        .with(std::cell::Cell::get)
        .unwrap_or(default_home_profile)());
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

/// Test-only stand-in for the profile endpoint: a 200 body (`Ok`) or an HTTP
/// status (`Err`).
#[cfg(test)]
pub(super) type ProfileResponder = fn() -> Result<Value, u16>;

#[cfg(test)]
thread_local! {
    /// The responder for this test's thread.
    pub(super) static PROFILE_TEST_RESPONSE: std::cell::Cell<Option<ProfileResponder>> =
        const { std::cell::Cell::new(None) };
}

/// Tests without a responder: the token belongs to the account the test
/// home's default `.claude.json` names.
#[cfg(test)]
fn default_home_profile() -> Result<Value, u16> {
    let path = ottto_core::ClaudeConfigDirSlot::Default.identity_path(&super::home_dir());
    let account = super::read_claude_cli_oauth_account(&path).ok_or(404_u16)?;
    Ok(serde_json::json!({
        "account": {"uuid": account.account_uuid},
        "organization": {"uuid": account.organization_uuid},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(account: &str) -> Result<Value, u16> {
        Ok(json!({
            "account": {"uuid": account},
            "organization": {"uuid": "11111111-1111-4111-8111-111111111111"},
        }))
    }
    fn first_owner() -> Result<Value, u16> {
        profile("22222222-2222-4222-8222-222222222222")
    }
    fn second_owner() -> Result<Value, u16> {
        profile("33333333-3333-4333-8333-333333333333")
    }
    fn unavailable() -> Result<Value, u16> {
        Err(503)
    }
    fn panics() -> Result<Value, u16> {
        panic!("this token's verdict is memoized")
    }
    fn answer(responder: ProfileResponder) {
        PROFILE_TEST_RESPONSE.with(|cell| cell.set(Some(responder)));
    }

    #[test]
    fn no_call_means_not_yet_and_asks_nothing() {
        answer(panics);
        assert_eq!(proven_slot_owner("slot-a", "token-none", false), None);
    }

    #[test]
    fn a_failed_call_means_not_yet_and_waits_for_its_back_off() {
        answer(unavailable);
        assert_eq!(proven_slot_owner("slot-a", "token-failed", true), None);
        answer(panics);
        assert_eq!(proven_slot_owner("slot-a", "token-failed", true), None);
    }

    #[test]
    fn one_call_per_token_per_slot_and_other_owners_are_told_apart() {
        answer(first_owner);
        let first = proven_slot_owner("slot-a", "token-1", true).unwrap();
        answer(second_owner);
        let other = proven_slot_owner("slot-b", "token-2", true).unwrap();
        assert_ne!(first.account_hash, other.account_hash);
        assert_eq!(first.organization_hash, other.organization_hash);
        // Same owner: each slot's verdict is memoized side by side.
        answer(panics);
        assert_eq!(
            proven_slot_owner("slot-a", "token-1", true).as_ref(),
            Some(&first)
        );
        assert_eq!(
            proven_slot_owner("slot-b", "token-2", false).as_ref(),
            Some(&other)
        );
        // A new token in the same slot is a new question.
        answer(second_owner);
        assert_eq!(
            proven_slot_owner("slot-a", "token-3", true).map(|owner| owner.account_hash),
            Some(other.account_hash)
        );
    }

    #[test]
    fn the_default_home_shares_the_slot_memo() {
        answer(first_owner);
        let default = proven_owner("token-d", true).unwrap();
        answer(panics);
        assert_eq!(proven_slot_owner("default", "token-d", true), Some(default));
    }
}
