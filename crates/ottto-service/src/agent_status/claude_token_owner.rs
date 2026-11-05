//! Which account owns a Claude home's stored token.
//!
//! A Claude folder has more than one writer: a Claude Desktop Code session
//! writes `.claude.json` `oauthAccount` for Desktop's account, while a
//! terminal `claude` keeps its own login in the folder's keychain item. The
//! token's owner is the account that is billed, so it is proven with that
//! token (`GET /api/oauth/profile`) and `.claude.json` is only a display cache.
//! The default home and registered slots use the same check.
//!
//! Only the account and organization uuids are read; they are hashed with the
//! existing identity scheme and the body is dropped. The verdict lives in
//! memory, one token per home (`"default"` or the slot id), keyed by a
//! fingerprint of the token itself: one call per token, with back-off after a
//! failure.

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

/// Each home's latest token and its verdict, keyed by home: one entry for
/// the default home and one per registered slot, bounded by the registered
/// slots. Tests keep one map per test thread.
type Owners = BTreeMap<String, (String, Verdict)>;

#[cfg(not(test))]
static OWNERS: Mutex<Owners> = Mutex::new(BTreeMap::new());

#[cfg(not(test))]
fn with_owners<R>(use_owners: impl FnOnce(&mut Owners) -> R) -> R {
    use_owners(
        &mut OWNERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

#[cfg(test)]
thread_local! {
    static OWNERS: std::cell::RefCell<Owners> = const { std::cell::RefCell::new(BTreeMap::new()) };
}

#[cfg(test)]
fn with_owners<R>(use_owners: impl FnOnce(&mut Owners) -> R) -> R {
    OWNERS.with(|owners| use_owners(&mut owners.borrow_mut()))
}

/// Drop a removed slot's verdict.
pub(super) fn forget(home: &str) {
    with_owners(|owners| {
        owners.remove(home);
    });
}

/// A content fingerprint of the stored token (never a file time).
fn credential_fingerprint(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-credential-fingerprint:v1\0");
    hasher.update(access_token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The proven owner of `access_token`, the token `home` stores, or `None`
/// while unproven. The provider is asked at most once per token, and again
/// after a failure only once its back-off has passed; `may_call` false serves
/// the remembered verdict only. No lock is held during the call.
pub(super) fn proven_owner(home: &str, access_token: &str, may_call: bool) -> Option<ProvenOwner> {
    let fingerprint = credential_fingerprint(access_token);
    let failures = with_owners(|owners| match owners.get(home) {
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
    #[cfg(test)]
    let injected = Some(test_profile_response(home, access_token));
    #[cfg(not(test))]
    let injected = None;
    let verdict = match fetch_owner(access_token, injected) {
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
    with_owners(|owners| {
        owners.insert(home.to_string(), (fingerprint, verdict));
    });
    owner
}

/// `injected` stands in for the endpoint in tests: a 200 body or a status.
fn fetch_owner(access_token: &str, injected: Option<Result<Value, u16>>) -> Option<ProvenOwner> {
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

/// Test-only stand-in for the profile endpoint, given the token sent: a 200
/// body (`Ok`) or an HTTP status (`Err`).
#[cfg(test)]
pub(super) type ProfileResponder = fn(&str) -> Result<Value, u16>;

#[cfg(test)]
thread_local! {
    /// The responder for this test's thread.
    pub(super) static PROFILE_TEST_RESPONSE: std::cell::Cell<Option<ProfileResponder>> =
        const { std::cell::Cell::new(None) };
}

/// The responder's answer; without one, the token belongs to the account its
/// own home's `.claude.json` names (the default home's, or the registered
/// slot's), as a sign-in there leaves it.
#[cfg(test)]
fn test_profile_response(home: &str, access_token: &str) -> Result<Value, u16> {
    if let Some(respond) = PROFILE_TEST_RESPONSE.with(std::cell::Cell::get) {
        return respond(access_token);
    }
    let slot = if home == "default" {
        ottto_core::ClaudeConfigDirSlot::Default
    } else {
        let settings = super::FileClaudeConfigSlotSettingsStore::default()
            .load()
            .map_err(|_| 404_u16)?;
        let descriptor = settings
            .managed_slots
            .iter()
            .chain(&settings.external_slots)
            .find(|descriptor| descriptor.slot_id == home)
            .ok_or(404_u16)?;
        super::claude_config_slot_for_descriptor(descriptor).ok_or(404_u16)?
    };
    let account = super::read_claude_cli_oauth_account(&slot.identity_path(&super::home_dir()))
        .ok_or(404_u16)?;
    Ok(serde_json::json!({
        "account": {"uuid": account.account_uuid},
        "organization": {"uuid": account.organization_uuid},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] Each home keeps its own verdict: the default home and a
    /// slot proving in turn over two passes make one call each, never
    /// evicting each other, and removing the slot drops only its verdict.
    #[test]
    fn each_home_keeps_its_own_verdict_until_the_slot_is_removed() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn respond(token: &str) -> Result<Value, u16> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({
                "account": {"uuid": format!("account-{token}")},
                "organization": {"uuid": format!("organization-{token}")},
            }))
        }
        PROFILE_TEST_RESPONSE.with(|cell| cell.set(Some(respond)));
        for _ in 0..2 {
            assert!(proven_owner("default", "default-token", true).is_some());
            assert!(proven_owner("claude_slot_owner", "slot-token", true).is_some());
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 2, "one call per home's token");
        forget("claude_slot_owner");
        assert!(proven_owner("claude_slot_owner", "slot-token", false).is_none());
        assert!(proven_owner("default", "default-token", false).is_some());
        PROFILE_TEST_RESPONSE.with(|cell| cell.set(None));
    }
}
