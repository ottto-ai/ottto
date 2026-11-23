//! The Codex logins a daily-reference read may use.
//!
//! A login is read with one secure read and one parse of its home's
//! `auth.json`. The request header, the attribution scope and the account
//! identity all come from that one parse, so they always describe the same
//! credential. Identity and expiry come from the live access token; an id
//! token only cross-checks it and never by itself skips a login.

use super::{
    codex_credential_from_auth, opaque_key, AccountIdentityHashes, CodexCredential, CodexLogin,
};
use crate::agent_status::{
    codex_jwt_claimed_ids, structurally_valid_codex_jwt_claims, DailyReferenceHome,
};
use ottto_core::{billing_identity_hash, read_codex_auth_file_secure, CodexHomeTrust};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A token that lapses within this margin is not used for a request.
pub(crate) const LAPSE_MARGIN_SECONDS: u64 = 300;

/// What an access token says about the read it would make.
pub(crate) enum ReadIdentity {
    /// Not a structurally valid Codex token, or its expiry is unreadable.
    Unusable,
    Usable {
        lapses_at: u64,
        /// `Some` only when the token names both ids, its workspace is the
        /// request's `ChatGPT-Account-Id`, and any id token agrees.
        identity: Option<AccountIdentityHashes>,
    },
}

/// The identity and expiry of one read, from its access token.
pub(crate) fn codex_read_identity(
    access_token: &str,
    id_token: Option<&str>,
    header_account_id: Option<&str>,
) -> ReadIdentity {
    let Some(claims) = structurally_valid_codex_jwt_claims(access_token) else {
        return ReadIdentity::Unusable;
    };
    let Some(lapses_at) = claims
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|expires_at| u64::try_from(expires_at).ok())
    else {
        return ReadIdentity::Unusable;
    };
    // An expired id token still cross-checks the pair; a conflicting or
    // unparseable one leaves the read unidentified rather than guessed.
    let identity = codex_jwt_claimed_ids(&claims)
        .filter(|(_, workspace)| header_account_id == Some(workspace.as_str()))
        .filter(|ids| {
            id_token.is_none_or(|token| {
                structurally_valid_codex_jwt_claims(token)
                    .and_then(|id_claims| codex_jwt_claimed_ids(&id_claims))
                    .as_ref()
                    == Some(ids)
            })
        })
        .and_then(|(user, workspace)| {
            Some(AccountIdentityHashes {
                account_identifier_hash: billing_identity_hash("openai", "account", &user)?,
                provider_workspace_hash: billing_identity_hash("openai", "workspace", &workspace)?,
            })
        });
    ReadIdentity::Usable {
        lapses_at,
        identity,
    }
}

/// Which kind of home a login was read from. The slot id only orders logins;
/// it is never serialized or formatted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LoginHomeKind {
    Default,
    Slot { slot_id: String },
}

impl std::fmt::Debug for LoginHomeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

impl LoginHomeKind {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            LoginHomeKind::Default => "default",
            LoginHomeKind::Slot { .. } => "slot",
        }
    }
}

/// Why a home yields no login this tick. Closed codes; never contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginSkip {
    /// No `auth.json`.
    Absent,
    /// Refused by the secure reader (unsafe mode, owner or symlink) or unreadable.
    Unreadable,
    /// Read, but holds no usable credential or a token without a readable expiry.
    Unusable,
    /// The access token lapses within [`LAPSE_MARGIN_SECONDS`].
    Expired,
    /// A registered slot whose token does not name both ids.
    SlotIdentityUnprovable,
    /// A registered slot now signed in to a different account or workspace.
    SlotIdentityMismatch,
    /// Another login of this tick has the same opaque account.
    SharedWorkspaceSkipped,
}

impl LoginSkip {
    pub(crate) fn code(self) -> &'static str {
        match self {
            LoginSkip::Absent => "codex_sign_in_unavailable",
            LoginSkip::Unreadable => "codex_sign_in_unreadable",
            LoginSkip::Unusable => "codex_sign_in_unusable",
            LoginSkip::Expired => "codex_sign_in_expired",
            LoginSkip::SlotIdentityUnprovable => "slot_identity_unprovable",
            LoginSkip::SlotIdentityMismatch => "slot_identity_mismatch",
            LoginSkip::SharedWorkspaceSkipped => "shared_workspace_skipped",
        }
    }

    /// The closed status reason this skip is reported under.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            LoginSkip::Absent => "sign_in_absent",
            LoginSkip::Unreadable => "sign_in_unreadable",
            LoginSkip::Unusable => "sign_in_unusable",
            LoginSkip::Expired => "sign_in_expired",
            LoginSkip::SlotIdentityUnprovable => "slot_identity_unprovable",
            LoginSkip::SlotIdentityMismatch => "slot_identity_mismatch",
            LoginSkip::SharedWorkspaceSkipped => "shared_workspace_skipped",
        }
    }
}

/// The one secure read of a home: its credential and id token, whatever the
/// token's expiry. Never refreshes or writes a credential.
fn read_signed_in(
    home: &Path,
    trust: CodexHomeTrust,
) -> Result<(CodexCredential, Option<String>), LoginSkip> {
    let body = match read_codex_auth_file_secure(home, trust) {
        Ok(Some(body)) => body,
        Ok(None) => return Err(LoginSkip::Absent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LoginSkip::Absent)
        }
        Err(_) => return Err(LoginSkip::Unreadable),
    };
    let json: Value = serde_json::from_slice(&body).map_err(|_| LoginSkip::Unusable)?;
    drop(body);
    let credential = codex_credential_from_auth(&json).ok_or(LoginSkip::Unusable)?;
    let id_token = json
        .pointer("/tokens/id_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    Ok((credential, id_token))
}

/// A signed-in credential as a login, when its live token proves an identity
/// and does not lapse within the margin.
fn usable_login(
    home_kind: LoginHomeKind,
    credential: CodexCredential,
    id_token: Option<&str>,
    now: u64,
) -> Result<CodexLogin, LoginSkip> {
    let ReadIdentity::Usable {
        lapses_at,
        identity,
    } = codex_read_identity(
        &credential.access_token,
        id_token,
        credential.account_id.as_deref(),
    )
    else {
        return Err(LoginSkip::Unusable);
    };
    if lapses_at <= now.saturating_add(LAPSE_MARGIN_SECONDS) {
        return Err(LoginSkip::Expired);
    }
    Ok(CodexLogin {
        home_kind,
        credential,
        identity,
        lapses_at,
    })
}

/// One discovered home's login, with the account it is signed in to
/// whatever the token's expiry: a registered slot is used only while its
/// live token proves the pair it was registered with.
pub(super) fn read_home(
    home: &DailyReferenceHome,
    now: u64,
) -> (Option<String>, Result<CodexLogin, LoginSkip>) {
    let kind = match &home.slot_id {
        None => LoginHomeKind::Default,
        Some(slot_id) => LoginHomeKind::Slot {
            slot_id: slot_id.clone(),
        },
    };
    let (credential, id_token) = match read_signed_in(&home.home, home.trust) {
        Ok(read) => read,
        Err(skip) => return (None, Err(skip)),
    };
    let signed_in = credential.account_scope.clone();
    let login = usable_login(kind, credential, id_token.as_deref(), now)
        .and_then(|login| proven_slot_login(home, login));
    (Some(signed_in), login)
}

/// A slot login only while its live token proves its registered pair.
fn proven_slot_login(
    home: &DailyReferenceHome,
    login: CodexLogin,
) -> Result<CodexLogin, LoginSkip> {
    if let Some((account, workspace)) = &home.registered_pair {
        let Some(identity) = &login.identity else {
            return Err(LoginSkip::SlotIdentityUnprovable);
        };
        if identity.account_identifier_hash != *account
            || identity.provider_workspace_hash != *workspace
        {
            return Err(LoginSkip::SlotIdentityMismatch);
        }
    } else if home.slot_id.is_some() {
        return Err(LoginSkip::SlotIdentityUnprovable);
    }
    Ok(login)
}

/// The default home's login this tick, for the compatibility status fields.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DefaultHomeState {
    /// `ok`, or the closed reason the default home yields no read.
    pub(crate) state: String,
    /// The default login's opaque account, also when a slot with the same
    /// account was selected for the read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fingerprint: Option<String>,
}

/// The reason only: the opaque fingerprint stays out of formatted output.
impl std::fmt::Debug for DefaultHomeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DefaultHomeState")
            .field("state", &self.state)
            .field("fingerprint_present", &self.fingerprint.is_some())
            .finish()
    }
}

/// The logins one tick reads, and what the other homes yielded.
#[derive(Debug)]
pub(crate) struct LoginDiscovery {
    /// At most one login per opaque account: default home first, then slots.
    pub(crate) logins: Vec<CodexLogin>,
    /// False when the slot registry, a slot home or a home's `auth.json` could
    /// not be read.
    pub(crate) complete: bool,
    /// Closed skip reason to count. No identifiers.
    pub(crate) skipped: BTreeMap<String, u32>,
    pub(crate) default_home: DefaultHomeState,
}

/// Read every home once and select one login per opaque account: an
/// identified login first, then the default home, then the lowest slot id.
/// Never writes, refreshes or probes anything.
pub(crate) fn discover(
    homes: Vec<DailyReferenceHome>,
    homes_complete: bool,
    grant_key: &[u8],
    now: u64,
) -> LoginDiscovery {
    let mut complete = homes_complete;
    let mut skipped = BTreeMap::new();
    let mut default_home = DefaultHomeState::default();
    let mut candidates = Vec::new();
    for home in &homes {
        let (signed_in, login) = read_home(home, now);
        if home.slot_id.is_none() {
            // The privacy controls act on the signed-in account even while
            // its token is renewing, so status keeps its label.
            default_home.fingerprint = signed_in.map(|scope| opaque_key(grant_key, &scope));
        }
        match login {
            Ok(login) => {
                let fingerprint = opaque_key(grant_key, &login.credential.account_scope);
                if login.home_kind == LoginHomeKind::Default {
                    default_home.state = "ok".to_string();
                }
                candidates.push((fingerprint, login));
            }
            Err(skip) => {
                // An unreadable home may still hold a live account, so this
                // discovery cannot justify forgetting one.
                if skip == LoginSkip::Unreadable {
                    complete = false;
                }
                if home.slot_id.is_none() {
                    default_home.state = skip.reason().to_string();
                }
                if skip != LoginSkip::Absent || home.slot_id.is_some() {
                    *skipped.entry(skip.reason().to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    candidates.sort_by(|(left_fp, left), (right_fp, right)| {
        left_fp
            .cmp(right_fp)
            .then(right.identity.is_some().cmp(&left.identity.is_some()))
            .then(left.home_kind.cmp(&right.home_kind))
    });
    let mut seen = BTreeSet::new();
    let mut logins = Vec::new();
    for (fingerprint, login) in candidates {
        if seen.insert(fingerprint) {
            logins.push(login);
        } else {
            *skipped
                .entry(LoginSkip::SharedWorkspaceSkipped.reason().to_string())
                .or_insert(0) += 1;
        }
    }
    logins.sort_by(|left, right| left.home_kind.cmp(&right.home_kind));
    LoginDiscovery {
        logins,
        complete,
        skipped,
        default_home,
    }
}

/// The account scope local privacy controls act on: the account the default
/// home is signed in to, or with `prepare_fallback` and no default sign-in,
/// the first live slot login. Called only by the control actions that need
/// it, after their token is consumed.
pub(crate) fn control_account_scope(prepare_fallback: bool, now: u64) -> Option<String> {
    let (homes, _) = crate::agent_status::daily_reference_homes();
    let default_scope = homes
        .iter()
        .filter(|home| home.slot_id.is_none())
        .find_map(signed_in_account_scope);
    if default_scope.is_some() || !prepare_fallback {
        return default_scope;
    }
    homes
        .iter()
        .filter(|home| home.slot_id.is_some())
        .find_map(|home| read_home(home, now).1.ok())
        .map(|login| login.credential.account_scope)
}

/// The account a home is signed in to, whatever its token's expiry: one
/// secure read and one parse. A privacy control must still reach an account
/// whose token is being renewed, before its next read.
pub(super) fn signed_in_account_scope(home: &DailyReferenceHome) -> Option<String> {
    read_signed_in(&home.home, home.trust)
        .ok()
        .map(|(credential, _)| credential.account_scope)
}
