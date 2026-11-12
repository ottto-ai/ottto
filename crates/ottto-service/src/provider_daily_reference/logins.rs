//! The Codex logins a daily-reference read may use.
//!
//! A login is read with one secure read and one parse of its home's
//! `auth.json`. The request header, the attribution scope and the account
//! identity all come from that one parse, so they always describe the same
//! credential. Identity and expiry come from the live access token; an id
//! token only cross-checks it and never by itself skips a login.

use super::{codex_credential_from_auth, AccountIdentityHashes, CodexLogin};
use crate::agent_status::{codex_jwt_claimed_ids, structurally_valid_codex_jwt_claims};
use ottto_core::{billing_identity_hash, read_codex_auth_file_secure, CodexHomeTrust};
use serde_json::Value;
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
}

impl LoginSkip {
    pub(crate) fn code(self) -> &'static str {
        match self {
            LoginSkip::Absent => "codex_sign_in_unavailable",
            LoginSkip::Unreadable => "codex_sign_in_unreadable",
            LoginSkip::Unusable => "codex_sign_in_unusable",
            LoginSkip::Expired => "codex_sign_in_expired",
        }
    }
}

/// Read one home's login. Never refreshes or writes a credential.
pub(crate) fn read_login(
    home: &Path,
    trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexLogin, LoginSkip> {
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
        .filter(|token| !token.is_empty());
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
        credential,
        identity,
        lapses_at,
    })
}
