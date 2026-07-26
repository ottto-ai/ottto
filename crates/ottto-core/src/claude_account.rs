//! Which Claude account owns the local Claude Code credential right now.
//!
//! Two crates need this answer and they must agree exactly: `ottto-cli` stamps
//! it onto the statusLine cache when a Claude Code surface renders, and
//! `ottto-service` compares against it before serving those numbers as an
//! account's quota. Two independent implementations of the same preference
//! order would silently stop matching, and a mismatch here reads as "foreign
//! cache" -- quota would just quietly disappear. So both call this.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const CLAUDE_CLI_CONFIG_FILE_NAME: &str = ".claude.json";

/// Stable, display-safe identifier for a billing identity: a salt-free SHA-256
/// over a normalized `provider:kind:value` triple. Salt-free on purpose -- the
/// same input must hash identically across processes and across restarts, which
/// is the entire point of using it as a cache key.
pub fn billing_identity_hash(provider: &str, kind: &str, value: &str) -> Option<String> {
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

/// Hash a Claude account from whatever identity fields are available, in the
/// same preference order the subscription grouping uses: provider account id,
/// then organization, then email. Empty when none of them names anything.
///
/// Organization is a deliberate second choice, not a peer: two accounts inside
/// one organization share it, so it can only separate accounts that also differ
/// by org. It is here because it is better than falling straight through to
/// email, not because it is sufficient.
pub fn claude_account_identifier_hash(
    account_uuid: Option<&str>,
    organization_uuid: Option<&str>,
    email_address: Option<&str>,
) -> String {
    account_uuid
        .and_then(|uuid| billing_identity_hash("anthropic", "account", uuid))
        .or_else(|| {
            organization_uuid
                .and_then(|uuid| billing_identity_hash("anthropic", "organization", uuid))
        })
        .or_else(|| {
            email_address.and_then(|email| billing_identity_hash("anthropic", "email", email))
        })
        .unwrap_or_default()
}

pub fn default_claude_cli_config_path() -> PathBuf {
    if let Ok(path) = std::env::var("OTTTO_CLAUDE_CLI_CONFIG_PATH") {
        return PathBuf::from(path);
    }
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(CLAUDE_CLI_CONFIG_FILE_NAME),
        Err(_) => PathBuf::from(CLAUDE_CLI_CONFIG_FILE_NAME),
    }
}

/// The account named by `~/.claude.json` `oauthAccount`, hashed. Empty when the
/// file is absent, unreadable, or names no account.
///
/// Claude Code rewrites `oauthAccount` itself on every profile refresh, so this
/// tracks the credential without being the credential: deliberately NOT a hash
/// of the access token, which rotates while the account does not.
pub fn claude_cli_account_identifier_hash_at(config_path: &Path) -> String {
    let Ok(body) = fs::read_to_string(config_path) else {
        return String::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&body) else {
        return String::new();
    };
    claude_cli_account_identifier_hash_from_config(&value)
}

pub fn claude_cli_account_identifier_hash_from_config(config: &Value) -> String {
    let Some(account) = config.get("oauthAccount") else {
        return String::new();
    };
    let field = |key: &str| {
        account
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    claude_account_identifier_hash(
        field("accountUuid"),
        field("organizationUuid"),
        field("emailAddress"),
    )
}

pub fn claude_cli_account_identifier_hash() -> String {
    claude_cli_account_identifier_hash_at(&default_claude_cli_config_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_identity_hash_normalizes_and_rejects_empty() {
        assert_eq!(
            billing_identity_hash("Anthropic", "Account", " ACCT-A "),
            billing_identity_hash("anthropic", "account", "acct-a")
        );
        assert!(billing_identity_hash("anthropic", "account", "   ").is_none());
    }

    #[test]
    fn account_hash_prefers_account_then_organization_then_email() {
        let account = claude_account_identifier_hash(
            Some("acct-a"),
            Some("org-shared"),
            Some("a@example.test"),
        );
        assert_eq!(
            account,
            billing_identity_hash("anthropic", "account", "acct-a").expect("account hash")
        );

        // Two accounts inside one organization must still separate.
        let other = claude_account_identifier_hash(
            Some("acct-b"),
            Some("org-shared"),
            Some("b@example.test"),
        );
        assert_ne!(account, other);

        assert_eq!(
            claude_account_identifier_hash(None, Some("org-shared"), Some("a@example.test")),
            billing_identity_hash("anthropic", "organization", "org-shared")
                .expect("organization hash")
        );
        assert_eq!(
            claude_account_identifier_hash(None, None, Some("a@example.test")),
            billing_identity_hash("anthropic", "email", "a@example.test").expect("email hash")
        );
        assert!(claude_account_identifier_hash(None, None, None).is_empty());
    }

    #[test]
    fn config_without_oauth_account_yields_no_hash() {
        assert!(claude_cli_account_identifier_hash_from_config(&serde_json::json!({})).is_empty());
        assert!(
            claude_cli_account_identifier_hash_from_config(&serde_json::json!({
                "oauthAccount": { "accountUuid": "   ", "displayName": "Ron" }
            }))
            .is_empty()
        );
    }

    #[test]
    fn config_with_oauth_account_matches_direct_hash() {
        let config = serde_json::json!({
            "oauthAccount": {
                "accountUuid": "acct-a",
                "organizationUuid": "org-shared",
                "emailAddress": "a@example.test"
            }
        });
        assert_eq!(
            claude_cli_account_identifier_hash_from_config(&config),
            claude_account_identifier_hash(Some("acct-a"), None, None)
        );
    }

    #[test]
    fn missing_config_file_yields_no_hash() {
        let path = std::env::temp_dir().join(format!(
            "ottto-claude-account-missing-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        assert!(claude_cli_account_identifier_hash_at(&path).is_empty());
    }
}
