//! The upload contract's wire shapes: the closed surface vocabulary, the row and
//! batch structs, and the proof that an outgoing batch carries only
//! contract-shaped scalars.

use super::normalize::provider_day;
use super::{
    ALL_MODELS, COLLECTOR_ID, MAX_ROWS_PER_BATCH, PROVIDER_DAY_TIMEZONE, SCHEMA_VERSION, SOURCE,
};
use crate::hex::is_uuid;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Closed surface vocabulary
// ---------------------------------------------------------------------------

/// The closed surface enum of the upload contract.
///
/// The daemon never invents a surface value. A provider `client_id` it does
/// not recognize maps to [`Surface::Other`]; `CODEX_UNKNOWN_DEFAULT` is the
/// provider's *own* unknown bucket and keeps its own slot so "the provider
/// could not attribute this" stays distinguishable from "Ottto has never seen
/// this client id".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    CodexWeb,
    CodexDesktopApp,
    CodexServiceExec,
    CodexWorkDesktop,
    CodexUnknownDefault,
    Other,
}

/// Reserved wire surface for provider-owned day totals and their day-level
/// model breakdown. Provider client ids can never map to this value. The
/// backend's additive v1 surface validator must be deployed before any runtime
/// containing this constant is released.
pub const PROVIDER_DAY_TOTAL_SURFACE: &str = "provider_day_total";

impl Surface {
    pub fn wire(self) -> &'static str {
        match self {
            Surface::CodexWeb => "codex_web",
            Surface::CodexDesktopApp => "codex_desktop_app",
            Surface::CodexServiceExec => "codex_service_exec",
            Surface::CodexWorkDesktop => "codex_work_desktop",
            Surface::CodexUnknownDefault => "codex_unknown_default",
            Surface::Other => "other",
        }
    }
}

/// Map a provider `client_id` onto the closed surface enum, locally.
///
/// Matching is case-insensitive and ignores surrounding whitespace because the
/// provider's own casing is not a contract. Anything unrecognized is `other`.
pub fn surface_for_client_id(client_id: &str) -> Surface {
    match client_id.trim().to_ascii_uppercase().as_str() {
        "CODEX_WEB" => Surface::CodexWeb,
        "CODEX_DESKTOP_APP" => Surface::CodexDesktopApp,
        "CODEX_SERVICE_EXEC" => Surface::CodexServiceExec,
        "CODEX_WORK_DESKTOP" => Surface::CodexWorkDesktop,
        "CODEX_UNKNOWN_DEFAULT" => Surface::CodexUnknownDefault,
        _ => Surface::Other,
    }
}

/// Normalize a provider model identifier to the contract's bounded slug, or
/// refuse it.
///
/// The contract pattern is `^(__all__|[a-z0-9][a-z0-9._-]{0,63})$`. Characters
/// outside the alphabet become `-` so an ordinary vendor id survives, but a
/// value that cannot begin with an alphanumeric, or that is empty, is refused
/// rather than coerced: the surface total row already carries the numbers, so
/// dropping an unrepresentable model loses nothing comparable and inventing a
/// slug would be a fabricated identifier.
pub fn normalized_model_slug(raw: &str) -> Option<String> {
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered.is_empty() || lowered == ALL_MODELS {
        return None;
    }
    let mut slug = String::with_capacity(lowered.len().min(64));
    for character in lowered.chars() {
        if slug.len() == 64 {
            break;
        }
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            slug.push(character);
        } else {
            slug.push('-');
        }
    }
    let first = slug.chars().next()?;
    if !first.is_ascii_alphanumeric() {
        return None;
    }
    Some(slug)
}

// ---------------------------------------------------------------------------
// Wire structs - the only shapes that may be serialized toward the backend
// ---------------------------------------------------------------------------

/// One provider-reported day at `(surface, model)` grain.
///
/// Every counter is `Option` because "the provider did not report this
/// counter" and "the provider reported zero" are different facts. Collapsing
/// them would manufacture a reconciliation delta, so an absent counter is
/// omitted from the payload rather than sent as `0`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DailyReferenceRow {
    pub provider_day: String,
    pub surface: &'static str,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_count: Option<u64>,
}

/// One bounded upload of provider-reported day aggregates.
#[derive(Clone, PartialEq, Serialize)]
pub struct DailyReferenceBatch {
    pub schema_version: &'static str,
    pub source: &'static str,
    pub collector_id: &'static str,
    pub collector_version: String,
    pub installation_id: String,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub grant_version: u64,
    pub provider_day_timezone: &'static str,
    pub coverage_start: String,
    pub coverage_end: String,
    pub collected_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_data_refreshed_at: Option<String>,
    pub rows: Vec<DailyReferenceRow>,
    /// The account this read's credential names. Set only under a v2 grant
    /// and only when the live access token proves it; every batch of one read
    /// carries the same value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) account_identity: Option<AccountIdentityHashes>,
}

/// Versions, dates and counts only: the installation id and the opaque
/// fingerprints stay out of formatted output.
impl fmt::Debug for DailyReferenceBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DailyReferenceBatch")
            .field("schema_version", &self.schema_version)
            .field("collector_version", &self.collector_version)
            .field("grant_version", &self.grant_version)
            .field("coverage_start", &self.coverage_start)
            .field("coverage_end", &self.coverage_end)
            .field("collected_at", &self.collected_at)
            .field("rows", &self.rows.len())
            .field("identified", &self.account_identity.is_some())
            .finish_non_exhaustive()
    }
}

/// Hash scheme of [`AccountIdentityHashes`]: the session-evidence scheme.
const IDENTITY_HASH_SCHEME: &str = "provider-sha256:v1";

/// The provider account and workspace one read's credential names, hashed
/// exactly as Codex session evidence hashes its creator pair.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AccountIdentityHashes {
    pub(super) account_identifier_hash: String,
    pub(super) provider_workspace_hash: String,
}

impl fmt::Debug for AccountIdentityHashes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountIdentityHashes(present)")
    }
}

impl Serialize for AccountIdentityHashes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut identity = serializer.serialize_struct("AccountIdentityHashes", 3)?;
        identity.serialize_field("identity_hash_scheme", IDENTITY_HASH_SCHEME)?;
        identity.serialize_field("account_identifier_hash", &self.account_identifier_hash)?;
        identity.serialize_field("provider_workspace_hash", &self.provider_workspace_hash)?;
        identity.end()
    }
}

/// The exact key set the batch envelope may carry. Pinned so a future field
/// cannot be added without failing `wire_key_sets_match_the_contract`.
pub(super) const BATCH_KEYS: &[&str] = &[
    "schema_version",
    "source",
    "collector_id",
    "collector_version",
    "installation_id",
    "grant_scope_fingerprint",
    "account_fingerprint",
    "grant_version",
    "provider_day_timezone",
    "coverage_start",
    "coverage_end",
    "collected_at",
    "provider_data_refreshed_at",
    "rows",
    "account_identity",
];

/// The exact key set of a batch's `account_identity`.
const ACCOUNT_IDENTITY_KEYS: &[&str] = &[
    "identity_hash_scheme",
    "account_identifier_hash",
    "provider_workspace_hash",
];

/// The exact key set one row may carry.
pub(super) const ROW_KEYS: &[&str] = &[
    "provider_day",
    "surface",
    "model",
    "credits_used",
    "uncached_input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
    "thread_count",
    "turn_count",
];

// ---------------------------------------------------------------------------
// Content-free proof
// ---------------------------------------------------------------------------

pub(super) fn is_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("hmac-sha256:")
        .is_some_and(is_sha256_hex)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// An `account_identity` is exactly the scheme literal and two hashes.
fn is_account_identity(value: &Value) -> bool {
    let Some(identity) = value.as_object() else {
        return false;
    };
    identity.len() == ACCOUNT_IDENTITY_KEYS.len()
        && identity
            .keys()
            .all(|key| ACCOUNT_IDENTITY_KEYS.contains(&key.as_str()))
        && identity.get("identity_hash_scheme").and_then(Value::as_str)
            == Some(IDENTITY_HASH_SCHEME)
        && ["account_identifier_hash", "provider_workspace_hash"]
            .iter()
            .all(|key| {
                identity
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(is_sha256_hex)
            })
}

fn is_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return false;
    }
    let parts: Vec<&str> = value.split(['.', '-']).collect();
    parts.len() >= 3
        && parts[..3]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_iso_day(value: &str) -> bool {
    provider_day(value).as_deref() == Some(value)
}

fn is_model_slug(value: &str) -> bool {
    if value == ALL_MODELS {
        return true;
    }
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// Prove that every string in an outgoing batch is a fixed literal, an opaque
/// fingerprint, a UUID, a date, a timestamp, a closed surface value, a bounded
/// model slug, or a decimal.
///
/// This is the daemon-side counterpart to the backend's must-not-persist key
/// pinning: the backend proves no unexpected *key* can reach storage, and this
/// proves no unexpected *value* can leave the machine.
pub fn wire_payload_is_content_free(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if object.keys().any(|key| !BATCH_KEYS.contains(&key.as_str())) {
        return false;
    }
    let string_at = |key: &str| object.get(key).and_then(Value::as_str);
    if string_at("schema_version") != Some(SCHEMA_VERSION)
        || string_at("source") != Some(SOURCE)
        || string_at("collector_id") != Some(COLLECTOR_ID)
        || string_at("provider_day_timezone") != Some(PROVIDER_DAY_TIMEZONE)
    {
        return false;
    }
    if !string_at("collector_version").is_some_and(is_semver)
        || !string_at("installation_id").is_some_and(is_uuid)
        || !string_at("grant_scope_fingerprint").is_some_and(is_fingerprint)
        || !string_at("account_fingerprint").is_some_and(is_fingerprint)
        || !string_at("coverage_start").is_some_and(is_iso_day)
        || !string_at("coverage_end").is_some_and(is_iso_day)
        || !string_at("collected_at").is_some_and(is_rfc3339)
    {
        return false;
    }
    if let Some(refreshed_at) = object.get("provider_data_refreshed_at") {
        if !refreshed_at.as_str().is_some_and(is_rfc3339) {
            return false;
        }
    }
    if object
        .get("account_identity")
        .is_some_and(|identity| !is_account_identity(identity))
    {
        return false;
    }
    if object
        .get("grant_version")
        .and_then(Value::as_u64)
        .is_none()
    {
        return false;
    }
    let Some(rows) = object.get("rows").and_then(Value::as_array) else {
        return false;
    };
    if rows.len() > MAX_ROWS_PER_BATCH {
        return false;
    }
    rows.iter().all(|row| {
        let Some(row) = row.as_object() else {
            return false;
        };
        if row.keys().any(|key| !ROW_KEYS.contains(&key.as_str())) {
            return false;
        }
        if !row
            .get("provider_day")
            .and_then(Value::as_str)
            .is_some_and(is_iso_day)
        {
            return false;
        }
        if !row
            .get("surface")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                [
                    Surface::CodexWeb,
                    Surface::CodexDesktopApp,
                    Surface::CodexServiceExec,
                    Surface::CodexWorkDesktop,
                    Surface::CodexUnknownDefault,
                    Surface::Other,
                ]
                .iter()
                .any(|surface| surface.wire() == value)
                    || value == PROVIDER_DAY_TOTAL_SURFACE
            })
        {
            return false;
        }
        if !row
            .get("model")
            .and_then(Value::as_str)
            .is_some_and(is_model_slug)
        {
            return false;
        }
        if let Some(credits) = row.get("credits_used") {
            if !credits.as_str().is_some_and(is_decimal) {
                return false;
            }
        }
        [
            "uncached_input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "total_tokens",
            "thread_count",
            "turn_count",
        ]
        .iter()
        .all(|key| match row.get(*key) {
            None => true,
            Some(value) => value.as_u64().is_some(),
        })
    })
}

fn is_rfc3339(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok()
}
