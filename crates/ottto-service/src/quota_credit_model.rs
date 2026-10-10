//! Shared daemon credit model (quota contract v2.1 §3-§6, v2.2 §11).
//!
//! One owner for the provider-neutral credit rules both provider adapters use:
//! grant identity, grant building (status map, field refusal, the 20-grant
//! sender cap and its order, `grants_state`), balance summaries, the one-time
//! pool shape, and sender stability across read cadence ([`SectionCache`]).
//!
//! Adapters own provider field names and parsing. They hand this module
//! provider-neutral inputs ([`ListObservation`], [`GrantInput`]) and never
//! re-implement a rule that lives here.
//!
//! Adapter flow:
//!
//! 1. build the balance with the adapter's name/unit/kind table, or
//!    [`one_time_credit`] for a one-time pool;
//! 2. for a balance with grants, `build_grants(observation).apply_to(&mut
//!    balance)` writes `grants`, `grants_state`, `grant_count`,
//!    `grants_observed_at`, the summaries and, for saved resets, `status`
//!    (and the Anthropic `remaining`);
//! 3. [`apply_readiness`] for provider readiness and [`apply_disabled`] for a
//!    balance the provider switched off;
//! 4. use [`SectionCache`] for sections this reading did not include.
//!
//! Credit balances never carry `updated_at`; consumers use the snapshot's
//! capture time.
//!
//! Summaries are complete-gated. One exception lives in
//! [`GrantsBuild::apply_to`]: when a complete provider enumeration was cut
//! only by the daemon's 20 cap, `next_expires_at` is still exact (computed over
//! the whole list before the cut) and is set although the state is `capped`.
//! A provider-capped list (fewer rows than the provider count) or a partial
//! one never gets one.

use std::collections::BTreeMap;

use ottto_protocol::{
    is_backend_safe_credit_text, is_credit_reason_code, AgentCreditBalance,
    AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentCreditGrant, AgentQuotaWindowFreshness,
    CreditBalanceKind, CreditGrantStatus, CreditGrantType, CreditGrantsState, Rfc3339Timestamp,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use unicode_normalization::UnicodeNormalization;

/// Most grants one balance carries on the wire (contract v2.1 §4).
pub(crate) const GRANTS_MAX: usize = 20;
/// Largest canonical JSON size of one grant (contract v2.1 §5).
pub(crate) const GRANT_MAX_BYTES: usize = 1024;
/// Title bounds (contract v2.1 §5, v2.2 §11.1).
pub(crate) const TITLE_MAX_CHARS: usize = 128;
pub(crate) const TITLE_MAX_BYTES: usize = 512;
/// Per-grant reset count bound (contract v2.1 §5).
pub(crate) const RESETS_MAX: u64 = 1000;
/// `clears` list bound (contract v2.1 §5).
pub(crate) const CLEARS_MAX_ITEMS: usize = 8;
/// Bound on `grant_count` (contract v2.1 §2.2).
pub(crate) const GRANT_COUNT_MAX: u64 = 10_000;
/// Longest Anthropic grant id (contract v2.1 §5).
const ANTHROPIC_GRANT_ID_MAX: usize = 40;
/// Longest OpenAI grant id the daemon keys. Ids are hashed, so this only
/// bounds work on a malformed body.
const OPENAI_GRANT_ID_MAX: usize = 256;

/// Provider whose grant ids are keyed. The token is part of `grant_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Provider {
    OpenAi,
    Anthropic,
}

impl Provider {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

/// `credit-grant-sha256:v1` (contract v2.1 §6): full lowercase hex SHA-256 of
/// the UTF-8 text `"<provider>:credit_grant:<id>"`. The id is opaque and
/// case-preserving: never trimmed, never case-folded.
pub(crate) fn credit_grant_key(provider: Provider, id: &str) -> String {
    let digest = Sha256::digest(format!("{}:credit_grant:{id}", provider.token()).as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A provider value the adapter extracted: absent (null or missing), present,
/// or present with the wrong JSON type. `Invalid` is refused like any other
/// bad value, so a drifted field is visible as a diagnostic, not silence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Field<T> {
    #[default]
    Absent,
    Value(T),
    Invalid,
}

/// A provider instant as the adapter found it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum TimeInput {
    #[default]
    Absent,
    /// RFC 3339 text with any offset; normalized to UTC.
    Rfc3339(String),
    /// Unix seconds.
    UnixSeconds(i64),
    Invalid,
}

/// How the provider states a grant's lifecycle; mapped by the model's single
/// status table (contract v2.1 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantStatusInput {
    /// The provider sends a status word (OpenAI `status`).
    Reported(Field<String>),
    /// The provider sends `paused` and `resets_left` (Anthropic): paused →
    /// `paused`; `resets_left == 0` → `redeemed`; else `available`.
    PausedResetsLeft {
        paused: Field<bool>,
        resets_left: Field<u64>,
    },
}

impl Default for GrantStatusInput {
    fn default() -> Self {
        Self::Reported(Field::Absent)
    }
}

/// One provider grant record, provider-neutral.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GrantInput {
    /// Provider grant id; missing or malformed drops the grant.
    pub(crate) id: Field<String>,
    /// OpenAI `resetType`. Anthropic grants are always rate-limit resets and
    /// leave this `Absent`.
    pub(crate) reset_type: Field<String>,
    pub(crate) status: GrantStatusInput,
    pub(crate) granted_at: TimeInput,
    pub(crate) starts_at: TimeInput,
    pub(crate) expires_at: TimeInput,
    pub(crate) resets_included: Field<u64>,
    pub(crate) resets_left: Field<u64>,
    pub(crate) clears: Field<Vec<String>>,
    pub(crate) title: Field<String>,
    pub(crate) usable_now: Field<bool>,
}

/// What a provider read said about a balance's grant list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListObservation {
    /// The detail list was read. `provider_count` is the provider's total for
    /// the enumeration scope (contract v2.1 §3 B): OpenAI `availableCount`,
    /// Anthropic the raw array length. The list is `complete` only when the
    /// count matches the records returned.
    Read {
        provider: Provider,
        provider_count: Option<u64>,
        records: Vec<GrantInput>,
        observed_at: Rfc3339Timestamp,
    },
    /// Details were not read, or the read failed. A provider count may still
    /// be known (count-only reading).
    Unavailable {
        provider: Provider,
        provider_count: Option<u64>,
    },
    /// The provider/plan has no per-grant details.
    NotSupported { provider: Provider },
}

/// A model rule that refused or shaped a value. Field paths only, never the
/// value, so a diagnostic cannot leak provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreditModelDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) field: &'static str,
}

impl CreditModelDiagnostic {
    const fn new(code: &'static str, field: &'static str) -> Self {
        Self { code, field }
    }
}

/// The grant section of one balance, built by [`build_grants`].
/// Its fields are the model's decisions; adapters only read the diagnostics
/// and call [`GrantsBuild::apply_to`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GrantsBuild {
    grants: Option<Vec<AgentCreditGrant>>,
    grants_state: Option<CreditGrantsState>,
    grant_count: Option<u64>,
    grants_observed_at: Option<Rfc3339Timestamp>,
    /// The provider enumeration was complete and only the daemon's 20 cap cut
    /// it, so the soonest expiry is still known exactly.
    sender_capped: bool,
    /// Soonest available/paused expiry over the whole list, computed before
    /// the cap dropped any grant. Set only with `sender_capped`.
    sender_capped_next_expires_at: Option<Rfc3339Timestamp>,
    /// Provider of the observation; `None` only for a default value.
    provider: Option<Provider>,
    diagnostics: Vec<CreditModelDiagnostic>,
}

impl GrantsBuild {
    pub(crate) fn diagnostics(&self) -> &[CreditModelDiagnostic] {
        &self.diagnostics
    }

    /// Write the grant section into `balance` and recompute its summaries.
    pub(crate) fn apply_to(self, balance: &mut AgentCreditBalance) -> Vec<CreditModelDiagnostic> {
        balance.grants = self.grants;
        balance.grants_state = self.grants_state;
        balance.grant_count = self.grant_count;
        balance.grants_observed_at = self.grants_observed_at;
        summarize(balance, self.provider);
        if self.sender_capped && balance.grants_state == Some(CreditGrantsState::Capped) {
            balance.next_expires_at = self.sender_capped_next_expires_at;
        }
        self.diagnostics
    }
}

/// Build a balance's grant section (contract v2.1 §4-§5).
///
/// - Grants are keyed with [`credit_grant_key`]; a missing or malformed id
///   drops the grant and makes the list `partial`.
/// - Every refused field becomes `None` with a diagnostic. Status, time and
///   reset-count refusals make the list `partial`; `grant_type`, `clears`,
///   `title` and `usable_now` refusals do not change the state.
/// - The list is ordered by `expires_at` ascending (no expiry last), then
///   `grant_key`, and capped at 20 (`capped` unless already `partial`).
/// - `grants_state` precedence: `partial` > `capped` > `complete`.
pub(crate) fn build_grants(obs: ListObservation) -> GrantsBuild {
    let (provider, provider_count, records, observed_at) = match obs {
        ListObservation::Read {
            provider,
            provider_count,
            records,
            observed_at,
        } => (provider, provider_count, records, observed_at),
        ListObservation::Unavailable {
            provider,
            provider_count,
        } => {
            let mut diagnostics = Vec::new();
            return GrantsBuild {
                grants_state: Some(CreditGrantsState::Unavailable),
                grant_count: bounded_grant_count(provider_count, &mut diagnostics),
                provider: Some(provider),
                diagnostics,
                ..GrantsBuild::default()
            };
        }
        ListObservation::NotSupported { provider } => {
            return GrantsBuild {
                grants_state: Some(CreditGrantsState::NotSupported),
                provider: Some(provider),
                ..GrantsBuild::default()
            };
        }
    };

    let mut diagnostics = Vec::new();
    let grant_count = bounded_grant_count(provider_count, &mut diagnostics);
    let mut partial = false;
    let returned = records.len();
    let mut grants = Vec::with_capacity(returned);
    for record in records {
        match build_grant(provider, record, &mut diagnostics) {
            Some((grant, refused_state_field)) => {
                partial |= refused_state_field;
                grants.push(grant);
            }
            None => partial = true,
        }
    }
    grants.sort_by(grant_order);

    let provider_capped = match provider_count {
        Some(count) if count == returned as u64 => false,
        Some(count) if count > returned as u64 => true,
        // An unknown total or a list longer than the provider's own count is
        // not a guarantee of completeness.
        _ => {
            partial = true;
            false
        }
    };
    let mut capped = provider_capped;
    let mut sender_capped = false;
    let mut sender_capped_next_expires_at = None;
    if grants.len() > GRANTS_MAX {
        // Only a list that was complete before the cut keeps an exact soonest
        // expiry, and it is taken over the whole list: redeemed grants that
        // expire earlier can push every eligible grant past the cut.
        if !provider_capped && !partial {
            sender_capped = true;
            sender_capped_next_expires_at = next_expires_at(&grants);
        }
        grants.truncate(GRANTS_MAX);
        capped = true;
        diagnostics.push(CreditModelDiagnostic::new("grants_capped", "grants"));
    }
    let state = if partial {
        CreditGrantsState::Partial
    } else if capped {
        CreditGrantsState::Capped
    } else {
        CreditGrantsState::Complete
    };
    GrantsBuild {
        grants: Some(grants),
        grants_state: Some(state),
        grant_count,
        grants_observed_at: Some(observed_at),
        sender_capped,
        sender_capped_next_expires_at,
        provider: Some(provider),
        diagnostics,
    }
}

fn bounded_grant_count(
    count: Option<u64>,
    diagnostics: &mut Vec<CreditModelDiagnostic>,
) -> Option<u64> {
    match count {
        Some(count) if count > GRANT_COUNT_MAX => {
            diagnostics.push(CreditModelDiagnostic::new("field_refused", "grant_count"));
            None
        }
        other => other,
    }
}

/// `expires_at` ascending with no expiry last, then `grant_key`. Times are
/// already UTC-normalized RFC 3339, so instants compare as parsed values.
fn grant_order(left: &AgentCreditGrant, right: &AgentCreditGrant) -> std::cmp::Ordering {
    let left_expiry = left.expires_at.as_deref().and_then(parse_instant);
    let right_expiry = right.expires_at.as_deref().and_then(parse_instant);
    match (left_expiry, right_expiry) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
    .then_with(|| left.grant_key.cmp(&right.grant_key))
}

/// Returns the grant and whether a refused field must make the list `partial`.
fn build_grant(
    provider: Provider,
    record: GrantInput,
    diagnostics: &mut Vec<CreditModelDiagnostic>,
) -> Option<(AgentCreditGrant, bool)> {
    let Field::Value(id) = record.id else {
        diagnostics.push(CreditModelDiagnostic::new("grant_dropped", "grants[].id"));
        return None;
    };
    if !grant_id_is_valid(provider, &id) {
        diagnostics.push(CreditModelDiagnostic::new("grant_dropped", "grants[].id"));
        return None;
    }
    let mut partial = false;
    let mut refuse = |field: &'static str, partial_on_refusal: bool, partial: &mut bool| {
        diagnostics.push(CreditModelDiagnostic::new("field_refused", field));
        *partial |= partial_on_refusal;
    };

    let grant_type = match (provider, record.reset_type) {
        (Provider::Anthropic, _) => CreditGrantType::RateLimitReset,
        (Provider::OpenAi, Field::Value(reset_type)) if reset_type == "codexRateLimits" => {
            CreditGrantType::RateLimitReset
        }
        (Provider::OpenAi, _) => {
            refuse("grants[].grant_type", false, &mut partial);
            CreditGrantType::Unknown
        }
    };

    let resets_left = bounded_resets(record.resets_left, "grants[].resets_left", &mut |f| {
        refuse(f, true, &mut partial)
    });
    let resets_included = bounded_resets(
        record.resets_included,
        "grants[].resets_included",
        &mut |f| refuse(f, true, &mut partial),
    );
    let status = match record.status {
        GrantStatusInput::Reported(Field::Value(word)) => match word.as_str() {
            "available" => Some(CreditGrantStatus::Available),
            "redeeming" => Some(CreditGrantStatus::Redeeming),
            "redeemed" => Some(CreditGrantStatus::Redeemed),
            "paused" => Some(CreditGrantStatus::Paused),
            _ => None,
        },
        GrantStatusInput::Reported(_) => None,
        GrantStatusInput::PausedResetsLeft {
            paused,
            resets_left,
        } => match (paused, resets_left) {
            (Field::Value(true), _) => Some(CreditGrantStatus::Paused),
            (Field::Value(false), Field::Value(0)) => Some(CreditGrantStatus::Redeemed),
            (Field::Value(false), Field::Value(left)) if left <= RESETS_MAX => {
                Some(CreditGrantStatus::Available)
            }
            _ => None,
        },
    };
    let status = status.unwrap_or_else(|| {
        refuse("grants[].status", true, &mut partial);
        CreditGrantStatus::Unknown
    });

    let mut time = |input: TimeInput, field: &'static str| -> Option<Rfc3339Timestamp> {
        match normalize_time(input) {
            Ok(value) => value,
            Err(()) => {
                refuse(field, true, &mut partial);
                None
            }
        }
    };
    let granted_at = time(record.granted_at, "grants[].granted_at");
    let starts_at = time(record.starts_at, "grants[].starts_at");
    let expires_at = time(record.expires_at, "grants[].expires_at");

    let clears = match record.clears {
        Field::Absent => None,
        Field::Value(names)
            if names.len() <= CLEARS_MAX_ITEMS
                && names.iter().all(|name| is_credit_reason_code(name)) =>
        {
            Some(names)
        }
        _ => {
            refuse("grants[].clears", false, &mut partial);
            None
        }
    };
    let usable_now = match record.usable_now {
        Field::Absent => None,
        Field::Value(value) => Some(value),
        Field::Invalid => {
            refuse("grants[].usable_now", false, &mut partial);
            None
        }
    };
    let (title, title_diagnostic) = bounded_title(record.title, "grants[].title");
    diagnostics.extend(title_diagnostic);

    let mut grant = AgentCreditGrant {
        grant_key: credit_grant_key(provider, &id),
        grant_type,
        status,
        granted_at,
        starts_at,
        expires_at,
        resets_included,
        resets_left,
        clears,
        title,
        usable_now,
    };
    // Display text gives way first so a grant always fits the 1 KiB bound.
    if grant_wire_size(&grant) > GRANT_MAX_BYTES && grant.title.take().is_some() {
        diagnostics.push(CreditModelDiagnostic::new(
            "field_refused",
            "grants[].title",
        ));
    }
    if grant_wire_size(&grant) > GRANT_MAX_BYTES && grant.clears.take().is_some() {
        diagnostics.push(CreditModelDiagnostic::new(
            "field_refused",
            "grants[].clears",
        ));
    }
    Some((grant, partial))
}

fn grant_id_is_valid(provider: Provider, id: &str) -> bool {
    match provider {
        // `^[a-z0-9_-]{1,40}$` (contract v2.1 §5, Claude client schema).
        Provider::Anthropic => {
            (1..=ANTHROPIC_GRANT_ID_MAX).contains(&id.len())
                && id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
        }
        // An opaque required string. Empty or control text is not an identity.
        Provider::OpenAi => {
            (1..=OPENAI_GRANT_ID_MAX).contains(&id.len()) && !id.chars().any(char::is_control)
        }
    }
}

fn bounded_resets(
    input: Field<u64>,
    field: &'static str,
    refuse: &mut dyn FnMut(&'static str),
) -> Option<u64> {
    match input {
        Field::Absent => None,
        Field::Value(value) if value <= RESETS_MAX => Some(value),
        _ => {
            refuse(field);
            None
        }
    }
}

/// Canonical JSON size the backend measures: compact, with every absent
/// optional key spelled as `null` (the backend dumps the full model).
fn grant_wire_size(grant: &AgentCreditGrant) -> usize {
    let present = serde_json::to_vec(grant).map_or(usize::MAX, |bytes| bytes.len());
    let absent_keys: usize = [
        ("granted_at", grant.granted_at.is_none()),
        ("starts_at", grant.starts_at.is_none()),
        ("expires_at", grant.expires_at.is_none()),
        ("resets_included", grant.resets_included.is_none()),
        ("resets_left", grant.resets_left.is_none()),
        ("clears", grant.clears.is_none()),
        ("title", grant.title.is_none()),
        ("usable_now", grant.usable_now.is_none()),
    ]
    .iter()
    .filter(|(_, absent)| *absent)
    // `,"key":null`
    .map(|(key, _)| key.len() + 8)
    .sum();
    present.saturating_add(absent_keys)
}

/// Normalize a provider instant to UTC RFC 3339. `Err` = refused.
pub(crate) fn normalize_time(input: TimeInput) -> Result<Option<Rfc3339Timestamp>, ()> {
    let instant = match input {
        TimeInput::Absent => return Ok(None),
        TimeInput::Invalid => return Err(()),
        TimeInput::Rfc3339(text) => OffsetDateTime::parse(text.trim(), &Rfc3339).map_err(|_| ())?,
        TimeInput::UnixSeconds(seconds) => {
            OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| ())?
        }
    };
    instant
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map(Some)
        .map_err(|_| ())
}

fn parse_instant(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// The backend's privacy match for provider display text: the value as given
/// and its NFKC form (compatibility characters such as mathematical letters,
/// full-width or small forms fold to ASCII) must both pass the protocol guard,
/// which then folds slash lookalikes, invisible format characters, whitespace
/// runs and case.
fn is_privacy_safe_display_text(text: &str) -> bool {
    is_backend_safe_credit_text(text)
        && is_backend_safe_credit_text(&text.nfkc().collect::<String>())
}

/// Provider display title (grant or pool), contract v2.1 §5: the privacy check
/// runs on the full value first (unsafe → refused), then an over-long value is
/// cut at a character boundary to ≤128 chars and ≤512 UTF-8 bytes.
pub(crate) fn bounded_title(
    input: Field<String>,
    field: &'static str,
) -> (Option<String>, Option<CreditModelDiagnostic>) {
    let text = match input {
        Field::Absent => return (None, None),
        Field::Invalid => {
            return (
                None,
                Some(CreditModelDiagnostic::new("field_refused", field)),
            );
        }
        Field::Value(text) => text,
    };
    if text.is_empty() {
        return (None, None);
    }
    if !is_privacy_safe_display_text(&text) || text.chars().any(char::is_control) {
        return (
            None,
            Some(CreditModelDiagnostic::new("field_refused", field)),
        );
    }
    if text.chars().count() <= TITLE_MAX_CHARS && text.len() <= TITLE_MAX_BYTES {
        return (Some(text), None);
    }
    let mut cut = String::new();
    for (count, ch) in text.chars().enumerate() {
        if count == TITLE_MAX_CHARS || cut.len() + ch.len_utf8() > TITLE_MAX_BYTES {
            break;
        }
        cut.push(ch);
    }
    (
        Some(cut),
        Some(CreditModelDiagnostic::new("title_truncated", field)),
    )
}

fn counts_toward_next_expiry(grant: &AgentCreditGrant) -> bool {
    matches!(
        grant.status,
        CreditGrantStatus::Available | CreditGrantStatus::Paused
    )
}

/// Soonest `expires_at` among available/paused grants (contract v2.2 §11.1).
fn next_expires_at(grants: &[AgentCreditGrant]) -> Option<Rfc3339Timestamp> {
    grants
        .iter()
        .filter(|grant| counts_toward_next_expiry(grant))
        .filter_map(|grant| {
            let text = grant.expires_at.as_ref()?;
            Some((parse_instant(text)?, text))
        })
        .min_by_key(|(instant, _)| *instant)
        .map(|(_, text)| text.clone())
}

/// Latest provider `granted_at` over every grant, whatever its status
/// (contract v2.2 §11.1): a grant used right after it was added is still the
/// latest one added.
fn latest_granted_at(grants: &[AgentCreditGrant]) -> Option<Rfc3339Timestamp> {
    grants
        .iter()
        .filter_map(|grant| {
            let text = grant.granted_at.as_ref()?;
            Some((parse_instant(text)?, text))
        })
        .max_by_key(|(instant, _)| *instant)
        .map(|(_, text)| text.clone())
}

/// Balance state for a balance whose `remaining` is a count of what is left
/// (contract v2.1 §2.2): zero is `exhausted`, a positive amount is `ok`, and
/// an unknown amount is `unknown`.
pub(crate) fn status_for_remaining(remaining: Option<u64>) -> AgentCreditBalanceStatus {
    match remaining {
        Some(0) => AgentCreditBalanceStatus::Exhausted,
        Some(_) => AgentCreditBalanceStatus::Ok,
        None => AgentCreditBalanceStatus::Unknown,
    }
}

/// Balance summaries over its grants (contract v2.2 §11.1, v2.1 §3 A). Only
/// [`GrantsBuild::apply_to`] calls this, with the provider of the list it just
/// built; nothing here guesses the provider from the data.
///
/// - Only a `complete` list is a basis. `next_expires_at` is the soonest
///   expiry among available/paused grants and `latest_granted_at` the latest
///   grant time over all grants, with no clock filter (the reader judges
///   whether an instant has passed). Otherwise both are `None`.
/// - Anthropic saved resets: `remaining` = Σ `resets_left` of non-paused
///   grants for a `complete` list (0 when empty) and `None` in every other
///   state. A provider count (OpenAI `availableCount`) is left as sent.
/// - Every saved-resets balance takes its `status` from
///   [`status_for_remaining`].
fn summarize(balance: &mut AgentCreditBalance, provider: Option<Provider>) {
    balance.next_expires_at = None;
    balance.latest_granted_at = None;
    let complete = balance.grants_state == Some(CreditGrantsState::Complete);
    if complete {
        let grants = balance.grants.as_deref().unwrap_or(&[]);
        balance.next_expires_at = next_expires_at(grants);
        balance.latest_granted_at = latest_granted_at(grants);
    }
    if balance.kind != Some(CreditBalanceKind::SavedResets)
        || balance.unit != AgentCreditBalanceUnit::Resets
    {
        return;
    }
    if provider == Some(Provider::Anthropic) {
        // Anthropic reports no saved-reset count of its own: the model's sum
        // over a complete list is the only source, so every other state
        // (partial, capped, unavailable, not supported) clears it.
        balance.remaining = if complete {
            Some(
                balance
                    .grants
                    .iter()
                    .flatten()
                    .filter(|grant| grant.status != CreditGrantStatus::Paused)
                    .filter_map(|grant| grant.resets_left)
                    .sum(),
            )
        } else {
            None
        };
    }
    balance.status = status_for_remaining(balance.remaining);
}

/// Provider readiness for saved resets, passed through and never derived
/// (design R6; contract v2.2 §11.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ReadinessInput {
    pub(crate) eligible: Field<bool>,
    pub(crate) at_limit: Field<bool>,
    pub(crate) ineligible_reason: Field<String>,
    pub(crate) cooldown_until: TimeInput,
}

/// Write provider readiness onto a saved-resets balance. Every field is valid
/// only with `unit: resets`; on any other balance each sent field is refused.
/// `ineligible_reason` must be a `^[a-z0-9_.-]{1,64}$` code that passes the
/// privacy guard, and `cooldown_until` is normalized to UTC. A refused field
/// stays `None` with a diagnostic.
pub(crate) fn apply_readiness(
    balance: &mut AgentCreditBalance,
    input: ReadinessInput,
) -> Vec<CreditModelDiagnostic> {
    let mut diagnostics = Vec::new();
    let resets = balance.unit == AgentCreditBalanceUnit::Resets;
    let mut refuse = |field: &'static str| {
        diagnostics.push(CreditModelDiagnostic::new("field_refused", field));
    };
    let mut flag = |value: Field<bool>, field: &'static str| match value {
        Field::Absent => None,
        Field::Value(value) if resets => Some(value),
        _ => {
            refuse(field);
            None
        }
    };
    balance.eligible = flag(input.eligible, "eligible");
    balance.at_limit = flag(input.at_limit, "at_limit");
    balance.ineligible_reason = match input.ineligible_reason {
        Field::Absent => None,
        Field::Value(reason)
            if resets && is_credit_reason_code(&reason) && is_backend_safe_credit_text(&reason) =>
        {
            Some(reason)
        }
        _ => {
            refuse("ineligible_reason");
            None
        }
    };
    balance.cooldown_until = match normalize_time(input.cooldown_until) {
        Ok(None) => None,
        Ok(Some(instant)) if resets => Some(instant),
        _ => {
            refuse("cooldown_until");
            None
        }
    };
    diagnostics
}

/// Mark a balance as switched off by the provider (contract v2.1 §2.2
/// "Disabled"): `enabled: false`, amounts absent, `status: unknown`, and the
/// provider's reason when it is a `^[a-z0-9_.-]{1,64}$` code that passes the
/// privacy guard; any other reason is refused with a diagnostic.
pub(crate) fn apply_disabled(
    balance: &mut AgentCreditBalance,
    reason: Field<String>,
) -> Vec<CreditModelDiagnostic> {
    balance.enabled = Some(false);
    balance.status = AgentCreditBalanceStatus::Unknown;
    balance.remaining = None;
    balance.used = None;
    balance.quota = None;
    balance.used_percent = None;
    balance.unlimited = None;
    let mut diagnostics = Vec::new();
    balance.disabled_reason = match reason {
        Field::Absent => None,
        Field::Value(reason)
            if is_credit_reason_code(&reason) && is_backend_safe_credit_text(&reason) =>
        {
            Some(reason)
        }
        _ => {
            diagnostics.push(CreditModelDiagnostic::new(
                "field_refused",
                "disabled_reason",
            ));
            None
        }
    };
    diagnostics
}

/// Why [`one_time_credit`] built no balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OneTimeCreditRefusal {
    /// The pool codename is not a `^[a-z0-9_.-]{1,64}$` code that passes the
    /// privacy guard. It would become the pool's `limit_id`, which splits the
    /// history series, so the pool is skipped rather than renamed.
    LimitId,
}

impl OneTimeCreditRefusal {
    /// The diagnostic an adapter records for the skipped pool.
    pub(crate) fn diagnostic(self) -> CreditModelDiagnostic {
        match self {
            Self::LimitId => CreditModelDiagnostic::new("field_refused", "limit_id"),
        }
    }
}

/// A one-time credit pool (contract v2.2 §11.3, names pinned by §11.7 C4):
/// `name:"one_time_credit"`, `unit:"usd"`, `currency:"USD"`, amounts in
/// cents, `limit_id` = the pool codename, `expires_at` = the pool's expiry,
/// `enabled: None` (the provider sends no flag), no `resets_at`.
///
/// The codename must be a `^[a-z0-9_.-]{1,64}$` code that passes the privacy
/// guard, else the whole pool is refused ([`OneTimeCreditRefusal::LimitId`]).
/// The title follows [`bounded_title`] and both instants are normalized to UTC
/// like grant times; a refused title or instant comes back as a diagnostic on
/// the built balance.
pub(crate) fn one_time_credit(
    limit_id: &str,
    title: Field<String>,
    limit_cents: Option<u64>,
    used_cents: Option<u64>,
    remaining_cents: Option<u64>,
    expires_at: TimeInput,
    observed_at: TimeInput,
) -> Result<(AgentCreditBalance, Vec<CreditModelDiagnostic>), OneTimeCreditRefusal> {
    if !is_credit_reason_code(limit_id) || !is_backend_safe_credit_text(limit_id) {
        return Err(OneTimeCreditRefusal::LimitId);
    }
    let (title, title_diagnostic) = bounded_title(title, "title");
    let mut diagnostics = title_diagnostic.into_iter().collect::<Vec<_>>();
    let mut instant = |input: TimeInput, field: &'static str| {
        normalize_time(input).unwrap_or_else(|()| {
            diagnostics.push(CreditModelDiagnostic::new("field_refused", field));
            None
        })
    };
    let expires_at = instant(expires_at, "expires_at");
    let observed_at = instant(observed_at, "observed_at");
    let balance = AgentCreditBalance {
        name: "one_time_credit".to_string(),
        status: status_for_remaining(remaining_cents),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining: remaining_cents,
        used: used_cents,
        quota: limit_cents,
        currency: Some("USD".to_string()),
        limit_id: Some(limit_id.to_string()),
        observed_at,
        expires_at,
        kind: Some(CreditBalanceKind::OneTimeCredit),
        title,
        ..Default::default()
    };
    Ok((balance, diagnostics))
}

/// The grant-list part of a balance, cached so a reading without details can
/// re-send the last observed list unchanged. Built only from an observed
/// balance; its fields are the model's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantListSection {
    grant_count: Option<u64>,
    grants: Vec<AgentCreditGrant>,
    grants_state: CreditGrantsState,
    grants_observed_at: Option<Rfc3339Timestamp>,
    next_expires_at: Option<Rfc3339Timestamp>,
    latest_granted_at: Option<Rfc3339Timestamp>,
}

impl GrantListSection {
    /// The observed list of `balance`, if it carries one.
    pub(crate) fn from_balance(balance: &AgentCreditBalance) -> Option<Self> {
        Some(Self {
            grant_count: balance.grant_count,
            grants: balance.grants.clone()?,
            grants_state: balance.grants_state?,
            grants_observed_at: balance.grants_observed_at.clone(),
            next_expires_at: balance.next_expires_at.clone(),
            latest_granted_at: balance.latest_granted_at.clone(),
        })
    }

    /// Copy the list into `balance` exactly as observed, keeping its original
    /// `grants_observed_at`. A saved-resets balance takes its `status` from its
    /// freshly read count, as with [`GrantsBuild::apply_to`].
    pub(crate) fn apply_to(&self, balance: &mut AgentCreditBalance) {
        balance.grant_count = self.grant_count;
        balance.grants = Some(self.grants.clone());
        balance.grants_state = Some(self.grants_state);
        balance.grants_observed_at = self.grants_observed_at.clone();
        balance.next_expires_at = self.next_expires_at.clone();
        balance.latest_granted_at = self.latest_granted_at.clone();
        if balance.kind == Some(CreditBalanceKind::SavedResets)
            && balance.unit == AgentCreditBalanceUnit::Resets
        {
            balance.status = status_for_remaining(balance.remaining);
        }
    }
}

/// Which credential a cached section belongs to. Built only from the
/// credential-identity hash the adapter resolved for the binding (account and
/// organization identity), never from a slot or directory name: a slot that
/// switches from account A to B must not re-send A's sections as B's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BindingKey(String);

impl BindingKey {
    pub(crate) fn from_credential_identity_hash(hash: &str) -> Self {
        Self(hash.to_string())
    }
}

/// A section one provider read produces. Each balance belongs to exactly one
/// section, so a snapshot never carries the same balance twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CreditSection {
    /// A grant list re-sent onto a freshly read count
    /// ([`SectionCache::observe_grant_list`]).
    GrantList,
    /// Usage-credit balances.
    UsageCredits,
    /// One-time credit pools; every read that reports them emits them fresh.
    OneTimeCredits,
    /// Saved-reset balances.
    SavedResets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedSection {
    Balances(Vec<AgentCreditBalance>),
    GrantList {
        provider_count: u64,
        list: GrantListSection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    section: CachedSection,
    stored_seq: u64,
}

/// Bound on cached sections across all bindings. Ottto watches at most 10
/// Claude and 10 Codex account slots; a Claude binding uses up to three
/// balance sections and a Codex binding one grant list, so the live set is at
/// most 40 entries. The rest holds sections of identities a slot switched
/// away from (A→B→A). Every section is re-observed on its read cadence, so the
/// oldest-stored entry is the stalest; evicting it emits a diagnostic.
const SECTION_CACHE_MAX_ENTRIES: usize = 64;

/// Sender stability across read cadence (design R7b; contract v2.2 §11.5,
/// §11.7 C8/C9).
///
/// - Keyed by [`BindingKey`] (credential identity) and [`CreditSection`]. An
///   entry is dropped only by [`SectionCache::clear_binding`] when that
///   binding's identity changes, or by the size bound, so A→B→A keeps A's
///   sections.
/// - A re-sent section is the last observed one unchanged: original
///   `observed_at`/`grants_observed_at`, same presence, `grants`,
///   `grants_state` and `status`. `updated_at` is never carried over: re-sent
///   balances leave it unset, like fresh ones, and consumers use the
///   snapshot's capture time.
/// - Cold cache: nothing is returned, so a section never read is never sent,
///   and nothing stands in for it with `status: unknown`.
/// - A cached grant list is offered only while the provider count still
///   equals the count it was read with; otherwise the caller reads details now.
#[derive(Debug, Default)]
pub(crate) struct SectionCache {
    entries: BTreeMap<(BindingKey, CreditSection), CacheEntry>,
    next_seq: u64,
    diagnostics: Vec<CreditModelDiagnostic>,
}

impl SectionCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, binding: &BindingKey, section: CreditSection, value: CachedSection) {
        self.next_seq += 1;
        self.entries.insert(
            (binding.clone(), section),
            CacheEntry {
                section: value,
                stored_seq: self.next_seq,
            },
        );
        while self.entries.len() > SECTION_CACHE_MAX_ENTRIES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored_seq)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
            if self.diagnostics.len() < SECTION_CACHE_MAX_ENTRIES {
                self.diagnostics.push(CreditModelDiagnostic::new(
                    "section_cache_evicted",
                    "section_cache",
                ));
            }
        }
    }

    /// Record the balances a fresh provider read produced for `section`. An
    /// empty list is a real observation (the provider offers none).
    pub(crate) fn observe_balances(
        &mut self,
        binding: &BindingKey,
        section: CreditSection,
        balances: &[AgentCreditBalance],
    ) {
        // The grant-list section holds only lists (`observe_grant_list`).
        debug_assert_ne!(section, CreditSection::GrantList);
        if section == CreditSection::GrantList {
            return;
        }
        let mut balances = balances.to_vec();
        for balance in &mut balances {
            balance.updated_at = None;
        }
        self.insert(binding, section, CachedSection::Balances(balances));
    }

    /// The last observed balances of `section`, unchanged, with `updated_at`
    /// unset. `None` on a cold cache.
    pub(crate) fn resend_balances(
        &self,
        binding: &BindingKey,
        section: CreditSection,
    ) -> Option<Vec<AgentCreditBalance>> {
        let entry = self.entries.get(&(binding.clone(), section))?;
        let CachedSection::Balances(balances) = &entry.section else {
            return None;
        };
        Some(balances.clone())
    }

    /// Record a successfully read grant list together with the provider count
    /// it was read against. A list-less balance is not recorded.
    pub(crate) fn observe_grant_list(
        &mut self,
        binding: &BindingKey,
        provider_count: u64,
        balance: &AgentCreditBalance,
    ) {
        if let Some(list) = GrantListSection::from_balance(balance) {
            self.insert(
                binding,
                CreditSection::GrantList,
                CachedSection::GrantList {
                    provider_count,
                    list,
                },
            );
        }
    }

    /// The cached list, only while `provider_count` equals the count it was
    /// read with. `None` means the caller must read details now.
    pub(crate) fn grant_list_for_count(
        &self,
        binding: &BindingKey,
        provider_count: u64,
    ) -> Option<GrantListSection> {
        let entry = self
            .entries
            .get(&(binding.clone(), CreditSection::GrantList))?;
        match &entry.section {
            CachedSection::GrantList {
                provider_count: cached,
                list,
            } if *cached == provider_count => Some(list.clone()),
            _ => None,
        }
    }

    /// The binding's credential identity changed: forget every section it had.
    pub(crate) fn clear_binding(&mut self, binding: &BindingKey) {
        self.entries.retain(|(key, _), _| key != binding);
    }

    /// Diagnostics since the last call (size-bound evictions).
    pub(crate) fn take_diagnostics(&mut self) -> Vec<CreditModelDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests;
