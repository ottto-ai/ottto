//! Claude credit-pool adapter: maps Claude usage-credit, one-time and
//! saved-reset fields into the shared credit model
//! (`crate::quota_credit_model`). Owned by the Claude adapter.
//!
//! This module owns the Claude provider field names for credits (quota
//! contract v2.2 §11.1 kinds, §11.3 one-time pools, §11.7 C4 pinned names) and
//! the Claude read cadence (design R7). Grant building, summaries,
//! the one-time pool shape and section re-send stay in the model.

use std::collections::BTreeMap;
use std::path::Path;

use ottto_protocol::{
    ActiveSessionReconciliation, AgentCreditBalance, AgentCreditBalanceUnit, AgentQuotaWindow,
    AgentQuotaWindowFreshness, CreditBalanceKind, CreditGrantsUnavailableCause,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::quota_credit_model::{
    apply_disabled, apply_readiness, build_grants, one_time_credit, BindingKey,
    CreditModelDiagnostic, CreditSection, Field, GrantInput, GrantListSection, GrantStatusInput,
    ListObservation, Provider, ReadinessInput, SectionCache, TimeInput,
};

/// A saved-reset variant response without a recognizable `cedar_ember` stops
/// the variant for that binding this long; every slot reads plain meanwhile.
const SAVED_RESETS_VARIANT_PAUSE_SECONDS: u64 = 24 * 60 * 60;
/// Query of the saved-reset read variant. It returns the same windows and
/// one-time pools as the plain read, `cedar_ember`, and no `spend`.
const CLAUDE_SAVED_RESETS_QUERY: &str = "?cedar_ember=1&skip_spend=1";

/// Name of the usage-credit balance (pinned by contract v2.2 §11.7 C4).
pub(super) const CLAUDE_USAGE_CREDITS_NAME: &str = "Usage credits";
/// Name of the Claude saved-reset balance: the same series name as Codex; the
/// pool identity's source and binding keep the two apart (§11.7 C4).
const CLAUDE_SAVED_RESETS_NAME: &str = "reset_bank";
/// Percent-only one-time pool: no amounts to carry, left unparsed.
const CLAUDE_PERCENT_ONLY_POOL: &str = "cinder_cove";
/// Bound on one-time pools taken from one body.
const ONE_TIME_POOLS_MAX: usize = 16;

/// While the account was active this recently (a session for it written on
/// this Mac), the account is in use and its slot is the active slot.
pub(super) const ACTIVE_WINDOW_SECONDS: u64 = 30 * 60;
/// A stalled activity feed can preserve the active cadence for at most 2 h.
const MAX_ACTIVITY_FEED_LAG_SECONDS: u64 = 2 * 60 * 60;
/// In-use account: one read per 5 min. A fresh local statusLine reading for
/// the exact binding stands in for it (`agent_status`), so the provider is
/// called only when that free local data is older than this.
pub(super) const ACTIVE_SLOT_SECONDS: u64 = 5 * 60;
/// Longest slot any binding can have: the unused-account gate at the top of
/// its spread. Bounds a stored "not before" hold (`claude_read_held`).
const LONGEST_SLOT_SECONDS: u64 = super::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS
    + super::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS;
/// While usage credits are off, the plain read runs about this often and the
/// other slots take the saved-reset read.
const PLAIN_WHILE_CREDITS_OFF_SECONDS: u64 = 6 * 60 * 60;
/// Admission slack at the slot boundary (well under one 5-min pass).
const SLOT_ADMISSION_SLACK_SECONDS: u64 = 60;
/// A passive reading stamped further ahead of the local clock is not trusted.
const PASSIVE_CLOCK_SKEW_SECONDS: u64 = 60;
/// Longest pause between two collection passes of one caller that still
/// counts as continuous observation of its sign-in (passes run every ~5 min).
const CALLER_BINDING_MAX_GAP_SECONDS: u64 = 15 * 60;
/// A window reset the stored reading predates earns one extra read this long
/// after the reset, spread per account over the next minute (design R7
/// amendment: reset read). The reading after it postdates the reset, so each
/// reset is read at most once.
const RESET_READ_DELAY_SECONDS: u64 = 60;
const RESET_READ_SPREAD_SECONDS: u64 = 60;
/// Persisted cadence state, next to the account's usage cache.
pub(super) const CLAUDE_READ_SCHEDULE_FILE: &str = "read-schedule.json";

/// Which OAuth usage read a slot makes. Exactly one per slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeUsageRead {
    /// `GET /api/oauth/usage`: windows, usage credits, one-time pools.
    Plain,
    /// The saved-reset variant: windows and `cedar_ember`; no `spend`.
    SavedResets,
}

impl ClaudeUsageRead {
    pub(super) fn query(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::SavedResets => CLAUDE_SAVED_RESETS_QUERY,
        }
    }

    /// The read named in diagnostics.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Plain => "usage",
            Self::SavedResets => "saved-resets",
        }
    }
}

// The model's sections, in emission order. Each read owns some of them; a
// read that does not carry a section re-sends the last observed one.
const SECTIONS: [CreditSection; 3] = [
    CreditSection::UsageCredits,
    CreditSection::OneTimeCredits,
    CreditSection::SavedResets,
];

/// Credit sections one read observed. `None` = this read does not carry the
/// section, so the last observed one is re-sent unchanged.
#[derive(Debug, Default)]
pub(super) struct ClaudeCreditRead {
    usage_credits: Option<Vec<AgentCreditBalance>>,
    one_time_credits: Option<Vec<AgentCreditBalance>>,
    saved_resets: Option<Vec<AgentCreditBalance>>,
    pub(super) diagnostics: Vec<CreditModelDiagnostic>,
}

/// Parse the credit sections of one OAuth usage body read at `observed_at`
/// (the local response time, or a passive reading's own fetch time).
///
/// - Usage credits (`spend`, else `extra_usage`): the plain read only; the
///   saved-reset variant skips `spend` by request.
/// - One-time dollar pools: every read of a full usage body (both readings
///   report them), so a pool is always fresh.
/// - A body without the usage-credit keys (a passive reading that kept only
///   windows, a provider drop) observes neither section: the stored ones are
///   re-sent rather than erased. Observed sections are real even when empty.
/// - `cedar_ember` is a saved-reset observation only when its shape is
///   recognized ([`claude_saved_resets_recognized`]); the plain read always
///   sends it as `null`. An unrecognized section yields no balance, never an
///   `unknown` stand-in, so the last observed one is re-sent.
pub(super) fn claude_credit_read(
    body: &Value,
    read: ClaudeUsageRead,
    observed_at: &str,
) -> ClaudeCreditRead {
    let mut diagnostics = Vec::new();
    let saved_resets = claude_saved_resets(body, observed_at, &mut diagnostics).map(|b| vec![b]);
    let full_body = carries_credit_sections(body);
    let one_time_credits =
        full_body.then(|| claude_one_time_credits(body, observed_at, &mut diagnostics));
    let usage_credits = (full_body && read == ClaudeUsageRead::Plain).then(|| {
        let (mut usage_credits, refusals) = super::claude_oauth_credit_balances_and_refusals(body);
        diagnostics.extend(refusals);
        // `spend`/`extra_usage` → `usage_credits` (contract v2.2 §11.1).
        for balance in &mut usage_credits {
            balance.kind = Some(CreditBalanceKind::UsageCredits);
            balance.observed_at = Some(observed_at.to_string());
        }
        usage_credits
    });
    ClaudeCreditRead {
        usage_credits,
        one_time_credits,
        saved_resets,
        diagnostics,
    }
}

/// A rejection of the saved-reset variant itself: a 4xx other than auth
/// (401/403) and rate limiting (429), which keep the endpoint's own handling.
pub(super) fn claude_saved_resets_variant_rejected(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 401 | 403 | 429)
}

/// A full usage body: it carries the usage-credit keys (`spend` or the older
/// `extra_usage`, null included, as both readings send them). Pool keys come
/// with it, null when inactive.
fn carries_credit_sections(body: &Value) -> bool {
    body.get("spend").is_some() || body.get("extra_usage").is_some()
}

/// The saved-reset variant self-check (owner decision): `cedar_ember` is an
/// object with a `grants` array, or with a boolean `eligible` status.
/// Anything else (missing, null, another type) is unrecognized.
pub(super) fn claude_saved_resets_recognized(body: &Value) -> bool {
    body.get("cedar_ember")
        .and_then(Value::as_object)
        .is_some_and(|cedar| {
            cedar.get("grants").is_some_and(Value::is_array)
                || cedar.get("eligible").is_some_and(Value::is_boolean)
        })
}

fn balance_section(balance: &AgentCreditBalance) -> Option<CreditSection> {
    match balance.kind {
        Some(CreditBalanceKind::UsageCredits) => Some(CreditSection::UsageCredits),
        Some(CreditBalanceKind::OneTimeCredit) => Some(CreditSection::OneTimeCredits),
        Some(CreditBalanceKind::SavedResets) => Some(CreditSection::SavedResets),
        // Caches written before kinds existed held only the usage-credit row.
        None if balance.name == CLAUDE_USAGE_CREDITS_NAME => Some(CreditSection::UsageCredits),
        _ => None,
    }
}

/// The balances to send after a read (design R7b, contract v2.2 §11.5, C8/C9).
///
/// `previous` is the binding's last stored reading (same account and
/// organization). Sections this read observed replace theirs; every other
/// section is re-sent through the model's [`SectionCache`] exactly as last
/// observed, with its original `observed_at`/`grants_observed_at`. A section
/// never observed is not sent. Credit balances never carry `updated_at`
/// (contract C9 as amended).
///
/// The stored reading is on disk per binding, so unlike an in-memory cache a
/// restart still re-sends the last observed sections (no presence flip).
pub(super) fn claude_merge_credit_sections(
    binding: &str,
    previous: &[AgentCreditBalance],
    read: &ClaudeCreditRead,
) -> Vec<AgentCreditBalance> {
    let binding = BindingKey::from_credential_identity_hash(binding);
    let binding = &binding;
    let mut sections = SectionCache::new();
    for section in SECTIONS {
        // A reader-blind section stored by an older daemon (complete, 0) is
        // re-sent in its §11.10 shape.
        let prior = previous
            .iter()
            .filter(|balance| balance_section(balance) == Some(section))
            .cloned()
            .map(|mut balance| {
                claude_mark_reader_unavailable(&mut balance);
                balance
            })
            .collect::<Vec<_>>();
        if !prior.is_empty() {
            sections.observe_balances(binding, section, &prior);
        }
    }
    let saved_resets = read
        .saved_resets
        .clone()
        .map(|fresh| keep_stored_grant_list(fresh, previous));
    for (section, fresh) in [
        (CreditSection::UsageCredits, &read.usage_credits),
        (CreditSection::OneTimeCredits, &read.one_time_credits),
        (CreditSection::SavedResets, &saved_resets),
    ] {
        if let Some(fresh) = fresh {
            sections.observe_balances(binding, section, fresh);
        }
    }
    SECTIONS
        .into_iter()
        .filter_map(|section| sections.resend_balances(binding, section))
        .flatten()
        .collect()
}

/// A saved-reset reading whose `cedar_ember` had readiness but no `grants`
/// array lacks the grant list: re-send the last observed list (with its
/// original `grants_observed_at`, count and `remaining`, so `status` holds)
/// instead of replacing it with an unavailable one. Readiness stays fresh.
/// A reader-blind reading keeps its own unavailable list: the stored one was
/// seen by a reader that no longer sees it.
fn keep_stored_grant_list(
    mut fresh: Vec<AgentCreditBalance>,
    previous: &[AgentCreditBalance],
) -> Vec<AgentCreditBalance> {
    let stored = previous
        .iter()
        .filter(|balance| balance_section(balance) == Some(CreditSection::SavedResets))
        .filter(|balance| !claude_reader_cannot_see_grants(balance))
        .find_map(|balance| Some((GrantListSection::from_balance(balance)?, balance.remaining)));
    if let Some((list, remaining)) = stored {
        for balance in fresh
            .iter_mut()
            .filter(|balance| balance.grants.is_none() && !claude_reader_cannot_see_grants(balance))
        {
            balance.remaining = remaining;
            list.apply_to(balance);
        }
    }
    fresh
}

/// Whether the last observed usage-credit balance says credits are off.
pub(super) fn claude_usage_credits_off(balances: &[AgentCreditBalance]) -> bool {
    balances.iter().any(|balance| {
        balance_section(balance) == Some(CreditSection::UsageCredits)
            && balance.enabled == Some(false)
    })
}

/// The usage-credit balance of a switched-off `spend` (or `extra_usage`)
/// section: the model's disabled shape with the provider's
/// `disabled_reason`. A refused reason is a field diagnostic only (added to
/// `refusals`), never a lost balance.
pub(super) fn claude_disabled_usage_credits(
    section: &Value,
    refusals: &mut Vec<CreditModelDiagnostic>,
) -> AgentCreditBalance {
    let mut balance = AgentCreditBalance {
        name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        kind: Some(CreditBalanceKind::UsageCredits),
        ..Default::default()
    };
    let reason = section.as_object().map_or(Field::Absent, |section| {
        string_field(section, "disabled_reason")
    });
    refusals.extend(apply_disabled(&mut balance, reason));
    balance
}

/// Top-level keys the window parser owns. A window may carry `*_dollars`
/// money, so it is never also read as a one-time pool.
fn is_window_key(key: &str) -> bool {
    key == "five_hour" || key == "seven_day" || key.starts_with("seven_day_")
}

/// Every top-level object with a numeric `limit_dollars` is a one-time dollar
/// pool (contract v2.2 §11.3): `iguana_necktie`, `amber_ladder`,
/// `wattle_ember`, ... `resets_at` on these pools is an expiry, not a cycle.
/// Null pools, pools whose expiry passed before the read, and the
/// percent-only `cinder_cove` are skipped.
fn claude_one_time_credits(
    body: &Value,
    observed_at: &str,
    diagnostics: &mut Vec<CreditModelDiagnostic>,
) -> Vec<AgentCreditBalance> {
    let Some(object) = body.as_object() else {
        return Vec::new();
    };
    let read_at = parse_instant(observed_at);
    let mut keys = object.keys().collect::<Vec<_>>();
    keys.sort();
    keys.into_iter()
        .filter(|key| !is_window_key(key) && key.as_str() != CLAUDE_PERCENT_ONLY_POOL)
        .filter_map(|key| {
            let pool = object.get(key)?.as_object()?;
            pool.get("limit_dollars")
                .filter(|value| value.is_number())?;
            // The codename becomes the pool's `limit_id`; the model refuses a
            // codename that is not a closed code shape (or is secret-shaped),
            // and the pool is skipped with that refusal's diagnostic.
            let (balance, refused) = match one_time_credit(
                key,
                string_field(pool, "label"),
                super::claude_oauth_money_cents(pool.get("limit_dollars")),
                super::claude_oauth_money_cents(pool.get("used_dollars")),
                super::claude_oauth_money_cents(pool.get("remaining_dollars")),
                time_field(pool, "resets_at"),
                TimeInput::Rfc3339(observed_at.to_string()),
            ) {
                Ok(built) => built,
                Err(refusal) => {
                    diagnostics.push(refusal.diagnostic());
                    return None;
                }
            };
            // A pool whose expiry passed before this read is gone, not empty.
            if let (Some(expiry), Some(read_at)) = (
                balance.expires_at.as_deref().and_then(parse_instant),
                read_at,
            ) {
                if expiry < read_at {
                    return None;
                }
            }
            diagnostics.extend(refused);
            Some(balance)
        })
        .take(ONE_TIME_POOLS_MAX)
        .collect()
}

/// `ineligible_reason` values saying the reader that took the reading cannot
/// see the grants (contract v2.2 §11.10): the answer is about Ottto's request,
/// not the account, so its empty list is not "no resets".
const CLAUDE_READER_INELIGIBLE_REASONS: [&str; 2] = ["surface", "cli_version"];

fn claude_reader_cannot_see_grants(balance: &AgentCreditBalance) -> bool {
    balance.kind == Some(CreditBalanceKind::SavedResets)
        && balance
            .ineligible_reason
            .as_deref()
            .is_some_and(|reason| CLAUDE_READER_INELIGIBLE_REASONS.contains(&reason))
}

/// Contract v2.2 §11.10: a saved-reset reading whose reader cannot see the
/// grants has an unavailable list (no grants, no `remaining`, no
/// `grant_count`, `status` unknown) with `grants_unavailable_cause: reader`.
/// Readiness stays as read. Idempotent; any other balance is left as is.
pub(super) fn claude_mark_reader_unavailable(balance: &mut AgentCreditBalance) {
    if !claude_reader_cannot_see_grants(balance) {
        return;
    }
    // Unavailable carries no diagnostics.
    let _ = build_grants(ListObservation::Unavailable {
        provider: Provider::Anthropic,
        provider_count: None,
    })
    .apply_to(balance);
    balance.grants_unavailable_cause = Some(CreditGrantsUnavailableCause::Reader);
}

/// `cedar_ember` → one saved-reset balance. Grants, `remaining`, `status` and
/// the readiness passthrough (`eligible`, `ineligible_reason`, `at_limit`,
/// `cooldown_until`) are all the model's rules; this only names the fields.
/// A reader-blind answer (`ineligible_reason` `surface`/`cli_version`) has an
/// unavailable list whatever `grants` holds
/// ([`claude_mark_reader_unavailable`]).
fn claude_saved_resets(
    body: &Value,
    observed_at: &str,
    diagnostics: &mut Vec<CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    if !claude_saved_resets_recognized(body) {
        return None;
    }
    let cedar = body.get("cedar_ember")?.as_object()?;
    let mut balance = AgentCreditBalance {
        name: CLAUDE_SAVED_RESETS_NAME.to_string(),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Resets,
        observed_at: Some(observed_at.to_string()),
        kind: Some(CreditBalanceKind::SavedResets),
        ..Default::default()
    };
    diagnostics.extend(apply_readiness(
        &mut balance,
        ReadinessInput {
            eligible: bool_field(cedar, "eligible"),
            at_limit: bool_field(cedar, "at_limit"),
            ineligible_reason: string_field(cedar, "ineligible_reason"),
            cooldown_until: time_field(cedar, "cooldown_until"),
        },
    ));
    if claude_reader_cannot_see_grants(&balance) {
        claude_mark_reader_unavailable(&mut balance);
        return Some(balance);
    }
    let observation = match cedar.get("grants").and_then(Value::as_array) {
        // The raw array is the provider's complete enumeration (contract v2.1
        // §3 B): its length is the count, invalid members included.
        Some(grants) => ListObservation::Read {
            provider: Provider::Anthropic,
            provider_count: Some(grants.len() as u64),
            records: grants.iter().map(claude_grant_input).collect(),
            observed_at: observed_at.to_string(),
        },
        None => ListObservation::Unavailable {
            provider: Provider::Anthropic,
            provider_count: None,
        },
    };
    diagnostics.extend(build_grants(observation).apply_to(&mut balance));
    Some(balance)
}

/// One `cedar_ember.grants[]` record, provider-neutral. Field names only; every
/// rule (key, status map, refusal, order) is the model's.
fn claude_grant_input(record: &Value) -> GrantInput {
    let Some(record) = record.as_object() else {
        return GrantInput::default();
    };
    GrantInput {
        id: string_field(record, "id"),
        status: GrantStatusInput::PausedResetsLeft {
            paused: bool_field(record, "paused"),
            resets_left: u64_field(record, "resets_left"),
        },
        starts_at: time_field(record, "starts_at"),
        expires_at: time_field(record, "ends_at"),
        resets_included: u64_field(record, "resets_total"),
        resets_left: u64_field(record, "resets_left"),
        clears: match record.get("clears") {
            None | Some(Value::Null) => Field::Absent,
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(ToString::to_string))
                .collect::<Option<Vec<_>>>()
                .map_or(Field::Invalid, Field::Value),
            Some(_) => Field::Invalid,
        },
        title: string_field(record, "label"),
        usable_now: bool_field(record, "usable_now"),
        ..GrantInput::default()
    }
}

fn string_field(object: &Map<String, Value>, key: &str) -> Field<String> {
    match object.get(key) {
        None | Some(Value::Null) => Field::Absent,
        Some(Value::String(text)) => Field::Value(text.clone()),
        Some(_) => Field::Invalid,
    }
}

fn bool_field(object: &Map<String, Value>, key: &str) -> Field<bool> {
    match object.get(key) {
        None | Some(Value::Null) => Field::Absent,
        Some(Value::Bool(value)) => Field::Value(*value),
        Some(_) => Field::Invalid,
    }
}

fn u64_field(object: &Map<String, Value>, key: &str) -> Field<u64> {
    match object.get(key) {
        None | Some(Value::Null) => Field::Absent,
        Some(value) => value.as_u64().map_or(Field::Invalid, Field::Value),
    }
}

fn time_field(object: &Map<String, Value>, key: &str) -> TimeInput {
    match object.get(key) {
        None | Some(Value::Null) => TimeInput::Absent,
        Some(Value::String(text)) => TimeInput::Rfc3339(text.clone()),
        Some(_) => TimeInput::Invalid,
    }
}

fn parse_instant(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Cadence state of one account binding, persisted next to its usage cache.
/// Times are local unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaudeReadSchedule {
    /// Last plain body used: a plain read, or a passive reading's fetch time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_plain_read_at: Option<u64>,
    /// Last saved-reset variant read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_saved_resets_read_at: Option<u64>,
    /// Latest account activity the active-session scan attributed to this
    /// binding (the scan itself only lists recent sessions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_activity_at: Option<u64>,
    /// First reading of this binding. Never counts as activity. Kept in the
    /// persisted format; no slot reads it since unused accounts share one
    /// gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tracked_since: Option<u64>,
    /// The saved-reset variant is not used before this time: its last
    /// response had no recognizable `cedar_ember`. Separate from the endpoint
    /// breaker; never a breaker strike.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) saved_resets_variant_paused_until: Option<u64>,
    /// No provider read before this time: a saved-reset reading without
    /// anything usable (or without windows) consumed this slot. Cleared by the
    /// next reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) next_read_not_before: Option<u64>,
}

impl ClaudeReadSchedule {
    /// Record a successful reading of `read` at `read_at` (the plain fetch
    /// time for a passive reading), seen at local time `now`.
    pub(super) fn after_reading(
        &mut self,
        read: ClaudeUsageRead,
        read_at: u64,
        latest_activity_at: Option<u64>,
        now: u64,
    ) {
        match read {
            ClaudeUsageRead::Plain => {
                self.last_plain_read_at = Some(
                    self.last_plain_read_at
                        .map_or(read_at, |at| at.max(read_at)),
                );
            }
            ClaudeUsageRead::SavedResets => self.last_saved_resets_read_at = Some(read_at),
        }
        self.last_activity_at = self.activity_at(latest_activity_at);
        self.tracked_since.get_or_insert(now);
        self.next_read_not_before = None;
    }

    /// Record the self-check of a saved-reset variant response: an
    /// unrecognized shape pauses the variant for 24 h; a recognized one ends
    /// any pause.
    pub(super) fn after_saved_resets_variant(&mut self, recognized: bool, now: u64) {
        self.saved_resets_variant_paused_until =
            (!recognized).then(|| now.saturating_add(SAVED_RESETS_VARIANT_PAUSE_SECONDS));
    }

    fn saved_resets_variant_paused(&self, now: u64) -> bool {
        self.saved_resets_variant_paused_until
            .is_some_and(|until| now < until)
    }

    fn activity_at(&self, latest_activity_at: Option<u64>) -> Option<u64> {
        self.last_activity_at.max(latest_activity_at)
    }

    /// Keep the newest activity the scan reported. The scan lists a session
    /// only while its activity advances, so a sighting must be kept even when
    /// no reading is due. Returns whether anything changed.
    pub(super) fn observe_activity(&mut self, latest_activity_at: Option<u64>) -> bool {
        let activity = self.activity_at(latest_activity_at);
        let changed = activity != self.last_activity_at;
        self.last_activity_at = activity;
        changed
    }
}

pub(super) fn read_claude_read_schedule(account_state_dir: &Path) -> ClaudeReadSchedule {
    std::fs::read(account_state_dir.join(CLAUDE_READ_SCHEDULE_FILE))
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

pub(super) fn write_claude_read_schedule(
    account_state_dir: &Path,
    schedule: &ClaudeReadSchedule,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(schedule).map_err(std::io::Error::other)?;
    ottto_core::write_owner_only_file_atomic(
        &account_state_dir.join(CLAUDE_READ_SCHEDULE_FILE),
        &body,
    )
}

/// The account's read slot (design R7: active-account freshness): the active
/// slot while the account was active within the feed's last 30 min, else the default
/// (unused-account) slot.
pub(super) fn claude_usage_slot_seconds(
    schedule: &ClaudeReadSchedule,
    latest_activity_at: Option<u64>,
    feed_fresh_at: Option<u64>,
    default_slot_seconds: u64,
    now: u64,
) -> u64 {
    if claude_binding_in_use(schedule, latest_activity_at, feed_fresh_at, now) {
        return ACTIVE_SLOT_SECONDS;
    }
    default_slot_seconds
}

/// Whether the binding is in use on this Mac: a session for it was written in
/// the feed's last 30 min (the latest sighting, or the one kept in `schedule`).
/// Unknown freshness or a feed lagging more than 2 h uses the wall clock.
pub(super) fn claude_binding_in_use(
    schedule: &ClaudeReadSchedule,
    latest_activity_at: Option<u64>,
    feed_fresh_at: Option<u64>,
    now: u64,
) -> bool {
    let activity_clock = feed_fresh_at
        .map(|at| at.min(now))
        .filter(|at| now.saturating_sub(*at) <= MAX_ACTIVITY_FEED_LAG_SECONDS)
        .unwrap_or(now);
    schedule
        .activity_at(latest_activity_at)
        .is_some_and(|at| activity_clock.saturating_sub(at) <= ACTIVE_WINDOW_SECONDS)
}

/// Whether the binding's "not before next slot" hold applies now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClaudeReadHold {
    pub(super) active: bool,
    /// A stale hold was dropped from `schedule` (persist it).
    pub(super) cleared: bool,
}

/// The hold set by an unusable saved-reset reading, written one slot ahead.
/// The slot can shrink after that (the account becomes active), so the bound
/// is the longest slot any binding can have (the unused-account maximum): a
/// value further ahead can only come from the clock stepping back after it
/// was written, and is ignored and cleared. A corrected clock therefore never
/// holds a binding for longer than that.
pub(super) fn claude_read_held(
    schedule: &mut ClaudeReadSchedule,
    slot_seconds: u64,
    now: u64,
) -> ClaudeReadHold {
    match schedule.next_read_not_before {
        Some(not_before)
            if not_before > now.saturating_add(slot_seconds.max(LONGEST_SLOT_SECONDS)) =>
        {
            schedule.next_read_not_before = None;
            ClaudeReadHold {
                active: false,
                cleared: true,
            }
        }
        Some(not_before) => ClaudeReadHold {
            active: now < not_before,
            cleared: false,
        },
        None => ClaudeReadHold {
            active: false,
            cleared: false,
        },
    }
}

/// Whether a slot has elapsed since a reading `age_seconds` old. Readings are
/// taken inside a collection pass (every ~5 min), so the pass one slot later
/// can see an age a few seconds short of the slot; this slack admits it at the
/// boundary instead of one pass late (a 15 min slot stays 15 min, not 20).
pub(super) fn claude_slot_elapsed(age_seconds: u64, slot_seconds: u64) -> bool {
    age_seconds.saturating_add(SLOT_ADMISSION_SLACK_SECONDS) >= slot_seconds
}

/// How long after a window reset this binding's reset read waits: 60-120 s,
/// spread deterministically per account (load spreading, like the slots).
pub(super) fn claude_reset_read_delay_seconds(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-reset-read:");
    hasher.update(account_identifier_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(organization_identifier_hash.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    RESET_READ_DELAY_SECONDS + u64::from_be_bytes(bytes) % (RESET_READ_SPREAD_SECONDS + 1)
}

/// When the reset read for a reading taken at `observed_at` is due: the first
/// window reset after the reading plus `delay_seconds`, but never before the
/// stored Retry-After/success spacing (`next_refresh_after`). `None` when no
/// window of the reading resets after it.
pub(super) fn claude_reset_read_at(
    windows: &[AgentQuotaWindow],
    observed_at: u64,
    next_refresh_after: u64,
    delay_seconds: u64,
) -> Option<u64> {
    windows
        .iter()
        .filter_map(|window| window.resets_at.as_deref().and_then(parse_instant))
        .filter_map(|reset| u64::try_from(reset.unix_timestamp()).ok())
        .filter(|reset| *reset > observed_at)
        .min()
        .map(|reset| reset.saturating_add(delay_seconds).max(next_refresh_after))
}

/// Whether a reset the stored reading predates is due its one extra read,
/// outside the slot.
pub(super) fn claude_reset_read_due(
    windows: &[AgentQuotaWindow],
    observed_at: u64,
    next_refresh_after: u64,
    delay_seconds: u64,
    now: u64,
) -> bool {
    claude_reset_read_at(windows, observed_at, next_refresh_after, delay_seconds)
        .is_some_and(|at| now >= at)
}

/// Whether the binding is due a new reading: never read, or its slot has
/// elapsed and any Retry-After/success spacing has passed.
pub(super) fn claude_reading_due(
    last_reading_at: Option<u64>,
    next_refresh_after: u64,
    slot_seconds: u64,
    now: u64,
) -> bool {
    last_reading_at.map_or(true, |at| {
        claude_slot_elapsed(now.saturating_sub(at), slot_seconds) && now >= next_refresh_after
    })
}

/// Which read a due slot makes (design R7: no extra calls). `stored` is the
/// binding's persisted reading.
///
/// - While the variant is paused by its self-check every slot is plain.
/// - A missing section is filled first: with plain data known but no stored
///   saved-reset section, the slot reads the variant; with saved resets stored
///   but no plain data known, it reads plain. Nothing known: plain.
/// - Otherwise slots alternate plain and saved-reset reads; while usage
///   credits are off the plain read runs only every ~6 h.
pub(super) fn claude_usage_read_kind(
    schedule: &ClaudeReadSchedule,
    stored: &[AgentCreditBalance],
    now: u64,
) -> ClaudeUsageRead {
    if schedule.saved_resets_variant_paused(now) {
        return ClaudeUsageRead::Plain;
    }
    let stored_section = |section| stored.iter().any(|b| balance_section(b) == Some(section));
    let plain_known = schedule.last_plain_read_at.is_some()
        || stored_section(CreditSection::UsageCredits)
        || stored_section(CreditSection::OneTimeCredits);
    let saved_stored = stored_section(CreditSection::SavedResets);
    match (plain_known, saved_stored) {
        (false, _) => return ClaudeUsageRead::Plain,
        (true, false) => return ClaudeUsageRead::SavedResets,
        (true, true) => {}
    }
    let (Some(plain_at), Some(saved_at)) = (
        schedule.last_plain_read_at,
        schedule.last_saved_resets_read_at,
    ) else {
        // Sections persisted but the schedule was lost: alternate from plain.
        return if schedule.last_plain_read_at.is_none() {
            ClaudeUsageRead::Plain
        } else {
            ClaudeUsageRead::SavedResets
        };
    };
    if claude_usage_credits_off(stored) {
        // A due threshold, serviced by the next eligible slot. Measured from
        // the usage-credit section's own read, so a windows-only body (a
        // passive reading without credit keys) never resets it.
        let credits_read_at =
            section_read_at(stored, CreditSection::UsageCredits).unwrap_or(plain_at);
        return if now.saturating_sub(credits_read_at) >= PLAIN_WHILE_CREDITS_OFF_SECONDS {
            ClaudeUsageRead::Plain
        } else {
            ClaudeUsageRead::SavedResets
        };
    }
    if saved_at >= plain_at {
        ClaudeUsageRead::Plain
    } else {
        ClaudeUsageRead::SavedResets
    }
}

/// When the stored `section` was observed (its newest balance's own
/// `grants_observed_at`, else `observed_at`), as unix seconds.
fn section_read_at(stored: &[AgentCreditBalance], section: CreditSection) -> Option<u64> {
    stored
        .iter()
        .filter(|balance| balance_section(balance) == Some(section))
        .filter_map(balance_read_at)
        .max()
}

fn balance_read_at(balance: &AgentCreditBalance) -> Option<u64> {
    balance
        .grants_observed_at
        .as_deref()
        .or(balance.observed_at.as_deref())
        .and_then(parse_instant)
        .and_then(|instant| u64::try_from(instant.unix_timestamp()).ok())
}

/// Label each credit balance Fresh or Stale from its own read time, never
/// from a newer windows or passive read of the same binding. Per-section ages,
/// for a binding whose slot gate is `gate_seconds`:
/// - saved resets, and usage credits while credits are on, are read once
///   every two slots (plain/variant alternation): fresh for two gates;
/// - usage credits while credits are off are re-read about every 6 h (a due
///   threshold serviced at the next slot): fresh for 6 h plus one gate;
/// - one-time pools come with every full usage body: fresh for two gates;
/// - a balance with no read time of its own (stored before read times
///   existed) falls back to the stored reading's time and one gate.
///
/// A 24 h variant pause or an open breaker therefore shows as Stale, with the
/// section's original read time kept.
pub(super) fn label_credit_freshness(
    balances: &mut [AgentCreditBalance],
    gate_seconds: u64,
    stored_read_at: u64,
    now: u64,
) {
    for balance in balances {
        // Every serve path labels here, so a reader-blind saved-reset section
        // stored by an older daemon is served in its §11.10 shape too.
        claude_mark_reader_unavailable(balance);
        let (read_at, max_age) = match balance_read_at(balance) {
            None => (stored_read_at, gate_seconds),
            Some(read_at)
                if balance_section(balance) == Some(CreditSection::UsageCredits)
                    && balance.enabled == Some(false) =>
            {
                (
                    read_at,
                    PLAIN_WHILE_CREDITS_OFF_SECONDS.saturating_add(gate_seconds),
                )
            }
            Some(read_at) => (read_at, gate_seconds.saturating_mul(2)),
        };
        balance.freshness = if now.saturating_sub(read_at) <= max_age {
            AgentQuotaWindowFreshness::Fresh
        } else {
            AgentQuotaWindowFreshness::Stale
        };
    }
}

/// How far the last completed Claude scan observed activity. Reconciliation
/// time cannot stand in for its start: a long scan may finish with old sightings.
pub(super) fn claude_activity_feed_fresh_at(
    reconciliation: Option<&ActiveSessionReconciliation>,
) -> Option<u64> {
    let at = parse_instant(reconciliation?.scan_started_at.as_deref()?)?;
    u64::try_from(at.unix_timestamp()).ok()
}

/// Latest Claude session activity the daemon's active-session scan attributed
/// to exactly this account and organization.
pub(super) fn claude_latest_activity_at(
    reconciliation: Option<&ActiveSessionReconciliation>,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<u64> {
    reconciliation?
        .sessions
        .iter()
        .filter(|session| {
            session.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && session.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
        .filter_map(|session| parse_instant(&session.source_last_activity_at))
        .filter_map(|instant| u64::try_from(instant.unix_timestamp()).ok())
        .max()
}

/// A plain usage body Claude Code itself fetched for this account
/// (`.claude.json` `cachedUsageUtilization`), usable without a call.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ClaudePassiveUsage {
    pub(super) fetched_at: u64,
    pub(super) body: Value,
}

/// One check of a Claude Code `.claude.json` against a binding.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct ClaudePassiveConfig {
    /// `oauthAccount` names exactly the binding's account and organization.
    pub(super) bound: bool,
    /// The passive reading, only when the config is bound and
    /// `cachedUsageUtilization.accountUuid` is that same account.
    pub(super) reading: Option<ClaudePassiveUsage>,
}

/// Check a Claude Code `.claude.json` against a binding. Reads only
/// `oauthAccount` and `cachedUsageUtilization`.
///
/// Passive input from Claude Code's own `cachedUsageUtilization` (design R7:
/// active-account freshness).
/// Every collection pass records where each caller is signed in, and a
/// registered slot's identity gate ends the caller's run when it refuses the
/// slot, as does a pass that skips the collector (an unresolved default-login
/// identity, a browser re-sign-in), so a body fetched under another
/// organization is never adopted.
pub(super) fn claude_passive_config(
    config: &Value,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> ClaudePassiveConfig {
    let Some((account_uuid, bound)) = config.get("oauthAccount").and_then(|oauth| {
        let account_uuid = oauth.get("accountUuid")?.as_str()?;
        let organization_uuid = oauth.get("organizationUuid")?.as_str()?;
        let bound = ottto_core::billing_identity_hash("anthropic", "account", account_uuid)
            .as_deref()
            == Some(account_identifier_hash)
            && ottto_core::billing_identity_hash("anthropic", "organization", organization_uuid)
                .as_deref()
                == Some(organization_identifier_hash);
        Some((account_uuid, bound))
    }) else {
        return ClaudePassiveConfig::default();
    };
    ClaudePassiveConfig {
        bound,
        reading: bound
            .then(|| claude_passive_reading(config.get("cachedUsageUtilization")?, account_uuid))
            .flatten(),
    }
}

/// When Claude Code fetched its cached usage body
/// (`cachedUsageUtilization.fetchedAtMs`, epoch milliseconds). The one parser
/// of that field: a non-negative integer or finite float.
pub(super) fn claude_cached_usage_fetched_at_ms(cached: &Value) -> Option<u64> {
    let fetched = cached.get("fetchedAtMs")?;
    fetched.as_u64().or_else(|| {
        fetched
            .as_f64()
            .filter(|ms| ms.is_finite() && *ms >= 0.0)
            .map(|ms| ms as u64)
    })
}

fn claude_passive_reading(cached: &Value, account_uuid: &str) -> Option<ClaudePassiveUsage> {
    if cached.get("accountUuid")?.as_str()? != account_uuid {
        return None;
    }
    let fetched_ms = claude_cached_usage_fetched_at_ms(cached)?;
    let body = cached.get("utilization")?;
    body.is_object().then(|| ClaudePassiveUsage {
        fetched_at: fetched_ms / 1000,
        body: body.clone(),
    })
}

/// Where one caller's sign-in has been seen, pass after pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClaudeCallerBinding {
    binding: String,
    since: u64,
    last_seen: u64,
}

/// Record that this collection pass found `caller_key` signed in to
/// `binding`, and return since when that caller has been continuously seen
/// on it. Any other binding, a gap longer than a few passes (sleep, restart,
/// an unresolved identity) or a clock going backwards starts a new run.
pub(super) fn claude_observe_caller_binding(
    callers: &mut BTreeMap<String, ClaudeCallerBinding>,
    caller_key: &str,
    binding: &str,
    now: u64,
) -> u64 {
    match callers.get_mut(caller_key) {
        Some(seen)
            if seen.binding == binding
                && now >= seen.last_seen
                && now - seen.last_seen <= CALLER_BINDING_MAX_GAP_SECONDS =>
        {
            seen.last_seen = now;
            seen.since
        }
        _ => {
            callers.insert(
                caller_key.to_string(),
                ClaudeCallerBinding {
                    binding: binding.to_string(),
                    since: now,
                    last_seen: now,
                },
            );
            now
        }
    }
}

/// A pass refused this caller's sign-in (a registered slot's identity gate):
/// its run ends, so no body fetched before the next accepted pass is adopted.
pub(super) fn claude_end_caller_binding(
    callers: &mut BTreeMap<String, ClaudeCallerBinding>,
    caller_key: &str,
) {
    callers.remove(caller_key);
}

/// End of a full collection pass: keep only the runs of callers that reached
/// the collector during it. A caller skipped for any reason loses its run.
pub(super) fn claude_keep_caller_bindings(
    callers: &mut BTreeMap<String, ClaudeCallerBinding>,
    reached: &std::collections::BTreeSet<String>,
) {
    callers.retain(|caller_key, _| reached.contains(caller_key));
}

/// Use the passive reading instead of a call when it is newer than our last
/// reading, still inside the slot (so it would serve as fresh), and fetched
/// while this caller was already seen signed in to this binding.
///
/// The cached body carries no organization, so the organization is proved by
/// bracketing: every collection pass of this caller since `bound_since` (one
/// per ~5 min, see [`claude_observe_caller_binding`]) found this exact account
/// and organization, and the body was fetched inside that run. A run never
/// adopts a body fetched before it started.
pub(super) fn claude_passive_reading_usable(
    fetched_at: u64,
    last_reading_at: Option<u64>,
    bound_since: Option<u64>,
    slot_seconds: u64,
    now: u64,
) -> bool {
    bound_since.is_some_and(|since| since <= fetched_at)
        && fetched_at <= now.saturating_add(PASSIVE_CLOCK_SKEW_SECONDS)
        && last_reading_at.map_or(true, |last| fetched_at > last)
        && now.saturating_sub(fetched_at) <= slot_seconds
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{AgentCreditBalanceStatus, CreditGrantStatus, CreditGrantsState};
    use serde_json::json;

    // Synthetic bodies shaped like the redacted real plain and saved-reset
    // variant responses (account/org/grant ids are invented).
    const READ_AT: &str = "2026-10-09T14:06:52Z";

    fn window(utilization: u64, resets_at: Option<&str>) -> Value {
        json!({
            "utilization": utilization, "resets_at": resets_at,
            "limit_dollars": null, "used_dollars": null, "remaining_dollars": null,
            "locked_reason": null
        })
    }

    fn pool(limit: f64, used: f64, remaining: f64, resets_at: &str) -> Value {
        json!({
            "utilization": 0, "resets_at": resets_at, "limit_dollars": limit,
            "used_dollars": used, "remaining_dollars": remaining, "locked_reason": null
        })
    }

    /// Plain read of a Max account: the $250 one-time pool, an expired pool,
    /// a percent-only pool, usage credits off.
    fn plain_max_body() -> Value {
        json!({
            "five_hour": window(0, None),
            "seven_day": window(100, Some("2026-10-10T05:00:00.377761+00:00")),
            "seven_day_opus": null,
            "iguana_necktie": pool(250.0, 0.0, 250.0, "2026-11-05T07:59:00+00:00"),
            "amber_ladder": {
                "utilization": 100, "resets_at": "2026-10-02T06:59:59+00:00",
                "limit_dollars": 2500, "used_dollars": 2501.367212,
                "remaining_dollars": 0.0, "locked_reason": null
            },
            "cinder_cove": {"utilization": 4, "resets_at": "2026-11-01T00:00:00+00:00"},
            "nimbus_quill": null,
            "wattle_ember": null,
            "cedar_ember": null,
            "extra_usage": {
                "is_enabled": false, "monthly_limit": null, "used_credits": null,
                "disabled_reason": null, "user_disabled": true
            },
            "spend": {
                "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
                "limit": null, "percent": 0, "severity": "normal", "enabled": false,
                "disabled_reason": null, "cap": null, "balance": null
            }
        })
    }

    fn cedar_grant(id: &str, label: &str, resets_left: u64, usable_now: bool) -> Value {
        json!({
            "id": id, "label": label, "resets_total": 1, "resets_left": resets_left,
            "starts_at": "2026-09-22T16:00:00+00:00", "ends_at": "2026-10-22T16:00:00+00:00",
            "clears": ["five_hour", "seven_day", "seven_day_overage_included"],
            "paused": false, "usable_now": usable_now, "use_requires_limit": false,
            "percent_used": {"five_hour": 0, "seven_day": 0}, "blocking": [], "arm": null
        })
    }

    fn variant_body(cedar: Value) -> Value {
        json!({
            "five_hour": window(38, Some("2026-10-04T20:20:00.508208+00:00")),
            "seven_day": window(100, Some("2026-10-08T17:00:00.508227+00:00")),
            "iguana_necktie": pool(250.0, 0.0, 250.0, "2026-11-05T07:59:00+00:00"),
            "cedar_ember": cedar,
            "extra_usage": null,
            "spend": null
        })
    }

    fn cedar_team() -> Value {
        json!({
            "eligible": true, "ineligible_reason": null, "at_limit": false, "exhausted": [],
            "grants": [cedar_grant("grant_team_01", "Launch: one usage-limit reset for Team members", 0, false)],
            "next_grant_id": null, "weekly_resets_at": "2026-09-25T14:00:00+00:00",
            "cooldown_until": "2026-09-23T16:21:19.342795+00:00",
            "event_props": {"tier": "claude_team"}
        })
    }

    fn cedar_max() -> Value {
        json!({
            "eligible": true, "ineligible_reason": null, "at_limit": true,
            "exhausted": ["seven_day"],
            "grants": [cedar_grant("grant_max_01", "Launch: one usage-limit reset for Pro and Max", 1, true)],
            "next_grant_id": "grant_max_01", "cooldown_until": null
        })
    }

    fn cedar_ineligible() -> Value {
        json!({
            "eligible": false, "ineligible_reason": "tenure", "at_limit": false,
            "exhausted": [], "grants": [], "next_grant_id": null,
            "cooldown_until": null, "paused_held": false
        })
    }

    fn saved_resets(cedar: Value) -> AgentCreditBalance {
        let read = claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT);
        // The variant skips `spend`; its one-time pools are fresh.
        assert!(read.usage_credits.is_none());
        assert_eq!(read.one_time_credits.as_ref().map(Vec::len), Some(1));
        let mut balances = read.saved_resets.expect("cedar_ember observed");
        assert_eq!(balances.len(), 1);
        balances.remove(0)
    }

    #[test]
    fn plain_body_maps_iguana_necktie_one_time_credit() {
        let read = claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT);
        let pools = read.one_time_credits.clone().unwrap();
        assert_eq!(
            pools.len(),
            1,
            "expired, percent-only and null pools are skipped"
        );
        let credit = &pools[0];
        assert_eq!(credit.name, "one_time_credit");
        assert_eq!(credit.kind, Some(CreditBalanceKind::OneTimeCredit));
        assert_eq!(credit.limit_id.as_deref(), Some("iguana_necktie"));
        assert_eq!(credit.unit, AgentCreditBalanceUnit::Usd);
        assert_eq!(credit.currency.as_deref(), Some("USD"));
        assert_eq!(credit.quota, Some(25_000));
        assert_eq!(credit.used, Some(0));
        assert_eq!(credit.remaining, Some(25_000));
        assert_eq!(credit.expires_at.as_deref(), Some("2026-11-05T07:59:00Z"));
        assert_eq!(credit.resets_at, None);
        assert_eq!(credit.enabled, None);
        assert_eq!(credit.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(credit.observed_at.as_deref(), Some(READ_AT));
        assert_eq!(credit.title, None);
        // The plain read carries the usage-credit section too, and never a
        // saved-reset one (`cedar_ember` is null there).
        let usage = read.usage_credits.clone().unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].kind, Some(CreditBalanceKind::UsageCredits));
        assert_eq!(usage[0].enabled, Some(false));
        assert_eq!(usage[0].observed_at.as_deref(), Some(READ_AT));
        assert!(read.saved_resets.is_none());
        assert!(read.diagnostics.is_empty());
    }

    #[test]
    fn one_time_pool_label_becomes_title_and_windows_are_never_pools() {
        let body = json!({
            "five_hour": {"utilization": 1, "resets_at": null, "limit_dollars": 9},
            "seven_day_cowork": {"utilization": 1, "resets_at": null, "limit_dollars": 9},
            "wattle_ember": {
                "utilization": 10, "resets_at": "2027-01-01T00:00:00Z", "label": "Promo credit",
                "limit_dollars": 20, "used_dollars": 2, "remaining_dollars": 18
            },
            "Bad Key": {"limit_dollars": 1}
        });
        let pools = claude_one_time_credits(&body, READ_AT, &mut Vec::new());
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].limit_id.as_deref(), Some("wattle_ember"));
        assert_eq!(pools[0].title.as_deref(), Some("Promo credit"));
        assert_eq!(pools[0].remaining, Some(1_800));
    }

    #[test]
    fn usage_credits_off_carries_the_reason_code() {
        let mut body = plain_max_body();
        body["spend"]["disabled_reason"] = json!("out_of_credits");
        let usage = super::super::claude_oauth_credit_balances(&body);
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].name, CLAUDE_USAGE_CREDITS_NAME);
        assert_eq!(usage[0].kind, Some(CreditBalanceKind::UsageCredits));
        assert_eq!(usage[0].enabled, Some(false));
        assert_eq!(usage[0].status, AgentCreditBalanceStatus::Unknown);
        assert_eq!(usage[0].disabled_reason.as_deref(), Some("out_of_credits"));
        assert!(claude_usage_credits_off(&usage));
        // Not a reason code: dropped, never sent as free text.
        body["spend"]["disabled_reason"] = json!("Out of credits!");
        let usage = super::super::claude_oauth_credit_balances(&body);
        assert_eq!(usage[0].disabled_reason, None);
        // The `extra_usage` fallback carries its own reason.
        let fallback = super::super::claude_oauth_credit_balances(&json!({
            "extra_usage": {"is_enabled": false, "disabled_reason": "org_level_disabled"}
        }));
        assert_eq!(
            fallback[0].disabled_reason.as_deref(),
            Some("org_level_disabled")
        );
        // Enabled credits never carry a reason.
        let enabled = super::super::claude_oauth_credit_balances(&json!({
            "spend": {"enabled": true, "disabled_reason": "out_of_credits",
                      "used": {"amount_minor": 1, "exponent": 2}}
        }));
        assert_eq!(enabled[0].disabled_reason, None);
        assert!(!claude_usage_credits_off(&enabled));
    }

    #[test]
    fn cedar_team_grant_used_with_cooldown() {
        let balance = saved_resets(cedar_team());
        assert_eq!(balance.name, "reset_bank");
        assert_eq!(balance.kind, Some(CreditBalanceKind::SavedResets));
        assert_eq!(balance.unit, AgentCreditBalanceUnit::Resets);
        assert_eq!(balance.limit_id, None);
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        assert_eq!(balance.grant_count, Some(1));
        assert_eq!(balance.grants_observed_at.as_deref(), Some(READ_AT));
        assert_eq!(balance.observed_at.as_deref(), Some(READ_AT));
        assert_eq!(balance.remaining, Some(0));
        assert_eq!(balance.status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(balance.eligible, Some(true));
        assert_eq!(balance.at_limit, Some(false));
        assert_eq!(balance.ineligible_reason, None);
        assert_eq!(
            balance.cooldown_until.as_deref(),
            Some("2026-09-23T16:21:19.342795Z")
        );
        // A redeemed grant is not a basis for the expiry summary.
        assert_eq!(balance.next_expires_at, None);
        assert_eq!(balance.latest_granted_at, None);
        assert_eq!(balance.enabled, None);
        let grants = balance.grants.as_ref().unwrap();
        assert_eq!(grants.len(), 1);
        let grant = &grants[0];
        assert_eq!(
            grant.grant_key,
            crate::quota_credit_model::credit_grant_key(Provider::Anthropic, "grant_team_01")
        );
        assert_eq!(grant.status, CreditGrantStatus::Redeemed);
        assert_eq!(grant.resets_included, Some(1));
        assert_eq!(grant.resets_left, Some(0));
        assert_eq!(grant.usable_now, Some(false));
        assert_eq!(grant.starts_at.as_deref(), Some("2026-09-22T16:00:00Z"));
        assert_eq!(grant.expires_at.as_deref(), Some("2026-10-22T16:00:00Z"));
        assert_eq!(grant.granted_at, None);
        assert_eq!(grant.clears.as_ref().map(Vec::len), Some(3));
        assert_eq!(
            grant.title.as_deref(),
            Some("Launch: one usage-limit reset for Team members")
        );
    }

    fn cedar_reader_blind(reason: &str, grants: Option<Value>) -> Value {
        let mut cedar = cedar_ineligible();
        cedar["ineligible_reason"] = json!(reason);
        match grants {
            Some(grants) => cedar["grants"] = grants,
            None => {
                cedar.as_object_mut().unwrap().remove("grants");
            }
        }
        cedar
    }

    fn assert_reader_unavailable(balance: &AgentCreditBalance, reason: &str) {
        assert_eq!(
            balance.grants_unavailable_cause,
            Some(CreditGrantsUnavailableCause::Reader),
            "{reason}"
        );
        assert!(ottto_protocol::credit_grants_unavailable_cause_allowed(
            balance
        ));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Unavailable));
        assert_eq!(balance.grants, None);
        assert_eq!(balance.remaining, None);
        assert_eq!(balance.grant_count, None);
        assert_eq!(balance.grants_observed_at, None);
        assert_eq!(balance.next_expires_at, None);
        assert_eq!(balance.latest_granted_at, None);
        assert_eq!(balance.status, AgentCreditBalanceStatus::Unknown);
        // Readiness stays exactly as read.
        assert_eq!(balance.eligible, Some(false));
        assert_eq!(balance.at_limit, Some(false));
        assert_eq!(balance.ineligible_reason.as_deref(), Some(reason));
    }

    /// The cause never appears on any other shape: across every Claude
    /// fixture, both reads, re-sends, a stored list followed by a reader-blind
    /// answer and back, and an older daemon's stored reader-blind reading.
    #[test]
    fn grants_unavailable_cause_appears_on_no_other_shape() {
        fn check(balances: &[AgentCreditBalance]) {
            for balance in balances {
                let blind = claude_reader_cannot_see_grants(balance);
                assert_eq!(
                    balance.grants_unavailable_cause.is_some(),
                    blind,
                    "{balance:?}"
                );
                if blind {
                    assert_reader_unavailable(
                        balance,
                        balance.ineligible_reason.as_deref().unwrap(),
                    );
                }
            }
        }
        for name in [
            "claude-oauth-usage-plain",
            "claude-oauth-usage-credits-off",
            "claude-usage-cedar",
            "claude-usage-cedar-ineligible",
            "claude-usage-cedar-reader-surface",
            "claude-usage-cedar-reader-cli-version",
            "claude-usage-cedar-refused-expiry",
        ] {
            for read in [ClaudeUsageRead::Plain, ClaudeUsageRead::SavedResets] {
                let body = fixture(&format!("provider/{name}.json"));
                let read = claude_credit_read(&body, read, READ_AT);
                check(&claude_merge_credit_sections("fixture", &[], &read));
            }
        }
        let read = |cedar: Value| {
            claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT)
        };
        let plain = claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT);
        let listed = claude_merge_credit_sections("b", &[], &read(cedar_max()));
        let blind = claude_merge_credit_sections(
            "b",
            &listed,
            &read(cedar_reader_blind("surface", Some(json!([])))),
        );
        // A readiness-only blind answer never takes the stored list.
        let blind_no_list =
            claude_merge_credit_sections("b", &listed, &read(cedar_reader_blind("surface", None)));
        let resent = claude_merge_credit_sections("b", &blind, &plain);
        // Back to a readable answer: an ordinary list again, without the cause.
        let back = claude_merge_credit_sections("b", &resent, &read(cedar_max()));
        let readiness_only = claude_merge_credit_sections(
            "b",
            &blind,
            &read(json!({"eligible": true, "ineligible_reason": null})),
        );
        for balances in [
            &listed,
            &blind,
            &blind_no_list,
            &resent,
            &back,
            &readiness_only,
        ] {
            check(balances);
        }
        let saved = |balances: &[AgentCreditBalance]| {
            balances
                .iter()
                .find(|balance| balance.kind == Some(CreditBalanceKind::SavedResets))
                .cloned()
                .expect("saved resets")
        };
        assert_reader_unavailable(&saved(&blind_no_list), "surface");
        assert_reader_unavailable(&saved(&resent), "surface");
        assert_eq!(saved(&back).grants_unavailable_cause, None);
        assert_eq!(saved(&back).remaining, Some(1));
        assert_eq!(saved(&readiness_only).grants_unavailable_cause, None);
        // An older daemon stored the blind answer as a complete, empty list:
        // re-sent and served in the §11.10 shape.
        let mut older = saved(&read_older_blind());
        older.grants_unavailable_cause = None;
        older.grants = Some(Vec::new());
        older.grants_state = Some(CreditGrantsState::Complete);
        older.grant_count = Some(0);
        older.remaining = Some(0);
        older.grants_observed_at = Some(READ_AT.to_string());
        older.status = AgentCreditBalanceStatus::Exhausted;
        let resent = claude_merge_credit_sections("b", &[older.clone()], &plain);
        assert_reader_unavailable(&saved(&resent), "surface");
        let mut served = vec![older];
        label_credit_freshness(&mut served, 3_600, 0, 0);
        assert_reader_unavailable(&served[0], "surface");
    }

    fn read_older_blind() -> Vec<AgentCreditBalance> {
        claude_credit_read(
            &variant_body(cedar_reader_blind("surface", Some(json!([])))),
            ClaudeUsageRead::SavedResets,
            READ_AT,
        )
        .saved_resets
        .unwrap()
    }

    #[test]
    fn cedar_drift_is_refused_field_by_field() {
        let mut cedar = cedar_max();
        cedar["ineligible_reason"] = json!("Not Eligible");
        cedar["at_limit"] = json!("yes");
        cedar["cooldown_until"] = json!("soon");
        cedar["grants"][0]["usable_now"] = json!(1);
        let read = claude_credit_read(&variant_body(cedar), ClaudeUsageRead::SavedResets, READ_AT);
        let balance = &read.saved_resets.as_ref().unwrap()[0];
        assert_eq!(balance.ineligible_reason, None);
        assert_eq!(balance.at_limit, None);
        assert_eq!(balance.cooldown_until, None);
        assert_eq!(balance.grants.as_ref().unwrap()[0].usable_now, None);
        // A refused readiness or `usable_now` value never changes the list state.
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        let fields = read.diagnostics.iter().map(|d| d.field).collect::<Vec<_>>();
        for field in [
            "ineligible_reason",
            "at_limit",
            "cooldown_until",
            "grants[].usable_now",
        ] {
            assert!(fields.contains(&field), "{field} refused with a diagnostic");
        }
        // No grants array: details unavailable, nothing invented.
        let read = claude_credit_read(
            &variant_body(json!({"eligible": true})),
            ClaudeUsageRead::SavedResets,
            READ_AT,
        );
        let balance = &read.saved_resets.as_ref().unwrap()[0];
        assert_eq!(balance.grants, None);
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Unavailable));
        assert_eq!(balance.remaining, None);
        assert_eq!(balance.status, AgentCreditBalanceStatus::Unknown);
    }

    fn presence(
        balances: &[AgentCreditBalance],
    ) -> Vec<(String, Option<String>, AgentCreditBalanceStatus)> {
        balances
            .iter()
            .map(|b| (b.name.clone(), b.limit_id.clone(), b.status.clone()))
            .collect()
    }

    /// R7b: alternation, restart (the stored reading round-trips through
    /// JSON) and A→B→A never toggle presence, `grants`, `grants_state` or
    /// `status`; a re-sent section keeps its original read times.
    #[test]
    fn sections_stay_stable_across_alternation_restart_and_account_switch() {
        let plain = plain_max_body();
        let variant = variant_body(cedar_max());
        let t1 = "2026-10-09T10:00:00Z";
        let t2 = "2026-10-09T11:00:00Z";
        let t3 = "2026-10-09T12:00:00Z";

        // Cold: a first saved-reset read sends only what it observed (the
        // pool and saved resets); nothing stands in for the unread usage
        // credits.
        let cold = claude_merge_credit_sections(
            "a",
            &[],
            &claude_credit_read(&variant, ClaudeUsageRead::SavedResets, t1),
        );
        assert_eq!(
            cold.iter().map(|b| b.kind).collect::<Vec<_>>(),
            [
                Some(CreditBalanceKind::OneTimeCredit),
                Some(CreditBalanceKind::SavedResets)
            ]
        );

        let first = claude_merge_credit_sections(
            "a",
            &cold,
            &claude_credit_read(&plain, ClaudeUsageRead::Plain, t1),
        );
        let expected = presence(&first);
        assert_eq!(expected.len(), 3, "usage credits, $250 pool, saved resets");
        let mut stored = first.clone();
        let mut timeline = vec![first];
        for (read, at) in [
            (ClaudeUsageRead::SavedResets, t2),
            (ClaudeUsageRead::Plain, t3),
            (ClaudeUsageRead::SavedResets, "2026-10-09T13:00:00Z"),
        ] {
            // Restart between every read: only the stored reading survives.
            let restored: Vec<AgentCreditBalance> =
                serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap();
            let body = if read == ClaudeUsageRead::Plain {
                &plain
            } else {
                &variant
            };
            stored =
                claude_merge_credit_sections("a", &restored, &claude_credit_read(body, read, at));
            assert_eq!(presence(&stored), expected);
            timeline.push(stored.clone());
        }
        for balances in &timeline {
            let saved = balances
                .iter()
                .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
                .unwrap();
            assert!(saved.grants.is_some());
            assert_eq!(saved.grants_state, Some(CreditGrantsState::Complete));
            assert!(balances.iter().all(|b| b.updated_at.is_none()));
        }
        // After the t2 variant read the usage credits are the t1 section,
        // unchanged.
        let usage_t2 = timeline[1]
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
            .unwrap();
        assert_eq!(
            usage_t2,
            timeline[0]
                .iter()
                .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
                .unwrap()
        );
        assert_eq!(usage_t2.observed_at.as_deref(), Some(t1));
        // After the t3 plain read the saved resets are the t2 section.
        let saved_t3 = timeline[2]
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .unwrap();
        assert_eq!(saved_t3.grants_observed_at.as_deref(), Some(t2));

        // A→B→A: each binding keeps its own stored reading, so B never
        // empties A and A comes back with its own sections.
        let b_stored = claude_merge_credit_sections(
            "b",
            &[],
            &claude_credit_read(&json!({"spend": null}), ClaudeUsageRead::Plain, t3),
        );
        assert!(b_stored.is_empty());
        let a_again = claude_merge_credit_sections(
            "a",
            &stored,
            &claude_credit_read(
                &variant,
                ClaudeUsageRead::SavedResets,
                "2026-10-09T14:00:00Z",
            ),
        );
        assert_eq!(presence(&a_again), expected);
    }

    /// A plain-read body without the credit keys (a passive reading that kept
    /// only windows) observes no credit section, so it never erases the stored
    /// usage credits or one-time pools.
    #[test]
    fn body_without_credit_keys_keeps_stored_credit_sections() {
        let stored = claude_merge_credit_sections(
            "a",
            &[],
            &claude_credit_read(&plain_max_body(), ClaudeUsageRead::Plain, READ_AT),
        );
        assert_eq!(stored.len(), 2);
        let windows_only = json!({
            "five_hour": window(10, Some("2026-10-09T18:00:00+00:00")),
            "seven_day": window(20, Some("2026-10-10T05:00:00+00:00"))
        });
        let read = claude_credit_read(
            &windows_only,
            ClaudeUsageRead::Plain,
            "2026-10-09T15:00:00Z",
        );
        assert!(read.usage_credits.is_none() && read.one_time_credits.is_none());
        assert_eq!(claude_merge_credit_sections("a", &stored, &read), stored);
        // A full plain body with `spend: null` still observes its sections.
        let mut no_spend = plain_max_body();
        no_spend["spend"] = Value::Null;
        no_spend["extra_usage"] = Value::Null;
        let read = claude_credit_read(&no_spend, ClaudeUsageRead::Plain, READ_AT);
        assert_eq!(read.usage_credits.as_deref(), Some(&[][..]));
        assert_eq!(read.one_time_credits.as_ref().map(Vec::len), Some(1));
    }

    /// A saved-reset reading whose `cedar_ember` has readiness but no
    /// `grants` array keeps the stored complete list (and so its status);
    /// readiness is fresh. complete → eligible-only → complete.
    #[test]
    fn eligible_only_cedar_keeps_the_stored_grant_list() {
        let t1 = "2026-10-09T10:00:00Z";
        let t2 = "2026-10-09T11:00:00Z";
        let t3 = "2026-10-09T12:00:00Z";
        let complete = claude_merge_credit_sections(
            "a",
            &[],
            &claude_credit_read(&variant_body(cedar_max()), ClaudeUsageRead::SavedResets, t1),
        );
        let stored = complete
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .unwrap()
            .clone();
        assert_eq!(stored.grants_state, Some(CreditGrantsState::Complete));
        let readiness_only = json!({"eligible": true, "at_limit": false});
        let next = claude_merge_credit_sections(
            "a",
            &complete,
            &claude_credit_read(
                &variant_body(readiness_only),
                ClaudeUsageRead::SavedResets,
                t2,
            ),
        );
        let kept = next
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .unwrap();
        assert_eq!(kept.grants, stored.grants);
        assert_eq!(kept.grants_state, Some(CreditGrantsState::Complete));
        assert_eq!(
            kept.grants_observed_at.as_deref(),
            Some(t1),
            "original list time"
        );
        assert_eq!(kept.grant_count, stored.grant_count);
        assert_eq!(kept.remaining, stored.remaining);
        assert_eq!(kept.status, stored.status, "no ok → unknown flip");
        assert_eq!(kept.at_limit, Some(false), "readiness is fresh");
        assert_eq!(kept.observed_at.as_deref(), Some(t2));
        // The next full list replaces it as usual.
        let after = claude_merge_credit_sections(
            "a",
            &next,
            &claude_credit_read(
                &variant_body(cedar_team()),
                ClaudeUsageRead::SavedResets,
                t3,
            ),
        );
        let replaced = after
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .unwrap();
        assert_eq!(replaced.grants_observed_at.as_deref(), Some(t3));
        assert_eq!(replaced.remaining, Some(0));
    }

    /// The model owns the codename check: a pool whose codename is not a code,
    /// or is secret-shaped, is skipped with the model's `limit_id` refusal.
    #[test]
    fn refused_codename_pools_are_skipped_with_the_model_refusal() {
        let mut body = plain_max_body();
        body["Bad Pool"] = json!({"limit_dollars": 5, "used_dollars": 0, "remaining_dollars": 5});
        body["sk-synthetic"] =
            json!({"limit_dollars": 5, "used_dollars": 0, "remaining_dollars": 5});
        let read = claude_credit_read(&body, ClaudeUsageRead::Plain, READ_AT);
        let pools = read.one_time_credits.unwrap();
        assert_eq!(
            pools
                .iter()
                .map(|pool| pool.limit_id.as_deref())
                .collect::<Vec<_>>(),
            [Some("iguana_necktie")]
        );
        let limit_id_refusals = read
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                **diagnostic
                    == crate::quota_credit_model::OneTimeCreditRefusal::LimitId.diagnostic()
            })
            .count();
        assert_eq!(limit_id_refusals, 2);
    }

    #[test]
    fn credit_freshness_follows_each_sections_own_read_time() {
        let now = 1_791_000_000;
        let at = |age: u64| Some(rfc3339(now - age));
        let gate = 3_600;
        let mut balances = vec![
            AgentCreditBalance {
                name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
                kind: Some(CreditBalanceKind::UsageCredits),
                enabled: Some(true),
                observed_at: at(gate + 60),
                ..Default::default()
            },
            AgentCreditBalance {
                name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
                kind: Some(CreditBalanceKind::UsageCredits),
                enabled: Some(false),
                observed_at: at(5 * 3_600),
                ..Default::default()
            },
            AgentCreditBalance {
                name: "reset_bank".to_string(),
                kind: Some(CreditBalanceKind::SavedResets),
                observed_at: at(10),
                grants_observed_at: at(3 * gate),
                ..Default::default()
            },
            AgentCreditBalance {
                name: "legacy".to_string(),
                ..Default::default()
            },
        ];
        // The stored reading itself is brand new (a windows-only read).
        label_credit_freshness(&mut balances, gate, now - 5, now);
        let fresh = |b: &AgentCreditBalance| b.freshness == AgentQuotaWindowFreshness::Fresh;
        assert!(fresh(&balances[0]), "alternated section: two gates");
        assert!(fresh(&balances[1]), "credits off: 6 h plus one gate");
        assert!(!fresh(&balances[2]), "grant list read 3 gates ago is stale");
        assert!(fresh(&balances[3]), "no own clock: the stored reading's");
    }

    #[test]
    fn legacy_cached_usage_credit_row_is_its_section() {
        let legacy = AgentCreditBalance {
            name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
            enabled: Some(false),
            ..Default::default()
        };
        let merged = claude_merge_credit_sections(
            "a",
            std::slice::from_ref(&legacy),
            &claude_credit_read(
                &variant_body(cedar_max()),
                ClaudeUsageRead::SavedResets,
                READ_AT,
            ),
        );
        assert_eq!(
            merged.len(),
            3,
            "legacy usage row, fresh pool, saved resets"
        );
        assert_eq!(merged[0], legacy);
        assert!(claude_usage_credits_off(&merged));
    }

    fn passive_config(
        cache_account: &str,
        oauth_account: &str,
        org: &str,
        fetched_ms: u64,
    ) -> Value {
        json!({
            "oauthAccount": {"accountUuid": oauth_account, "organizationUuid": org},
            "cachedUsageUtilization": {
                "fetchedAtMs": fetched_ms, "accountUuid": cache_account,
                "utilization": plain_max_body()
            }
        })
    }

    fn hashes(account: &str, org: &str) -> (String, String) {
        (
            ottto_core::billing_identity_hash("anthropic", "account", account).unwrap(),
            ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap(),
        )
    }

    #[test]
    fn passive_reading_is_used_only_for_the_exact_binding() {
        let (account, org) = hashes("acct-1", "org-1");
        let config = claude_passive_config(
            &passive_config("acct-1", "acct-1", "org-1", 1_791_000_000_500),
            &account,
            &org,
        );
        assert!(config.bound);
        let passive = config.reading.expect("matching binding");
        assert_eq!(passive.fetched_at, 1_791_000_000);
        // Same plain-body parser: the passive body yields the same pools.
        let read = claude_credit_read(&passive.body, ClaudeUsageRead::Plain, READ_AT);
        assert_eq!(
            read.one_time_credits.unwrap()[0].limit_id.as_deref(),
            Some("iguana_necktie")
        );
        // Signed in to this binding, but the cached body is another account's.
        let other_cache = claude_passive_config(
            &passive_config("acct-2", "acct-1", "org-1", 1),
            &account,
            &org,
        );
        assert!(other_cache.bound && other_cache.reading.is_none());
        let no_cache = claude_passive_config(
            &json!({"oauthAccount": {"accountUuid": "acct-1", "organizationUuid": "org-1"}}),
            &account,
            &org,
        );
        assert!(no_cache.bound && no_cache.reading.is_none());
        // Signed in to another account or organization, or not at all.
        for config in [
            passive_config("acct-1", "acct-2", "org-1", 1),
            passive_config("acct-1", "acct-1", "org-2", 1),
            json!({"cachedUsageUtilization": {"fetchedAtMs": 1, "accountUuid": "acct-1",
                                              "utilization": {}}}),
        ] {
            assert_eq!(
                claude_passive_config(&config, &account, &org),
                ClaudePassiveConfig::default()
            );
        }
        // Newer than our reading and inside the slot, else a call is made.
        let since = Some(0);
        assert!(claude_passive_reading_usable(
            1_000,
            Some(900),
            since,
            3_600,
            1_100
        ));
        assert!(claude_passive_reading_usable(
            1_000, None, since, 3_600, 1_100
        ));
        assert!(!claude_passive_reading_usable(
            900,
            Some(900),
            since,
            3_600,
            1_100
        ));
        assert!(!claude_passive_reading_usable(
            1_000,
            Some(900),
            since,
            3_600,
            5_000
        ));
        assert!(!claude_passive_reading_usable(
            2_000, None, since, 3_600, 1_000
        ));
    }

    /// The cached body has no organization: it is adopted only when it was
    /// fetched inside a continuous run of passes that all saw this caller on
    /// this exact binding, so a body fetched while the same account was on
    /// another organization is never stamped with this one.
    #[test]
    fn passive_reading_needs_a_continuous_run_on_the_binding() {
        let mut callers = BTreeMap::new();
        let mut seen = |caller: &str, binding: &str, now: u64| {
            claude_observe_caller_binding(&mut callers, caller, binding, now)
        };
        // First pass: nothing earlier proves the organization.
        assert_eq!(seen("default", "a/x", 1_000), 1_000);
        assert!(!claude_passive_reading_usable(
            900,
            None,
            Some(1_000),
            3_600,
            1_000
        ));
        // Continuous passes keep the run; a body fetched inside it is adopted.
        assert_eq!(seen("default", "a/x", 1_300), 1_000);
        assert_eq!(seen("default", "a/x", 1_600), 1_000);
        assert!(claude_passive_reading_usable(
            1_100,
            None,
            Some(1_000),
            3_600,
            1_600
        ));
        // Same account, other organization, then back: a body fetched while
        // on the other organization predates the new run.
        assert_eq!(seen("default", "a/y", 1_900), 1_900);
        assert_eq!(seen("default", "a/x", 2_200), 2_200);
        assert!(!claude_passive_reading_usable(
            2_000,
            None,
            Some(2_200),
            3_600,
            2_500
        ));
        // A long gap (sleep, restart, unresolved identity) starts a new run.
        assert_eq!(seen("default", "a/x", 2_200 + 16 * 60), 2_200 + 16 * 60);
        // A clock going backwards starts a new run.
        assert_eq!(seen("default", "a/x", 2_000), 2_000);
        // Runs are per caller.
        assert_eq!(seen("slot-sha256:1", "a/x", 2_100), 2_100);
        assert_eq!(seen("default", "a/x", 2_100), 2_000);
    }

    #[test]
    fn in_use_survives_a_stalled_activity_scan() {
        let activity_at = 10_000;
        let now = activity_at + 45 * 60;
        let mut schedule = ClaudeReadSchedule::default();
        schedule.observe_activity(Some(activity_at));
        let mut reconciliation: ActiveSessionReconciliation = serde_json::from_value(json!({
            "scan_started_at": rfc3339(activity_at - 30),
            "reconciled_at": rfc3339(now),
            "changed_session_count": 0,
            "sessions": []
        }))
        .unwrap();
        let slot = |feed: Option<&ActiveSessionReconciliation>, now| {
            claude_usage_slot_seconds(
                &schedule,
                claude_latest_activity_at(feed, "a", "o"),
                claude_activity_feed_fresh_at(feed),
                DEFAULT_SLOT,
                now,
            )
        };
        assert_eq!(slot(Some(&reconciliation), now), ACTIVE_SLOT_SECONDS);
        // A newly completed scan sees no newer activity: return to idle.
        reconciliation.scan_started_at = Some(rfc3339(activity_at + 40 * 60));
        assert_eq!(slot(Some(&reconciliation), now), DEFAULT_SLOT);
        // A dead scanner cannot preserve the active slot indefinitely.
        let scan_at = activity_at - 30;
        reconciliation.scan_started_at = Some(rfc3339(scan_at));
        assert_eq!(
            slot(
                Some(&reconciliation),
                scan_at + MAX_ACTIVITY_FEED_LAG_SECONDS
            ),
            ACTIVE_SLOT_SECONDS
        );
        assert_eq!(
            slot(
                Some(&reconciliation),
                scan_at + MAX_ACTIVITY_FEED_LAG_SECONDS + 1
            ),
            DEFAULT_SLOT
        );
        // Missing, older and invalid feed metadata retain wall-clock judging.
        assert_eq!(slot(None, now), DEFAULT_SLOT);
        for scan_at in [None, Some("invalid".to_string()), Some(rfc3339(now + 60))] {
            reconciliation.scan_started_at = scan_at;
            assert_eq!(slot(Some(&reconciliation), now), DEFAULT_SLOT);
        }
    }

    /// A stored reading holding the given sections.
    fn stored(usage_credits_off: Option<bool>, saved_resets: bool) -> Vec<AgentCreditBalance> {
        let mut balances = Vec::new();
        if let Some(off) = usage_credits_off {
            balances.push(AgentCreditBalance {
                name: CLAUDE_USAGE_CREDITS_NAME.to_string(),
                kind: Some(CreditBalanceKind::UsageCredits),
                enabled: Some(!off),
                ..Default::default()
            });
        }
        if saved_resets {
            balances.push(AgentCreditBalance {
                name: "reset_bank".to_string(),
                unit: AgentCreditBalanceUnit::Resets,
                kind: Some(CreditBalanceKind::SavedResets),
                ..Default::default()
            });
        }
        balances
    }

    /// The default slot of the simulated binding (inside the 38-42 min band).
    const DEFAULT_SLOT: u64 = 2_460;
    /// Collection passes run every 5 min.
    const PASS: u64 = 300;
    const HOUR: u64 = 3_600;

    /// A reading the simulated binding took: a provider call or a passive body.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Reading {
        at: u64,
        read: ClaudeUsageRead,
        passive: bool,
        slot: u64,
    }

    /// One simulated binding driven like the collection path, one decision
    /// per 5-min pass: record the caller's sign-in, keep activity, check the
    /// slot, choose the read, then adopt a passive body only in a plain slot,
    /// else make one call.
    struct Simulation {
        schedule: ClaudeReadSchedule,
        last_reading_at: Option<u64>,
        next_refresh_after: u64,
        usage_credits_off: bool,
        stored: Vec<AgentCreditBalance>,
        callers: BTreeMap<String, ClaudeCallerBinding>,
        readings: Vec<Reading>,
        passes_with_more_than_one_call: usize,
    }

    impl Simulation {
        fn new(usage_credits_off: bool) -> Self {
            Self {
                schedule: ClaudeReadSchedule::default(),
                last_reading_at: None,
                next_refresh_after: 0,
                usage_credits_off,
                stored: Vec::new(),
                callers: BTreeMap::new(),
                readings: Vec::new(),
                passes_with_more_than_one_call: 0,
            }
        }

        /// One pass at `now`. `passive_fetched_at` is the matching body
        /// Claude Code holds, if any.
        fn pass(&mut self, now: u64, activity: Option<u64>, passive_fetched_at: Option<u64>) {
            let since = claude_observe_caller_binding(&mut self.callers, "default", "a/o", now);
            self.schedule.observe_activity(activity);
            let slot = claude_usage_slot_seconds(&self.schedule, activity, None, DEFAULT_SLOT, now);
            if !claude_reading_due(self.last_reading_at, self.next_refresh_after, slot, now) {
                return;
            }
            let read = claude_usage_read_kind(&self.schedule, &self.stored, now);
            if read == ClaudeUsageRead::Plain {
                if let Some(fetched) = passive_fetched_at.filter(|at| {
                    claude_passive_reading_usable(*at, self.last_reading_at, Some(since), slot, now)
                }) {
                    self.record(read, fetched, true, slot, activity, now);
                    return;
                }
            }
            // The provider answers a few seconds into the pass.
            self.record(read, now + 3, false, slot, activity, now);
        }

        fn record(
            &mut self,
            read: ClaudeUsageRead,
            at: u64,
            passive: bool,
            slot: u64,
            activity: Option<u64>,
            now: u64,
        ) {
            if self
                .readings
                .last()
                // Two calls within half a pass are one pass's calls (passes
                // drift by under 20 s; in-use reads are one pass apart).
                .is_some_and(|last| !last.passive && !passive && last.at + PASS / 2 > at)
            {
                self.passes_with_more_than_one_call += 1;
            }
            self.readings.push(Reading {
                at,
                read,
                passive,
                slot,
            });
            self.last_reading_at = Some(at);
            self.next_refresh_after = now + super::super::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
            self.schedule.after_reading(read, at, activity, now);
            let observed = rfc3339(at);
            match read {
                ClaudeUsageRead::Plain => {
                    self.stored
                        .retain(|b| b.kind != Some(CreditBalanceKind::UsageCredits));
                    let mut usage = stored(Some(self.usage_credits_off), false);
                    usage[0].observed_at = Some(observed);
                    self.stored.extend(usage);
                }
                ClaudeUsageRead::SavedResets => {
                    self.stored
                        .retain(|b| b.kind != Some(CreditBalanceKind::SavedResets));
                    let mut saved = stored(None, true);
                    saved[0].observed_at = Some(observed);
                    self.stored.extend(saved);
                }
            }
        }

        fn calls(&self) -> impl Iterator<Item = &Reading> {
            self.readings.iter().filter(|reading| !reading.passive)
        }
    }

    fn rfc3339(at: u64) -> String {
        OffsetDateTime::from_unix_timestamp(at as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    const START: u64 = 1_791_000_000;

    /// 24 h of 5-min passes: idle start, active 08:00-10:00 (the scan reports
    /// activity only while it advances), then idle; the machine sleeps
    /// 13:00-16:00 (no passes).
    fn run_day(usage_credits_off: bool, passive: &dyn Fn(u64) -> Option<u64>) -> Simulation {
        let mut simulation = Simulation::new(usage_credits_off);
        let mut tick = 0;
        let mut latency = 0;
        while tick * PASS < 24 * HOUR {
            let offset = tick * PASS;
            tick += 1;
            if (13 * HOUR..16 * HOUR).contains(&offset) {
                continue;
            }
            // The lane times each pass from the previous pass's start, and a
            // pass wakes up to a couple of seconds late, so starts drift
            // later, never closer than 5 min.
            latency += (tick * 7) % 3;
            let now = START + offset + latency;
            let activity = (8 * HOUR..10 * HOUR).contains(&offset).then_some(now);
            simulation.pass(now, activity, passive(now));
        }
        simulation
    }

    fn gaps_between(readings: &[Reading], from: u64, to: u64) -> Vec<u64> {
        readings
            .windows(2)
            .filter(|pair| (START + from..START + to).contains(&pair[1].at))
            .map(|pair| pair[1].at - pair[0].at)
            .collect()
    }

    #[test]
    fn scheduler_day_on_five_minute_passes() {
        let simulation = run_day(false, &|_| None);
        let calls = simulation.calls().copied().collect::<Vec<_>>();
        // One read per slot, never two in one pass, no catch-up burst.
        assert_eq!(simulation.passes_with_more_than_one_call, 0);
        for pair in calls.windows(2) {
            assert!(
                pair[1].at - pair[0].at + 60 >= pair[1].slot,
                "read inside its slot"
            );
        }
        // Credits on: plain and saved-reset reads strictly alternate.
        assert_eq!(calls[0].read, ClaudeUsageRead::Plain);
        for pair in calls.windows(2) {
            assert_ne!(pair[0].read, pair[1].read);
        }
        // Default slot: the first pass at or after the boundary (≤ one pass late).
        let default = gaps_between(&calls, 0, 6 * HOUR);
        assert!(!default.is_empty());
        assert!(default
            .iter()
            .all(|gap| (DEFAULT_SLOT - 60..=DEFAULT_SLOT + PASS).contains(gap)));
        // In use: every 5-min pass (± the pass drift), not every other one.
        let active = gaps_between(&calls, 8 * HOUR + 5 * 60, 10 * HOUR);
        assert!(active.len() >= 20);
        assert!(
            active
                .iter()
                .all(|gap| (5 * 60 - 20..=5 * 60 + 20).contains(gap)),
            "{active:?}"
        );
        // The active slot holds for 30 min after the last activity.
        assert!(calls.iter().any(|call| {
            (START + 10 * HOUR + 10 * 60..=START + 10 * HOUR + 30 * 60).contains(&call.at)
                && call.slot == ACTIVE_SLOT_SECONDS
        }));
        // Unused for more than 6 h: still the unused-account slot.
        let idle = gaps_between(&calls, 17 * HOUR, 24 * HOUR);
        assert!(!idle.is_empty());
        assert!(idle
            .iter()
            .all(|gap| (DEFAULT_SLOT - 60..=DEFAULT_SLOT + PASS).contains(gap)));
        // Waking from a 3 h sleep: one read at the first pass, then the slot.
        let woke = calls
            .iter()
            .filter(|call| call.at >= START + 16 * HOUR)
            .map(|call| call.at)
            .collect::<Vec<_>>();
        assert!(woke[0] < START + 16 * HOUR + PASS);
        assert!(woke[1] - woke[0] >= DEFAULT_SLOT - 60);
        // 2.5 h in use at 5 min plus the unused hours at about 40 min.
        assert!(calls.len() <= 30 + 24 * 2, "{}", calls.len());
    }

    /// Claude Code keeps a fresh matching body at every pass (an account in
    /// constant use): passive input stands in for the plain slots only, and
    /// the saved-reset read still happens every other slot.
    #[test]
    fn continuous_passive_input_never_starves_saved_resets() {
        let simulation = run_day(false, &|now| Some(now - 30));
        assert!(simulation.readings.iter().any(|reading| reading.passive));
        assert!(simulation
            .readings
            .iter()
            .filter(|reading| reading.passive)
            .all(|reading| reading.read == ClaudeUsageRead::Plain));
        for pair in simulation.readings.windows(2) {
            assert_ne!(
                pair[0].read, pair[1].read,
                "plain and saved-reset slots alternate"
            );
        }
        let saved = simulation
            .readings
            .iter()
            .filter(|reading| reading.read == ClaudeUsageRead::SavedResets)
            .collect::<Vec<_>>();
        assert!(saved.iter().all(|reading| !reading.passive));
        // Active hours: a saved-reset read every ~10 min (two 5-min slots).
        let active_saved = saved
            .windows(2)
            .filter(|pair| (START + 8 * HOUR + 30 * 60..START + 10 * HOUR).contains(&pair[1].at))
            .map(|pair| pair[1].at - pair[0].at)
            .collect::<Vec<_>>();
        assert!(!active_saved.is_empty());
        assert!(
            active_saved.iter().all(|gap| *gap <= 10 * 60 + 60),
            "{active_saved:?}"
        );
        // Over the whole day no saved-reset gap exceeds two unused slots
        // (plus the 3 h sleep).
        for pair in saved.windows(2) {
            assert!(pair[1].at - pair[0].at <= 2 * (DEFAULT_SLOT + PASS) + 3 * HOUR + PASS);
        }
        // Passive bodies replace calls; never more than one reading per slot.
        assert!(simulation.calls().count() < run_day(false, &|_| None).calls().count());
        assert_eq!(simulation.passes_with_more_than_one_call, 0);
    }

    /// A windows-only passive body adopted in a plain slot never resets the
    /// credits-off plain clock: it is measured from the usage-credit section.
    #[test]
    fn windows_only_passive_body_keeps_the_credits_off_clock() {
        let now = 100_000;
        let mut credits = stored(Some(true), true);
        credits[0].observed_at = Some(rfc3339(now - 7 * HOUR));
        let schedule = ClaudeReadSchedule {
            // A passive windows-only body was adopted 10 min ago.
            last_plain_read_at: Some(now - 600),
            last_saved_resets_read_at: Some(now - 1_800),
            ..ClaudeReadSchedule::default()
        };
        assert_eq!(
            claude_usage_read_kind(&schedule, &credits, now),
            ClaudeUsageRead::Plain
        );
        credits[0].observed_at = Some(rfc3339(now - HOUR));
        assert_eq!(
            claude_usage_read_kind(&schedule, &credits, now),
            ClaudeUsageRead::SavedResets
        );
    }

    #[test]
    fn a_window_reset_after_the_reading_gets_one_read_soon_after_it() {
        let observed = 1_000_000;
        let window = |reset: Option<u64>| AgentQuotaWindow {
            resets_at: reset.map(rfc3339),
            ..Default::default()
        };
        let windows = [
            window(Some(observed + 5 * HOUR)),
            window(Some(observed + 2 * HOUR)),
            window(Some(observed - 10)),
            window(None),
        ];
        let delay = claude_reset_read_delay_seconds("account-a", "org-a");
        assert!((60..=120).contains(&delay), "delay {delay}");
        assert_eq!(
            claude_reset_read_at(&windows, observed, 0, delay),
            Some(observed + 2 * HOUR + delay),
            "the first reset after the reading, plus the delay"
        );
        assert_eq!(
            claude_reset_read_at(&windows, observed, observed + 2 * HOUR + 290, delay),
            Some(observed + 2 * HOUR + 290),
            "never before the stored spacing"
        );
        let reset = observed + 2 * HOUR;
        // Before the delay: not due. After it: due, inside any slot.
        assert!(!claude_reset_read_due(
            &windows,
            observed,
            0,
            delay,
            reset + delay - 1
        ));
        assert!(claude_reset_read_due(
            &windows,
            observed,
            0,
            delay,
            reset + delay
        ));
        // Retry-After/success spacing still holds it back.
        assert!(!claude_reset_read_due(
            &windows,
            observed,
            reset + delay + 300,
            delay,
            reset + delay
        ));
        // The reading after the reset postdates it: no second read.
        assert!(!claude_reset_read_due(
            &windows,
            reset + delay,
            0,
            delay,
            reset + delay + 600
        ));
        assert_eq!(
            claude_reset_read_at(&windows[2..], observed, 0, delay),
            None
        );
    }

    #[test]
    fn read_kind_fills_a_missing_section_first() {
        let none = ClaudeReadSchedule::default();
        let plain_only = ClaudeReadSchedule {
            last_plain_read_at: Some(100),
            ..ClaudeReadSchedule::default()
        };
        let kind = |schedule: &ClaudeReadSchedule, stored: &[AgentCreditBalance]| {
            claude_usage_read_kind(schedule, stored, 1_000)
        };
        assert_eq!(kind(&none, &[]), ClaudeUsageRead::Plain);
        assert_eq!(
            kind(&none, &stored(Some(false), false)),
            ClaudeUsageRead::SavedResets
        );
        assert_eq!(kind(&plain_only, &[]), ClaudeUsageRead::SavedResets);
        assert_eq!(kind(&none, &stored(None, true)), ClaudeUsageRead::Plain);
        // Both sections stored, schedule lost: alternate from plain.
        assert_eq!(
            kind(&none, &stored(Some(false), true)),
            ClaudeUsageRead::Plain
        );
        assert_eq!(
            kind(&plain_only, &stored(Some(false), true)),
            ClaudeUsageRead::SavedResets
        );
        // A paused variant never fills the section.
        let paused = ClaudeReadSchedule {
            saved_resets_variant_paused_until: Some(2_000),
            ..plain_only.clone()
        };
        assert_eq!(
            kind(&paused, &stored(Some(false), false)),
            ClaudeUsageRead::Plain
        );
    }

    #[test]
    fn read_schedule_file_is_owner_only_and_survives_restart() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ottto-claude-read-schedule-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            read_claude_read_schedule(&dir),
            ClaudeReadSchedule::default()
        );
        let schedule = ClaudeReadSchedule {
            last_plain_read_at: Some(1),
            last_saved_resets_read_at: Some(2),
            last_activity_at: Some(3),
            tracked_since: Some(4),
            saved_resets_variant_paused_until: Some(5),
            next_read_not_before: Some(6),
        };
        write_claude_read_schedule(&dir, &schedule).unwrap();
        let mode = std::fs::metadata(dir.join(CLAUDE_READ_SCHEDULE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group/world access: {mode:o}");
        // A restarted daemon reads the same schedule back.
        assert_eq!(read_claude_read_schedule(&dir), schedule);
        std::fs::write(dir.join(CLAUDE_READ_SCHEDULE_FILE), b"{not json").unwrap();
        assert_eq!(
            read_claude_read_schedule(&dir),
            ClaudeReadSchedule::default()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/agent-status/quota-contract-v2.2")
    }

    fn fixture(path: &str) -> Value {
        serde_json::from_slice(&std::fs::read(fixture_dir().join(path)).unwrap()).unwrap()
    }

    /// The emitted balances without the fields stamped outside the adapter:
    /// packaging time (`updated_at`, contract C9) and the binding hashes.
    fn comparable(balances: &Value) -> Value {
        let mut balances = balances.clone();
        for balance in balances.as_array_mut().unwrap() {
            let balance = balance.as_object_mut().unwrap();
            for key in [
                "updated_at",
                "account_identifier_hash",
                "organization_identifier_hash",
            ] {
                balance.remove(key);
            }
        }
        balances
    }

    /// Each canonical Claude provider body, read once on a cold binding,
    /// produces the canonical expected wire file byte for byte (rendered the
    /// way the model writes it: pretty JSON, sorted keys, trailing newline).
    #[test]
    fn canonical_claude_fixtures_match_expected_wire() {
        for name in [
            "claude-oauth-usage-plain",
            "claude-oauth-usage-credits-off",
            "claude-usage-cedar",
            "claude-usage-cedar-ineligible",
            "claude-usage-cedar-reader-surface",
            "claude-usage-cedar-reader-cli-version",
            "claude-usage-cedar-refused-expiry",
        ] {
            let body = fixture(&format!("provider/{name}.json"));
            let read = claude_credit_read(&body, ClaudeUsageRead::Plain, "2026-10-01T12:00:00Z");
            let emitted = claude_merge_credit_sections("fixture", &[], &read);
            let mut rendered = serde_json::to_string_pretty(
                &json!({ "credit_balances": serde_json::to_value(&emitted).unwrap() }),
            )
            .unwrap();
            rendered.push('\n');
            let on_disk =
                std::fs::read_to_string(fixture_dir().join(format!("expected/{name}.wire.json")))
                    .unwrap();
            assert_eq!(rendered, on_disk, "{name}");
            assert!(emitted.iter().all(|balance| balance.enabled != Some(true)
                || balance.kind != Some(CreditBalanceKind::OneTimeCredit)));
        }
    }

    /// The canonical alternation sequence, with each binding's stored reading
    /// carried between steps. The adapter's stored reading is on disk per
    /// binding, so after a restart it is still the last observed section and
    /// is re-sent (no presence flip); the in-memory model fixture starts cold.
    #[test]
    fn canonical_claude_sequence_matches_expected_wire() {
        let sequence = fixture("expected/sequence-claude-plain-saved-resets.wire.json");
        let mut stored: BTreeMap<String, Vec<AgentCreditBalance>> = BTreeMap::new();
        for step in sequence["steps"].as_array().unwrap() {
            let label = step["step"].as_str().unwrap();
            let expected = &step["credit_balances"];
            let binding = expected[0]["account_identifier_hash"]
                .as_str()
                .unwrap()
                .to_string();
            let input = step["provider_inputs"][0].as_str().unwrap();
            let read = if input.ends_with("claude-oauth-usage-plain.json") {
                ClaudeUsageRead::Plain
            } else {
                ClaudeUsageRead::SavedResets
            };
            let observed_at = step["captured_at"]
                .as_str()
                .unwrap()
                .replace(":05Z", ":00Z");
            let previous = stored.get(&binding).cloned().unwrap_or_default();
            let emitted = claude_merge_credit_sections(
                &binding,
                &previous,
                &claude_credit_read(&fixture(input), read, &observed_at),
            );
            let emitted_value = comparable(&serde_json::to_value(&emitted).unwrap());
            if label.starts_with("restart") {
                let saved = emitted
                    .iter()
                    .find(|b| b.kind == Some(CreditBalanceKind::SavedResets))
                    .expect("stored saved resets re-sent after a restart");
                assert_eq!(
                    saved.grants_observed_at.as_deref(),
                    Some("2026-10-01T14:00:00Z")
                );
                let without_saved = Value::Array(
                    emitted_value
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|b| b["kind"] != "saved_resets")
                        .cloned()
                        .collect(),
                );
                assert_eq!(without_saved, comparable(expected), "{label}");
            } else {
                assert_eq!(emitted_value, comparable(expected), "{label}");
            }
            stored.insert(binding, emitted);
        }
    }

    /// Restores one environment variable on drop.
    struct EnvGuard(&'static str, Option<std::ffi::OsString>);

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self(key, previous)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.1 {
                Some(value) => std::env::set_var(self.0, value),
                None => std::env::remove_var(self.0),
            }
        }
    }

    static REQUESTED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    fn respond_with(endpoint: &str, cedar: Value) -> Value {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        let mut body = fixture("provider/claude-usage-cedar.json");
        body["cedar_ember"] = cedar;
        body
    }

    fn respond_recognized(endpoint: &str) -> Result<Value, u16> {
        Ok(respond_with(
            endpoint,
            fixture("provider/claude-usage-cedar.json")["cedar_ember"].clone(),
        ))
    }

    fn respond_server_error(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Err(500)
    }

    fn respond_rate_limited(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Err(429)
    }

    fn respond_cedar_null(endpoint: &str) -> Result<Value, u16> {
        Ok(respond_with(endpoint, Value::Null))
    }

    fn respond_plain(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Ok(fixture("provider/claude-oauth-usage-plain.json"))
    }

    fn respond_empty(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Ok(json!({}))
    }

    fn respond_cedar_only(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Ok(json!({"cedar_ember": {"eligible": true}}))
    }

    fn respond_status(endpoint: &str, status: u16) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        if endpoint.contains("cedar_ember") {
            Err(status)
        } else {
            Ok(fixture("provider/claude-oauth-usage-plain.json"))
        }
    }

    fn respond_variant_400(endpoint: &str) -> Result<Value, u16> {
        respond_status(endpoint, 400)
    }

    /// End to end through the collector with a stand-in provider: a binding
    /// whose plain read is recent and saved resets never read takes the
    /// variant in its next due slot.
    struct VariantHarness {
        dir: std::path::PathBuf,
        _support: EnvGuard,
        account: &'static str,
        organization: &'static str,
    }

    impl VariantHarness {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ottto-claude-variant-{label}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &dir);
            super::super::CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN
                .store(false, std::sync::atomic::Ordering::SeqCst);
            REQUESTED.lock().unwrap().clear();
            super::super::claude_explicit_refresh_request().at = 0;
            super::super::claude_explicit_refresh_attempts().clear();
            super::super::claude_transient_failures().clear();
            super::super::claude_rate_limit_holds().clear();
            Self {
                dir,
                _support: support,
                account: "account-variant",
                organization: "organization-variant",
            }
        }

        fn state_dir(&self) -> std::path::PathBuf {
            super::super::claude_oauth_usage_account_state_dir(self.account, self.organization)
        }

        /// Make the binding due, with the plain read an hour ago.
        fn due(&self, mut schedule: ClaudeReadSchedule) {
            let _ = std::fs::remove_file(super::super::claude_oauth_usage_cache_path(
                self.account,
                self.organization,
            ));
            let now = super::super::current_unix_seconds();
            schedule.last_plain_read_at.get_or_insert(now - 3_600);
            schedule.next_read_not_before = None;
            write_claude_read_schedule(&self.state_dir(), &schedule).unwrap();
        }

        /// Make the binding due while keeping its stored reading, as after a
        /// daemon restart that slept past the slot.
        fn due_keeping_reading(&self) {
            let mut cache =
                super::super::read_claude_oauth_usage_cache(self.account, self.organization)
                    .expect("stored reading");
            cache.observed_at_epoch_seconds -= 3 * 3_600;
            cache.next_refresh_after_epoch_seconds = 0;
            super::super::write_claude_oauth_usage_cache(&cache).unwrap();
            // The slot has passed: any "not before the next slot" hold is over.
            let mut schedule = self.schedule();
            schedule.next_read_not_before = None;
            write_claude_read_schedule(&self.state_dir(), &schedule).unwrap();
        }

        fn schedule(&self) -> ClaudeReadSchedule {
            read_claude_read_schedule(&self.state_dir())
        }

        fn collect(
            &self,
            respond: super::super::ClaudeOAuthTestResponder,
        ) -> super::super::ClaudeOAuthUsageOutcome {
            *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond);
            let outcome = super::super::collect_claude_oauth_usage_with_access_token(
                self.account,
                self.organization,
                Some("fixture-token".to_string()),
                &super::super::ClaudeOAuthUsageCaller::RegisteredSlot("slot-variant".to_string()),
            );
            *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
            outcome
        }

        fn shape_failures(&self) -> u32 {
            super::super::read_claude_oauth_usage_breaker(
                self.account,
                self.organization,
                &super::super::claude_oauth_usage_config_fingerprint(),
            )
            .map_or(0, |breaker| breaker.shape_failures)
        }
    }

    impl Drop for VariantHarness {
        fn drop(&mut self) {
            *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl VariantHarness {
        fn collect_as(
            &self,
            caller: super::super::ClaudeOAuthUsageCaller,
            respond: super::super::ClaudeOAuthTestResponder,
        ) -> super::super::ClaudeOAuthUsageOutcome {
            *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(respond);
            let outcome = super::super::collect_claude_oauth_usage_with_access_token(
                self.account,
                self.organization,
                Some("fixture-token".to_string()),
                &caller,
            );
            *super::super::CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = None;
            outcome
        }

        /// Let `seconds` pass for the stored reading and any Refresh request,
        /// keeping only the plain spacing after a successful read.
        fn age_reading(&self, seconds: u64) {
            {
                let mut request = super::super::claude_explicit_refresh_request();
                request.at = request.at.saturating_sub(seconds);
            }
            for attempt in super::super::claude_explicit_refresh_attempts().iter_mut() {
                attempt.at -= seconds;
            }
            for failure in super::super::claude_transient_failures().iter_mut() {
                failure.at -= seconds;
            }
            let mut cache =
                super::super::read_claude_oauth_usage_cache(self.account, self.organization)
                    .expect("stored reading");
            cache.observed_at_epoch_seconds -= seconds;
            cache.next_refresh_after_epoch_seconds =
                cache.observed_at_epoch_seconds + super::super::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
            super::super::write_claude_oauth_usage_cache(&cache).unwrap();
        }

        fn requests(&self) -> usize {
            REQUESTED.lock().unwrap().len()
        }

        /// A statusLine reading Claude Code wrote for exactly this binding.
        fn write_statusline(&self, observed_at: u64) {
            ottto_core::write_claude_statusline_cache(
                &self.dir,
                &ottto_core::ClaudeStatusLineRateLimitCache {
                    schema_version: ottto_core::CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                    observed_under_account_identifier_hash: self.account.to_string(),
                    observed_under_organization_identifier_hash: Some(
                        self.organization.to_string(),
                    ),
                    observed_under_account_method: "config_dir".to_string(),
                    observed_at_epoch_seconds: observed_at,
                    windows: vec![ottto_core::ClaudeStatusLineRateLimitWindow {
                        name: "five_hour".to_string(),
                        used_percent: 12,
                        resets_at_epoch_seconds: observed_at + 3_600,
                    }],
                },
            )
            .unwrap();
        }
    }

    /// A server error records no backoff of its own: the binding still waits
    /// a minute before the next provider request, whatever asks for it.
    #[test]
    #[serial_test::serial]
    fn a_server_error_waits_a_minute_before_the_next_request() {
        let harness = VariantHarness::new("server-error");
        harness.due(ClaudeReadSchedule::default());
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 1);
        for _ in 0..3 {
            harness.collect(respond_server_error);
        }
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 1);
        for failure in super::super::claude_transient_failures().iter_mut() {
            failure.at -= super::super::CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS;
        }
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 2);
    }

    /// Each Anthropic usage request is one provider-call log line saying why
    /// it ran and how it ended; a reading served from storage logs nothing.
    #[test]
    #[serial_test::serial]
    fn each_usage_request_is_one_provider_call_line() {
        use crate::provider_calls::{with_trigger, CallKind, Trigger};
        let mut harness = VariantHarness::new("call-log");
        harness.account = "c1a0de0100000000000000000000000000000000000000000000000000000000";
        harness.due(ClaudeReadSchedule::default());
        with_trigger(Trigger::Setup, || harness.collect(respond_recognized));
        // A fresh reading inside its slot: served, no request, no line.
        harness.collect(respond_recognized);
        // An older app's status refresh marks the read; the lane thread that
        // makes it keeps that label.
        harness.age_reading(90);
        with_trigger(
            Trigger::OlderAppCompat,
            super::super::request_claude_explicit_refresh,
        );
        harness.collect(respond_recognized);
        harness.age_reading(90);
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 3);
        let lines = crate::provider_calls::test_lines(CallKind::ClaudeOauthUsage, harness.account);
        let summary = lines
            .iter()
            .map(|line| {
                (
                    line.provider.as_str(),
                    line.trigger.as_str(),
                    line.result.as_str(),
                    line.basis.as_str(),
                    line.requests_at_least,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                ("anthropic", "setup", "ok", "observed", 1),
                ("anthropic", "older_app_compat", "ok", "observed", 1),
                ("anthropic", "explicit_refresh", "http_500", "observed", 1),
            ]
        );
        let raw = crate::provider_calls::test_raw_log();
        for secret in [
            "fixture-token",
            "Bearer",
            "api.anthropic.com",
            "organization-variant",
        ] {
            assert!(!raw.contains(secret), "{secret} in the provider-call log");
        }
    }

    /// The Refresh button reads an account now, at most once a minute, and
    /// never inside a Retry-After hold.
    #[test]
    #[serial_test::serial]
    fn explicit_refresh_reads_now_once_a_minute_and_never_inside_retry_after() {
        let harness = VariantHarness::new("explicit-refresh");
        harness.due(ClaudeReadSchedule::default());
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 1);
        // A fresh reading inside its slot: no call without a request.
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 1);
        // A request 30 s after a read waits out the minute.
        harness.age_reading(30);
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 1);
        // Past the minute (still inside the slot): the request reads now.
        harness.age_reading(90);
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 2);
        // The request is consumed by that read.
        harness.age_reading(90);
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 2);
        // A refresh whose read fails still counts: the request is used up and
        // the next one waits out the minute.
        harness.age_reading(90);
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 3);
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 3);
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_server_error);
        assert_eq!(harness.requests(), 3);
        // Retry-After on record: a request never reads inside it.
        let now = super::super::current_unix_seconds();
        let mut cache =
            super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
                .expect("stored reading");
        cache.observed_at_epoch_seconds = now - 120;
        cache.next_refresh_after_epoch_seconds = now + 600;
        super::super::write_claude_oauth_usage_cache(&cache).unwrap();
        super::super::record_claude_oauth_usage_failure(
            super::super::ClaudeOAuthUsageFailure::RateLimited,
            harness.account,
            harness.organization,
            &super::super::claude_oauth_usage_config_fingerprint(),
            now,
        );
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 3);
    }

    /// A 429 with a short Retry-After inside the success spacing: an explicit
    /// refresh still waits it out when the persisted breaker cannot say so
    /// (for example after a configuration change).
    #[test]
    #[serial_test::serial]
    fn explicit_refresh_never_reads_inside_a_rate_limit_even_without_the_breaker() {
        let harness = VariantHarness::new("explicit-429");
        harness.due(ClaudeReadSchedule::default());
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 1);
        harness.due_keeping_reading();
        harness.collect(respond_rate_limited);
        assert_eq!(harness.requests(), 2);
        let now = super::super::current_unix_seconds();
        let mut cache =
            super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
                .expect("stored reading");
        cache.observed_at_epoch_seconds = now - 120;
        cache.next_refresh_after_epoch_seconds = now + 60;
        super::super::write_claude_oauth_usage_cache(&cache).unwrap();
        std::fs::remove_file(super::super::claude_oauth_usage_breaker_path(
            harness.account,
            harness.organization,
        ))
        .expect("the 429 recorded a breaker");
        super::super::request_claude_explicit_refresh();
        harness.collect(respond_recognized);
        assert_eq!(harness.requests(), 2, "Refresh waits out the 429");
    }

    /// Product rule: a status read an app starts never calls the provider. It
    /// serves the stored reading even for a due account; the daemon's own
    /// pass reads it, and an explicit refresh is the one read such a request
    /// may make.
    #[test]
    #[serial_test::serial]
    fn an_app_status_read_serves_the_stored_reading_and_never_calls_anthropic() {
        let harness = VariantHarness::new("app-status-read");
        harness.due(ClaudeReadSchedule::default());
        let now = super::super::current_unix_seconds();
        let app = |respond| super::super::with_claude_pass(true, now, || harness.collect(respond));
        // Due with nothing stored: no request, and no reading to show yet.
        assert!(app(respond_recognized).result.is_err());
        assert_eq!(harness.requests(), 0);
        // The daemon's pass reads it.
        let daemon =
            super::super::with_claude_pass(false, now, || harness.collect(respond_recognized));
        assert!(daemon.result.is_ok());
        assert_eq!(harness.requests(), 1);
        // Due again: the app is served the stored reading, no request.
        harness.due_keeping_reading();
        assert!(app(respond_recognized).result.is_ok());
        assert_eq!(harness.requests(), 1);
        // An explicit refresh reads now, even in the app's request.
        super::super::request_claude_explicit_refresh();
        assert!(app(respond_recognized).result.is_ok());
        assert_eq!(harness.requests(), 2);
    }

    /// "Background limit refresh" off: the daemon's own passes read no
    /// Claude account, the default login included, and serve the stored
    /// reading. A person's Refresh, a setup check and a read outside a pass
    /// (an account check) still read; switching it on resumes the schedule.
    #[test]
    #[serial_test::serial]
    fn background_refresh_off_stops_scheduled_reads_for_every_login() {
        use super::super::ClaudeOAuthUsageCaller::{Default as DefaultLogin, RegisteredSlot};
        use crate::provider_calls::{with_trigger, Trigger};
        let harness = VariantHarness::new("background-refresh-off");
        let settings = ottto_core::FileClaudeConfigSlotSettingsStore::default();
        settings.set_upkeep_consent(1, false).expect("turn off");
        let slot = || RegisteredSlot("slot-variant".to_string());
        let now = super::super::current_unix_seconds();
        let pass = |caller| {
            super::super::with_claude_pass(false, now, || {
                harness.collect_as(caller, respond_recognized)
            })
        };

        // Due with nothing stored: no request for either login, and the
        // status says why.
        harness.due(ClaudeReadSchedule::default());
        for caller in [DefaultLogin, slot()] {
            assert_eq!(
                pass(caller).result.err().as_deref(),
                Some(super::super::CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE)
            );
        }
        assert_eq!(harness.requests(), 0);

        // A setup check reads, even inside a pass.
        assert!(with_trigger(Trigger::Setup, || pass(DefaultLogin))
            .result
            .is_ok());
        assert_eq!(harness.requests(), 1);

        // Due again: the pass serves the stored reading, no request.
        harness.due_keeping_reading();
        assert!(pass(DefaultLogin).result.is_ok());
        assert!(pass(slot()).result.is_ok());
        assert_eq!(harness.requests(), 1);

        // An account check runs outside any pass: it reads.
        assert!(harness
            .collect_as(slot(), respond_recognized)
            .result
            .is_ok());
        assert_eq!(harness.requests(), 2);

        // A person's Refresh reads in the daemon's pass.
        harness.due_keeping_reading();
        super::super::request_claude_explicit_refresh();
        assert!(pass(DefaultLogin).result.is_ok());
        assert_eq!(harness.requests(), 3);

        // On again: the schedule reads a due account.
        harness.due_keeping_reading();
        settings.set_upkeep_consent(1, true).expect("turn on");
        super::super::claude_explicit_refresh_request().at = 0;
        assert!(pass(DefaultLogin).result.is_ok());
        assert_eq!(harness.requests(), 4);
    }

    /// An in-use account (default login) prefers Claude Code's free
    /// statusLine reading: no provider call at the 5-min slot while that
    /// reading is fresh for the exact binding; a call once it is older.
    #[test]
    #[serial_test::serial]
    fn in_use_default_login_calls_only_when_the_statusline_is_stale() {
        let harness = VariantHarness::new("statusline-in-use");
        let _home = EnvGuard::set("HOME", &harness.dir);
        let now = super::super::current_unix_seconds();
        harness.due(ClaudeReadSchedule {
            last_activity_at: Some(now - 60),
            ..ClaudeReadSchedule::default()
        });
        let default = || super::super::ClaudeOAuthUsageCaller::Default;
        harness.collect_as(default(), respond_recognized);
        assert_eq!(harness.requests(), 1);
        // Five minutes later the in-use slot is due, but the statusLine wrote
        // this binding's numbers 30 s ago: no call.
        harness.age_reading(5 * 60 + 1);
        harness.write_statusline(now - 30);
        assert!(super::super::claude_statusline_fresh_for_binding(
            harness.account,
            harness.organization,
            super::super::current_unix_seconds(),
        ));
        harness.collect_as(default(), respond_recognized);
        assert_eq!(harness.requests(), 1);
        // A registered slot's collection does not merge the statusLine, so it
        // keeps its 5-min reads.
        harness.collect_as(
            super::super::ClaudeOAuthUsageCaller::RegisteredSlot("slot-variant".to_string()),
            respond_recognized,
        );
        assert_eq!(harness.requests(), 2);
        // StatusLine older than the slot: the default login calls again.
        harness.age_reading(5 * 60 + 1);
        harness.write_statusline(now - 6 * 60);
        harness.collect_as(default(), respond_recognized);
        assert_eq!(harness.requests(), 3);
    }

    fn saved_resets_of(outcome: &super::super::ClaudeOAuthUsageOutcome) -> Vec<AgentCreditBalance> {
        outcome
            .result
            .as_ref()
            .unwrap()
            .credit_balances
            .iter()
            .filter(|b| b.kind == Some(CreditBalanceKind::SavedResets))
            .cloned()
            .collect()
    }

    fn has_unrecognized(outcome: &super::super::ClaudeOAuthUsageOutcome) -> bool {
        outcome
            .diagnostics
            .iter()
            .any(|d| d.code == "claude_saved_reset_variant_unrecognized")
    }

    fn balances_of(outcome: &super::super::ClaudeOAuthUsageOutcome) -> &[AgentCreditBalance] {
        &outcome.result.as_ref().unwrap().credit_balances
    }

    /// The saved-reset and one-time sections are persisted with the stored
    /// reading, so a restarted daemon re-sends them with their original read
    /// times instead of dropping them until the next variant read (a
    /// disappearance and a return would each be stored by the backend).
    #[test]
    #[serial_test::serial]
    fn restart_resends_persisted_saved_resets_with_original_read_times() {
        let harness = VariantHarness::new("restart");
        harness.due(ClaudeReadSchedule::default());
        let first = harness.collect(respond_recognized);
        let saved = saved_resets_of(&first);
        assert_eq!(saved.len(), 1);
        let read_at = saved[0].grants_observed_at.clone().expect("read time");
        assert_eq!(saved[0].observed_at.as_ref(), Some(&read_at));
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        // Restart: nothing in memory survives; the stored reading is served.
        super::super::CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap()
            .clear();
        REQUESTED.lock().unwrap().clear();
        let served = harness.collect(respond_plain);
        assert!(
            REQUESTED.lock().unwrap().is_empty(),
            "no call inside the slot"
        );
        assert_eq!(saved_resets_of(&served), saved);

        // The first due slot after the restart reads plain; the saved-reset
        // section is re-sent unchanged, the plain sections are fresh.
        harness.due_keeping_reading();
        let after = harness.collect(respond_plain);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage"]
        );
        assert_eq!(saved_resets_of(&after), saved);
        let usage = balances_of(&after)
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
            .expect("usage credits");
        assert_ne!(usage.observed_at.as_ref(), Some(&read_at));
        assert!(balances_of(&after)
            .iter()
            .any(|b| b.kind == Some(CreditBalanceKind::OneTimeCredit)));
    }

    /// A stored plain reading, then a due saved-reset slot that the provider
    /// answers with `respond`. The stored reading must be served unchanged,
    /// the variant paused, no breaker strike recorded, and the next read
    /// moved out by one slot (no second call in this slot or the next pass).
    fn assert_unusable_variant_keeps_the_stored_reading(
        respond: super::super::ClaudeOAuthTestResponder,
    ) {
        let harness = VariantHarness::new("unusable-variant");
        let _ = std::fs::remove_file(harness.state_dir().join(CLAUDE_READ_SCHEDULE_FILE));
        let stored = harness.collect(respond_plain);
        let stored_credits = balances_of(&stored).to_vec();
        assert!(!stored_credits.is_empty());
        harness.due_keeping_reading();
        REQUESTED.lock().unwrap().clear();

        let outcome = harness.collect(respond);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
        );
        assert!(has_unrecognized(&outcome));
        assert_eq!(harness.shape_failures(), 0, "never a breaker strike");
        let usage = outcome.result.as_ref().expect("stored reading served");
        assert!(!usage.windows.is_empty(), "windows do not flip off");
        let kinds = |balances: &[AgentCreditBalance]| {
            balances
                .iter()
                .map(|b| (b.kind, b.observed_at.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(kinds(&usage.credit_balances), kinds(&stored_credits));
        assert!(harness
            .schedule()
            .saved_resets_variant_paused_until
            .is_some());

        // The next passes inside the pushed-out slot make no call.
        REQUESTED.lock().unwrap().clear();
        harness.collect(respond);
        harness.collect(respond);
        assert!(REQUESTED.lock().unwrap().is_empty(), "no retry every pass");

        // One slot later: the paused variant gives way to the plain read.
        harness.due_keeping_reading();
        harness.collect(respond_plain);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage"]
        );
    }

    #[test]
    #[serial_test::serial]
    fn variant_400_pauses_it_and_keeps_the_stored_reading() {
        assert_unusable_variant_keeps_the_stored_reading(respond_variant_400);
    }

    fn breaker_open(harness: &VariantHarness) -> bool {
        super::super::read_claude_oauth_usage_breaker(
            harness.account,
            harness.organization,
            &super::super::claude_oauth_usage_config_fingerprint(),
        )
        .is_some_and(|breaker| {
            super::super::claude_oauth_usage_breaker_is_open(
                &breaker,
                super::super::current_unix_seconds(),
            )
        })
    }

    /// A windowless variant 200 whose `cedar_ember` is recognizable: the
    /// saved-reset section is kept fresh, the stored windows and other
    /// sections are served, no breaker strike, and no call until the next
    /// slot, over several passes.
    #[test]
    #[serial_test::serial]
    fn recognized_windowless_variant_keeps_cedar_and_the_stored_reading() {
        let harness = VariantHarness::new("cedar-only");
        let _ = std::fs::remove_file(harness.state_dir().join(CLAUDE_READ_SCHEDULE_FILE));
        let stored = harness.collect(respond_plain);
        let stored_usage = balances_of(&stored)
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
            .unwrap()
            .clone();
        harness.due_keeping_reading();
        REQUESTED.lock().unwrap().clear();

        let outcome = harness.collect(respond_cedar_only);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
        );
        assert!(!has_unrecognized(&outcome));
        let usage = outcome.result.as_ref().expect("stored reading served");
        assert!(!usage.windows.is_empty(), "windows do not flip off");
        let saved = saved_resets_of(&outcome);
        assert_eq!(saved.len(), 1, "the fresh saved-reset section is kept");
        assert_eq!(saved[0].eligible, Some(true));
        let usage_now = balances_of(&outcome)
            .iter()
            .find(|b| b.kind == Some(CreditBalanceKind::UsageCredits))
            .unwrap();
        assert_eq!(usage_now.observed_at, stored_usage.observed_at);
        assert_eq!(harness.shape_failures(), 0);
        assert_eq!(harness.schedule().saved_resets_variant_paused_until, None);

        // Repeated passes inside the slot: no call, breaker closed.
        REQUESTED.lock().unwrap().clear();
        for _ in 0..3 {
            let served = harness.collect(respond_cedar_only);
            assert_eq!(saved_resets_of(&served).len(), 1);
        }
        assert!(REQUESTED.lock().unwrap().is_empty(), "no retry every pass");
        assert_eq!(harness.shape_failures(), 0);
        assert!(!breaker_open(&harness));

        // Next slot: one read again. Usage credits are off in this body, so
        // the saved-reset variant takes the slots between ~6 h plain reads.
        harness.due_keeping_reading();
        harness.collect(respond_recognized);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
        );
    }

    /// No stored reading at all: a variant that is rejected, or that answers
    /// without windows, never leads to a plain call in the same slot.
    #[test]
    #[serial_test::serial]
    fn unusable_variant_without_a_stored_reading_waits_for_the_next_slot() {
        for respond in [
            respond_variant_400 as super::super::ClaudeOAuthTestResponder,
            respond_cedar_only,
        ] {
            let harness = VariantHarness::new("no-stored-reading");
            harness.due(ClaudeReadSchedule::default());
            assert!(super::super::read_claude_oauth_usage_cache(
                harness.account,
                harness.organization
            )
            .is_none());
            harness.collect(respond);
            assert_eq!(
                REQUESTED.lock().unwrap().as_slice(),
                ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
            );
            REQUESTED.lock().unwrap().clear();
            for _ in 0..3 {
                harness.collect(respond_plain);
            }
            assert!(
                REQUESTED.lock().unwrap().is_empty(),
                "no call in the same slot"
            );
            assert_eq!(harness.shape_failures(), 0);
            // Once the slot has passed, the next read happens.
            let mut schedule = harness.schedule();
            schedule.next_read_not_before = None;
            write_claude_read_schedule(&harness.state_dir(), &schedule).unwrap();
            let _ = std::fs::remove_file(super::super::claude_oauth_usage_cache_path(
                harness.account,
                harness.organization,
            ));
            harness.collect(respond_plain);
            assert_eq!(REQUESTED.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn read_hold_is_bounded_to_the_longest_slot() {
        let now = 1_000_000;
        let slot = 300;
        let mut schedule = ClaudeReadSchedule {
            next_read_not_before: Some(now + slot),
            ..ClaudeReadSchedule::default()
        };
        assert_eq!(
            claude_read_held(&mut schedule, slot, now),
            ClaudeReadHold {
                active: true,
                cleared: false
            }
        );
        assert!(!claude_read_held(&mut schedule, slot, now + slot).active);
        // Written under the unused-account slot, read under the shorter in-use
        // slot: still a legitimate hold.
        schedule.next_read_not_before = Some(now + LONGEST_SLOT_SECONDS);
        assert_eq!(
            claude_read_held(&mut schedule, 300, now),
            ClaudeReadHold {
                active: true,
                cleared: false
            }
        );
        // Further ahead than the longest slot (42 min): a clock that stepped
        // back. Ignored and cleared.
        schedule.next_read_not_before = Some(now + LONGEST_SLOT_SECONDS + 1);
        assert_eq!(
            claude_read_held(&mut schedule, slot, now),
            ClaudeReadHold {
                active: false,
                cleared: true
            }
        );
        assert_eq!(schedule.next_read_not_before, None);
    }

    fn respond_429(endpoint: &str) -> Result<Value, u16> {
        REQUESTED.lock().unwrap().push(endpoint.to_string());
        Err(429)
    }

    /// A 429 adds the rate-limited diagnostic naming the read and the wait,
    /// with no extra call and the existing backoff unchanged (one rate-limit
    /// strike, the stored reading held until the Retry-After time).
    #[test]
    #[serial_test::serial]
    fn rate_limited_read_names_the_read_and_wait_without_changing_backoff() {
        for (schedule, label) in [
            (ClaudeReadSchedule::default(), "saved-resets"),
            (
                ClaudeReadSchedule {
                    saved_resets_variant_paused_until: Some(
                        super::super::current_unix_seconds() + 3_600,
                    ),
                    ..Default::default()
                },
                "usage",
            ),
        ] {
            let harness = VariantHarness::new("rate-limited");
            harness.due(schedule);
            REQUESTED.lock().unwrap().clear();
            let before = super::super::current_unix_seconds();
            let outcome = harness.collect(respond_429);
            let after = super::super::current_unix_seconds();
            assert_eq!(REQUESTED.lock().unwrap().len(), 1, "{label}: one call");
            let limited = outcome
                .diagnostics
                .iter()
                .filter(|d| d.code == "claude_oauth_usage_rate_limited")
                .collect::<Vec<_>>();
            assert_eq!(limited.len(), 1, "{label}");
            assert!(
                limited[0]
                    .message
                    .starts_with("Claude asked Ottto to wait until "),
                "{label}"
            );
            assert!(
                limited[0]
                    .message
                    .ends_with(&format!(" UTC before the next {label} read.")),
                "{label}"
            );
            let retry_after = limited[0]
                .retry_after
                .as_deref()
                .and_then(parse_instant)
                .map(|at| at.unix_timestamp() as u64)
                .expect("retry_after");
            // No Retry-After header: the existing 5-minute fallback.
            assert!(
                (before + 300..=after + 300).contains(&retry_after),
                "{label}"
            );
            let cache =
                super::super::read_claude_oauth_usage_cache(harness.account, harness.organization)
                    .expect("cache written");
            assert_eq!(cache.next_refresh_after_epoch_seconds, retry_after);
            let breaker = super::super::read_claude_oauth_usage_breaker(
                harness.account,
                harness.organization,
                &super::super::claude_oauth_usage_config_fingerprint(),
            )
            .expect("breaker");
            assert_eq!(breaker.rate_limit_failures, 1, "{label}");
            assert_eq!(harness.shape_failures(), 0);
        }
    }

    #[test]
    #[serial_test::serial]
    fn unrecognized_variant_goes_plain_for_24_hours_without_a_breaker_strike() {
        let harness = VariantHarness::new("unrecognized");
        harness.due(ClaudeReadSchedule::default());
        let outcome = harness.collect(respond_cedar_null);
        assert!(has_unrecognized(&outcome));
        assert!(
            saved_resets_of(&outcome).is_empty(),
            "no saved-reset balance"
        );
        assert!(outcome
            .result
            .as_ref()
            .unwrap()
            .credit_balances
            .iter()
            .all(|b| b.status != AgentCreditBalanceStatus::Unknown
                || b.kind != Some(CreditBalanceKind::SavedResets)));
        assert_eq!(harness.shape_failures(), 0);
        let now = super::super::current_unix_seconds();
        let paused_until = harness
            .schedule()
            .saved_resets_variant_paused_until
            .unwrap();
        assert!((now + 24 * 3_600 - 5..=now + 24 * 3_600).contains(&paused_until));

        // A variant body with no windows at all is still variant state, not a
        // shape strike on the shared endpoint breaker.
        harness.due(ClaudeReadSchedule::default());
        let outcome = harness.collect(respond_empty);
        assert!(has_unrecognized(&outcome));
        assert_eq!(harness.shape_failures(), 0);

        // While paused, the next due slot reads plain.
        harness.due(harness.schedule());
        REQUESTED.lock().unwrap().clear();
        harness.collect(respond_recognized);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage"]
        );

        // Recovery after 24 h: the variant is read and re-checked again.
        let mut schedule = harness.schedule();
        schedule.saved_resets_variant_paused_until = Some(now - 1);
        schedule.last_plain_read_at = Some(now - 3_600);
        schedule.last_saved_resets_read_at = Some(now - 7_200);
        harness.due(schedule);
        REQUESTED.lock().unwrap().clear();
        let outcome = harness.collect(respond_recognized);
        assert_eq!(
            REQUESTED.lock().unwrap().as_slice(),
            ["https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"]
        );
        assert_eq!(saved_resets_of(&outcome).len(), 1);
        assert_eq!(harness.schedule().saved_resets_variant_paused_until, None);
    }
}
