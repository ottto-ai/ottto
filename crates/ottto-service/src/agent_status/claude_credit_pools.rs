//! Claude credit-pool adapter: maps Claude usage-credit, one-time and
//! saved-reset fields into the shared credit model
//! (`crate::quota_credit_model`). Owned by the Claude adapter.
//!
//! This module owns the Claude provider field names for credits (quota
//! contract v2.2 §11.1 kinds, §11.3 one-time pools, §11.7 C4 pinned names) and
//! the Claude read cadence. Grant building, summaries,
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
/// Admission slack at the slot boundary (well under one 5-min pass).
const SLOT_ADMISSION_SLACK_SECONDS: u64 = 60;
/// A passive reading stamped further ahead of the local clock is not trusted.
const PASSIVE_CLOCK_SKEW_SECONDS: u64 = 60;
/// Longest pause between two collection passes of one caller that still
/// counts as continuous observation of its sign-in (passes run every ~5 min).
const CALLER_BINDING_MAX_GAP_SECONDS: u64 = 15 * 60;
/// A window reset the stored reading predates earns one extra read this long
/// after the reset, spread per account over the next minute. The reading
/// after it postdates the reset, so each
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

/// The balances to send after a read (contract v2.2 §11.5, C8/C9).
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

/// Every top-level object with a readable `limit_dollars` amount is a one-time
/// dollar pool (contract v2.2 §11.3): `iguana_necktie`, `amber_ladder`,
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
            let limit_cents = super::claude_oauth_money_cents(pool.get("limit_dollars"))?;
            // The codename becomes the pool's `limit_id`; the model refuses a
            // codename that is not a closed code shape (or is secret-shaped),
            // and the pool is skipped with that refusal's diagnostic.
            let (balance, refused) = match one_time_credit(
                key,
                string_field(pool, "label"),
                Some(limit_cents),
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
    crate::agent_status::write_owner_only_file_atomic_if_changed(
        &account_state_dir.join(CLAUDE_READ_SCHEDULE_FILE),
        &body,
    )
}

/// The account's read slot (active-account freshness): the active
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

/// Which read a due slot makes (no extra calls). `stored` is the
/// binding's persisted reading.
///
/// - While the variant is paused by its self-check every slot is plain.
/// - A missing section is filled first: with plain data known but no stored
///   saved-reset section, the slot reads the variant; with saved resets stored
///   but no plain data known, it reads plain. Nothing known: plain.
/// - Otherwise slots alternate plain and saved-reset reads.
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
    if saved_at >= plain_at {
        ClaudeUsageRead::Plain
    } else {
        ClaudeUsageRead::SavedResets
    }
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
/// - saved resets and usage credits are read once every two slots
///   (plain/variant alternation): fresh for two gates;
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
/// Passive input from Claude Code's own `cachedUsageUtilization`
/// (active-account freshness).
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
#[rustfmt::skip]
mod tests;
