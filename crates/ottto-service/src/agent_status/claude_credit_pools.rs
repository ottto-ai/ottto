//! Claude credit-pool adapter: maps Claude usage-credit, one-time and
//! saved-reset fields into the shared credit model
//! (`crate::quota_credit_model`). Owned by the Claude adapter.
//!
//! This module owns the Claude provider field names for credits (quota
//! contract v2.2 §11.1 kinds, §11.3 one-time pools, §11.7 C4 pinned names) and
//! the Claude read cadence (design R7, Ron Q1/Q3). Grant building, summaries,
//! the one-time pool shape and section re-send stay in the model.

use std::path::Path;

use ottto_protocol::{
    is_credit_reason_code, ActiveSessionReconciliation, AgentCreditBalance,
    AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentQuotaWindowFreshness, CreditBalanceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::quota_credit_model::{
    build_grants, normalize_time, one_time_credit, CreditModelDiagnostic, Field, GrantInput,
    GrantStatusInput, ListObservation, Provider, SectionCache, TimeInput,
};

/// The saved-reset read variant (`cedar_ember`). Held off until the OAuth twin
/// of the observed web variant is witnessed and the lead confirms its shape.
/// While `false` every read is the plain read, exactly as before.
pub(super) const CLAUDE_SAVED_RESETS_READ_ENABLED: bool = false;
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

/// While the account was active this recently, the slot is the active slot.
const ACTIVE_WINDOW_SECONDS: u64 = 30 * 60;
const ACTIVE_SLOT_SECONDS: u64 = 15 * 60;
/// Idle longer than this, the slot is the idle slot (2-3 h, spread per
/// account like the default slot).
const IDLE_AFTER_SECONDS: u64 = 6 * 60 * 60;
const IDLE_SLOT_BASE_SECONDS: u64 = 2 * 60 * 60;
const IDLE_SLOT_SPREAD_SECONDS: u64 = 60 * 60;
/// While usage credits are off, the plain read runs about this often and the
/// other slots take the saved-reset read.
const PLAIN_WHILE_CREDITS_OFF_SECONDS: u64 = 6 * 60 * 60;
/// A passive reading stamped further ahead of the local clock is not trusted.
const PASSIVE_CLOCK_SKEW_SECONDS: u64 = 60;
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
}

// Section names for the model's `SectionCache`. Each read owns some sections;
// a read that does not carry a section re-sends the last observed one.
const SECTION_USAGE_CREDITS: &str = "claude_usage_credits";
const SECTION_ONE_TIME_CREDITS: &str = "claude_one_time_credits";
const SECTION_SAVED_RESETS: &str = "claude_saved_resets";
const SECTIONS: [&str; 3] = [
    SECTION_USAGE_CREDITS,
    SECTION_ONE_TIME_CREDITS,
    SECTION_SAVED_RESETS,
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
/// - Plain: usage credits (`spend`, else `extra_usage`) and every one-time
///   dollar pool. Both are real observations even when empty.
/// - Saved-reset variant: `cedar_ember` only. Its `spend` is skipped by
///   request, and its pools stay owned by the plain read so a variant that
///   omitted them can never toggle their presence.
/// - `cedar_ember` is a saved-reset observation only when it is an object; the
///   plain read always sends it as `null`.
pub(super) fn claude_credit_read(
    body: &Value,
    read: ClaudeUsageRead,
    observed_at: &str,
) -> ClaudeCreditRead {
    let mut diagnostics = Vec::new();
    let saved_resets = claude_saved_resets(body, observed_at, &mut diagnostics).map(|b| vec![b]);
    match read {
        ClaudeUsageRead::Plain => {
            let mut usage_credits = super::claude_oauth_credit_balances(body);
            for balance in &mut usage_credits {
                balance.observed_at = Some(observed_at.to_string());
            }
            ClaudeCreditRead {
                usage_credits: Some(usage_credits),
                one_time_credits: Some(claude_one_time_credits(body, observed_at)),
                saved_resets,
                diagnostics,
            }
        }
        ClaudeUsageRead::SavedResets => ClaudeCreditRead {
            saved_resets,
            diagnostics,
            ..ClaudeCreditRead::default()
        },
    }
}

fn balance_section(balance: &AgentCreditBalance) -> Option<&'static str> {
    match balance.kind {
        Some(CreditBalanceKind::UsageCredits) => Some(SECTION_USAGE_CREDITS),
        Some(CreditBalanceKind::OneTimeCredit) => Some(SECTION_ONE_TIME_CREDITS),
        Some(CreditBalanceKind::SavedResets) => Some(SECTION_SAVED_RESETS),
        // Caches written before kinds existed held only the usage-credit row.
        None if balance.name == CLAUDE_USAGE_CREDITS_NAME => Some(SECTION_USAGE_CREDITS),
        _ => None,
    }
}

/// The balances to send after a read (design R7b, contract v2.2 §11.5, C8/C9).
///
/// `previous` is the binding's last stored reading (same account and
/// organization). Sections this read observed replace theirs; every other
/// section is re-sent through the model's [`SectionCache`] exactly as last
/// observed, with its original `observed_at`/`grants_observed_at`. A section
/// never observed is not sent. Claude balances carry no `updated_at` (as
/// before): the snapshot's packaging time is the row time, never carried over.
pub(super) fn claude_merge_credit_sections(
    binding: &str,
    previous: &[AgentCreditBalance],
    read: &ClaudeCreditRead,
) -> Vec<AgentCreditBalance> {
    let mut sections = SectionCache::new();
    for section in SECTIONS {
        let prior = previous
            .iter()
            .filter(|balance| balance_section(balance) == Some(section))
            .cloned()
            .collect::<Vec<_>>();
        if !prior.is_empty() {
            sections.observe_balances(binding, section, &prior);
        }
    }
    for (section, fresh) in [
        (SECTION_USAGE_CREDITS, &read.usage_credits),
        (SECTION_ONE_TIME_CREDITS, &read.one_time_credits),
        (SECTION_SAVED_RESETS, &read.saved_resets),
    ] {
        if let Some(fresh) = fresh {
            sections.observe_balances(binding, section, fresh);
        }
    }
    SECTIONS
        .into_iter()
        .filter_map(|section| sections.resend_balances(binding, section, ""))
        .flatten()
        .map(|mut balance| {
            balance.updated_at = None;
            balance
        })
        .collect()
}

/// Whether the last observed usage-credit balance says credits are off.
pub(super) fn claude_usage_credits_off(balances: &[AgentCreditBalance]) -> bool {
    balances.iter().any(|balance| {
        balance_section(balance) == Some(SECTION_USAGE_CREDITS) && balance.enabled == Some(false)
    })
}

/// Provider reason a usage-credit balance is off (`spend.disabled_reason`,
/// else `extra_usage.disabled_reason`). Only a reason-code shaped value is
/// kept (contract v2.1 §2.2, v2.2 §11.1).
pub(super) fn claude_usage_credits_disabled_reason(section: &Value) -> Option<String> {
    section
        .get("disabled_reason")
        .and_then(Value::as_str)
        .filter(|reason| is_credit_reason_code(reason))
        .map(ToString::to_string)
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
fn claude_one_time_credits(body: &Value, observed_at: &str) -> Vec<AgentCreditBalance> {
    let Some(object) = body.as_object() else {
        return Vec::new();
    };
    let read_at = parse_instant(observed_at);
    let mut keys = object.keys().collect::<Vec<_>>();
    keys.sort();
    keys.into_iter()
        .filter(|key| {
            !is_window_key(key) && key.as_str() != CLAUDE_PERCENT_ONLY_POOL
                // The codename is the pool's `limit_id`: a closed code shape.
                && is_credit_reason_code(key)
        })
        .filter_map(|key| {
            let pool = object.get(key)?.as_object()?;
            pool.get("limit_dollars")
                .filter(|value| value.is_number())?;
            let expires_at = match pool.get("resets_at") {
                Some(Value::String(text)) => normalize_time(TimeInput::Rfc3339(text.clone()))
                    .ok()
                    .flatten(),
                _ => None,
            };
            if let (Some(expiry), Some(read_at)) =
                (expires_at.as_deref().and_then(parse_instant), read_at)
            {
                if expiry < read_at {
                    return None;
                }
            }
            Some(one_time_credit(
                key,
                string_field(pool, "label"),
                super::claude_oauth_money_cents(pool.get("limit_dollars")),
                super::claude_oauth_money_cents(pool.get("used_dollars")),
                super::claude_oauth_money_cents(pool.get("remaining_dollars")),
                expires_at,
                Some(observed_at.to_string()),
            ))
        })
        .take(ONE_TIME_POOLS_MAX)
        .collect()
}

/// `cedar_ember` → one saved-reset balance: grants through the model, plus the
/// provider's readiness passthrough (`eligible`, `ineligible_reason`,
/// `at_limit`, `cooldown_until`). `remaining` is the model's summary.
fn claude_saved_resets(
    body: &Value,
    observed_at: &str,
    diagnostics: &mut Vec<CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    let cedar = body.get("cedar_ember")?.as_object()?;
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
            provider_count: None,
        },
    };
    let mut refuse = |field: &'static str| {
        diagnostics.push(CreditModelDiagnostic {
            code: "field_refused",
            field,
        });
    };
    let ineligible_reason = match cedar.get("ineligible_reason") {
        None | Some(Value::Null) => None,
        Some(Value::String(reason)) if is_credit_reason_code(reason) => Some(reason.clone()),
        Some(_) => {
            refuse("ineligible_reason");
            None
        }
    };
    let cooldown_until = match normalize_time(time_field(cedar, "cooldown_until")) {
        Ok(value) => value,
        Err(()) => {
            refuse("cooldown_until");
            None
        }
    };
    let mut readiness_bool = |key: &'static str| match bool_field(cedar, key) {
        Field::Value(value) => Some(value),
        Field::Absent => None,
        Field::Invalid => {
            refuse(key);
            None
        }
    };
    let eligible = readiness_bool("eligible");
    let at_limit = readiness_bool("at_limit");
    let mut balance = AgentCreditBalance {
        name: CLAUDE_SAVED_RESETS_NAME.to_string(),
        status: AgentCreditBalanceStatus::Unknown,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Resets,
        observed_at: Some(observed_at.to_string()),
        kind: Some(CreditBalanceKind::SavedResets),
        eligible,
        at_limit,
        ineligible_reason,
        cooldown_until,
        ..Default::default()
    };
    diagnostics.extend(build_grants(observation).apply_to(&mut balance));
    // Contract v2.1 §2.2 state table, as the Codex `reset_bank` row sends it.
    balance.status = match balance.remaining {
        Some(0) => AgentCreditBalanceStatus::Exhausted,
        Some(_) => AgentCreditBalanceStatus::Ok,
        None => AgentCreditBalanceStatus::Unknown,
    };
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
    /// First reading of this binding: the idle clock of an account never seen
    /// active. Never counts as activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tracked_since: Option<u64>,
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
    }

    fn activity_at(&self, latest_activity_at: Option<u64>) -> Option<u64> {
        self.last_activity_at.max(latest_activity_at)
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

/// The idle slot for one binding: 2-3 h, spread deterministically per account
/// the same way the default 55-65 min slot is (load spreading across our own
/// installs, not evasion).
pub(super) fn claude_idle_slot_seconds(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-idle-cadence:");
    hasher.update(account_identifier_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(organization_identifier_hash.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    IDLE_SLOT_BASE_SECONDS + u64::from_be_bytes(bytes) % (IDLE_SLOT_SPREAD_SECONDS + 1)
}

/// The account's read slot (Ron Q3): the active slot while the account was
/// active in the last 30 min, the idle slot once idle more than 6 h, else the
/// default slot (today's 55-65 min gate).
pub(super) fn claude_usage_slot_seconds(
    schedule: &ClaudeReadSchedule,
    latest_activity_at: Option<u64>,
    default_slot_seconds: u64,
    idle_slot_seconds: u64,
    now: u64,
) -> u64 {
    let activity = schedule.activity_at(latest_activity_at);
    if activity.is_some_and(|at| now.saturating_sub(at) <= ACTIVE_WINDOW_SECONDS) {
        return ACTIVE_SLOT_SECONDS;
    }
    match activity.max(schedule.tracked_since) {
        Some(idle_since) if now.saturating_sub(idle_since) > IDLE_AFTER_SECONDS => {
            idle_slot_seconds
        }
        _ => default_slot_seconds,
    }
}

/// Whether the binding is due a new reading: never read, or its last reading
/// is older than the slot and any Retry-After/success spacing has passed.
pub(super) fn claude_reading_due(
    last_reading_at: Option<u64>,
    next_refresh_after: u64,
    slot_seconds: u64,
    now: u64,
) -> bool {
    last_reading_at.map_or(true, |at| {
        now.saturating_sub(at) > slot_seconds && now >= next_refresh_after
    })
}

/// Which read a due slot makes (Ron Q1: no extra calls). Without the variant
/// every slot is plain. Otherwise slots alternate plain and saved-reset reads;
/// while usage credits are off the plain read runs only every ~6 h.
pub(super) fn claude_usage_read_kind(
    schedule: &ClaudeReadSchedule,
    usage_credits_off: bool,
    saved_resets_read_enabled: bool,
    now: u64,
) -> ClaudeUsageRead {
    if !saved_resets_read_enabled {
        return ClaudeUsageRead::Plain;
    }
    let Some(plain_at) = schedule.last_plain_read_at else {
        return ClaudeUsageRead::Plain;
    };
    let Some(saved_at) = schedule.last_saved_resets_read_at else {
        return ClaudeUsageRead::SavedResets;
    };
    if usage_credits_off {
        return if now.saturating_sub(plain_at) >= PLAIN_WHILE_CREDITS_OFF_SECONDS {
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

/// The passive reading in a Claude Code `.claude.json`, only when it is
/// provably this binding's: `cachedUsageUtilization.accountUuid` hashes to the
/// binding's account, and the config's own `oauthAccount` names that same
/// account under the binding's organization (the cache itself has no org).
pub(super) fn claude_passive_usage(
    config: &Value,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<ClaudePassiveUsage> {
    let cached = config.get("cachedUsageUtilization")?;
    let account_uuid = cached.get("accountUuid")?.as_str()?;
    let oauth = config.get("oauthAccount")?;
    let organization_uuid = oauth.get("organizationUuid")?.as_str()?;
    if oauth.get("accountUuid")?.as_str()? != account_uuid
        || ottto_core::billing_identity_hash("anthropic", "account", account_uuid).as_deref()
            != Some(account_identifier_hash)
        || ottto_core::billing_identity_hash("anthropic", "organization", organization_uuid)
            .as_deref()
            != Some(organization_identifier_hash)
    {
        return None;
    }
    let fetched = cached.get("fetchedAtMs")?;
    let fetched_ms = fetched.as_u64().or_else(|| {
        fetched
            .as_f64()
            .filter(|ms| ms.is_finite() && *ms >= 0.0)
            .map(|ms| ms as u64)
    })?;
    let body = cached.get("utilization")?;
    body.is_object().then(|| ClaudePassiveUsage {
        fetched_at: fetched_ms / 1000,
        body: body.clone(),
    })
}

/// Use the passive reading instead of a call when it is newer than our last
/// reading and still inside the slot (so it would serve as fresh).
pub(super) fn claude_passive_reading_usable(
    fetched_at: u64,
    last_reading_at: Option<u64>,
    slot_seconds: u64,
    now: u64,
) -> bool {
    fetched_at <= now.saturating_add(PASSIVE_CLOCK_SKEW_SECONDS)
        && last_reading_at.map_or(true, |last| fetched_at > last)
        && now.saturating_sub(fetched_at) <= slot_seconds
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{CreditGrantStatus, CreditGrantsState};
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
        assert!(read.usage_credits.is_none() && read.one_time_credits.is_none());
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
    fn expired_one_time_pool_is_skipped_and_live_one_is_kept() {
        let body = plain_max_body();
        let after_expiry = claude_one_time_credits(&body, READ_AT);
        assert!(after_expiry
            .iter()
            .all(|credit| credit.limit_id.as_deref() != Some("amber_ladder")));
        let before_expiry = claude_one_time_credits(&body, "2026-09-25T10:00:00Z");
        let amber = before_expiry
            .iter()
            .find(|credit| credit.limit_id.as_deref() == Some("amber_ladder"))
            .expect("amber_ladder before its expiry");
        assert_eq!(amber.quota, Some(250_000));
        assert_eq!(amber.used, Some(250_137));
        assert_eq!(amber.remaining, Some(0));
        assert_eq!(amber.status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(amber.expires_at.as_deref(), Some("2026-10-02T06:59:59Z"));
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
        let pools = claude_one_time_credits(&body, READ_AT);
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].limit_id.as_deref(), Some("wattle_ember"));
        assert_eq!(pools[0].title.as_deref(), Some("Promo credit"));
        assert_eq!(pools[0].remaining, Some(1_800));
    }

    #[test]
    fn no_one_time_balance_is_ever_enabled() {
        let mut bodies = vec![plain_max_body(), variant_body(cedar_max())];
        bodies.push(json!({"iguana_necktie": {"limit_dollars": 1, "enabled": true}}));
        for body in bodies {
            for credit in claude_one_time_credits(&body, "2026-09-01T00:00:00Z") {
                assert_eq!(credit.enabled, None);
            }
        }
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

    #[test]
    fn cedar_max_grant_usable_now_at_limit() {
        let balance = saved_resets(cedar_max());
        assert_eq!(balance.at_limit, Some(true));
        assert_eq!(balance.eligible, Some(true));
        assert_eq!(balance.cooldown_until, None);
        assert_eq!(balance.remaining, Some(1));
        assert_eq!(balance.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(
            balance.next_expires_at.as_deref(),
            Some("2026-10-22T16:00:00Z")
        );
        let grant = &balance.grants.as_ref().unwrap()[0];
        assert_eq!(grant.status, CreditGrantStatus::Available);
        assert_eq!(grant.usable_now, Some(true));
    }

    #[test]
    fn cedar_ineligible_tenure_with_empty_grants() {
        let balance = saved_resets(cedar_ineligible());
        assert_eq!(balance.eligible, Some(false));
        assert_eq!(balance.ineligible_reason.as_deref(), Some("tenure"));
        assert_eq!(balance.grants.as_deref(), Some(&[][..]));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        assert_eq!(balance.grant_count, Some(0));
        assert_eq!(balance.remaining, Some(0));
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

        // Cold: a first saved-reset read sends only what it observed; nothing
        // stands in for the unread usage credits.
        let cold = claude_merge_credit_sections(
            "a",
            &[],
            &claude_credit_read(&variant, ClaudeUsageRead::SavedResets, t1),
        );
        assert_eq!(cold.len(), 1);
        assert_eq!(cold[0].kind, Some(CreditBalanceKind::SavedResets));

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
        assert_eq!(merged.len(), 2);
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
        let passive = claude_passive_usage(
            &passive_config("acct-1", "acct-1", "org-1", 1_791_000_000_500),
            &account,
            &org,
        )
        .expect("matching binding");
        assert_eq!(passive.fetched_at, 1_791_000_000);
        // Same plain-body parser: the passive body yields the same pools.
        let read = claude_credit_read(&passive.body, ClaudeUsageRead::Plain, READ_AT);
        assert_eq!(
            read.one_time_credits.unwrap()[0].limit_id.as_deref(),
            Some("iguana_necktie")
        );
        for config in [
            passive_config("acct-2", "acct-1", "org-1", 1),
            passive_config("acct-1", "acct-2", "org-1", 1),
            passive_config("acct-1", "acct-1", "org-2", 1),
            json!({"oauthAccount": {"accountUuid": "acct-1", "organizationUuid": "org-1"}}),
        ] {
            assert_eq!(claude_passive_usage(&config, &account, &org), None);
        }
        // Newer than our reading and inside the slot, else a call is made.
        assert!(claude_passive_reading_usable(
            1_000,
            Some(900),
            3_600,
            1_100
        ));
        assert!(claude_passive_reading_usable(1_000, None, 3_600, 1_100));
        assert!(!claude_passive_reading_usable(900, Some(900), 3_600, 1_100));
        assert!(!claude_passive_reading_usable(
            1_000,
            Some(900),
            3_600,
            5_000
        ));
        assert!(!claude_passive_reading_usable(2_000, None, 3_600, 1_000));
    }

    #[test]
    fn latest_activity_is_the_exact_binding_sessions_newest() {
        let session = |account: &str, org: &str, at: &str| {
            json!({"source_session_id": format!("s-{at}"), "source_last_activity_at": at,
                   "account_identifier_hash": account, "organization_identifier_hash": org})
        };
        let reconciliation: ActiveSessionReconciliation = serde_json::from_value(json!({
            "reconciled_at": "2026-10-09T12:00:00Z", "changed_session_count": 3,
            "sessions": [
                session("a", "o", "2026-10-09T11:50:00Z"),
                session("a", "o", "2026-10-09T11:55:00Z"),
                session("a", "other", "2026-10-09T11:59:00Z"),
            ]
        }))
        .unwrap();
        let expected = OffsetDateTime::parse("2026-10-09T11:55:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp() as u64;
        assert_eq!(
            claude_latest_activity_at(Some(&reconciliation), "a", "o"),
            Some(expected)
        );
        assert_eq!(
            claude_latest_activity_at(Some(&reconciliation), "b", "o"),
            None
        );
        assert_eq!(claude_latest_activity_at(None, "a", "o"), None);
    }

    #[test]
    fn idle_slot_is_two_to_three_hours_and_stable_per_binding() {
        for seed in 0..64 {
            let slot = claude_idle_slot_seconds(&format!("account-{seed}"), "org");
            assert!((2 * 3_600..=3 * 3_600).contains(&slot));
            assert_eq!(
                slot,
                claude_idle_slot_seconds(&format!("account-{seed}"), "org")
            );
        }
    }

    const DEFAULT_SLOT: u64 = 3_600;
    const TICK: u64 = 60;
    const HOUR: u64 = 3_600;

    /// One simulated binding driven exactly like the collection path: due
    /// check, then passive input, then one read of the scheduled kind.
    struct Simulation {
        schedule: ClaudeReadSchedule,
        last_reading_at: Option<u64>,
        next_refresh_after: u64,
        usage_credits_off: bool,
        calls: Vec<(u64, ClaudeUsageRead, u64)>,
        passive_used: Vec<u64>,
    }

    impl Simulation {
        fn new(usage_credits_off: bool) -> Self {
            Self {
                schedule: ClaudeReadSchedule::default(),
                last_reading_at: None,
                next_refresh_after: 0,
                usage_credits_off,
                calls: Vec::new(),
                passive_used: Vec::new(),
            }
        }

        fn tick(&mut self, now: u64, activity: Option<u64>, passive_fetched_at: Option<u64>) {
            let idle = claude_idle_slot_seconds("account-sim", "org-sim");
            let slot = claude_usage_slot_seconds(&self.schedule, activity, DEFAULT_SLOT, idle, now);
            if !claude_reading_due(self.last_reading_at, self.next_refresh_after, slot, now) {
                return;
            }
            if let Some(fetched) = passive_fetched_at
                .filter(|at| claude_passive_reading_usable(*at, self.last_reading_at, slot, now))
            {
                self.passive_used.push(now);
                self.record(ClaudeUsageRead::Plain, fetched, activity, now);
                return;
            }
            let read = claude_usage_read_kind(&self.schedule, self.usage_credits_off, true, now);
            self.calls.push((now, read, slot));
            self.record(read, now, activity, now);
        }

        fn record(&mut self, read: ClaudeUsageRead, at: u64, activity: Option<u64>, now: u64) {
            self.last_reading_at = Some(at);
            self.next_refresh_after = now + 300;
            self.schedule.after_reading(read, at, activity, now);
        }
    }

    /// 24 h: idle start, active 08:00-10:00, idle again; activity is visible
    /// only while the active-session scan still lists it (15 min).
    fn run_day(usage_credits_off: bool, passive: &dyn Fn(u64) -> Option<u64>) -> Simulation {
        let start = 1_791_000_000;
        let mut simulation = Simulation::new(usage_credits_off);
        let mut last_activity = None;
        let mut now = start;
        while now < start + 24 * HOUR {
            let hour = (now - start) / HOUR;
            if (8..10).contains(&hour) {
                last_activity = Some(now);
            }
            let visible = last_activity.filter(|at| now - at <= 15 * 60);
            simulation.tick(
                now,
                visible,
                passive(now - start).map(|offset| start + offset),
            );
            now += TICK;
        }
        simulation
    }

    #[test]
    fn scheduler_day_respects_slots_alternation_and_activity() {
        let start = 1_791_000_000;
        let simulation = run_day(false, &|_| None);
        let calls = &simulation.calls;
        // At most one OAuth usage read per account-slot.
        for pair in calls.windows(2) {
            let (at, _, slot) = pair[1];
            assert!(at - pair[0].0 > slot, "read inside its slot");
            assert!(at - pair[0].0 >= ACTIVE_SLOT_SECONDS);
        }
        // Credits on: plain and saved-reset reads strictly alternate.
        assert_eq!(calls[0].1, ClaudeUsageRead::Plain);
        for pair in calls.windows(2) {
            assert_ne!(pair[0].1, pair[1].1);
        }
        let gaps_in = |from: u64, to: u64| {
            calls
                .windows(2)
                .filter(|pair| pair[1].0 >= start + from && pair[1].0 < start + to)
                .map(|pair| pair[1].0 - pair[0].0)
                .collect::<Vec<_>>()
        };
        // 00:00-06:00: default slot (55-65 min).
        assert!(gaps_in(0, 6 * HOUR)
            .iter()
            .all(|gap| (55 * 60..=66 * 60).contains(gap)));
        // 08:15-10:00: active, 15-min slots.
        let active = gaps_in(8 * HOUR + 15 * 60, 10 * HOUR);
        assert!(active.len() >= 6);
        assert!(active.iter().all(|gap| (15 * 60..=17 * 60).contains(gap)));
        // Idle more than 6 h (06:00-08:00 and after 16:30): 2-3 h slots.
        let idle = gaps_in(17 * HOUR, 24 * HOUR);
        assert!(!idle.is_empty());
        assert!(idle
            .iter()
            .all(|gap| (2 * HOUR..=3 * HOUR + TICK).contains(gap)));
        assert!(gaps_in(6 * HOUR + 30 * 60, 8 * HOUR)
            .iter()
            .all(|gap| *gap >= 2 * HOUR));
        // Same posture as today: never more reads than the active slot allows.
        assert!(calls.len() <= 24 * 4);
    }

    #[test]
    fn scheduler_reads_plain_about_every_six_hours_while_credits_are_off() {
        let simulation = run_day(true, &|_| None);
        let plain = simulation
            .calls
            .iter()
            .filter(|(_, read, _)| *read == ClaudeUsageRead::Plain)
            .map(|(at, _, _)| *at)
            .collect::<Vec<_>>();
        assert!(plain.len() >= 3);
        for pair in plain.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                (6 * HOUR..=9 * HOUR + TICK).contains(&gap),
                "plain gap {gap}"
            );
        }
        let saved = simulation
            .calls
            .iter()
            .filter(|(_, read, _)| *read == ClaudeUsageRead::SavedResets)
            .count();
        assert!(
            saved > plain.len() * 2,
            "saved-reset reads take the other slots"
        );
    }

    #[test]
    fn scheduler_uses_newer_passive_reading_instead_of_a_call() {
        // Claude Code refreshed its own reading every 20 min during 03:00-04:00.
        let passive = |offset: u64| {
            (3 * HOUR..4 * HOUR)
                .contains(&offset)
                .then(|| offset - offset % (20 * 60))
        };
        let with_passive = run_day(false, &passive);
        let without = run_day(false, &|_| None);
        assert!(!with_passive.passive_used.is_empty());
        assert!(with_passive.calls.len() < without.calls.len());
        // A passive reading is never newer than one we already used.
        let stale_passive = run_day(false, &|offset| (offset >= HOUR).then_some(0));
        assert!(stale_passive.passive_used.is_empty());
        assert_eq!(stale_passive.calls.len(), without.calls.len());
    }

    #[test]
    fn saved_reset_variant_disabled_keeps_every_read_plain() {
        let schedule = ClaudeReadSchedule {
            last_plain_read_at: Some(1),
            last_saved_resets_read_at: None,
            last_activity_at: None,
            tracked_since: None,
        };
        assert_eq!(
            claude_usage_read_kind(&schedule, false, CLAUDE_SAVED_RESETS_READ_ENABLED, 10),
            ClaudeUsageRead::Plain
        );
        assert_eq!(ClaudeUsageRead::Plain.query(), "");
        assert_eq!(
            ClaudeUsageRead::SavedResets.query(),
            "?cedar_ember=1&skip_spend=1"
        );
    }
}
