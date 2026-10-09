//! Codex credit adapter: maps Codex app-server credit fields into the shared
//! credit model (`crate::quota_credit_model`) and owns the Codex detail-read
//! cadence (design R1, R7; quota contract v2.1 §3-§6, v2.2 §11).
//!
//! Codex field names are read here and nowhere else:
//! - `rateLimitResetCredits.credits[]` rows become [`GrantInput`]s on the
//!   existing `reset_bank` balance (`id`, `resetType`, `status`, `grantedAt`,
//!   `expiresAt`, `title`; `description` is never read). `availableCount` is
//!   the provider count, so the list is `complete` only when every counted
//!   grant came back. `credits: null` is a count-only reading (`unavailable`).
//! - The Codex balance-name → `kind` table ([`codex_balance_kind`]).
//! - A counts-only diagnostic over `rateLimitsByLimitId`
//!   ([`rate_limit_pools_summary`]). Pools are not emitted as meters.
//!
//! # Cadence (R7)
//!
//! Every detailed `account/rateLimits/read` costs Codex a second backend call
//! for the reset-credit list. Routine polls therefore send
//! `excludeResetCreditDetails: true`; the count still comes back. A detailed
//! read (no params, byte-identical to the historical request) runs when:
//! - the binding has no successful detailed read (hourly or count-triggered)
//!   in the last hour ([`DETAIL_INTERVAL_SECS`], with [`POLL_SLACK_SECS`] so a 5-minute poll
//!   lands on the hour rather than one poll after it);
//! - a routine read reports an `availableCount` with no cached list for that
//!   count (a count change, a cold cache, or an account switch); the detailed
//!   read is sent at once in the same app-server session;
//! - the app-server rejects the routine parameter.
//!
//! A failed detailed read (Codex silently falls back to `credits: null`) is
//! retried after [`DETAIL_RETRY_SECS`], not on every poll, so a failing detail
//! endpoint never costs more calls than the old every-poll detailed read.
//! [`DetailCadence`] holds these decisions as pure functions of the clock.
//!
//! # Sender stability (R7b)
//!
//! A reading without the list re-sends the binding's last observed list from
//! the model's [`SectionCache`] unchanged (original `grants_observed_at`),
//! but only while the provider count equals the count the list was read with.
//! Cadence never turns a list into `unavailable`; only a failed detail read
//! with no matching cached list does. The cache is keyed by the credential
//! identity (account + workspace hash), so A→B→A keeps A's list, and a cold
//! cache (restart) starts with a detailed read instead of a guess.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ottto_protocol::{AgentCreditBalance, CreditBalanceKind};
use serde_json::Value;

use super::json_u64;
use crate::quota_credit_model::{
    build_grants, CreditModelDiagnostic, Field, GrantInput, GrantStatusInput, ListObservation,
    Provider, SectionCache, TimeInput,
};

/// The Codex saved-reset balance (name pinned by contract v2.2 §11.7 C4).
pub(super) const RESET_BANK: &str = "reset_bank";
/// [`SectionCache`] section holding the `reset_bank` grant list.
const RESET_BANK_GRANTS_SECTION: &str = "codex.reset_bank.grants";
/// Longest gap between successful detailed reads of one binding.
pub(super) const DETAIL_INTERVAL_SECS: u64 = 3_600;
/// Wait after a failed detailed read before the next one for the same count.
pub(super) const DETAIL_RETRY_SECS: u64 = 900;
/// A poll this close to a deadline counts as reaching it.
pub(super) const POLL_SLACK_SECS: u64 = 60;
/// Bound on bindings and homes the cadence remembers.
const TRACKED_ENTRIES_MAX: usize = 64;
/// JSON-RPC id of a detailed read sent after a routine one in the same session.
pub(super) const DETAIL_READ_ID: &str = "ottto_rate_limits_details";
/// A pool window whose reset sits this close to `read + duration` is idle: its
/// boundary slides forward with every read.
const IDLE_SLIDE_TOLERANCE_SECS: u64 = 120;
/// Most pool ids one diagnostic lists by name.
const POOL_IDS_LISTED_MAX: usize = 8;

/// Which `account/rateLimits/read` request a poll sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CodexRateLimitsRead {
    /// No params: usage plus the reset-credit list.
    Detailed,
    /// `excludeResetCreditDetails: true`: usage and the count only.
    Routine,
}

impl CodexRateLimitsRead {
    pub(super) fn request(self, id: &str) -> Value {
        match self {
            Self::Detailed => serde_json::json!({
                "method": "account/rateLimits/read",
                "id": id
            }),
            Self::Routine => serde_json::json!({
                "method": "account/rateLimits/read",
                "id": id,
                "params": {"excludeResetCreditDetails": true}
            }),
        }
    }
}

/// Detail-read bookkeeping of one binding. Every decision is a pure function
/// of this state and the caller's clock (unix seconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DetailCadence {
    last_detail_ok_at: Option<u64>,
    /// When the last detailed read failed, and the count it reported.
    last_detail_failed: Option<(u64, Option<u64>)>,
}

/// `since` is at least `secs` ago, within the poll slack. A clock that moved
/// backwards counts as elapsed so a wrong clock cannot stall detail reads.
fn elapsed_at_least(since: u64, now: u64, secs: u64) -> bool {
    now < since || (now - since).saturating_add(POLL_SLACK_SECS) >= secs
}

impl DetailCadence {
    /// The hourly detailed read is due.
    pub(super) fn detail_due(&self, now: u64) -> bool {
        let stale = self
            .last_detail_ok_at
            .map_or(true, |at| elapsed_at_least(at, now, DETAIL_INTERVAL_SECS));
        let retry_allowed = self
            .last_detail_failed
            .map_or(true, |(at, _)| elapsed_at_least(at, now, DETAIL_RETRY_SECS));
        stale && retry_allowed
    }

    /// After a routine read: send the detailed read now? `count` is the
    /// routine `availableCount`; `cached_list_for_count` says whether the
    /// cache holds a list read against exactly that count.
    pub(super) fn routine_needs_details(
        &self,
        count: Option<u64>,
        cached_list_for_count: bool,
        now: u64,
    ) -> bool {
        if self.detail_due(now) {
            return true;
        }
        let Some(count) = count else {
            return false;
        };
        if cached_list_for_count {
            return false;
        }
        // The same count already failed to detail recently: wait for the retry.
        !matches!(
            self.last_detail_failed,
            Some((at, Some(failed))) if failed == count
                && !elapsed_at_least(at, now, DETAIL_RETRY_SECS)
        )
    }

    fn record_detail(&mut self, ok: bool, count: Option<u64>, now: u64) {
        if ok {
            self.last_detail_ok_at = Some(now);
            self.last_detail_failed = None;
        } else {
            self.last_detail_failed = Some((now, count));
        }
    }
}

/// What one app-server reading needs from the cadence and cache.
#[derive(Debug, Clone, Copy)]
pub(super) struct CodexCreditRead<'a> {
    /// [`binding_key`] of the validated credential identity; `None` when the
    /// reading is not bound (its meters are dropped downstream).
    pub(super) binding: Option<&'a str>,
    pub(super) home: Option<&'a Path>,
    /// A detailed read was sent in this session (planned or escalated).
    pub(super) details_requested: bool,
    /// Completion clock of the provider read.
    pub(super) observed_at: Option<&'a str>,
    pub(super) now: u64,
}

/// Cadence state and the grant-list cache for every Codex binding.
#[derive(Debug, Default)]
pub(super) struct CodexCreditTracker {
    sections: SectionCache,
    cadence: BTreeMap<String, DetailCadence>,
    /// The binding each Codex home was last read as; plans the next request
    /// before the reading reveals its identity.
    home_binding: BTreeMap<PathBuf, String>,
}

impl CodexCreditTracker {
    /// The request to send for `home`. An unknown home reads details.
    pub(super) fn plan_read(&self, home: &Path, now: u64) -> CodexRateLimitsRead {
        let due = self
            .home_binding
            .get(home)
            .and_then(|binding| self.cadence.get(binding))
            .map_or(true, |cadence| cadence.detail_due(now));
        if due {
            CodexRateLimitsRead::Detailed
        } else {
            CodexRateLimitsRead::Routine
        }
    }

    /// After a routine reading, whether to send the detailed read at once.
    pub(super) fn routine_needs_details(
        &self,
        binding: Option<&str>,
        rate_limits: &Value,
        now: u64,
    ) -> bool {
        let Some(binding) = binding else {
            return false;
        };
        let count = available_count(rate_limits);
        let cached = count.is_some_and(|count| {
            self.sections
                .grant_list_for_count(binding, RESET_BANK_GRANTS_SECTION, count)
                .is_some()
        });
        self.cadence
            .get(binding)
            .copied()
            .unwrap_or_default()
            .routine_needs_details(count, cached, now)
    }

    /// Give the `reset_bank` balance in `balances` its grant section and
    /// record the reading for cadence. Returns the model's diagnostics.
    pub(super) fn attach_reset_bank_grants(
        &mut self,
        balances: &mut [AgentCreditBalance],
        rate_limits: &Value,
        read: CodexCreditRead<'_>,
    ) -> Vec<CreditModelDiagnostic> {
        let count = available_count(rate_limits);
        let rows = reset_credit_rows(rate_limits);
        if let Some(binding) = read.binding {
            if read.details_requested {
                // No reset section at all is a complete answer, not a failure.
                let ok = rows.is_some() || count.is_none();
                bounded_entry(&mut self.cadence, binding.to_string())
                    .record_detail(ok, count, read.now);
            }
            if let Some(home) = read.home {
                *bounded_entry(&mut self.home_binding, home.to_path_buf()) = binding.to_string();
            }
        }
        let Some(balance) = balances
            .iter_mut()
            .find(|balance| balance.name == RESET_BANK)
        else {
            return Vec::new();
        };
        let provider_count = balance.remaining;
        if let (Some(rows), Some(observed_at)) = (rows, read.observed_at) {
            let diagnostics = build_grants(ListObservation::Read {
                provider: Provider::OpenAi,
                provider_count,
                records: rows.iter().map(grant_input).collect(),
                observed_at: observed_at.to_string(),
            })
            .apply_to(balance);
            if let (Some(binding), Some(count)) = (read.binding, provider_count) {
                self.sections.observe_grant_list(
                    binding,
                    RESET_BANK_GRANTS_SECTION,
                    count,
                    balance,
                );
            }
            return diagnostics;
        }
        let cached = read
            .binding
            .zip(provider_count)
            .and_then(|(binding, count)| {
                self.sections
                    .grant_list_for_count(binding, RESET_BANK_GRANTS_SECTION, count)
            });
        match cached {
            Some(list) => {
                list.apply_to(balance);
                Vec::new()
            }
            None => build_grants(ListObservation::Unavailable { provider_count }).apply_to(balance),
        }
    }
}

/// Insert-or-get with a size bound; the evicted entry is simply re-learned.
fn bounded_entry<K: Ord + Clone, V: Default>(map: &mut BTreeMap<K, V>, key: K) -> &mut V {
    if !map.contains_key(&key) && map.len() >= TRACKED_ENTRIES_MAX {
        if let Some(evict) = map.keys().next().cloned() {
            map.remove(&evict);
        }
    }
    map.entry(key).or_default()
}

fn tracker() -> MutexGuard<'static, CodexCreditTracker> {
    static TRACKER: OnceLock<Mutex<CodexCreditTracker>> = OnceLock::new();
    TRACKER
        .get_or_init(|| Mutex::new(CodexCreditTracker::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Process-wide [`CodexCreditTracker::plan_read`].
pub(super) fn plan_rate_limits_read(home: &Path, now: u64) -> CodexRateLimitsRead {
    tracker().plan_read(home, now)
}

/// Process-wide [`CodexCreditTracker::routine_needs_details`].
pub(super) fn routine_read_needs_details(
    binding: Option<&str>,
    rate_limits: &Value,
    now: u64,
) -> bool {
    tracker().routine_needs_details(binding, rate_limits, now)
}

/// Process-wide [`CodexCreditTracker::attach_reset_bank_grants`].
pub(super) fn attach_reset_bank_grants(
    balances: &mut [AgentCreditBalance],
    rate_limits: &Value,
    read: CodexCreditRead<'_>,
) -> Vec<CreditModelDiagnostic> {
    tracker().attach_reset_bank_grants(balances, rate_limits, read)
}

/// Cache key of one Codex credential identity.
pub(super) fn binding_key(
    account_identifier_hash: &str,
    workspace_identifier_hash: &str,
) -> String {
    format!("{account_identifier_hash}:{workspace_identifier_hash}")
}

fn reset_credits(rate_limits: &Value) -> Option<&Value> {
    rate_limits
        .get("rateLimitResetCredits")
        .filter(|value| value.is_object())
}

/// `availableCount`, parsed exactly as the `reset_bank` balance parses it.
fn available_count(rate_limits: &Value) -> Option<u64> {
    json_u64(
        reset_credits(rate_limits)?,
        &["availableCount", "available_count"],
    )
}

/// The detail list; `None` when Codex returned the count only.
fn reset_credit_rows(rate_limits: &Value) -> Option<&Vec<Value>> {
    reset_credits(rate_limits)?
        .get("credits")
        .and_then(Value::as_array)
}

/// First present key: JSON null is absent, a string is a value, anything else
/// is invalid.
fn string_field(row: &Value, keys: &[&str]) -> Field<String> {
    match keys.iter().find_map(|key| row.get(*key)) {
        None | Some(Value::Null) => Field::Absent,
        Some(Value::String(text)) => Field::Value(text.clone()),
        Some(_) => Field::Invalid,
    }
}

/// Codex sends unix seconds; RFC 3339 text is accepted as well.
fn time_field(row: &Value, keys: &[&str]) -> TimeInput {
    match keys.iter().find_map(|key| row.get(*key)) {
        None | Some(Value::Null) => TimeInput::Absent,
        Some(Value::String(text)) => TimeInput::Rfc3339(text.clone()),
        Some(value) => value
            .as_i64()
            .map_or(TimeInput::Invalid, TimeInput::UnixSeconds),
    }
}

/// One `RateLimitResetCredit` row. `description` is never read.
fn grant_input(row: &Value) -> GrantInput {
    GrantInput {
        id: string_field(row, &["id"]),
        reset_type: string_field(row, &["resetType", "reset_type"]),
        status: GrantStatusInput::Reported(string_field(row, &["status"])),
        granted_at: time_field(row, &["grantedAt", "granted_at"]),
        expires_at: time_field(row, &["expiresAt", "expires_at"]),
        title: string_field(row, &["title"]),
        ..GrantInput::default()
    }
}

/// The Codex provider → `kind` table (contract v2.2 §11.1, names pinned by
/// §11.7 C4). A pool other than `codex` prefixes its id to the base name.
pub(super) fn codex_balance_kind(balance: &AgentCreditBalance) -> CreditBalanceKind {
    let base = balance
        .limit_id
        .as_deref()
        .filter(|limit_id| *limit_id != "codex")
        .and_then(|limit_id| balance.name.strip_prefix(limit_id)?.strip_prefix('_'))
        .unwrap_or(&balance.name);
    match base {
        "credits" => CreditBalanceKind::PlanCredits,
        RESET_BANK => CreditBalanceKind::SavedResets,
        "workspace_monthly_credits" => CreditBalanceKind::WorkspaceAllowance,
        _ => CreditBalanceKind::Unknown,
    }
}

/// Every Codex balance carries a `kind`.
pub(super) fn stamp_codex_balance_kinds(balances: &mut [AgentCreditBalance]) {
    for balance in balances {
        balance.kind = Some(codex_balance_kind(balance));
    }
}

/// The reset-credit counts diagnostic for a routine read, which asked for no
/// list (the detailed-read wording stays with the caller).
pub(super) fn routine_reset_credit_summary(rate_limits: &Value) -> Option<String> {
    reset_credits(rate_limits)?;
    let count = available_count(rate_limits)
        .filter(|count| *count <= 10_000)
        .map_or_else(|| "unreported".to_string(), |count| count.to_string());
    Some(format!(
        "Codex reset details: count {count}; list not requested on this routine read."
    ))
}

/// Field paths only, never values.
pub(super) fn model_diagnostics_suffix(diagnostics: &[CreditModelDiagnostic]) -> String {
    if diagnostics.is_empty() {
        return String::new();
    }
    let mut counts = BTreeMap::<(&str, &str), usize>::new();
    for diagnostic in diagnostics {
        *counts
            .entry((diagnostic.code, diagnostic.field))
            .or_default() += 1;
    }
    let parts = counts
        .iter()
        .map(|((code, field), count)| format!("{code} {field} {count}"))
        .collect::<Vec<_>>();
    format!(" Credit model: {}.", parts.join(", "))
}

/// Design C2a: a counts-only view of `rateLimitsByLimitId` and two top-level
/// fields, so the next decision on emitting pools rests on evidence. Pool ids
/// are provider codenames; ids outside `^[a-z0-9_.-]{1,64}$` are only counted.
pub(super) fn rate_limit_pools_summary(rate_limits: &Value, read_at: u64) -> String {
    let presence = |key: &str| match rate_limits.get(key) {
        None => "absent",
        Some(Value::Null) => "null",
        Some(_) => "present",
    };
    let tail = format!(
        "ordinaryUsageAllowed {}; accountId {}.",
        presence("ordinaryUsageAllowed"),
        presence("accountId")
    );
    let Some(pools) = rate_limits
        .get("rateLimitsByLimitId")
        .and_then(Value::as_object)
    else {
        return format!("Codex rate-limit pools: map unobserved; {tail}");
    };
    let mut listed = Vec::new();
    let mut unlisted = 0usize;
    let mut idle = 0usize;
    // zero, under half, half or more, full, no windows
    let mut buckets = [0usize; 5];
    let mut others = pools
        .iter()
        .filter(|(limit_id, _)| limit_id.as_str() != "codex")
        .collect::<Vec<_>>();
    others.sort_by(|left, right| left.0.cmp(right.0));
    for (limit_id, pool) in &others {
        if ottto_protocol::is_credit_reason_code(limit_id) && listed.len() < POOL_IDS_LISTED_MAX {
            listed.push(limit_id.as_str());
        } else {
            unlisted += 1;
        }
        let windows = ["primary", "secondary"]
            .iter()
            .filter_map(|field| pool.get(*field).filter(|window| window.is_object()))
            .collect::<Vec<_>>();
        if windows
            .iter()
            .any(|window| window_slides_with_read(window, read_at))
        {
            idle += 1;
        }
        let used = windows
            .iter()
            .filter_map(|window| json_u64(window, &["usedPercent", "used_percent"]))
            .max();
        let bucket = match used {
            Some(0) => 0,
            Some(1..=49) => 1,
            Some(50..=99) => 2,
            Some(_) => 3,
            None => 4,
        };
        buckets[bucket] += 1;
    }
    let ids = if unlisted > 0 {
        format!("{} +{unlisted} unlisted", listed.join(", "))
    } else {
        listed.join(", ")
    };
    format!(
        "Codex rate-limit pools: other pools {} [{ids}]; idle sliding {idle}; used zero {}, under half {}, half or more {}, full {}, no windows {}; {tail}",
        others.len(),
        buckets[0],
        buckets[1],
        buckets[2],
        buckets[3],
        buckets[4],
    )
}

/// `resetsAt` equals the read time plus the window length: nothing has been
/// used, so the provider restarts the window on every read.
fn window_slides_with_read(window: &Value, read_at: u64) -> bool {
    let Some(resets_at) = json_u64(window, &["resetsAt", "resets_at"]) else {
        return false;
    };
    let Some(minutes) = json_u64(window, &["windowDurationMins", "window_duration_mins"]) else {
        return false;
    };
    let window_start = resets_at.saturating_sub(minutes.saturating_mul(60));
    window_start.abs_diff(read_at) <= IDLE_SLIDE_TOLERANCE_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota_credit_model::credit_grant_key;
    use ottto_protocol::{
        AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentQuotaWindowFreshness,
        CreditGrantsState,
    };
    use serde_json::json;

    const READ_AT: &str = "2026-10-09T14:44:45Z";
    // 2026-10-09T14:44:45Z
    const T0: u64 = 1_791_557_085;
    const BINDING_A: &str = "account-a:workspace-a";
    const BINDING_B: &str = "account-b:workspace-b";

    fn reset_bank(count: u64) -> AgentCreditBalance {
        AgentCreditBalance {
            name: RESET_BANK.to_string(),
            status: if count == 0 {
                AgentCreditBalanceStatus::Exhausted
            } else {
                AgentCreditBalanceStatus::Ok
            },
            freshness: AgentQuotaWindowFreshness::Fresh,
            unit: AgentCreditBalanceUnit::Resets,
            remaining: Some(count),
            unlimited: Some(false),
            kind: Some(CreditBalanceKind::SavedResets),
            ..Default::default()
        }
    }

    /// A synthetic Codex grant row (shape of the app-server
    /// `RateLimitResetCredit`, ids made up).
    fn row(id: &str, granted_at: i64, expires_at: Option<i64>) -> Value {
        json!({
            "id": id,
            "resetType": "codexRateLimits",
            "status": "available",
            "grantedAt": granted_at,
            "expiresAt": expires_at,
            "title": "Full reset",
            "description": "Thanks for using Codex! You've been granted one free rate limit reset."
        })
    }

    fn detailed(count: u64, rows: Vec<Value>) -> Value {
        json!({"rateLimitResetCredits": {"availableCount": count, "credits": rows}})
    }

    fn count_only(count: u64) -> Value {
        json!({"rateLimitResetCredits": {"availableCount": count, "credits": null}})
    }

    fn read<'a>(
        binding: Option<&'a str>,
        details_requested: bool,
        now: u64,
    ) -> CodexCreditRead<'a> {
        CodexCreditRead {
            binding,
            home: None,
            details_requested,
            observed_at: Some(READ_AT),
            now,
        }
    }

    fn attach(
        tracker: &mut CodexCreditTracker,
        rate_limits: &Value,
        read: CodexCreditRead<'_>,
    ) -> (AgentCreditBalance, Vec<CreditModelDiagnostic>) {
        let count = available_count(rate_limits).expect("fixture count");
        let mut balances = vec![reset_bank(count)];
        let diagnostics = tracker.attach_reset_bank_grants(&mut balances, rate_limits, read);
        (balances.remove(0), diagnostics)
    }

    fn wire(balance: &AgentCreditBalance) -> Value {
        serde_json::to_value(balance).expect("balance serializes")
    }

    // 2026-09-29T19:14:56Z / 2026-10-29T19:14:56Z
    const GRANTED_1: i64 = 1_790_709_296;
    const EXPIRES_1: i64 = 1_793_301_296;
    // 2026-10-07T23:42:35Z / 2026-11-06T23:42:35Z
    const GRANTED_2: i64 = 1_791_416_555;
    const EXPIRES_2: i64 = 1_794_008_555;
    // 2026-10-08T08:00:00Z / 2026-11-07T08:00:00Z
    const GRANTED_3: i64 = 1_791_446_400;
    const EXPIRES_3: i64 = 1_794_038_400;

    #[test]
    fn complete_two_grant_list_maps_to_expected_wire() {
        let mut tracker = CodexCreditTracker::default();
        let provider = detailed(
            2,
            vec![
                // Out of expiry order on purpose: the model sorts.
                row("grant-two", GRANTED_2, Some(EXPIRES_2)),
                row("grant-one", GRANTED_1, Some(EXPIRES_1)),
            ],
        );
        let (balance, diagnostics) =
            attach(&mut tracker, &provider, read(Some(BINDING_A), true, T0));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let expected = json!({
            "name": "reset_bank",
            "status": "ok",
            "freshness": "fresh",
            "unit": "resets",
            "remaining": 2,
            "unlimited": false,
            "kind": "saved_resets",
            "grant_count": 2,
            "grants_state": "complete",
            "grants_observed_at": READ_AT,
            "next_expires_at": "2026-10-29T19:14:56Z",
            "latest_granted_at": "2026-10-07T23:42:35Z",
            "grants": [
                {
                    "grant_key": credit_grant_key(Provider::OpenAi, "grant-one"),
                    "grant_type": "rate_limit_reset",
                    "status": "available",
                    "granted_at": "2026-09-29T19:14:56Z",
                    "expires_at": "2026-10-29T19:14:56Z",
                    "title": "Full reset"
                },
                {
                    "grant_key": credit_grant_key(Provider::OpenAi, "grant-two"),
                    "grant_type": "rate_limit_reset",
                    "status": "available",
                    "granted_at": "2026-10-07T23:42:35Z",
                    "expires_at": "2026-11-06T23:42:35Z",
                    "title": "Full reset"
                }
            ]
        });
        assert_eq!(wire(&balance), expected);
        assert!(
            !wire(&balance)
                .to_string()
                .contains("Thanks for using Codex"),
            "description is never carried"
        );
    }

    #[test]
    fn complete_three_grant_list_keeps_count_and_orders_by_expiry() {
        let mut tracker = CodexCreditTracker::default();
        let provider = detailed(
            3,
            vec![
                row("grant-three", GRANTED_3, Some(EXPIRES_3)),
                row("grant-one", GRANTED_1, Some(EXPIRES_1)),
                row("grant-two", GRANTED_2, Some(EXPIRES_2)),
            ],
        );
        let (balance, diagnostics) =
            attach(&mut tracker, &provider, read(Some(BINDING_A), true, T0));
        assert!(diagnostics.is_empty());
        assert_eq!(balance.remaining, Some(3), "remaining stays availableCount");
        assert_eq!(balance.grant_count, Some(3));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        let keys = balance
            .grants
            .as_ref()
            .expect("grants")
            .iter()
            .map(|grant| grant.grant_key.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            ["grant-one", "grant-two", "grant-three"]
                .map(|id| credit_grant_key(Provider::OpenAi, id))
        );
        assert_eq!(
            balance.next_expires_at.as_deref(),
            Some("2026-10-29T19:14:56Z")
        );
        assert_eq!(
            balance.latest_granted_at.as_deref(),
            Some("2026-10-08T08:00:00Z")
        );
    }

    #[test]
    fn count_only_and_null_lists_are_unavailable_never_empty() {
        for provider in [
            count_only(2),
            json!({"rateLimitResetCredits": {"availableCount": 2}}),
        ] {
            let mut tracker = CodexCreditTracker::default();
            let (balance, _) = attach(&mut tracker, &provider, read(Some(BINDING_A), true, T0));
            assert_eq!(
                wire(&balance),
                json!({
                    "name": "reset_bank",
                    "status": "ok",
                    "freshness": "fresh",
                    "unit": "resets",
                    "remaining": 2,
                    "unlimited": false,
                    "kind": "saved_resets",
                    "grant_count": 2,
                    "grants_state": "unavailable"
                })
            );
        }
    }

    #[test]
    fn empty_list_with_zero_count_is_complete_and_empty() {
        let mut tracker = CodexCreditTracker::default();
        let (balance, _) = attach(
            &mut tracker,
            &detailed(0, vec![]),
            read(Some(BINDING_A), true, T0),
        );
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        assert_eq!(balance.grants.as_deref(), Some(&[][..]));
        assert_eq!(balance.remaining, Some(0));
        assert_eq!(balance.status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(balance.next_expires_at, None);
    }

    #[test]
    fn provider_capped_list_is_capped_without_summaries() {
        let mut tracker = CodexCreditTracker::default();
        let provider = detailed(
            3,
            vec![
                row("grant-one", GRANTED_1, Some(EXPIRES_1)),
                row("grant-two", GRANTED_2, Some(EXPIRES_2)),
            ],
        );
        let (balance, _) = attach(&mut tracker, &provider, read(Some(BINDING_A), true, T0));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Capped));
        assert_eq!(balance.grant_count, Some(3));
        assert_eq!(balance.grants.as_ref().map(Vec::len), Some(2));
        assert_eq!(balance.remaining, Some(3));
        // Codex capped, not the sender: no expiry or added-time claims.
        assert_eq!(balance.next_expires_at, None);
        assert_eq!(balance.latest_granted_at, None);
    }

    #[test]
    fn invalid_rows_make_the_list_partial_with_field_diagnostics() {
        let mut tracker = CodexCreditTracker::default();
        let provider = detailed(
            4,
            vec![
                row("grant-one", GRANTED_1, Some(EXPIRES_1)),
                // No id: dropped.
                json!({"resetType": "codexRateLimits", "status": "available", "grantedAt": GRANTED_2}),
                // Bad status and a non-integer expiry: refused fields.
                json!({"id": "grant-bad", "resetType": "codexRateLimits", "status": "lost", "grantedAt": GRANTED_3, "expiresAt": 1.5}),
                // Unknown reset type: kept as unknown type.
                json!({"id": "grant-new-type", "resetType": "somethingNew", "status": "available", "grantedAt": GRANTED_3, "expiresAt": null}),
            ],
        );
        let (balance, diagnostics) =
            attach(&mut tracker, &provider, read(Some(BINDING_A), true, T0));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Partial));
        assert_eq!(balance.grants.as_ref().map(Vec::len), Some(3));
        assert_eq!(
            balance.next_expires_at, None,
            "partial lists have no summaries"
        );
        let fields = diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.field))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("grant_dropped", "grants[].id")));
        assert!(fields.contains(&("field_refused", "grants[].status")));
        assert!(fields.contains(&("field_refused", "grants[].expires_at")));
        assert!(fields.contains(&("field_refused", "grants[].grant_type")));
        let suffix = model_diagnostics_suffix(&diagnostics);
        assert!(suffix.contains("grant_dropped grants[].id 1"), "{suffix}");
        assert!(
            !suffix.contains("grant-bad"),
            "values never reach diagnostics"
        );
    }

    #[test]
    fn non_object_reset_credits_and_missing_balance_attach_nothing() {
        let mut tracker = CodexCreditTracker::default();
        let mut balances = vec![];
        assert!(tracker
            .attach_reset_bank_grants(
                &mut balances,
                &detailed(1, vec![]),
                read(Some(BINDING_A), true, T0)
            )
            .is_empty());
        assert_eq!(
            available_count(&json!({"rateLimitResetCredits": null})),
            None
        );
    }

    #[test]
    fn kinds_cover_every_codex_balance_name() {
        let balance = |name: &str, limit_id: Option<&str>| AgentCreditBalance {
            name: name.to_string(),
            limit_id: limit_id.map(str::to_string),
            ..Default::default()
        };
        let cases = [
            (
                balance("credits", Some("codex")),
                CreditBalanceKind::PlanCredits,
            ),
            (balance("credits", None), CreditBalanceKind::PlanCredits),
            (
                balance("premium_credits", Some("premium")),
                CreditBalanceKind::PlanCredits,
            ),
            (balance("reset_bank", None), CreditBalanceKind::SavedResets),
            (
                balance("workspace_monthly_credits", Some("codex")),
                CreditBalanceKind::WorkspaceAllowance,
            ),
            (
                balance("premium_workspace_monthly_credits", Some("premium")),
                CreditBalanceKind::WorkspaceAllowance,
            ),
            // A pool id that ends like a base name still resolves by its id.
            (
                balance("x_workspace_monthly_credits", Some("x_workspace_monthly")),
                CreditBalanceKind::PlanCredits,
            ),
            (balance("something_else", None), CreditBalanceKind::Unknown),
        ];
        for (balance, kind) in cases {
            assert_eq!(codex_balance_kind(&balance), kind, "{}", balance.name);
        }
        let mut balances = vec![balance("credits", Some("codex")), balance("other", None)];
        stamp_codex_balance_kinds(&mut balances);
        assert_eq!(balances[0].kind, Some(CreditBalanceKind::PlanCredits));
        assert_eq!(balances[1].kind, Some(CreditBalanceKind::Unknown));
    }

    #[test]
    fn requests_carry_the_exclude_param_only_on_routine_reads() {
        assert_eq!(
            CodexRateLimitsRead::Detailed.request("ottto_rate_limits"),
            json!({"method": "account/rateLimits/read", "id": "ottto_rate_limits"})
        );
        assert_eq!(
            CodexRateLimitsRead::Routine.request("ottto_rate_limits"),
            json!({
                "method": "account/rateLimits/read",
                "id": "ottto_rate_limits",
                "params": {"excludeResetCreditDetails": true}
            })
        );
    }

    /// One simulated poll through the tracker, returning the request kinds the
    /// session sent and the emitted balance. `provider` answers a request:
    /// routine reads get the count only.
    fn poll(
        tracker: &mut CodexCreditTracker,
        home: &Path,
        binding: &str,
        now: u64,
        count: u64,
        list: &[Value],
    ) -> (Vec<CodexRateLimitsRead>, AgentCreditBalance) {
        let answer = |kind| match kind {
            CodexRateLimitsRead::Detailed => detailed(count, list.to_vec()),
            CodexRateLimitsRead::Routine => count_only(count),
        };
        let planned = tracker.plan_read(home, now);
        let mut sent = vec![planned];
        let mut rate_limits = answer(planned);
        if planned == CodexRateLimitsRead::Routine
            && tracker.routine_needs_details(Some(binding), &rate_limits, now)
        {
            sent.push(CodexRateLimitsRead::Detailed);
            rate_limits = answer(CodexRateLimitsRead::Detailed);
        }
        let read = CodexCreditRead {
            binding: Some(binding),
            home: Some(home),
            details_requested: sent.contains(&CodexRateLimitsRead::Detailed),
            observed_at: Some(READ_AT),
            now,
        };
        let (balance, _) = attach(tracker, &rate_limits, read);
        (sent, balance)
    }

    fn rows(count: usize) -> Vec<Value> {
        [
            row("grant-one", GRANTED_1, Some(EXPIRES_1)),
            row("grant-two", GRANTED_2, Some(EXPIRES_2)),
            row("grant-three", GRANTED_3, Some(EXPIRES_3)),
        ][..count]
            .to_vec()
    }

    #[test]
    fn simulated_hour_is_one_detailed_read_plus_one_per_count_change() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        let mut detailed_reads = 0;
        let mut routine_reads = 0;
        // Twelve 5-minute polls; the count goes 2 → 3 at minute 20 and
        // 3 → 2 at minute 40.
        for poll_index in 0..12u64 {
            let minute = poll_index * 5;
            let count = match minute {
                0..=19 => 2,
                20..=39 => 3,
                _ => 2,
            };
            let (sent, balance) = poll(
                &mut tracker,
                home,
                BINDING_A,
                T0 + minute * 60,
                count,
                &rows(count as usize),
            );
            detailed_reads += sent
                .iter()
                .filter(|kind| **kind == CodexRateLimitsRead::Detailed)
                .count();
            routine_reads += sent
                .iter()
                .filter(|kind| **kind == CodexRateLimitsRead::Routine)
                .count();
            assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
            assert_eq!(balance.grants.as_ref().map(Vec::len), Some(count as usize));
        }
        assert_eq!(detailed_reads, 1 + 2, "one hourly + one per count change");
        assert_eq!(routine_reads, 11, "every other poll is routine");
        // Any successful detailed read restarts the hour: the last one ran at
        // minute 40, so minute 95 is routine and minute 100 is detailed.
        let last_detail = T0 + 40 * 60;
        let (sent, _) = poll(
            &mut tracker,
            home,
            BINDING_A,
            last_detail + 55 * 60,
            2,
            &rows(2),
        );
        assert_eq!(sent, vec![CodexRateLimitsRead::Routine]);
        let (sent, _) = poll(
            &mut tracker,
            home,
            BINDING_A,
            last_detail + 60 * 60,
            2,
            &rows(2),
        );
        assert_eq!(sent, vec![CodexRateLimitsRead::Detailed]);
    }

    #[test]
    fn grants_stay_continuous_across_routine_polls_with_original_read_time() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        let (sent, first) = poll(&mut tracker, home, BINDING_A, T0, 2, &rows(2));
        assert_eq!(sent, vec![CodexRateLimitsRead::Detailed]);
        for step in 1..=4u64 {
            let mut balances = vec![reset_bank(2)];
            let now = T0 + step * 300;
            assert_eq!(tracker.plan_read(home, now), CodexRateLimitsRead::Routine);
            assert!(!tracker.routine_needs_details(Some(BINDING_A), &count_only(2), now));
            tracker.attach_reset_bank_grants(
                &mut balances,
                &count_only(2),
                CodexCreditRead {
                    binding: Some(BINDING_A),
                    home: Some(home),
                    details_requested: false,
                    // A later read clock: the list keeps its own.
                    observed_at: Some("2026-10-09T15:05:00Z"),
                    now,
                },
            );
            assert_eq!(wire(&balances[0]), wire(&first), "routine poll {step}");
            assert_eq!(balances[0].grants_observed_at.as_deref(), Some(READ_AT));
        }
    }

    #[test]
    fn cold_cache_reads_details_first_and_never_sends_unknown() {
        // A restart: a fresh tracker for a binding that had a list before.
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        assert_eq!(tracker.plan_read(home, T0), CodexRateLimitsRead::Detailed);
        // Even if a routine reading arrives first (e.g. the planned home
        // changed hands), a missing list escalates instead of guessing.
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(2), T0));
        let (sent, balance) = poll(&mut tracker, home, BINDING_A, T0, 2, &rows(2));
        assert_eq!(sent, vec![CodexRateLimitsRead::Detailed]);
        assert_eq!(balance.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    }

    #[test]
    fn account_switch_a_b_a_keeps_a_list() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        let (_, a_first) = poll(&mut tracker, home, BINDING_A, T0, 2, &rows(2));
        // B signs in at the same home: its first routine reading has no list
        // for B, so details are read at once.
        let (sent, b) = poll(&mut tracker, home, BINDING_B, T0 + 300, 3, &rows(3));
        assert!(sent.contains(&CodexRateLimitsRead::Detailed));
        assert_eq!(b.grants.as_ref().map(Vec::len), Some(3));
        // Back to A within the hour: A's list is re-sent unchanged.
        let (sent, a_again) = poll(&mut tracker, home, BINDING_A, T0 + 600, 2, &rows(2));
        assert_eq!(sent, vec![CodexRateLimitsRead::Routine]);
        assert_eq!(wire(&a_again), wire(&a_first));
    }

    #[test]
    fn failed_detail_read_resends_matching_list_and_retries_later() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        let (_, first) = poll(&mut tracker, home, BINDING_A, T0, 2, &rows(2));
        // The hourly detailed read fails (Codex falls back to the count).
        let hour = T0 + 3_600;
        assert_eq!(tracker.plan_read(home, hour), CodexRateLimitsRead::Detailed);
        let mut balances = vec![reset_bank(2)];
        tracker.attach_reset_bank_grants(
            &mut balances,
            &count_only(2),
            read(Some(BINDING_A), true, hour),
        );
        assert_eq!(
            wire(&balances[0]),
            wire(&first),
            "same count: last list re-sent"
        );
        // Not retried on every poll ...
        assert_eq!(
            tracker.plan_read(home, hour + 300),
            CodexRateLimitsRead::Routine
        );
        // ... but after the retry wait.
        assert_eq!(
            tracker.plan_read(home, hour + DETAIL_RETRY_SECS),
            CodexRateLimitsRead::Detailed
        );
    }

    #[test]
    fn count_change_with_failed_details_is_unavailable_then_retried() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        poll(&mut tracker, home, BINDING_A, T0, 2, &rows(2));
        let now = T0 + 300;
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(3), now));
        // The escalated detailed read fails: the old list is not re-sent
        // against a new count.
        let mut balances = vec![reset_bank(3)];
        tracker.attach_reset_bank_grants(
            &mut balances,
            &count_only(3),
            read(Some(BINDING_A), true, now),
        );
        assert_eq!(
            balances[0].grants_state,
            Some(CreditGrantsState::Unavailable)
        );
        assert_eq!(balances[0].grants, None);
        assert_eq!(balances[0].grant_count, Some(3));
        // The same count does not re-escalate on the next poll ...
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &count_only(3), now + 300));
        // ... a different count does, and so does the retry wait.
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(4), now + 300));
        assert!(tracker.routine_needs_details(
            Some(BINDING_A),
            &count_only(3),
            now + DETAIL_RETRY_SECS
        ));
    }

    #[test]
    fn unbound_readings_neither_escalate_nor_touch_the_cache() {
        let mut tracker = CodexCreditTracker::default();
        assert!(!tracker.routine_needs_details(None, &count_only(2), T0));
        let (balance, _) = attach(&mut tracker, &detailed(2, rows(2)), read(None, true, T0));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        assert!(tracker.cadence.is_empty());
        assert!(tracker
            .sections
            .grant_list_for_count(BINDING_A, RESET_BANK_GRANTS_SECTION, 2)
            .is_none());
    }

    #[test]
    fn accounts_without_saved_resets_are_detailed_hourly_not_every_poll() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new("/synthetic/codex-home");
        let no_resets = json!({"rateLimits": {}});
        assert_eq!(tracker.plan_read(home, T0), CodexRateLimitsRead::Detailed);
        tracker.attach_reset_bank_grants(
            &mut [],
            &no_resets,
            CodexCreditRead {
                home: Some(home),
                ..read(Some(BINDING_A), true, T0)
            },
        );
        assert_eq!(
            tracker.plan_read(home, T0 + 300),
            CodexRateLimitsRead::Routine
        );
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0 + 300));
    }

    #[test]
    fn cadence_clock_rules() {
        let cadence = DetailCadence::default();
        assert!(cadence.detail_due(T0));
        let mut cadence = DetailCadence::default();
        cadence.record_detail(true, Some(2), T0);
        assert!(!cadence.detail_due(T0 + 3_000));
        assert!(cadence.detail_due(T0 + DETAIL_INTERVAL_SECS - POLL_SLACK_SECS));
        assert!(cadence.detail_due(T0 + 3 * 3_600), "after a 3 h sleep");
        assert!(cadence.detail_due(T0 - 1), "a clock that went back");
    }

    #[test]
    fn pools_diagnostic_counts_without_values() {
        let rate_limits = json!({
            "rateLimits": {"limitId": "codex"},
            "rateLimitsByLimitId": {
                "codex": {"primary": {"usedPercent": 40, "windowDurationMins": 300, "resetsAt": T0 + 600}},
                "codex_bengalfox": {
                    "limitName": "Synthetic Spark",
                    "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": T0 + 300 * 60},
                    "secondary": {"usedPercent": 0, "windowDurationMins": 10080, "resetsAt": T0 + 10080 * 60 + 5}
                },
                "premium": {"credits": {"hasCredits": true}},
                "Weird Id": {"primary": {"usedPercent": 100, "windowDurationMins": 300, "resetsAt": T0 + 60}}
            },
            "ordinaryUsageAllowed": true,
            "accountId": "acct-synthetic"
        });
        let summary = rate_limit_pools_summary(&rate_limits, T0);
        assert_eq!(
            summary,
            "Codex rate-limit pools: other pools 3 [codex_bengalfox, premium +1 unlisted]; idle sliding 1; used zero 1, under half 0, half or more 0, full 1, no windows 1; ordinaryUsageAllowed present; accountId present."
        );
        assert!(!summary.contains("acct-synthetic"));
        assert!(!summary.contains("Spark"));
        assert_eq!(
            rate_limit_pools_summary(&json!({"ordinaryUsageAllowed": null}), T0),
            "Codex rate-limit pools: map unobserved; ordinaryUsageAllowed null; accountId absent."
        );
    }

    #[test]
    fn routine_summary_reports_the_count_only() {
        assert_eq!(
            routine_reset_credit_summary(&count_only(2)).as_deref(),
            Some("Codex reset details: count 2; list not requested on this routine read.")
        );
        assert_eq!(routine_reset_credit_summary(&json!({})), None);
    }

    /// The in-session read sequence against a scripted app-server: routine
    /// requests carry the exclude parameter, and a detailed read follows in
    /// the same session when the caller asks for it.
    mod session {
        use super::*;
        use crate::agent_status::{
            call_codex_app_server_rate_limits_for_home, CodexAppServerObservation,
        };
        use crate::test_scratch::ScratchDir;
        use ottto_core::CodexHomeTrust;
        use serial_test::serial;
        use std::ffi::OsString;
        use std::os::unix::fs::PermissionsExt;

        /// `mode`: `count` answers a routine read with the count only;
        /// `reject` answers a routine read with an error, like a server that
        /// does not know the parameter; `exit` closes its stdin, answers the
        /// routine read and quits.
        /// Every request line is logged.
        const FAKE_APP_SERVER: &str = r#"import json
import os
import sys

if sys.argv[1:] != ["app-server", "--stdio"]:
    sys.exit(1)
mode = os.environ["FAKE_CODEX_MODE"]
log = open(os.environ["FAKE_CODEX_LOG"], "a")
detailed = {"rateLimits": {"limitId": "codex", "primary": {"usedPercent": 5, "windowDurationMins": 300}},
            "rateLimitResetCredits": {"availableCount": 2, "credits": [
                {"id": "grant-one", "resetType": "codexRateLimits", "status": "available", "grantedAt": 1790709296, "expiresAt": 1793301296, "title": "Full reset"},
                {"id": "grant-two", "resetType": "codexRateLimits", "status": "available", "grantedAt": 1791416555, "expiresAt": 1794008555, "title": "Full reset"}]}}
routine = {"rateLimits": detailed["rateLimits"], "rateLimitResetCredits": {"availableCount": 2, "credits": None}}
for line in sys.stdin:
    request = json.loads(line)
    log.write(line)
    log.flush()
    if request.get("id") == 1:
        print(json.dumps({"id": 1, "result": {"userAgent": "fake"}}), flush=True)
    elif request.get("id") == "ottto_account":
        print(json.dumps({"id": "ottto_account", "result": {"account": {"type": "chatgpt", "planType": "pro"}}}), flush=True)
    elif request.get("method") == "account/rateLimits/read":
        excluded = request.get("params", {}).get("excludeResetCreditDetails") is True
        if excluded and mode == "exit":
            # Close the only read end before answering, so the collector's
            # follow-up write fails with a broken pipe.
            os.close(0)
            print(json.dumps({"id": request["id"], "result": routine}), flush=True)
            sys.exit(0)
        if excluded and mode == "reject":
            print(json.dumps({"id": request["id"], "error": {"code": -32602, "message": "unknown field"}}), flush=True)
        else:
            print(json.dumps({"id": request["id"], "result": routine if excluded else detailed}), flush=True)
"#;

        struct EnvGuard(Vec<(&'static str, Option<OsString>)>);

        impl EnvGuard {
            fn set(values: &[(&'static str, OsString)]) -> Self {
                let previous = values
                    .iter()
                    .map(|(key, value)| {
                        let previous = std::env::var_os(key);
                        std::env::set_var(key, value);
                        (*key, previous)
                    })
                    .collect();
                Self(previous)
            }
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (key, previous) in &self.0 {
                    match previous {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }

        fn run(
            mode: &str,
            read_kind: CodexRateLimitsRead,
            escalate: bool,
        ) -> (CodexAppServerObservation, Vec<Value>) {
            let dir = ScratchDir::new("codex-credit-session");
            let bin = dir.join("bin");
            let home = dir.join("codex-home");
            std::fs::create_dir_all(&bin).expect("bin dir");
            std::fs::create_dir_all(&home).expect("home dir");
            let script = dir.join("fake_codex.py");
            std::fs::write(&script, FAKE_APP_SERVER).expect("fake app-server");
            let log = dir.join("requests.jsonl");
            // The app-server child runs with a cleared environment, so the
            // launcher itself carries the fake's mode and log path.
            let executable = bin.join("codex");
            std::fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nFAKE_CODEX_MODE='{mode}' FAKE_CODEX_LOG='{}' exec /usr/bin/python3 '{}' \"$@\"\n",
                    log.display(),
                    script.display()
                ),
            )
            .expect("fake codex");
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            let observation = {
                let _env =
                    EnvGuard::set(&[("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string())]);
                call_codex_app_server_rate_limits_for_home(
                    &home,
                    CodexHomeTrust::Managed,
                    read_kind,
                    &|_, _, _| escalate,
                )
                .expect("scripted read")
            };
            let requests = std::fs::read_to_string(&log)
                .expect("request log")
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|request| request["method"] == "account/rateLimits/read")
                .collect();
            (observation, requests)
        }

        fn has_list(observation: &CodexAppServerObservation) -> bool {
            reset_credit_rows(&observation.rate_limits).is_some()
        }

        #[test]
        #[serial]
        fn routine_read_sends_the_exclude_param_and_keeps_the_count() {
            let (observation, requests) = run("count", CodexRateLimitsRead::Routine, false);
            assert_eq!(
                requests,
                vec![CodexRateLimitsRead::Routine.request("ottto_rate_limits")]
            );
            assert!(!observation.details_requested);
            assert!(!has_list(&observation));
            assert_eq!(available_count(&observation.rate_limits), Some(2));
        }

        #[test]
        #[serial]
        fn routine_read_escalates_to_details_in_the_same_session() {
            let (observation, requests) = run("count", CodexRateLimitsRead::Routine, true);
            assert_eq!(
                requests,
                vec![
                    CodexRateLimitsRead::Routine.request("ottto_rate_limits"),
                    CodexRateLimitsRead::Detailed.request(DETAIL_READ_ID),
                ]
            );
            assert!(observation.details_requested);
            assert!(has_list(&observation));
        }

        #[test]
        #[serial]
        fn detailed_plan_sends_the_historical_request_once() {
            let (observation, requests) = run("count", CodexRateLimitsRead::Detailed, true);
            assert_eq!(
                requests,
                vec![CodexRateLimitsRead::Detailed.request("ottto_rate_limits")]
            );
            assert!(observation.details_requested);
            assert!(has_list(&observation));
        }

        #[test]
        #[serial]
        fn a_server_gone_before_the_detail_read_keeps_the_routine_reading() {
            let (observation, requests) = run("exit", CodexRateLimitsRead::Routine, true);
            assert_eq!(requests.len(), 1);
            assert!(
                observation.details_requested,
                "the attempt counts as failed"
            );
            assert!(!has_list(&observation));
            assert_eq!(available_count(&observation.rate_limits), Some(2));
        }

        #[test]
        #[serial]
        fn a_server_rejecting_the_param_falls_back_to_the_plain_read() {
            let (observation, requests) = run("reject", CodexRateLimitsRead::Routine, false);
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[1],
                CodexRateLimitsRead::Detailed.request(DETAIL_READ_ID)
            );
            assert!(observation.details_requested);
            assert!(has_list(&observation));
        }
    }
}
