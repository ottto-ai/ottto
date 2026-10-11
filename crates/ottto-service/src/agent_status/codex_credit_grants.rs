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
//! for the reset-credit list. Every poll therefore first sends the routine
//! read, `excludeResetCreditDetails: true`, which still returns usage and the
//! count. The detailed read (no params, byte-identical to the historical
//! request) follows in the same app-server session when
//! [`CodexCreditTracker::routine_needs_details`] asks for it:
//! - the binding has no successful detailed read (hourly or count-triggered)
//!   in the last hour ([`DETAIL_INTERVAL_SECS`], with [`POLL_SLACK_SECS`] so a
//!   5-minute poll lands on the hour rather than one poll after it), which
//!   includes the first poll after a daemon start;
//! - the routine count has no cached list for that count (a count change or
//!   an account switch).
//!
//! The routine answer already carries usage and the count, so a detailed read
//! that errors or times out never costs the reading; only the list is missing.
//! A routine answer that already carries the list (a server ignoring the
//! parameter) is used as the detailed read. A server that rejects the
//! parameter as invalid ([`routine_param_rejected`]) gets the plain request
//! instead; any other error fails the reading as before.
//!
//! At most one detailed read is sent per session. A failed detailed read
//! (Codex silently falls back to `credits: null`) is retried after
//! [`DETAIL_RETRY_SECS`], not on every poll; a count with no cached list still
//! escalates at once. A whole session that fails (spawn, RPC error or timeout
//! before any reading) counts as a failed detailed read for the binding last
//! validated at that Codex home ([`CodexCreditTracker::record_session_failure`]):
//! the next 5-minute routine read still runs, but the hourly detailed read waits
//! for the retry gate. A home never validated records nothing; no identity or
//! count is invented. [`DetailCadence`] holds these decisions as pure functions
//! of the clock.
//!
//! Cost, assuming Codex answers a routine read with one backend call and a
//! detailed read with two (inferred from the upstream client, not measured):
//! with a stable count an hour is 11 routine polls plus 1 routine-and-detailed
//! poll, about 14 calls instead of the historical 24 (12 detailed polls). Two
//! count changes in an hour give about 18. An escalated poll costs 3, more than
//! the old 2, so a count that keeps changing, a persistent routine/detail count
//! disagreement or a server rejecting the parameter can cost more than before
//! in that hour. There is never more than one escalation per session.
//!
//! # Sender stability (R7b)
//!
//! A reading without the list re-sends the binding's last observed list from
//! the model's [`SectionCache`] unchanged (original `grants_observed_at`),
//! but only while the provider count equals the count the list was read with.
//! Cadence never turns a list into `unavailable`; only a failed detail read
//! with no matching cached list does. The cache is keyed by the credential
//! identity (account + workspace hash), so A→B→A keeps A's list.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use ottto_protocol::{AgentCreditBalance, CreditBalanceKind};
use serde_json::Value;

use super::json_u64;
use crate::quota_credit_model::{
    build_grants, BindingKey, CreditModelDiagnostic, Field, GrantInput, GrantStatusInput,
    ListObservation, Provider, SectionCache, TimeInput,
};

/// The Codex saved-reset balance (name pinned by contract v2.2 §11.7 C4).
pub(super) const RESET_BANK: &str = "reset_bank";
/// Longest gap between successful detailed reads of one binding.
pub(super) const DETAIL_INTERVAL_SECS: u64 = 3_600;
/// Wait after a failed detailed read before the next one for the same count.
pub(super) const DETAIL_RETRY_SECS: u64 = 900;
/// A poll this close to a deadline counts as reaching it.
pub(super) const POLL_SLACK_SECS: u64 = 60;
/// Bound on bindings (and Codex homes) the cadence remembers.
const TRACKED_BINDINGS_MAX: usize = 64;
/// JSON-RPC id of a detailed read sent after a routine one in the same session.
pub(super) const DETAIL_READ_ID: &str = "ottto_rate_limits_details";
/// Least time a detailed read sent after the routine one gets to answer, even
/// when the routine read used most of the session bound; at most
/// [`DETAIL_READ_MAX_BUDGET`].
pub(super) const DETAIL_READ_MIN_BUDGET: Duration = Duration::from_secs(10);
pub(super) const DETAIL_READ_MAX_BUDGET: Duration = Duration::from_secs(20);
/// JSON-RPC "invalid request" and "invalid params": the only answers that mean
/// the server does not accept the routine parameter.
const JSON_RPC_INVALID_REQUEST: i64 = -32600;
const JSON_RPC_INVALID_PARAMS: i64 = -32602;
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

/// The routine read was refused because the server does not accept its
/// parameter, so the plain request is worth sending. Any other error (auth,
/// provider outage) is not retried with the costlier detailed read.
pub(super) fn routine_param_rejected(error: &Value) -> bool {
    matches!(
        error.get("code").and_then(Value::as_i64),
        Some(JSON_RPC_INVALID_REQUEST | JSON_RPC_INVALID_PARAMS)
    )
}

/// Time the detailed read sent after the routine one may take: what is left of
/// the session bound, but never less than [`DETAIL_READ_MIN_BUDGET`].
pub(super) fn detail_read_budget(session_remaining: Duration) -> Duration {
    session_remaining.clamp(DETAIL_READ_MIN_BUDGET, DETAIL_READ_MAX_BUDGET)
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

    /// Latest detailed read, failed or not; the eviction order.
    fn last_activity(&self) -> Option<u64> {
        self.last_detail_ok_at
            .max(self.last_detail_failed.map(|(at, _)| at))
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
    /// A detailed read was sent in this session.
    pub(super) details_requested: bool,
    /// That detailed read answered with a result (not an error, timeout,
    /// output-bound failure or unsent request).
    pub(super) details_answered: bool,
    /// Completion clock of the provider read.
    pub(super) observed_at: Option<&'a str>,
    pub(super) now: u64,
}

/// Cadence state and the grant-list cache for every Codex binding.
#[derive(Debug, Default)]
pub(super) struct CodexCreditTracker {
    sections: SectionCache,
    cadence: BTreeMap<String, DetailCadence>,
    /// The binding last validated at each Codex home. Used only to charge a
    /// whole-session failure to a known identity; never to plan a request or
    /// to attach a list.
    home_binding: BTreeMap<PathBuf, String>,
}

impl CodexCreditTracker {
    /// After a routine reading, whether to send the detailed read at once. A
    /// cold binding (first poll after start, or never read) is due.
    pub(super) fn routine_needs_details(
        &self,
        binding: Option<&str>,
        rate_limits: &Value,
        now: u64,
    ) -> bool {
        let Some(binding) = binding else {
            return false;
        };
        if reset_credit_rows(rate_limits).is_some() {
            // The routine answer already carries the list.
            return false;
        }
        let count = available_count(rate_limits);
        let key = BindingKey::from_credential_identity_hash(binding);
        let cached =
            count.is_some_and(|count| self.sections.grant_list_for_count(&key, count).is_some());
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
            // A list in any answer is a detailed reading. A detailed answer
            // without any reset section is complete, not a failure; a detailed
            // read that never answered is a failure even then.
            if read.details_requested || rows.is_some() {
                let ok = rows.is_some() || (count.is_none() && read.details_answered);
                self.cadence_entry(binding)
                    .record_detail(ok, count, read.now);
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
                    &BindingKey::from_credential_identity_hash(binding),
                    count,
                    balance,
                );
            }
            let mut diagnostics = diagnostics;
            diagnostics.extend(self.sections.take_diagnostics());
            return diagnostics;
        }
        let cached = read
            .binding
            .zip(provider_count)
            .and_then(|(binding, count)| {
                self.sections.grant_list_for_count(
                    &BindingKey::from_credential_identity_hash(binding),
                    count,
                )
            });
        match cached {
            Some(list) => {
                list.apply_to(balance);
                Vec::new()
            }
            None => build_grants(ListObservation::Unavailable {
                provider: Provider::OpenAi,
                provider_count,
            })
            .apply_to(balance),
        }
    }
}

impl CodexCreditTracker {
    /// A reading at `home` validated as `binding`.
    pub(super) fn remember_home_binding(&mut self, home: &Path, binding: &str) {
        if !self.home_binding.contains_key(home) && self.home_binding.len() >= TRACKED_BINDINGS_MAX
        {
            // Homes are re-learned on their next successful reading.
            if let Some(evict) = self.home_binding.keys().next().cloned() {
                self.home_binding.remove(&evict);
            }
        }
        self.home_binding
            .insert(home.to_path_buf(), binding.to_string());
    }

    /// The whole app-server session at `home` failed before any reading
    /// (spawn, RPC error, timeout). Charge it as a failed detailed read to the
    /// binding last validated there, so the next poll does not escalate for
    /// the hourly read before [`DETAIL_RETRY_SECS`]. The failed count is
    /// unknown, so a count with no cached list still escalates. A home with no
    /// validated binding records nothing.
    pub(super) fn record_session_failure(&mut self, home: &Path, now: u64) {
        let Some(binding) = self.home_binding.get(home).cloned() else {
            return;
        };
        self.cadence_entry(&binding).record_detail(false, None, now);
    }

    /// The binding's cadence, evicting the least recently read other binding
    /// at the bound. An evicted binding is simply re-learned (it reads
    /// details on its next poll).
    fn cadence_entry(&mut self, binding: &str) -> &mut DetailCadence {
        if !self.cadence.contains_key(binding) && self.cadence.len() >= TRACKED_BINDINGS_MAX {
            if let Some(evict) = self
                .cadence
                .iter()
                .min_by_key(|(_, cadence)| cadence.last_activity())
                .map(|(key, _)| key.clone())
            {
                self.cadence.remove(&evict);
            }
        }
        self.cadence.entry(binding.to_string()).or_default()
    }
}

fn tracker() -> MutexGuard<'static, CodexCreditTracker> {
    static TRACKER: OnceLock<Mutex<CodexCreditTracker>> = OnceLock::new();
    TRACKER
        .get_or_init(|| Mutex::new(CodexCreditTracker::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Process-wide [`CodexCreditTracker::remember_home_binding`].
pub(super) fn remember_home_binding(home: &Path, binding: &str) {
    tracker().remember_home_binding(home, binding);
}

/// Process-wide [`CodexCreditTracker::record_session_failure`].
pub(super) fn record_session_failure(home: &Path, now: u64) {
    tracker().record_session_failure(home, now);
}

/// The binding's last failed detailed read, for tests of the process-wide
/// tracker.
#[cfg(test)]
pub(super) fn last_detail_failed_at(binding: &str) -> Option<u64> {
    tracker()
        .cadence
        .get(binding)
        .and_then(|cadence| cadence.last_detail_failed)
        .map(|(at, _)| at)
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

/// `availableCount`: the one parse behind the `reset_bank` balance, the
/// cadence and the counts diagnostic.
pub(super) fn available_count(rate_limits: &Value) -> Option<u64> {
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

/// Every balance of an app-server reading carries that reading's completion
/// clock (`observed_at`). A re-sent grant list keeps its own
/// `grants_observed_at`. Credit balances never carry `updated_at` (contract
/// v2.2 §11.7 C9 as amended); consumers use the snapshot's capture time.
pub(super) fn stamp_read_clock(balances: &mut [AgentCreditBalance], observed_at: Option<&str>) {
    for balance in balances {
        balance.observed_at = observed_at.map(str::to_string);
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
            details_requested,
            details_answered: details_requested,
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

    /// One simulated poll as the session runs it: the routine read first, then
    /// the detailed read in the same session when the tracker asks for it.
    /// Returns the requests sent and the emitted balance.
    fn poll(
        tracker: &mut CodexCreditTracker,
        binding: &str,
        now: u64,
        count: u64,
        list: &[Value],
    ) -> (Vec<CodexRateLimitsRead>, AgentCreditBalance) {
        let mut sent = vec![CodexRateLimitsRead::Routine];
        let mut rate_limits = count_only(count);
        if tracker.routine_needs_details(Some(binding), &rate_limits, now) {
            sent.push(CodexRateLimitsRead::Detailed);
            rate_limits = detailed(count, list.to_vec());
        }
        let read = CodexCreditRead {
            binding: Some(binding),
            details_requested: sent.contains(&CodexRateLimitsRead::Detailed),
            details_answered: sent.contains(&CodexRateLimitsRead::Detailed),
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

    const ROUTINE: CodexRateLimitsRead = CodexRateLimitsRead::Routine;
    const DETAILED: CodexRateLimitsRead = CodexRateLimitsRead::Detailed;

    #[test]
    fn simulated_hour_is_one_detailed_read_plus_one_per_count_change() {
        let mut tracker = CodexCreditTracker::default();
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
                BINDING_A,
                T0 + minute * 60,
                count,
                &rows(count as usize),
            );
            assert_eq!(sent[0], ROUTINE, "every poll starts with the routine read");
            detailed_reads += sent.iter().filter(|kind| **kind == DETAILED).count();
            routine_reads += sent.iter().filter(|kind| **kind == ROUTINE).count();
            assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
            assert_eq!(balance.grants.as_ref().map(Vec::len), Some(count as usize));
        }
        assert_eq!(detailed_reads, 1 + 2, "one hourly + one per count change");
        assert_eq!(routine_reads, 12, "every poll sends the routine read");
        // Any successful detailed read restarts the hour: the last one ran at
        // minute 40, so minute 95 is routine only and minute 100 escalates.
        let last_detail = T0 + 40 * 60;
        let (sent, _) = poll(&mut tracker, BINDING_A, last_detail + 55 * 60, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE]);
        let (sent, _) = poll(&mut tracker, BINDING_A, last_detail + 60 * 60, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
    }

    #[test]
    fn grants_stay_continuous_across_routine_polls_with_original_read_time() {
        let mut tracker = CodexCreditTracker::default();
        let (sent, first) = poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
        for step in 1..=4u64 {
            let mut balances = vec![reset_bank(2)];
            let now = T0 + step * 300;
            assert!(!tracker.routine_needs_details(Some(BINDING_A), &count_only(2), now));
            tracker.attach_reset_bank_grants(
                &mut balances,
                &count_only(2),
                CodexCreditRead {
                    binding: Some(BINDING_A),
                    details_requested: false,
                    details_answered: false,
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
    fn cold_cache_escalates_at_once_and_never_sends_unknown() {
        let mut tracker = CodexCreditTracker::default();
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(2), T0));
        let (sent, balance) = poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
        assert_eq!(balance.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
    }

    #[test]
    fn daemon_restart_reads_details_on_the_first_poll_so_the_list_never_blinks() {
        let mut tracker = CodexCreditTracker::default();
        let mut emitted = Vec::new();
        for step in 0..3u64 {
            emitted.push(poll(&mut tracker, BINDING_A, T0 + step * 300, 2, &rows(2)));
        }
        // Daemon restart: every in-memory cadence and cache entry is gone.
        let mut tracker = CodexCreditTracker::default();
        let restarted_at = T0 + 3 * 300;
        let (sent, first_after_restart) = poll(&mut tracker, BINDING_A, restarted_at, 2, &rows(2));
        assert_eq!(
            sent,
            vec![ROUTINE, DETAILED],
            "the first poll after start reads details in the same session"
        );
        emitted.push((sent, first_after_restart.clone()));
        emitted.push(poll(
            &mut tracker,
            BINDING_A,
            restarted_at + 300,
            2,
            &rows(2),
        ));
        for (index, (_, balance)) in emitted.iter().enumerate() {
            assert_eq!(
                balance.grants_state,
                Some(CreditGrantsState::Complete),
                "reading {index}"
            );
            assert_eq!(
                balance.grants.as_ref().map(Vec::len),
                Some(2),
                "reading {index}"
            );
            assert_eq!(
                balance.status,
                AgentCreditBalanceStatus::Ok,
                "reading {index}"
            );
        }
        // The same grants before and after the restart.
        assert_eq!(first_after_restart.grants, emitted[0].1.grants);
        // The process-wide tracker treats a never-read binding the same way.
        assert!(routine_read_needs_details(
            Some("synthetic-never-read:workspace"),
            &count_only(2),
            restarted_at
        ));
    }

    #[test]
    fn account_switch_a_b_a_keeps_a_list() {
        let mut tracker = CodexCreditTracker::default();
        let (_, a_first) = poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        // B signs in at the same home: its first routine reading has no list
        // for B, so details are read at once.
        let (sent, b) = poll(&mut tracker, BINDING_B, T0 + 300, 3, &rows(3));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
        assert_eq!(b.grants.as_ref().map(Vec::len), Some(3));
        // Back to A within the hour: A's list is re-sent unchanged.
        let (sent, a_again) = poll(&mut tracker, BINDING_A, T0 + 600, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE]);
        assert_eq!(wire(&a_again), wire(&a_first));
    }

    #[test]
    fn failed_detail_read_resends_matching_list_and_retries_later() {
        let mut tracker = CodexCreditTracker::default();
        let (_, first) = poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        // The hourly detailed read is due and fails (Codex falls back to the
        // count); the routine reading still stands.
        let hour = T0 + 3_600;
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(2), hour));
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
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &count_only(2), hour + 300));
        // ... but after the retry wait.
        assert!(tracker.routine_needs_details(
            Some(BINDING_A),
            &count_only(2),
            hour + DETAIL_RETRY_SECS
        ));
    }

    #[test]
    fn count_change_with_failed_details_is_unavailable_then_retried() {
        let mut tracker = CodexCreditTracker::default();
        poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
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
    fn a_failed_detailed_read_without_reset_section_keeps_the_retry_gate() {
        // Plan credits only: neither answer carries a reset section.
        let mut tracker = CodexCreditTracker::default();
        let no_resets = json!({"rateLimits": {}});
        assert!(tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0));
        // The escalated detailed read errors or times out; the routine
        // reading stands, but the attempt is a failure.
        tracker.attach_reset_bank_grants(
            &mut [],
            &no_resets,
            CodexCreditRead {
                details_answered: false,
                ..read(Some(BINDING_A), true, T0)
            },
        );
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0 + 300));
        // Retried after 15 minutes, not an hour.
        assert!(tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0 + DETAIL_RETRY_SECS));
    }

    #[test]
    fn a_routine_answer_that_carries_the_list_is_the_detailed_read() {
        // A server that ignores the parameter answers the routine read in full.
        let mut tracker = CodexCreditTracker::default();
        let full = detailed(2, rows(2));
        assert!(
            !tracker.routine_needs_details(Some(BINDING_A), &full, T0),
            "no second request"
        );
        let (balance, _) = attach(&mut tracker, &full, read(Some(BINDING_A), false, T0));
        assert_eq!(balance.grants_state, Some(CreditGrantsState::Complete));
        // Recorded as a detailed read: nothing is due for the next hour.
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &count_only(2), T0 + 300));
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
            .grant_list_for_count(&BindingKey::from_credential_identity_hash(BINDING_A), 2)
            .is_none());
    }

    #[test]
    fn accounts_without_saved_resets_are_detailed_hourly_not_every_poll() {
        let mut tracker = CodexCreditTracker::default();
        let no_resets = json!({"rateLimits": {}});
        assert!(tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0));
        tracker.attach_reset_bank_grants(&mut [], &no_resets, read(Some(BINDING_A), true, T0));
        assert!(!tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0 + 300));
        assert!(tracker.routine_needs_details(Some(BINDING_A), &no_resets, T0 + 3_600));
    }

    const HOME: &str = "/synthetic/codex-home";

    #[test]
    fn whole_session_failure_backs_off_the_hourly_detail_read() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new(HOME);
        let (_, first) = poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        tracker.remember_home_binding(home, BINDING_A);
        // At the hour the whole session fails before any reading (spawn,
        // RPC error or timeout), so not even the routine read came back.
        let hour = T0 + 3_600;
        assert!(tracker.routine_needs_details(Some(BINDING_A), &count_only(2), hour));
        tracker.record_session_failure(home, hour);
        // The next 5-minute poll still sends the routine read, and re-sends
        // the cached list, but does not escalate for the hourly read ...
        let (sent, balance) = poll(&mut tracker, BINDING_A, hour + 300, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE]);
        assert_eq!(wire(&balance), wire(&first));
        // ... until the retry gate.
        let (sent, _) = poll(
            &mut tracker,
            BINDING_A,
            hour + DETAIL_RETRY_SECS,
            2,
            &rows(2),
        );
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
    }

    #[test]
    fn whole_session_failures_never_suppress_a_count_change_read() {
        let mut tracker = CodexCreditTracker::default();
        let home = Path::new(HOME);
        poll(&mut tracker, BINDING_A, T0, 2, &rows(2));
        tracker.remember_home_binding(home, BINDING_A);
        tracker.record_session_failure(home, T0 + 300);
        // The failed session had no count; a count without a cached list is
        // still read at once.
        let (sent, balance) = poll(&mut tracker, BINDING_A, T0 + 600, 3, &rows(3));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
        assert_eq!(balance.grants.as_ref().map(Vec::len), Some(3));
    }

    #[test]
    fn whole_session_failure_at_an_unvalidated_home_records_nothing() {
        // Cold start: the first session fails before any identity is known.
        let mut tracker = CodexCreditTracker::default();
        tracker.record_session_failure(Path::new(HOME), T0);
        assert!(tracker.cadence.is_empty(), "no identity is invented");
        // The next successful routine read escalates as any cold binding.
        let (sent, _) = poll(&mut tracker, BINDING_A, T0 + 300, 2, &rows(2));
        assert_eq!(sent, vec![ROUTINE, DETAILED]);
        // A home charges only the binding last validated there.
        tracker.remember_home_binding(Path::new(HOME), BINDING_B);
        tracker.record_session_failure(Path::new(HOME), T0 + 600);
        assert!(tracker.cadence[BINDING_A].last_detail_failed.is_none());
        assert!(tracker.cadence[BINDING_B].last_detail_failed.is_some());
    }

    #[test]
    fn cadence_bound_evicts_the_least_recently_read_binding() {
        let mut tracker = CodexCreditTracker::default();
        for index in 0..TRACKED_BINDINGS_MAX as u64 {
            // Binding "b00" is read last, so it is the most recent.
            let at = T0 + (TRACKED_BINDINGS_MAX as u64 - index) * 60;
            tracker
                .cadence_entry(&format!("b{index:02}"))
                .record_detail(true, Some(1), at);
        }
        tracker
            .cadence_entry("new")
            .record_detail(true, Some(1), T0 + 10_000);
        assert_eq!(tracker.cadence.len(), TRACKED_BINDINGS_MAX);
        assert!(tracker.cadence.contains_key("b00"), "the most recent stays");
        assert!(tracker.cadence.contains_key("new"));
        let oldest = format!("b{:02}", TRACKED_BINDINGS_MAX - 1);
        assert!(!tracker.cadence.contains_key(&oldest), "the oldest goes");
    }

    #[test]
    fn param_rejection_and_detail_budget_rules() {
        assert!(routine_param_rejected(
            &json!({"code": -32602, "message": "x"})
        ));
        assert!(routine_param_rejected(&json!({"code": -32600})));
        assert!(!routine_param_rejected(&json!({"code": -32603})));
        assert!(!routine_param_rejected(&json!({"code": 401})));
        assert!(!routine_param_rejected(&json!({"message": "no code"})));
        assert_eq!(
            detail_read_budget(Duration::from_secs(1)),
            DETAIL_READ_MIN_BUDGET
        );
        assert_eq!(
            detail_read_budget(Duration::from_secs(15)),
            Duration::from_secs(15)
        );
        assert_eq!(
            detail_read_budget(Duration::from_secs(60)),
            DETAIL_READ_MAX_BUDGET
        );
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

    /// The canonical v2.2 producer fixtures: each Codex provider body, read by
    /// this adapter, yields exactly the expected wire balances.
    mod canonical {
        use super::*;
        use crate::agent_status::codex_app_server_credit_balances;
        use time::{format_description::well_known::Rfc3339, OffsetDateTime};

        const READ_AT: &str = "2026-10-01T12:00:00Z";

        fn fixture(relative: &str) -> Value {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/agent-status/quota-contract-v2.2")
                .join(relative);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            serde_json::from_str(&text).expect("fixture JSON")
        }

        fn unix(rfc3339: &str) -> u64 {
            OffsetDateTime::parse(rfc3339, &Rfc3339)
                .expect("fixture time")
                .unix_timestamp() as u64
        }

        /// One reading through the adapter, as the collector runs it.
        fn reading(
            tracker: &mut CodexCreditTracker,
            provider: &Value,
            details_requested: bool,
            read_at: &str,
        ) -> Value {
            let mut balances = codex_app_server_credit_balances(provider);
            tracker.attach_reset_bank_grants(
                &mut balances,
                provider,
                CodexCreditRead {
                    binding: Some(BINDING_A),
                    details_requested,
                    details_answered: details_requested,
                    observed_at: Some(read_at),
                    now: unix(read_at),
                },
            );
            stamp_read_clock(&mut balances, Some(read_at));
            json!({ "credit_balances": balances })
        }

        #[test]
        fn single_readings_match_the_expected_wire() {
            for (provider, expected) in [
                (
                    "codex-reset-credits-complete",
                    "codex-reset-credits-complete",
                ),
                (
                    "codex-reset-credits-provider-capped",
                    "codex-reset-credits-provider-capped",
                ),
                ("codex-reset-credits-21", "codex-reset-credits-21"),
                // Plan credits and the workspace allowance, no reset section.
                (
                    "codex-rate-limits-plan-and-workspace",
                    "codex-rate-limits-plan-and-workspace",
                ),
                // A detailed read Codex answered with the count only.
                (
                    "codex-reset-credits-count-only",
                    "codex-reset-credits-details-unavailable",
                ),
            ] {
                let input = fixture(&format!("provider/{provider}.json"));
                let actual = reading(&mut CodexCreditTracker::default(), &input, true, READ_AT);
                assert_eq!(
                    actual,
                    fixture(&format!("expected/{expected}.wire.json")),
                    "{provider}"
                );
            }
        }

        #[test]
        fn resend_sequence_matches_the_expected_wire() {
            let sequence = fixture("expected/sequence-codex-reset-credits.wire.json");
            let steps = sequence["steps"].as_array().expect("steps");
            let mut tracker = CodexCreditTracker::default();
            for (index, step) in steps.iter().enumerate() {
                let label = step["step"].as_str().expect("step label");
                if label.starts_with("restart") {
                    tracker = CodexCreditTracker::default();
                }
                let captured_at = step["captured_at"].as_str().expect("captured_at");
                let read_at = captured_at.replace(":05Z", ":00Z");
                let answers = step["provider_inputs"]
                    .as_array()
                    .expect("inputs")
                    .iter()
                    .map(|input| fixture(input.as_str().expect("input path")))
                    .collect::<Vec<_>>();
                // A body with a list answered a detailed read. A count-only
                // body answered a routine read, followed by the detailed read
                // when the adapter asks for it (the next input, or a failure).
                let (provider, details_requested) = if reset_credit_rows(&answers[0]).is_some() {
                    (&answers[0], true)
                } else if tracker.routine_needs_details(
                    Some(BINDING_A),
                    &answers[0],
                    unix(&read_at),
                ) {
                    (answers.get(1).unwrap_or(&answers[0]), true)
                } else {
                    (&answers[0], false)
                };
                let actual = reading(&mut tracker, provider, details_requested, &read_at);
                let expected = json!({ "credit_balances": step["credit_balances"] });
                assert_eq!(actual, expected, "step {index}: {label}");
            }
        }
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

        /// The fake answers the routine read with the count only and the
        /// detailed read with the list, except as `mode` says:
        /// - `reject`: the routine read is refused as invalid params (-32602);
        /// - `outage`: the routine read fails with a non-parameter error;
        /// - `reject_then_error`: `reject`, then the detailed read fails too;
        /// - `detail_error`: the detailed read fails;
        /// - `detail_silent`: the detailed read is never answered;
        /// - `detail_oversized`: the detailed answer exceeds the line bound;
        /// - `exit`: closes its stdin, answers the routine read and quits.
        ///
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

def answer(request, result=None, code=None):
    if code is None:
        print(json.dumps({"id": request["id"], "result": result}), flush=True)
    else:
        print(json.dumps({"id": request["id"], "error": {"code": code, "message": "synthetic"}}), flush=True)

for line in sys.stdin:
    request = json.loads(line)
    log.write(line)
    log.flush()
    if request.get("id") == 1:
        answer(request, {"userAgent": "fake"})
    elif request.get("id") == "ottto_account":
        answer(request, {"account": {"type": "chatgpt", "planType": "pro"}})
    elif request.get("method") == "account/rateLimits/read":
        excluded = request.get("params", {}).get("excludeResetCreditDetails") is True
        if excluded:
            if mode == "exit":
                # Close the only read end before answering, so the collector's
                # follow-up write fails with a broken pipe.
                os.close(0)
                answer(request, routine)
                sys.exit(0)
            elif mode in ("reject", "reject_then_error"):
                answer(request, code=-32602)
            elif mode == "outage":
                answer(request, code=-32603)
            else:
                answer(request, routine)
        elif mode in ("detail_error", "reject_then_error"):
            answer(request, code=-32603)
        elif mode == "detail_oversized":
            answer(request, dict(detailed, padding="x" * (300 * 1024)))
        elif mode != "detail_silent":
            answer(request, detailed)
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

        /// One scripted session; `escalate` is the cadence's answer after the
        /// routine reading.
        fn run(
            mode: &str,
            escalate: bool,
        ) -> (Result<CodexAppServerObservation, String>, Vec<Value>) {
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
                    &|_, _, _| escalate,
                )
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

        fn routine_request() -> Value {
            CodexRateLimitsRead::Routine.request("ottto_rate_limits")
        }

        fn detail_request() -> Value {
            CodexRateLimitsRead::Detailed.request(DETAIL_READ_ID)
        }

        /// The routine reading stood: usage and the count are kept, the list
        /// is missing, and the detail attempt counts (as failed).
        fn assert_routine_reading_kept(observation: &CodexAppServerObservation) {
            assert!(
                observation.details_requested,
                "the attempt counts as failed"
            );
            assert!(
                !observation.details_answered,
                "the detailed read never answered"
            );
            assert!(!has_list(observation));
            assert_eq!(available_count(&observation.rate_limits), Some(2));
            assert!(observation.rate_limits.get("rateLimits").is_some());
        }

        #[test]
        #[serial]
        fn routine_read_sends_the_exclude_param_and_keeps_the_count() {
            let (observation, requests) = run("count", false);
            let observation = observation.expect("reading");
            assert_eq!(requests, vec![routine_request()]);
            assert!(!observation.details_requested);
            assert!(!has_list(&observation));
            assert_eq!(available_count(&observation.rate_limits), Some(2));
        }

        #[test]
        #[serial]
        fn routine_read_escalates_to_the_historical_detailed_read_in_the_same_session() {
            let (observation, requests) = run("count", true);
            let observation = observation.expect("reading");
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            // The detailed request carries no params, byte-identical to the
            // historical read.
            assert!(detail_request().get("params").is_none());
            assert!(observation.details_requested);
            assert!(has_list(&observation));
        }

        #[test]
        #[serial]
        fn an_escalated_detail_error_keeps_the_routine_reading() {
            let (observation, requests) = run("detail_error", true);
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            assert_routine_reading_kept(&observation.expect("reading"));
        }

        #[test]
        #[serial]
        fn an_unanswered_escalated_detail_read_keeps_the_routine_reading() {
            let started = std::time::Instant::now();
            let (observation, requests) = run("detail_silent", true);
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            assert_routine_reading_kept(&observation.expect("reading"));
            // The detailed read had its own budget, then gave up.
            assert!(started.elapsed() >= DETAIL_READ_MIN_BUDGET);
        }

        #[test]
        #[serial]
        fn an_oversized_escalated_answer_keeps_the_routine_reading() {
            let (observation, requests) = run("detail_oversized", true);
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            assert_routine_reading_kept(&observation.expect("reading"));
        }

        #[test]
        #[serial]
        fn a_server_gone_before_the_detail_read_keeps_the_routine_reading() {
            let (observation, requests) = run("exit", true);
            assert_eq!(requests, vec![routine_request()]);
            assert_routine_reading_kept(&observation.expect("reading"));
        }

        #[test]
        #[serial]
        fn a_server_rejecting_the_param_falls_back_to_the_plain_read() {
            let (observation, requests) = run("reject", false);
            let observation = observation.expect("reading");
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            assert!(observation.details_requested);
            assert!(has_list(&observation));
        }

        #[test]
        #[serial]
        fn a_rejected_param_then_a_failing_detailed_read_fails_the_reading() {
            let (observation, requests) = run("reject_then_error", false);
            assert_eq!(requests, vec![routine_request(), detail_request()]);
            assert!(observation.is_err(), "no reading to keep");
        }

        /// A failed detailed read never costs a routine reading; only when no
        /// routine reading exists does the session fail, with the precise
        /// message of the failed request and no provider text.
        #[test]
        #[serial]
        fn a_detailed_failure_keeps_the_routine_reading_or_reports_the_precise_message() {
            for mode in ["detail_error", "detail_oversized"] {
                let (observation, _) = run(mode, true);
                assert_routine_reading_kept(&observation.expect(mode));
            }
            let (observation, _) = run("reject_then_error", false);
            let message = observation.err().expect("no routine reading");
            assert_eq!(
                message,
                "Codex app-server quota RPC failed with code -32603."
            );
            assert!(
                !message.contains("synthetic"),
                "no provider text: {message}"
            );
        }

        #[test]
        #[serial]
        fn other_routine_errors_do_not_retry_with_the_detailed_read() {
            let (observation, requests) = run("outage", true);
            assert_eq!(requests, vec![routine_request()], "no costlier retry");
            assert!(observation.is_err());
        }
    }
}
