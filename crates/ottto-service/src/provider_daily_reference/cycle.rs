//! One collection tick: the tick-wide gates, each login's gated read and upload,
//! the per-account outcome, and acknowledgement validation.

use super::batching::{collection_window, date_string, pack_batches};
use super::grant::{
    grant_runtime_block_reason, same_binding, BackendGrantBinding, DailyReferenceGrant, GrantStore,
};
use super::normalize::{normalize_provider_window, NormalizedWindow};
use super::provider_read::{CodexLogin, ProviderDailyUsageReader, ProviderReadError};
use super::state::{
    breaker_is_open, fetch_due, fetch_interval_seconds, state_after_failure, state_after_success,
    state_identity_for_account, CollectorState, DiscoverySummary, ProviderFailure, SeenAccount,
    SeriesProof, StateBinding, StateStore,
};
use super::transport::{DailyReferenceTransport, UploadError};
use super::wire::{wire_payload_is_content_free, DailyReferenceBatch, DailyReferenceRow};
use super::{
    logins, opaque_key, sentinel_path, timestamp, unix_seconds, ACK_SCHEMA_VERSION, COLLECTOR_ID,
    DISCLOSURE_VERSION, DISCLOSURE_VERSION_V1, PROVIDER_DAY_TIMEZONE, SCHEMA_VERSION, SOURCE,
    STATE_FILE_SCHEMA_VERSION,
};
use crate::hex::encode as hex;
use anyhow::{anyhow, Result};
use ottto_core::compiled_release_version;
use ottto_protocol::{AgentDiagnosticSeverity, AgentStatusDiagnostic};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Cycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Sentinel, absent consent, mismatched disclosure, or unapproved policy.
    Disabled,
    /// The breaker is open; no provider request was made.
    CircuitOpen,
    /// Nothing to do this tick - the cadence gate has not elapsed.
    Noop,
    /// The transport or the credential is not available yet.
    Deferred,
    /// Batches landed.
    Uploaded,
    /// The backend has not admitted this collector version. Expected.
    NotAdmitted,
    /// Current account is explicitly excluded; no retry loop is entered.
    AccountExcluded,
    /// A provider or upload failure this cycle.
    Failed,
}

#[derive(Debug, Clone)]
pub struct Cycle {
    pub outcome: CycleOutcome,
    /// Normalized scalar rows observed when the provider read reached that
    /// stage, summed over the tick's logins. `None` means no provider window
    /// was observed this cycle.
    pub normalized_row_count: Option<usize>,
    pub diagnostics: Vec<AgentStatusDiagnostic>,
    /// One element per login a tick evaluated. Empty when a tick-wide gate
    /// stopped it first.
    pub(crate) accounts: Vec<AccountCycle>,
}

impl Cycle {
    fn new(outcome: CycleOutcome) -> Self {
        Self {
            outcome,
            normalized_row_count: None,
            diagnostics: Vec::new(),
            accounts: Vec::new(),
        }
    }

    fn with(outcome: CycleOutcome, diagnostic: AgentStatusDiagnostic) -> Self {
        Self {
            outcome,
            normalized_row_count: None,
            diagnostics: vec![diagnostic],
            accounts: Vec::new(),
        }
    }
}

/// What one login did in a tick. Ordinals and kinds only, never ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountCycle {
    /// 1-based position in the tick's discovery order.
    pub(crate) ordinal: usize,
    pub(crate) home_kind: &'static str,
    pub(crate) outcome: CycleOutcome,
    /// Closed reason; `None` when the login was not yet due.
    pub(crate) reason: Option<&'static str>,
}

/// Raw runtime identity the cycle proves against the grant's fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    /// Relay device id. Equals the wire `installation_id`.
    pub installation_id: String,
}

fn info(code: &str, message: &str) -> AgentStatusDiagnostic {
    AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Info, message)
}

fn warning(code: &str, message: &str) -> AgentStatusDiagnostic {
    AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Warning, message)
}

fn normalization_counter_summary(normalized: &NormalizedWindow) -> String {
    let mut counters = Vec::new();
    macro_rules! add_nonzero {
        ($name:ident) => {
            if normalized.$name > 0 {
                counters.push(format!("{}={}", stringify!($name), normalized.$name));
            }
        };
    }
    add_nonzero!(days_seen);
    add_nonzero!(days_recognized);
    add_nonzero!(days_missing_date);
    add_nonzero!(days_out_of_window);
    add_nonzero!(days_no_client_breakdown);
    add_nonzero!(days_used_fallback);
    add_nonzero!(clients_seen);
    add_nonzero!(clients_missing_id);
    add_nonzero!(clients_no_model_breakdown);
    add_nonzero!(models_seen);
    add_nonzero!(models_missing_id);
    add_nonzero!(entries_empty_counters);
    add_nonzero!(dropped_model_rows);
    add_nonzero!(day_totals_seen);
    add_nonzero!(day_totals_compared);
    add_nonzero!(day_total_mismatch_days);
    add_nonzero!(user_count_fields_seen);
    add_nonzero!(user_count_fields_unreadable);
    counters.join(", ")
}

fn has_normalization_accounting_events(normalized: &NormalizedWindow) -> bool {
    normalized.days_missing_date > 0
        || normalized.days_out_of_window > 0
        || normalized.days_no_client_breakdown > 0
        || normalized.days_used_fallback > 0
        || normalized.clients_missing_id > 0
        || normalized.clients_no_model_breakdown > 0
        || normalized.models_missing_id > 0
        || normalized.entries_empty_counters > 0
        || normalized.user_count_fields_unreadable > 0
        || normalized.day_total_mismatch_days > 0
}

fn format_unrecognized_keys(keys: &BTreeSet<String>) -> String {
    format!(
        "[{}]",
        keys.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub(super) fn append_normalization_diagnostics(
    normalized: &NormalizedWindow,
    diagnostics: &mut Vec<AgentStatusDiagnostic>,
) {
    if has_normalization_accounting_events(normalized) {
        diagnostics.push(info(
            "codex_daily_aggregates_normalization_accounting",
            &format!(
                "Provider normalization accounting: {}.",
                normalization_counter_summary(normalized)
            ),
        ));
    }
    for mismatch in &normalized.day_total_mismatches {
        diagnostics.push(warning(
            "codex_daily_aggregates_provider_total_mismatch",
            &format!(
                "Provider day total differs from recognized client sum: day={} metric={} provider={} recognized_clients={}.",
                mismatch.provider_day,
                mismatch.metric,
                mismatch.provider_value,
                mismatch.recognized_client_value
            ),
        ));
    }
    for (code, level, keys) in [
        (
            "codex_daily_aggregates_unrecognized_day_keys",
            "day",
            &normalized.unrecognized_day_keys,
        ),
        (
            "codex_daily_aggregates_unrecognized_client_keys",
            "client",
            &normalized.unrecognized_client_keys,
        ),
        (
            "codex_daily_aggregates_unrecognized_model_keys",
            "model",
            &normalized.unrecognized_model_keys,
        ),
    ] {
        if !keys.is_empty() {
            diagnostics.push(info(
                code,
                &format!(
                    "Unrecognized {level}-level keys: {}.",
                    format_unrecognized_keys(keys)
                ),
            ));
        }
    }
}

/// Consent, cadence state, and the off-switch for one installation.
#[derive(Debug, Clone)]
pub struct Collector {
    pub(super) grants: GrantStore,
    pub(super) state: StateStore,
    pub(super) sentinel: PathBuf,
}

impl Default for Collector {
    fn default() -> Self {
        Self {
            grants: GrantStore::default(),
            state: StateStore::default(),
            sentinel: sentinel_path(),
        }
    }
}

impl Collector {
    pub fn new(grants: GrantStore, state: StateStore, sentinel: impl Into<PathBuf>) -> Self {
        Self {
            grants,
            state,
            sentinel: sentinel.into(),
        }
    }

    pub fn grants(&self) -> &GrantStore {
        &self.grants
    }

    pub fn state_path(&self) -> &Path {
        self.state.path()
    }

    /// Presence of the sentinel disables the capability. Absent is the default
    /// and is not by itself permission: the grant still has to be live.
    pub fn network_disabled(&self) -> bool {
        self.sentinel.is_file()
    }

    /// Run one collection tick over every discovered login.
    ///
    /// The tick-wide gates run first, before any socket is opened: the
    /// sentinel, live consent at the current epoch and disclosure, and the
    /// installation consent was recorded for. Each login then runs its own
    /// gates in [`collect_account_once`], most overdue first. `clock` is
    /// sampled once per login, so a login's cadence, window and
    /// `collected_at` share one instant.
    pub(crate) fn run_tick(
        &self,
        runtime: &Runtime,
        discovery: &logins::LoginDiscovery,
        reader: &dyn ProviderDailyUsageReader,
        transport: &dyn DailyReferenceTransport,
        clock: &dyn Fn() -> OffsetDateTime,
    ) -> Cycle {
        let grants = &self.grants;
        if self.network_disabled() {
            self.state.clear();
            return network_disabled_cycle();
        }
        let grant = match runtime_ready_grant(grants) {
            Ok(grant) => grant,
            Err(cycle) => return cycle,
        };
        let Some(expected) = grant.backend_binding.clone() else {
            return Cycle::new(CycleOutcome::Disabled);
        };
        // Consent is bound to this installation. The live account is
        // attribution, not authorization under disclosure v2: each login's
        // opaque fingerprint is derived on every tick so accounts can never
        // overwrite one another.
        let installation_matches = grants
            .installation_fingerprint_for(&runtime.installation_id)
            .ok()
            .flatten()
            .is_some_and(|fingerprint| fingerprint == grant.installation_fingerprint);
        if !installation_matches {
            return Cycle::with(
                CycleOutcome::Disabled,
                warning(
                    "codex_daily_aggregates_installation_mismatch",
                    "Codex daily aggregates consent was recorded for a different installation; collection is stopped.",
                ),
            );
        }
        if !transport.is_configured() {
            return deferred("transport_not_configured");
        }
        let Some(key) = grants.hmac_key().ok().flatten() else {
            return attribution_unavailable_cycle();
        };

        let total = discovery.logins.len();
        let mut seen = discovery
            .logins
            .iter()
            .map(|login| {
                let account_fingerprint = opaque_key(&key, &login.credential.account_scope);
                SeenAccount {
                    identity: state_identity_for_account(&grant, &account_fingerprint, false),
                    account_fingerprint,
                    home_kind: login.home_kind.label(),
                    reason: None,
                }
            })
            .collect::<Vec<_>>();
        // Most overdue first; ties (every never-read login is due since the
        // epoch) keep discovery order: default home, then slot id. No caps:
        // every selected login is evaluated.
        let state_file = self.state.load_file();
        let mut order = seen
            .iter()
            .enumerate()
            .map(|(index, account)| {
                let due_at = state_file
                    .entries
                    .get(&account.identity)
                    .map(|state| state.last_fetch_epoch_seconds)
                    .filter(|last_fetch| *last_fetch > 0)
                    .map_or(0, |last_fetch| {
                        last_fetch.saturating_add(fetch_interval_seconds(&account.identity))
                    });
                (due_at, index)
            })
            .collect::<Vec<_>>();

        drop(state_file);
        order.sort_unstable();

        let mut accounts = Vec::new();
        let mut diagnostics = Vec::new();
        let mut normalized_row_count: Option<usize> = None;
        let mut consent_changed = false;
        let selected = seen
            .iter()
            .map(|account| account.identity.clone())
            .collect::<BTreeSet<_>>();
        let tick = TickContext {
            expected: &expected,
            selected: &selected,
        };
        let mut last_now = clock();
        for (_, index) in order {
            let login = &discovery.logins[index];
            last_now = clock();
            let attempt =
                collect_account_once(self, &tick, runtime, login, reader, transport, last_now);
            let home_kind = login.home_kind.label();
            let prefix = format!("login {}/{total} ({home_kind}): ", index + 1);
            diagnostics.extend(attempt.cycle.diagnostics.into_iter().map(|mut diagnostic| {
                diagnostic.message = format!("{prefix}{}", diagnostic.message);
                diagnostic
            }));
            if let Some(rows) = attempt.cycle.normalized_row_count {
                normalized_row_count = Some(normalized_row_count.unwrap_or(0).saturating_add(rows));
            }
            accounts.push(AccountCycle {
                ordinal: index + 1,
                home_kind,
                outcome: attempt.cycle.outcome,
                reason: attempt.reason,
            });
            seen[index].reason = attempt.reason;
            match attempt.stop {
                None => {}
                Some(TickStop::Grant) => break,
                Some(TickStop::Consent) => {
                    consent_changed = true;
                    break;
                }
            }
        }

        // A consent change or the off-switch mid-tick leaves no summary: the
        // next tick discovers again under whatever consent is then live.
        if !consent_changed {
            let summary = DiscoverySummary {
                binding: StateBinding::of(&expected),
                complete: discovery.complete,
                accounts: seen
                    .iter()
                    .map(|account| account.identity.clone())
                    .collect(),
                skipped: discovery.skipped.clone(),
                default_home: discovery.default_home.clone(),
            };
            let _ = self
                .state
                .record_tick(summary, &seen, &date_string(last_now));
        }

        // No live login: nothing was read, and the saved summary now says so.
        if discovery.logins.is_empty() && discovery.skipped.is_empty() {
            return deferred(logins::LoginSkip::Absent.code());
        }
        if discovery.logins.is_empty() {
            return Cycle::with(
                CycleOutcome::Deferred,
                warning(
                    "codex_daily_aggregates_deferred",
                    &format!(
                        "Consent is ready but no Codex sign-in on this Mac can be read: {}. Nothing was read.",
                        skip_summary(discovery)
                    ),
                ),
            );
        }
        let outcome = tick_outcome(&accounts);
        if outcome != CycleOutcome::Noop && (!discovery.skipped.is_empty() || !discovery.complete) {
            diagnostics.push(info(
                "codex_daily_aggregates_logins_skipped",
                &format!(
                    "Some Codex sign-ins on this Mac were not read: {}.",
                    skip_summary(discovery)
                ),
            ));
        }
        Cycle {
            outcome,
            normalized_row_count,
            diagnostics,
            accounts,
        }
    }
}

/// Closed skip reasons and their counts, plus whether discovery was complete.
fn skip_summary(discovery: &logins::LoginDiscovery) -> String {
    let mut parts = discovery
        .skipped
        .iter()
        .map(|(reason, count)| format!("{reason}={count}"))
        .collect::<Vec<_>>();
    if !discovery.complete {
        parts.push("discovery_incomplete".to_string());
    }
    parts.join(" ")
}

/// The tick's outcome: `Uploaded` if any login uploaded, else `Failed` if any
/// failed, else the most restrictive gate a login stopped at.
fn tick_outcome(accounts: &[AccountCycle]) -> CycleOutcome {
    [
        CycleOutcome::Uploaded,
        CycleOutcome::Failed,
        CycleOutcome::Disabled,
        CycleOutcome::NotAdmitted,
        CycleOutcome::AccountExcluded,
        CycleOutcome::CircuitOpen,
        CycleOutcome::Deferred,
    ]
    .into_iter()
    .find(|outcome| accounts.iter().any(|account| account.outcome == *outcome))
    .unwrap_or(CycleOutcome::Noop)
}

pub(super) fn network_disabled_cycle() -> Cycle {
    Cycle::with(
        CycleOutcome::Disabled,
        info(
            "codex_daily_aggregates_network_disabled",
            "Codex daily aggregates are disabled by the local off-switch; the provider endpoint is never contacted.",
        ),
    )
}

pub(super) fn attribution_unavailable_cycle() -> Cycle {
    Cycle::with(
        CycleOutcome::Disabled,
        warning(
            "codex_daily_aggregates_account_attribution_unavailable",
            "The live Codex account could not be assigned an opaque attribution label; collection is stopped.",
        ),
    )
}

/// The consent gate both cycle entry points run first.
///
/// No consent file is the silent case: nothing was promised, so nothing is
/// owed. A consent file that exists but cannot be used, or a grant that cannot
/// collect, is the opposite case and must say so, or "consent is on" and
/// "nothing is being read" look identical. Either way the cycle is `Disabled`.
pub(super) fn runtime_ready_grant(
    grants: &GrantStore,
) -> std::result::Result<DailyReferenceGrant, Cycle> {
    let grant = match grants.load_for_cycle() {
        Ok(Some(grant)) => grant,
        Ok(None) => return Err(Cycle::new(CycleOutcome::Disabled)),
        Err(reason) => {
            return Err(Cycle::with(
                CycleOutcome::Disabled,
                warning(
                    "codex_daily_aggregates_consent_unreadable",
                    &format!(
                        "Stored consent exists on this Mac but could not be used: {reason}. Nothing was collected."
                    ),
                ),
            ))
        }
    };
    if let Some(reason) = grant_runtime_block_reason(&grant) {
        return Err(Cycle::with(
            CycleOutcome::Disabled,
            warning(
                "codex_daily_aggregates_consent_not_runtime_ready",
                &format!(
                    "Stored consent exists but cannot collect on this Mac: {reason}. Nothing was read."
                ),
            ),
        ));
    }
    Ok(grant)
}

/// A runtime-ready consent that this cycle cannot act on yet. `reason` is a
/// closed code naming the missing local piece, never its contents.
pub(super) fn deferred(reason: &'static str) -> Cycle {
    Cycle::with(
        CycleOutcome::Deferred,
        warning(
            "codex_daily_aggregates_deferred",
            &format!(
                "Consent is ready but this Mac cannot collect yet: {reason}. Nothing was read."
            ),
        ),
    )
}

/// Why a login's attempt ends the whole tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TickStop {
    /// A grant-wide answer (429, not admitted, epoch conflict): the other
    /// logins wait for the next tick. The tick's summary is still saved.
    Grant,
    /// The off-switch or the consent changed under the tick: nothing more is
    /// read or recorded.
    Consent,
}

/// What one login's attempt did inside a tick.
struct AccountAttempt {
    cycle: Cycle,
    /// The closed status reason, or `None` to keep the account's previous
    /// one (the cadence gate has not elapsed).
    reason: Option<&'static str>,
    stop: Option<TickStop>,
}

impl AccountAttempt {
    fn next(cycle: Cycle, reason: &'static str) -> Self {
        Self {
            cycle,
            reason: Some(reason),
            stop: None,
        }
    }

    fn stop(cycle: Cycle, reason: &'static str, stop: TickStop) -> Self {
        Self {
            cycle,
            reason: Some(reason),
            stop: Some(stop),
        }
    }
}

/// One login's read inside a tick: every local gate is checked again, then
/// the attempt time is saved, and only then is at most one provider request
/// made with `login`'s own credential.
fn collect_account_once(
    collector: &Collector,
    tick: &TickContext<'_>,
    runtime: &Runtime,
    login: &CodexLogin,
    reader: &dyn ProviderDailyUsageReader,
    transport: &dyn DailyReferenceTransport,
    now: OffsetDateTime,
) -> AccountAttempt {
    let expected = tick.expected;
    let grants = &collector.grants;
    let state_store = &collector.state;
    if collector.network_disabled() {
        state_store.clear();
        return AccountAttempt::stop(
            network_disabled_cycle(),
            "network_disabled",
            TickStop::Consent,
        );
    }
    let grant = match runtime_ready_grant(grants) {
        Ok(grant) if same_binding(grant.backend_binding.as_ref(), expected) => grant,
        Ok(_) => {
            return AccountAttempt::stop(
                Cycle::with(
                    CycleOutcome::Disabled,
                    warning(
                        "codex_daily_aggregates_consent_changed",
                        "Consent changed during this tick; the remaining accounts wait for the next tick.",
                    ),
                ),
                "consent_changed",
                TickStop::Consent,
            )
        }
        Err(cycle) => return AccountAttempt::stop(cycle, "consent_changed", TickStop::Consent),
    };
    let Some(account_fingerprint) = grants
        .account_fingerprint_for(&login.credential.account_scope)
        .ok()
        .flatten()
    else {
        return AccountAttempt::stop(
            attribution_unavailable_cycle(),
            "consent_changed",
            TickStop::Consent,
        );
    };
    if grant.disclosure_version == DISCLOSURE_VERSION_V1
        && account_fingerprint != grant.account_fingerprint
    {
        return AccountAttempt::next(
            Cycle::with(
                CycleOutcome::Disabled,
                warning(
                    "codex_daily_aggregates_account_mismatch",
                    "The live Codex account is not the account this v1 consent covers; it is not read.",
                ),
            ),
            "not_covered_by_v1_consent",
        );
    }
    if grants
        .account_is_excluded(&account_fingerprint)
        .unwrap_or(false)
    {
        return AccountAttempt::next(
            Cycle::with(
                CycleOutcome::AccountExcluded,
                info(
                    "codex_daily_aggregates_account_excluded",
                    "This Codex account is excluded. No provider read or upload was attempted.",
                ),
            ),
            "excluded",
        );
    }

    let identity = state_identity_for_account(&grant, &account_fingerprint, false);
    let mut state = state_store.load(&identity);
    let now_seconds = unix_seconds(now);
    if breaker_is_open(&state, now_seconds) {
        return AccountAttempt::next(
            Cycle::with(
                CycleOutcome::CircuitOpen,
                warning(
                    "codex_daily_aggregates_circuit_open",
                    &format!(
                        "The Codex daily aggregate read is paused after repeated {} answers; it will retry after the cool-down.",
                        state.opened_by
                    ),
                ),
            ),
            "circuit_open",
        );
    }
    if !fetch_due(&state, &identity, now_seconds) {
        return AccountAttempt {
            cycle: Cycle::new(CycleOutcome::Noop),
            reason: None,
            stop: None,
        };
    }
    // The token may have lapsed since the login was read. It is never
    // refreshed here: an expired sign-in waits for Codex to renew it.
    if login.lapses_at <= now_seconds.saturating_add(logins::LAPSE_MARGIN_SECONDS) {
        return AccountAttempt::next(
            deferred(logins::LoginSkip::Expired.code()),
            logins::LoginSkip::Expired.reason(),
        );
    }

    // Admission: the attempt time is durable before the request, so every
    // outcome below is next due at the ordinary cadence. The same save clears
    // this account's series proof, so no older proof can outlive a newer
    // attempt. A failed save makes no request at all.
    let (window_start, window_end) = collection_window(now);
    state.last_fetch_epoch_seconds = now_seconds;
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.clone();
    state.last_seen_day = Some(date_string(now));
    state.account_fingerprint = Some(account_fingerprint.clone());
    state.home_kind = Some(login.home_kind.label().to_string());
    state.binding = Some(StateBinding::of(expected));
    state.proof = None;
    if state_store.save(&state).is_err() {
        return AccountAttempt::next(
            Cycle::with(
                CycleOutcome::Deferred,
                warning(
                    "codex_daily_aggregates_state_unwritable",
                    "The collector state could not be saved, so this account was not read.",
                ),
            ),
            "state_unwritable",
        );
    }

    let payload = match reader.fetch_window(&login.credential, &window_start, &window_end) {
        Ok(payload) => payload,
        Err(error) => {
            return provider_failure_attempt(
                grants,
                expected,
                state_store,
                state,
                &identity,
                error,
                now_seconds,
            )
        }
    };
    // A count above one anywhere in the answer means it is not this user's
    // own usage; nothing from it is uploaded.
    if max_user_count(&payload) > 1.0 {
        return provider_failure_attempt(
            grants,
            expected,
            state_store,
            state,
            &identity,
            ProviderReadError::WorkspaceWide,
            now_seconds,
        );
    }
    let normalized = match normalize_provider_window(&payload, &window_start, &window_end) {
        Ok(normalized) => normalized,
        Err(error) => {
            return provider_failure_attempt(
                grants,
                expected,
                state_store,
                state,
                &identity,
                error,
                now_seconds,
            )
        }
    };
    // The payload has served its purpose; nothing derived from it beyond the
    // normalized scalars may outlive this point.
    drop(payload);
    let normalized_row_count = normalized.rows.len();

    let mut diagnostics = Vec::new();
    if normalized.dropped_model_rows > 0 {
        diagnostics.push(info(
            "codex_daily_aggregates_model_slug_dropped",
            &format!(
                "{} provider model rows could not be expressed as a bounded model slug and were not uploaded.",
                normalized.dropped_model_rows
            ),
        ));
    }
    if normalized_row_count == 0 {
        diagnostics.push(info(
            "codex_daily_aggregates_zero_rows_explained",
            &format!(
                "The provider request succeeded but normalized zero rows; stage accounting: {}.",
                normalization_counter_summary(&normalized)
            ),
        ));
    }
    append_normalization_diagnostics(&normalized, &mut diagnostics);
    let failed = |diagnostics: Vec<AgentStatusDiagnostic>, outcome: CycleOutcome| Cycle {
        outcome,
        normalized_row_count: Some(normalized_row_count),
        diagnostics,
        accounts: Vec::new(),
    };

    // Another login of this tick already proved this exact series current
    // under this consent: the read is the same account seen twice, so it is
    // not uploaded again. Due again only at cadence; not a success.
    let digest = series_digest(&normalized.rows, &window_start, &window_end);
    if let Some(digest) = digest.as_deref() {
        if identical_series_owned_elsewhere(
            grants,
            state_store,
            tick,
            &identity,
            &window_start,
            &window_end,
            digest,
        ) {
            diagnostics.push(info(
                "codex_daily_aggregates_identical_series",
                "This Codex account returned the same series another account already uploaded this tick; it was not uploaded again.",
            ));
            return AccountAttempt::next(
                failed(diagnostics, CycleOutcome::Deferred),
                "identical_series",
            );
        }
    }

    let batches = match pack_batches(normalized.rows, &window_start, &window_end) {
        Ok(batches) => batches,
        Err(error) => {
            state.last_error_category = Some("row_budget_exceeded".to_string());
            let _ = state_store.save(&state);
            let _ = grants.record_health_for(expected, None, Some("row_budget_exceeded"));
            diagnostics.push(warning(
                "codex_daily_aggregates_row_budget_exceeded",
                &format!("The provider window did not fit the upload contract: {error}"),
            ));
            return AccountAttempt::next(
                failed(diagnostics, CycleOutcome::Failed),
                "upload_refused",
            );
        }
    };

    let collected_at = timestamp(now);
    // Disclosure v1 did not cover the account identity; only v2 carries it.
    let account_identity = if grant.disclosure_version == DISCLOSURE_VERSION {
        login.identity.clone()
    } else {
        None
    };

    // A full current-read proof: every batch acknowledged with none of its
    // rows superseded.
    let mut every_batch_current = true;
    for (coverage_start, coverage_end, rows) in batches {
        let row_count = rows.len();
        let batch = DailyReferenceBatch {
            schema_version: SCHEMA_VERSION,
            source: SOURCE,
            collector_id: COLLECTOR_ID,
            collector_version: compiled_release_version(),
            installation_id: runtime.installation_id.clone(),
            grant_scope_fingerprint: grant.grant_scope_fingerprint.clone(),
            account_fingerprint: account_fingerprint.clone(),
            grant_version: expected.grant_version,
            provider_day_timezone: PROVIDER_DAY_TIMEZONE,
            coverage_start: coverage_start.clone(),
            coverage_end: coverage_end.clone(),
            collected_at: collected_at.clone(),
            provider_data_refreshed_at: normalized.provider_data_refreshed_at.clone(),
            rows,
            account_identity: account_identity.clone(),
        };
        let payload = match serde_json::to_value(&batch) {
            Ok(payload) => payload,
            Err(error) => {
                diagnostics.push(warning(
                    "codex_daily_aggregates_batch_invalid",
                    &format!("The normalized batch could not be encoded: {error}"),
                ));
                return AccountAttempt::next(
                    failed(diagnostics, CycleOutcome::Failed),
                    "upload_refused",
                );
            }
        };
        // Last line of defence: refuse to send anything the contract's closed
        // vocabulary cannot describe, whatever the provider returned.
        if !wire_payload_is_content_free(&payload) {
            diagnostics.push(warning(
                "codex_daily_aggregates_batch_invalid",
                "The normalized batch failed the content-free check and was not uploaded.",
            ));
            state.last_error_category = Some("batch_not_content_free".to_string());
            let _ = state_store.save(&state);
            return AccountAttempt::next(
                failed(diagnostics, CycleOutcome::Failed),
                "upload_refused",
            );
        }

        match transport.send_batch(&payload) {
            Ok(receipt) => match validate_ack(
                &receipt,
                &expected.grant_id,
                &coverage_start,
                &coverage_end,
                row_count,
            ) {
                Ok(proof) => every_batch_current &= proof.current,
                Err(error) => {
                    diagnostics.push(warning(
                        "codex_daily_aggregates_ack_invalid",
                        &format!("The backend acknowledgement did not match the batch: {error}"),
                    ));
                    state.last_error_category = Some("ack_invalid".to_string());
                    let _ = state_store.save(&state);
                    return AccountAttempt::next(
                        failed(diagnostics, CycleOutcome::Failed),
                        "upload_failed",
                    );
                }
            },
            Err(UploadError::NotAdmitted(status)) => {
                // Expected until a reviewed backend change admits this build.
                // Not a provider failure, so the circuit breaker is untouched.
                state.last_error_category = Some("collector_not_admitted".to_string());
                let _ = state_store.save(&state);
                let _ = grants.record_health_for(expected, None, Some("collector_not_admitted"));
                diagnostics.push(info(
                    "codex_daily_aggregates_collector_not_admitted",
                    &format!(
                        "The backend has not admitted this collector build yet (HTTP {status}); nothing was stored."
                    ),
                ));
                return AccountAttempt::stop(
                    failed(diagnostics, CycleOutcome::NotAdmitted),
                    "upload_refused",
                    TickStop::Grant,
                );
            }
            Err(UploadError::AccountExcluded) => {
                // Backend ownership is authoritative. Persist only this opaque
                // label locally so the next cycle stops before another
                // provider read instead of retrying a non-retryable refusal.
                let _ = grants.set_account_excluded_for(expected, &account_fingerprint);
                state.last_error_category = Some("account_excluded".to_string());
                let _ = state_store.save(&state);
                let _ = grants.record_health_for(expected, None, Some("account_excluded"));
                diagnostics.push(info(
                    "codex_daily_aggregates_account_excluded",
                    "The backend excluded this Codex account. Future cycles stop before reading it until the customer includes it again.",
                ));
                return AccountAttempt::next(
                    failed(diagnostics, CycleOutcome::AccountExcluded),
                    "excluded",
                );
            }
            Err(error) => {
                state.last_error_category = Some(error.category().to_string());
                let _ = state_store.save(&state);
                let _ = grants.record_health_for(expected, None, Some(error.category()));
                diagnostics.push(warning(
                    "codex_daily_aggregates_upload_unavailable",
                    &format!(
                        "A Codex daily aggregate batch was not stored: {}",
                        error.category()
                    ),
                ));
                let cycle = failed(diagnostics, CycleOutcome::Failed);
                return match error {
                    UploadError::GrantEpochConflict => {
                        AccountAttempt::stop(cycle, "upload_refused", TickStop::Grant)
                    }
                    UploadError::ContractRejected(_) => {
                        AccountAttempt::next(cycle, "upload_refused")
                    }
                    _ => AccountAttempt::next(cycle, "upload_failed"),
                };
            }
        }
    }

    let diagnostic_code = if normalized_row_count == 0 {
        "codex_daily_aggregates_window_empty"
    } else {
        "codex_daily_aggregates_window_collected"
    };
    diagnostics.push(info(
        diagnostic_code,
        &format!(
            "Observed Codex daily aggregate window {window_start} through {window_end}; normalized {normalized_row_count} rows."
        ),
    ));
    let mut state = state_after_success(
        state,
        &identity,
        now_seconds,
        normalized_row_count,
        &window_start,
        &window_end,
    );
    // Only a full current-read proof may later stand for an identical series.
    state.proof = digest
        .filter(|_| every_batch_current)
        .map(|digest| SeriesProof {
            binding: StateBinding::of(expected),
            window_start: window_start.clone(),
            window_end: window_end.clone(),
            digest,
        });
    let _ = state_store.save(&state);
    let _ = grants.record_health_for(expected, Some(&collected_at), None);
    AccountAttempt::next(failed(diagnostics, CycleOutcome::Uploaded), "ok")
}

/// What every login of one tick shares.
struct TickContext<'a> {
    /// The binding the tick began with. Every write from inside the tick is
    /// guarded by it.
    expected: &'a BackendGrantBinding,
    /// State keys of every login this tick's discovery selected.
    selected: &'a BTreeSet<String>,
}

/// The largest `users` count anywhere in a provider answer: day totals,
/// clients, client and day models, unknown models, and days without a date
/// or outside the window. Above one, the answer is not one user's own usage.
pub(super) fn max_user_count(value: &Value) -> f64 {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                let own = if key == "users" {
                    value.as_f64().unwrap_or(0.0)
                } else {
                    0.0
                };
                own.max(max_user_count(value))
            })
            .fold(0.0, f64::max),
        Value::Array(items) => items.iter().map(max_user_count).fold(0.0, f64::max),
        _ => 0.0,
    }
}

/// A digest of one read's normalized series and window. An empty or
/// all-zero series has none: it can never stand for another account.
pub(super) fn series_digest(
    rows: &[DailyReferenceRow],
    window_start: &str,
    window_end: &str,
) -> Option<String> {
    let nonzero = rows.iter().any(|row| {
        row.credits_used
            .as_deref()
            .and_then(|credits| credits.parse::<f64>().ok())
            .is_some_and(|credits| credits != 0.0)
            || [
                row.uncached_input_tokens,
                row.cached_input_tokens,
                row.output_tokens,
                row.total_tokens,
                row.thread_count,
                row.turn_count,
            ]
            .into_iter()
            .flatten()
            .any(|counter| counter != 0)
    });
    if !nonzero {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:codex-daily-aggregates-series:");
    for part in [window_start, window_end] {
        hasher.update(part.as_bytes());
        hasher.update([0_u8]);
    }
    hasher.update(serde_json::to_vec(rows).ok()?);
    Some(hex(&hasher.finalize()))
}

/// Whether another account selected this tick holds a full current-read
/// proof of exactly this series and window under this consent, and is not
/// excluded.
fn identical_series_owned_elsewhere(
    grants: &GrantStore,
    state_store: &StateStore,
    tick: &TickContext<'_>,
    identity: &str,
    window_start: &str,
    window_end: &str,
    digest: &str,
) -> bool {
    let binding = StateBinding::of(tick.expected);
    state_store
        .load_file()
        .entries
        .iter()
        .any(|(owner, entry)| {
            owner != identity
                && tick.selected.contains(owner)
                && entry.proof.as_ref().is_some_and(|proof| {
                    proof.binding == binding
                        && proof.window_start == window_start
                        && proof.window_end == window_end
                        && proof.digest == digest
                })
                && entry
                    .account_fingerprint
                    .as_deref()
                    .is_some_and(|fingerprint| {
                        !grants.account_is_excluded(fingerprint).unwrap_or(true)
                    })
        })
}

/// [`record_provider_failure`] as an attempt: a 429 also ends the tick.
fn provider_failure_attempt(
    grants: &GrantStore,
    expected: &BackendGrantBinding,
    state_store: &StateStore,
    state: CollectorState,
    identity: &str,
    error: ProviderReadError,
    now: u64,
) -> AccountAttempt {
    let rate_limited = error == ProviderReadError::RateLimited;
    let workspace_wide = error == ProviderReadError::WorkspaceWide;
    let cycle = record_provider_failure(grants, expected, state_store, state, identity, error, now);
    let reason = if rate_limited {
        "rate_limited"
    } else if workspace_wide {
        "workspace_wide_answer"
    } else if cycle.outcome == CycleOutcome::CircuitOpen {
        "circuit_open"
    } else {
        "provider_unavailable"
    };
    AccountAttempt {
        cycle,
        reason: Some(reason),
        stop: rate_limited.then_some(TickStop::Grant),
    }
}

fn record_provider_failure(
    grants: &GrantStore,
    expected: &BackendGrantBinding,
    state_store: &StateStore,
    state: CollectorState,
    identity: &str,
    error: ProviderReadError,
    now: u64,
) -> Cycle {
    let category = error.category();
    let status = error
        .http_status()
        .map(|status| format!(" http_status={status}"))
        .unwrap_or_default();
    let Some(failure) = error.failure_class() else {
        // Transport and 5xx: record the reason, count nothing.
        let mut state = state;
        state.last_error_category = Some(category.to_string());
        let _ = state_store.save(&state);
        let _ = grants.record_health_for(expected, None, Some(category));
        return Cycle::with(
            CycleOutcome::Failed,
            warning(
                "codex_daily_aggregates_provider_read_failed",
                &format!(
                    "The Codex daily aggregate read failed: category={category}{status}; not counted toward a pause; retried at the next fetch."
                ),
            ),
        );
    };
    let was_open = breaker_is_open(&state, now);
    let state = state_after_failure(state, identity, failure, category, now);
    let _ = state_store.save(&state);
    let _ = grants.record_health_for(expected, None, Some(category));
    if breaker_is_open(&state, now) && !was_open {
        return Cycle::with(
            CycleOutcome::CircuitOpen,
            warning(
                "codex_daily_aggregates_circuit_open",
                &format!(
                    "The Codex daily aggregate read stopped after repeated {} answers; it will retry after the cool-down.",
                    failure.code()
                ),
            ),
        );
    }
    // Below the threshold the breaker says nothing yet, so the category is the
    // only early sign of a credential or route that has stopped working.
    let consecutive = match failure {
        ProviderFailure::AuthRejected => state.auth_failures,
        ProviderFailure::ResponseShape => state.shape_failures,
        ProviderFailure::RateLimited => state.rate_limit_failures,
    };
    Cycle::with(
        CycleOutcome::Failed,
        warning(
            "codex_daily_aggregates_provider_read_failed",
            &format!(
                "The Codex daily aggregate read failed: category={category}{status} consecutive={consecutive} pause_at={}; retried at the next fetch.",
                failure.threshold()
            ),
        ),
    )
}

/// What a valid acknowledgement proves about one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AckProof {
    /// No accepted row was superseded: the backend now holds this batch as
    /// the current series. An empty batch is current.
    pub(super) current: bool,
}

/// Check that a receipt acknowledges exactly this batch under this grant,
/// with self-consistent counts. Every count is checked; none is assumed.
pub(super) fn validate_ack(
    receipt: &Value,
    expected_grant_id: &str,
    coverage_start: &str,
    coverage_end: &str,
    row_count: usize,
) -> Result<AckProof> {
    let schema_version = receipt
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema_version != ACK_SCHEMA_VERSION {
        return Err(anyhow!("unexpected ack schema {schema_version}"));
    }
    if receipt.get("coverage_start").and_then(Value::as_str) != Some(coverage_start)
        || receipt.get("coverage_end").and_then(Value::as_str) != Some(coverage_end)
    {
        return Err(anyhow!("ack does not echo the declared coverage window"));
    }
    if receipt.get("grant_id").and_then(Value::as_str) != Some(expected_grant_id) {
        return Err(anyhow!("ack names a different grant"));
    }
    let count = |key: &str| {
        receipt
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("ack is missing {key}"))
    };
    let accepted = count("accepted_row_count")?;
    let stored = count("stored_row_count")?;
    let superseded = count("superseded_row_count")?;
    if u64::try_from(row_count).ok() != Some(accepted) {
        return Err(anyhow!("ack accepted a different number of rows"));
    }
    if accepted.checked_sub(stored) != Some(superseded) {
        return Err(anyhow!("ack row counts do not add up"));
    }
    Ok(AckProof {
        current: superseded == 0,
    })
}
