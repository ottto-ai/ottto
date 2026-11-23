//! Collector state per account read: the on-disk cadence and circuit-breaker
//! record, the per-tick discovery summary, and the pure functions that advance
//! them.

use super::batching::parse_day;
use super::grant::{BackendGrantBinding, DailyReferenceGrant};
use super::{
    atomic_json_write, logins, BREAKER_AUTH_THRESHOLD, BREAKER_COOLDOWN_SECONDS,
    BREAKER_RATE_LIMIT_THRESHOLD, BREAKER_SHAPE_THRESHOLD, FETCH_INTERVAL_JITTER_SECONDS,
    FETCH_INTERVAL_SECONDS, GRANT_DIR, PROVIDER_ENDPOINT, STATE_ENTRY_RETENTION_DAYS, STATE_FILE,
    STATE_FILE_SCHEMA_VERSION,
};
use crate::hex::encode as hex;
use anyhow::Result;
use ottto_core::default_support_dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use time::Duration as TimeDuration;

// ---------------------------------------------------------------------------
// Collector state: cadence, circuit breaker, covered window
// ---------------------------------------------------------------------------

/// Failure classes that open the breaker. Transport errors and 5xx are absent
/// on purpose: they say the network or the vendor had a bad moment, not that
/// we should stop asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    AuthRejected,
    ResponseShape,
    RateLimited,
}

impl ProviderFailure {
    pub fn code(self) -> &'static str {
        match self {
            ProviderFailure::AuthRejected => "auth_rejected",
            ProviderFailure::ResponseShape => "response_shape_changed",
            ProviderFailure::RateLimited => "rate_limited",
        }
    }

    pub(super) fn threshold(self) -> u32 {
        match self {
            ProviderFailure::AuthRejected => BREAKER_AUTH_THRESHOLD,
            ProviderFailure::ResponseShape => BREAKER_SHAPE_THRESHOLD,
            ProviderFailure::RateLimited => BREAKER_RATE_LIMIT_THRESHOLD,
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CollectorState {
    pub(super) schema_version: u16,
    #[serde(default)]
    pub(super) identity: String,
    #[serde(default)]
    pub(super) last_fetch_epoch_seconds: u64,
    #[serde(default)]
    pub(super) last_success_epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_observed_row_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_coverage_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_coverage_end: Option<String>,
    #[serde(default)]
    pub(super) auth_failures: u32,
    #[serde(default)]
    pub(super) shape_failures: u32,
    #[serde(default)]
    pub(super) rate_limit_failures: u32,
    #[serde(default)]
    pub(super) reopen_after_epoch_seconds: u64,
    #[serde(default)]
    pub(super) opened_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_error_category: Option<String>,
    /// The opaque account this entry reads. Never a provider identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) account_fingerprint: Option<String>,
    /// `default` or `slot`. Never a slot id or a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) home_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) binding: Option<StateBinding>,
    /// The last UTC day a discovery selected this account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_seen_day: Option<String>,
    /// The closed reason of this account's last evaluated attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_reason: Option<String>,
    /// Set only after a full current-read proof; cleared by the admission
    /// save of every newer attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) proof: Option<SeriesProof>,
}

/// One account's proof that the backend stored its whole series as current.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SeriesProof {
    pub(super) binding: StateBinding,
    pub(super) window_start: String,
    pub(super) window_end: String,
    pub(super) digest: String,
}

/// The consent epoch an entry or summary was written under.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StateBinding {
    pub(super) grant_id: String,
    pub(super) grant_version: u64,
}

impl StateBinding {
    pub(super) fn of(binding: &BackendGrantBinding) -> Self {
        Self {
            grant_id: binding.grant_id.clone(),
            grant_version: binding.grant_version,
        }
    }
}

/// What the last discovery under a binding found. Counts, closed reasons and
/// opaque labels only; status reads it instead of any credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DiscoverySummary {
    pub(super) binding: StateBinding,
    pub(super) complete: bool,
    /// State keys of the selected logins, in discovery order.
    #[serde(default)]
    pub(super) accounts: Vec<String>,
    #[serde(default)]
    pub(super) skipped: BTreeMap<String, u32>,
    #[serde(default)]
    pub(super) default_home: logins::DefaultHomeState,
}

/// The whole `state.json`: one entry per account read, and the latest
/// discovery.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CollectorStateFile {
    pub(super) schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) discovery: Option<DiscoverySummary>,
    #[serde(default)]
    pub(super) entries: BTreeMap<String, CollectorState>,
}

// State types format counts, timings and closed reasons only: never a
// fingerprint, binding id, state key or digest.

impl fmt::Debug for CollectorState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectorState")
            .field("last_fetch_epoch_seconds", &self.last_fetch_epoch_seconds)
            .field(
                "last_success_epoch_seconds",
                &self.last_success_epoch_seconds,
            )
            .field("auth_failures", &self.auth_failures)
            .field("shape_failures", &self.shape_failures)
            .field("rate_limit_failures", &self.rate_limit_failures)
            .field(
                "reopen_after_epoch_seconds",
                &self.reopen_after_epoch_seconds,
            )
            .field("last_error_category", &self.last_error_category)
            .field("home_kind", &self.home_kind)
            .field("last_reason", &self.last_reason)
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SeriesProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeriesProof")
            .field("window_start", &self.window_start)
            .field("window_end", &self.window_end)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StateBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateBinding")
            .field("grant_version", &self.grant_version)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DiscoverySummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoverySummary")
            .field("binding", &self.binding)
            .field("complete", &self.complete)
            .field("accounts", &self.accounts.len())
            .field("skipped", &self.skipped)
            .field("default_home", &self.default_home)
            .finish()
    }
}

impl fmt::Debug for CollectorStateFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectorStateFile")
            .field("schema_version", &self.schema_version)
            .field("discovery", &self.discovery)
            .field("entries", &self.entries.values().collect::<Vec<_>>())
            .finish()
    }
}

/// One selected login's bookkeeping at the end of a tick.
pub(super) struct SeenAccount {
    pub(super) identity: String,
    pub(super) account_fingerprint: String,
    pub(super) home_kind: &'static str,
    /// `None` keeps the entry's previous reason (not yet due, or the tick
    /// stopped before this login).
    pub(super) reason: Option<&'static str>,
}

/// Cadence and breaker state per account read, keyed to one grant epoch.
#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new(default_support_dir().join(GRANT_DIR).join(STATE_FILE))
    }
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The whole file. Unreadable, corrupt or another schema reads as empty.
    pub(super) fn load_file(&self) -> CollectorStateFile {
        let empty = CollectorStateFile {
            schema_version: STATE_FILE_SCHEMA_VERSION,
            ..CollectorStateFile::default()
        };
        let Ok(raw) = fs::read_to_string(&self.path) else {
            return empty;
        };
        match serde_json::from_str::<CollectorStateFile>(&raw) {
            Ok(file) if file.schema_version == STATE_FILE_SCHEMA_VERSION => file,
            _ => empty,
        }
    }

    /// Load one account's state. Any change to the account, the endpoint
    /// configuration, or the consent epoch is another identity and reads as a
    /// clean slate, so a prior verdict never carries across a change the
    /// customer made.
    pub(super) fn load(&self, identity: &str) -> CollectorState {
        self.load_file()
            .entries
            .remove(identity)
            .unwrap_or_default()
    }

    /// Save one account's state under its identity; other entries are kept.
    pub(super) fn save(&self, state: &CollectorState) -> Result<()> {
        let mut file = self.load_file();
        file.entries.insert(state.identity.clone(), state.clone());
        atomic_json_write(&self.path, &file)
    }

    /// End-of-tick bookkeeping: the discovery summary, each selected entry's
    /// last-seen day and reason, and (after a complete discovery) pruning.
    /// Writes only when something changed.
    pub(super) fn record_tick(
        &self,
        summary: DiscoverySummary,
        seen: &[SeenAccount],
        today: &str,
    ) -> Result<()> {
        let before = self.load_file();
        let mut file = before.clone();
        for account in seen {
            let entry = file.entries.entry(account.identity.clone()).or_default();
            entry.schema_version = STATE_FILE_SCHEMA_VERSION;
            entry.identity = account.identity.clone();
            entry.account_fingerprint = Some(account.account_fingerprint.clone());
            entry.home_kind = Some(account.home_kind.to_string());
            entry.binding = Some(summary.binding.clone());
            entry.last_seen_day = Some(today.to_string());
            if let Some(reason) = account.reason {
                entry.last_reason = Some(reason.to_string());
            }
        }
        if summary.complete {
            let oldest_kept = parse_day(today)
                .and_then(|day| day.checked_sub(TimeDuration::days(STATE_ENTRY_RETENTION_DAYS)));
            file.entries.retain(|_, entry| {
                entry
                    .last_seen_day
                    .as_deref()
                    .and_then(parse_day)
                    .zip(oldest_kept)
                    .is_some_and(|(seen, oldest)| seen >= oldest)
            });
        }
        file.discovery = Some(summary);
        if file == before {
            return Ok(());
        }
        atomic_json_write(&self.path, &file)
    }

    pub(super) fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Identity the breaker and cadence are keyed by: the grant epoch plus the
/// call's own configuration.
#[cfg(test)]
pub(super) fn state_identity(grant: &DailyReferenceGrant, sentinel_disabled: bool) -> String {
    state_identity_for_account(grant, &grant.account_fingerprint, sentinel_disabled)
}

pub(super) fn state_identity_for_account(
    grant: &DailyReferenceGrant,
    account_fingerprint: &str,
    sentinel_disabled: bool,
) -> String {
    let binding = grant
        .backend_binding
        .as_ref()
        .map(|binding| (binding.grant_id.as_str(), binding.grant_version))
        .unwrap_or(("", 0));
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:codex-daily-aggregates-identity:");
    for part in [
        account_fingerprint,
        grant.grant_scope_fingerprint.as_str(),
        binding.0,
        &binding.1.to_string(),
        PROVIDER_ENDPOINT,
        &crate::agent_status::ottto_user_agent(),
        if sentinel_disabled { "off" } else { "on" },
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0_u8]);
    }
    hex(&hasher.finalize())[..32].to_string()
}

pub(super) fn breaker_is_open(state: &CollectorState, now: u64) -> bool {
    now < state.reopen_after_epoch_seconds
}

/// Fold one failure into the breaker. Pure so the thresholds are testable
/// without a network or a clock.
pub(super) fn state_after_failure(
    mut state: CollectorState,
    identity: &str,
    failure: ProviderFailure,
    category: &str,
    now: u64,
) -> CollectorState {
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.to_string();
    state.last_error_category = Some(category.to_string());
    let counter = match failure {
        ProviderFailure::AuthRejected => &mut state.auth_failures,
        ProviderFailure::ResponseShape => &mut state.shape_failures,
        ProviderFailure::RateLimited => &mut state.rate_limit_failures,
    };
    *counter = counter.saturating_add(1);
    if *counter >= failure.threshold() && !breaker_is_open(&state, now) {
        state.reopen_after_epoch_seconds = now.saturating_add(BREAKER_COOLDOWN_SECONDS);
        state.opened_by = failure.code().to_string();
    }
    state
}

/// Clear the failure counters after one clean answer. The thresholds are about
/// *consecutive* failures.
pub(super) fn state_after_success(
    mut state: CollectorState,
    identity: &str,
    now: u64,
    observed_row_count: usize,
    coverage_start: &str,
    coverage_end: &str,
) -> CollectorState {
    state.schema_version = STATE_FILE_SCHEMA_VERSION;
    state.identity = identity.to_string();
    state.auth_failures = 0;
    state.shape_failures = 0;
    state.rate_limit_failures = 0;
    state.reopen_after_epoch_seconds = 0;
    state.opened_by = String::new();
    state.last_error_category = None;
    state.last_success_epoch_seconds = now;
    state.last_observed_row_count = Some(observed_row_count);
    state.last_coverage_start = Some(coverage_start.to_string());
    state.last_coverage_end = Some(coverage_end.to_string());
    state
}

/// Deterministic 5h45m-6h15m gate.
///
/// The spread is load-spreading across our own installs so every Ottto machine
/// does not wake on the same wall-clock minute. It is derived from the grant
/// identity rather than redrawn per tick, so a machine holds one steady phase,
/// and it hides nothing: the request identifies itself honestly and a
/// timer-driven daemon is recognizable from its behaviour regardless of phase.
pub(super) fn fetch_interval_seconds(identity: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:codex-daily-aggregates-cadence:");
    hasher.update(identity.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let span = FETCH_INTERVAL_JITTER_SECONDS * 2 + 1;
    let offset = u64::from_be_bytes(bytes) % span;
    FETCH_INTERVAL_SECONDS + offset - FETCH_INTERVAL_JITTER_SECONDS
}

pub(super) fn fetch_due(state: &CollectorState, identity: &str, now: u64) -> bool {
    now.saturating_sub(state.last_fetch_epoch_seconds) >= fetch_interval_seconds(identity)
}
