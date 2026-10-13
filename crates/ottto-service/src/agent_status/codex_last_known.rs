//! Last-known Codex meters for a failed probe, for local display only.
//!
//! A Codex home whose app-server probe fails (spawn error, JSON-RPC error,
//! timeout) has no reading of its own. This module keeps each account
//! binding's last fresh, bound reading in memory. The local status of the
//! same binding then shows those meters marked `Stale`, with their original
//! read clocks (`observed_at`, `grants_observed_at`) untouched, for at most
//! [`LAST_KNOWN_MAX_AGE_SECS`]. The reading is never uploaded: the server
//! keeps its own last good reading, and the upload copy strips stale meters
//! from a failed Codex read.
//!
//! The reading is keyed by the credential identity (account and workspace
//! hashes), the same key as the reset-grant cache, so a reading never moves
//! to another account. Callers additionally require that the failed home was
//! last validated as that binding and that its local credential still names
//! it, so a home that signed out or switched accounts shows nothing. Nothing
//! is persisted: after a daemon restart the first failure before any success
//! shows nothing.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ottto_protocol::{AgentCreditBalance, AgentQuotaWindow};

use super::mark_quota_meters_stale;

/// How long after its read a reading may still be shown as last-known.
///
/// Shorter than the Claude display fallback (24 h): a Codex reading's primary
/// window is five hours, so a reading older than one full window says little
/// about the account now.
pub(super) const LAST_KNOWN_MAX_AGE_SECS: u64 = 6 * 60 * 60;
/// Readings kept at most; the least recently read binding is evicted first.
const TRACKED_READINGS_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq)]
struct LastKnownReading {
    read_at: u64,
    quota_windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
}

#[derive(Debug, Default)]
pub(super) struct LastKnownCodexReadings {
    readings: BTreeMap<String, LastKnownReading>,
}

impl LastKnownCodexReadings {
    /// A fresh reading bound to `binding`, read at `now`.
    pub(super) fn record(
        &mut self,
        binding: &str,
        quota_windows: &[AgentQuotaWindow],
        credit_balances: &[AgentCreditBalance],
        now: u64,
    ) {
        if !self.readings.contains_key(binding) && self.readings.len() >= TRACKED_READINGS_MAX {
            if let Some(evict) = self
                .readings
                .iter()
                .min_by_key(|(_, reading)| reading.read_at)
                .map(|(key, _)| key.clone())
            {
                self.readings.remove(&evict);
            }
        }
        self.readings.insert(
            binding.to_string(),
            LastKnownReading {
                read_at: now,
                quota_windows: quota_windows.to_vec(),
                credit_balances: credit_balances.to_vec(),
            },
        );
    }

    /// The binding's last reading marked `Stale`, if it is at most
    /// [`LAST_KNOWN_MAX_AGE_SECS`] old.
    pub(super) fn stale_reading(
        &self,
        binding: &str,
        now: u64,
    ) -> Option<(Vec<AgentQuotaWindow>, Vec<AgentCreditBalance>)> {
        let reading = self.readings.get(binding)?;
        if now.saturating_sub(reading.read_at) > LAST_KNOWN_MAX_AGE_SECS {
            return None;
        }
        let mut quota_windows = reading.quota_windows.clone();
        let mut credit_balances = reading.credit_balances.clone();
        mark_quota_meters_stale(&mut quota_windows, &mut credit_balances);
        Some((quota_windows, credit_balances))
    }
}

fn readings() -> MutexGuard<'static, LastKnownCodexReadings> {
    static READINGS: OnceLock<Mutex<LastKnownCodexReadings>> = OnceLock::new();
    READINGS
        .get_or_init(|| Mutex::new(LastKnownCodexReadings::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Process-wide [`LastKnownCodexReadings::record`].
pub(super) fn record(
    binding: &str,
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
    now: u64,
) {
    readings().record(binding, quota_windows, credit_balances, now);
}

/// Process-wide [`LastKnownCodexReadings::stale_reading`].
pub(super) fn stale_reading(
    binding: &str,
    now: u64,
) -> Option<(Vec<AgentQuotaWindow>, Vec<AgentCreditBalance>)> {
    readings().stale_reading(binding, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::AgentQuotaWindowFreshness;

    fn window(observed_at: &str) -> AgentQuotaWindow {
        AgentQuotaWindow {
            name: "primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            observed_at: Some(observed_at.to_string()),
            used_percent: Some(42),
            ..Default::default()
        }
    }

    fn balance(observed_at: &str) -> AgentCreditBalance {
        AgentCreditBalance {
            name: "credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            observed_at: Some(observed_at.to_string()),
            remaining: Some(120),
            ..Default::default()
        }
    }

    #[test]
    fn a_recorded_reading_comes_back_stale_with_its_read_clocks() {
        let mut store = LastKnownCodexReadings::default();
        let windows = vec![window("2026-01-01T00:00:00Z")];
        let balances = vec![balance("2026-01-01T00:00:00Z")];
        store.record("a:w", &windows, &balances, 1_000);

        let (stale_windows, stale_balances) =
            store.stale_reading("a:w", 1_000 + 300).expect("last known");
        assert_eq!(stale_windows.len(), 1);
        assert_eq!(stale_balances.len(), 1);
        assert_eq!(stale_windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert_eq!(
            stale_balances[0].freshness,
            AgentQuotaWindowFreshness::Stale
        );
        assert_eq!(
            stale_windows[0].observed_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            stale_balances[0].observed_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        // Only freshness changes.
        let mut expected = windows[0].clone();
        expected.freshness = AgentQuotaWindowFreshness::Stale;
        assert_eq!(stale_windows[0], expected);
        let mut expected = balances[0].clone();
        expected.freshness = AgentQuotaWindowFreshness::Stale;
        assert_eq!(stale_balances[0], expected);
        // The stored reading itself stays fresh.
        assert_eq!(
            store.readings["a:w"].quota_windows[0].freshness,
            AgentQuotaWindowFreshness::Fresh
        );
    }

    #[test]
    fn a_reading_past_the_age_cap_is_not_shown() {
        let mut store = LastKnownCodexReadings::default();
        store.record("a:w", &[window("t")], &[balance("t")], 1_000);
        assert!(store
            .stale_reading("a:w", 1_000 + LAST_KNOWN_MAX_AGE_SECS)
            .is_some());
        assert!(store
            .stale_reading("a:w", 1_000 + LAST_KNOWN_MAX_AGE_SECS + 1)
            .is_none());
    }

    #[test]
    fn a_reading_never_moves_to_another_binding() {
        let mut store = LastKnownCodexReadings::default();
        store.record("a:w", &[window("t")], &[balance("t")], 1_000);
        assert!(store.stale_reading("b:w", 1_000).is_none());
        assert!(store.stale_reading("a:other", 1_000).is_none());
    }

    #[test]
    fn a_newer_reading_replaces_the_older_one() {
        let mut store = LastKnownCodexReadings::default();
        store.record("a:w", &[window("old")], &[], 1_000);
        store.record("a:w", &[window("new")], &[balance("new")], 2_000);
        let (windows, balances) = store.stale_reading("a:w", 2_000).expect("last known");
        assert_eq!(windows[0].observed_at.as_deref(), Some("new"));
        assert_eq!(balances.len(), 1);
    }

    #[test]
    fn the_least_recently_read_binding_is_evicted_at_the_bound() {
        let mut store = LastKnownCodexReadings::default();
        for index in 0..TRACKED_READINGS_MAX {
            store.record(
                &format!("a{index}:w"),
                &[window("t")],
                &[],
                1_000 + index as u64,
            );
        }
        store.record("new:w", &[window("t")], &[], 5_000);
        assert_eq!(store.readings.len(), TRACKED_READINGS_MAX);
        assert!(!store.readings.contains_key("a0:w"));
        assert!(store.readings.contains_key("a1:w"));
        assert!(store.readings.contains_key("new:w"));
    }
}
