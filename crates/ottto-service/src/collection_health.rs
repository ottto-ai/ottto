//! Local scan observations in the existing per-source collector state. No scheduling effects.
use std::time::{Duration, Instant};

use ottto_protocol::{SourceCollectionHealth, SourceCollectionState};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone)]
pub(crate) struct Pulse {
    baseline: Instant,
    completed: Option<(Instant, String)>,
    backoff_until: Option<Instant>,
    offline: bool,
}

impl Pulse {
    pub(crate) fn start() -> Self {
        Self {
            baseline: crate::scan_clock::now(),
            completed: None,
            backoff_until: None,
            offline: false,
        }
    }

    pub(crate) fn complete(&mut self, at: &str) {
        let now = crate::scan_clock::now();
        self.completed = Some((now, at.to_owned()));
        // An independent upload lane may have shed while this scan was running.
        self.backoff_until = self.backoff_until.filter(|end| *end > now);
        self.offline = false;
    }

    pub(crate) fn defer(&mut self, deadline: Instant) {
        self.backoff_until = Some(self.backoff_until.map_or(deadline, |old| old.max(deadline)));
    }

    pub(crate) fn prepare_outcome(&mut self, error: Option<&anyhow::Error>) {
        use crate::net_resilience::{transport_signal_from_error, TransportSignal};
        self.offline = error.is_some_and(|error| {
            matches!(
                transport_signal_from_error(error),
                TransportSignal::TransportFailure | TransportSignal::Neutral
            )
        });
    }

    pub(crate) fn project(&self, planned: Duration, wall: &str) -> SourceCollectionHealth {
        let now = crate::scan_clock::now();
        let baseline = self
            .completed
            .as_ref()
            .map_or(self.baseline, |(at, _)| *at)
            .max(self.baseline);
        let baseline = self.backoff_until.map_or(baseline, |end| baseline.max(end));
        let threshold =
            Duration::from_secs(60 * 60).max(planned.saturating_add(Duration::from_secs(30 * 60)));
        let backoff = self.backoff_until.filter(|end| *end > now);
        let state = if now.saturating_duration_since(baseline) > threshold {
            SourceCollectionState::Stalled
        } else if backoff.is_some() {
            SourceCollectionState::ServerBackoff
        } else if self.offline {
            SourceCollectionState::Offline
        } else {
            SourceCollectionState::Collecting
        };
        let until = backoff.and_then(|end| {
            OffsetDateTime::parse(wall, &Rfc3339)
                .ok()?
                .checked_add(time::Duration::try_from(end.duration_since(now)).ok()?)?
                .format(&Rfc3339)
                .ok()
        });
        SourceCollectionHealth {
            state,
            last_scan_at: self.completed.as_ref().map(|(_, at)| at.clone()),
            until,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive_collector::{CadenceConfig, SourceCadence};
    use crate::scan_clock::with_clock;
    use SourceCollectionState::{Collecting, Offline, ServerBackoff, Stalled};

    const WALL: &str = "2026-11-15T10:00:00Z";

    fn error(family: &'static str) -> anyhow::Error {
        crate::snapshot_client::UploadFailureDiagnostics::for_test(
            "local snapshot scan",
            "activity_hint",
            family,
            true,
            false,
        )
        .into()
    }

    #[test]
    fn pulse_completes_empty_scans_and_allows_the_full_failure_ladder() {
        with_clock(0, || {
            let mut cadence = SourceCadence::new(CadenceConfig::default());
            let mut pulse = Pulse::start();
            let health = pulse.project(cadence.ordinary_interval(), WALL);
            assert_eq!(health.state, Collecting);
            assert!(health.last_scan_at.is_none());
            assert!(health.until.is_none());
            pulse.complete(WALL); // Zero sessions, regardless of cache-write outcome.
            assert_eq!(
                pulse
                    .project(cadence.ordinary_interval(), WALL)
                    .last_scan_at
                    .as_deref(),
                Some(WALL)
            );
            for failures in 0..=5 {
                if failures > 0 {
                    cadence.record_scan_failure(crate::scan_clock::now());
                }
                let threshold = Duration::from_secs(3600)
                    .max(cadence.ordinary_interval() + Duration::from_secs(1800))
                    .as_secs();
                with_clock(threshold, || {
                    assert_eq!(
                        pulse.project(cadence.ordinary_interval(), WALL).state,
                        Collecting,
                        "failures: {failures}"
                    )
                });
                with_clock(threshold + 1, || {
                    assert_eq!(
                        pulse.project(cadence.ordinary_interval(), WALL).state,
                        Stalled,
                        "failures: {failures}"
                    )
                });
            }
            assert_eq!(cadence.ordinary_interval().as_secs(), 3600);
            // Upload work failing after reconciliation cannot erase the scan fact.
            assert_eq!(
                pulse
                    .project(cadence.ordinary_interval(), WALL)
                    .last_scan_at
                    .as_deref(),
                Some(WALL)
            );
        });
    }

    #[test]
    fn pulse_projects_backoff_with_an_awake_clock_and_resets_on_completion() {
        with_clock(0, || {
            let mut pulse = Pulse::start();
            pulse.defer(crate::scan_clock::now() + Duration::from_secs(1800));
            pulse.defer(crate::scan_clock::now() + Duration::from_secs(60));
            let status = pulse.project(Duration::ZERO, WALL);
            assert_eq!(status.state, ServerBackoff);
            assert_eq!(status.until.as_deref(), Some("2026-11-15T10:30:00Z"));
            // Simulated Mac sleep: wall time jumps but scan_clock has not advanced.
            let after_sleep = pulse.project(Duration::ZERO, "2026-11-16T10:00:00Z");
            assert_eq!(after_sleep.state, ServerBackoff);
            assert_eq!(after_sleep.until.as_deref(), Some("2026-11-16T10:30:00Z"));
            with_clock(60, || {
                let completed_at = "2026-11-15T10:01:00Z";
                pulse.complete(completed_at);
                let status = pulse.project(Duration::ZERO, completed_at);
                assert_eq!(status.state, ServerBackoff, "concurrent shed");
                assert_eq!(status.until.as_deref(), Some("2026-11-15T10:30:00Z"));
                assert_eq!(status.last_scan_at.as_deref(), Some(completed_at));
            });
            with_clock(1800, || {
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Collecting);
                assert!(pulse.project(Duration::ZERO, WALL).until.is_none());
            });
            with_clock(5400, || {
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Collecting)
            });
            with_clock(5401, || {
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Stalled)
            });
            with_clock(6000, || {
                pulse.complete(WALL);
                let status = pulse.project(Duration::ZERO, WALL);
                assert_eq!(status.state, Collecting);
                assert!(status.until.is_none());
            });
        });
    }

    #[test]
    fn pulse_classifies_transport_and_recovers_without_masking_stalls() {
        with_clock(0, || {
            let mut pulse = Pulse::start();
            for family in ["transport_connection", "transport_timeout", "transport_dns"] {
                pulse.prepare_outcome(Some(&error(family)));
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Offline);
                with_clock(3601, || {
                    assert_eq!(pulse.project(Duration::ZERO, WALL).state, Stalled)
                });
                pulse.complete(WALL);
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Collecting);
            }
            for family in ["http_401", "http_500", "decode_error"] {
                pulse.prepare_outcome(Some(&error("transport_connection")));
                pulse.prepare_outcome(Some(&error(family)));
                assert_eq!(pulse.project(Duration::ZERO, WALL).state, Collecting);
                with_clock(3601, || {
                    assert_eq!(pulse.project(Duration::ZERO, WALL).state, Stalled)
                });
            }
            pulse.prepare_outcome(Some(&error("transport_connection")));
            pulse.prepare_outcome(None);
            assert_eq!(pulse.project(Duration::ZERO, WALL).state, Collecting);
        });
    }
}
