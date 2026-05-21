use ottto_protocol::LocalCollectorState;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CadenceConfig {
    pub hot_min_interval: Duration,
    pub warm_interval: Duration,
    pub warm_window: Duration,
    pub idle_interval: Duration,
    pub cold_interval: Duration,
    pub full_sweep_interval: Duration,
    pub failure_backoffs: Vec<Duration>,
}

impl Default for CadenceConfig {
    fn default() -> Self {
        Self {
            hot_min_interval: Duration::from_secs(10),
            warm_interval: Duration::from_secs(60),
            warm_window: Duration::from_secs(15 * 60),
            idle_interval: Duration::from_secs(10 * 60),
            cold_interval: Duration::from_secs(30 * 60),
            full_sweep_interval: Duration::from_secs(6 * 60 * 60),
            failure_backoffs: vec![
                Duration::from_secs(60),
                Duration::from_secs(2 * 60),
                Duration::from_secs(5 * 60),
                Duration::from_secs(15 * 60),
                Duration::from_secs(60 * 60),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceCadence {
    config: CadenceConfig,
    state: LocalCollectorState,
    last_activity_at: Option<Instant>,
    last_scan_at: Option<Instant>,
    last_full_sweep_at: Option<Instant>,
    consecutive_failures: usize,
    disabled: bool,
}

impl SourceCadence {
    pub fn new(config: CadenceConfig) -> Self {
        Self {
            config,
            state: LocalCollectorState::Cold,
            last_activity_at: None,
            last_scan_at: None,
            last_full_sweep_at: None,
            consecutive_failures: 0,
            disabled: false,
        }
    }

    pub fn state(&self) -> LocalCollectorState {
        self.state.clone()
    }

    pub fn set_disabled(&mut self, disabled: bool) {
        self.disabled = disabled;
        if disabled {
            self.state = LocalCollectorState::Disabled;
        } else if self.state == LocalCollectorState::Disabled {
            self.state = LocalCollectorState::Cold;
        }
    }

    pub fn record_file_event(&mut self, now: Instant) {
        if self.disabled {
            return;
        }
        self.last_activity_at = Some(now);
        self.state = LocalCollectorState::Hot;
    }

    pub fn record_backend_hint(
        &mut self,
        now: Instant,
        record_count_15m: u64,
        last_data_is_newer_than_local_success: bool,
        reconciliation_enabled: bool,
    ) {
        self.set_disabled(!reconciliation_enabled);
        if self.disabled {
            return;
        }
        if record_count_15m > 0 || last_data_is_newer_than_local_success {
            self.last_activity_at = Some(now);
            self.state = LocalCollectorState::Warm;
        }
    }

    pub fn record_scan_success(&mut self, now: Instant, uploaded_count: u64) {
        if self.disabled {
            return;
        }
        self.last_scan_at = Some(now);
        self.consecutive_failures = 0;
        if uploaded_count > 0 {
            self.last_activity_at = Some(now);
            self.state = LocalCollectorState::Warm;
        } else if self
            .last_activity_at
            .is_some_and(|activity| now.duration_since(activity) <= self.config.warm_window)
        {
            self.state = LocalCollectorState::Warm;
        } else {
            self.state = LocalCollectorState::Idle;
        }
    }

    pub fn record_scan_failure(&mut self, now: Instant) {
        if self.disabled {
            return;
        }
        self.last_scan_at = Some(now);
        self.consecutive_failures += 1;
        self.state = LocalCollectorState::Failing;
    }

    pub fn record_full_sweep(&mut self, now: Instant) {
        self.last_full_sweep_at = Some(now);
    }

    pub fn next_scan_after(&self, now: Instant) -> Duration {
        if self.disabled {
            return self.config.cold_interval;
        }
        let interval = match self.state {
            LocalCollectorState::Hot => self.config.hot_min_interval,
            LocalCollectorState::Warm => self.config.warm_interval,
            LocalCollectorState::Idle => self.config.idle_interval,
            LocalCollectorState::Cold => self.config.cold_interval,
            LocalCollectorState::Failing => self.failure_backoff(),
            LocalCollectorState::Disabled => self.config.cold_interval,
        };
        let since_scan = self
            .last_scan_at
            .map(|last_scan| now.saturating_duration_since(last_scan));
        let cadence_due = remaining_after(interval, since_scan);

        let sweep_due = self
            .last_full_sweep_at
            .map(|last_sweep| {
                remaining_after(
                    self.config.full_sweep_interval,
                    Some(now.saturating_duration_since(last_sweep)),
                )
            })
            .unwrap_or(self.config.full_sweep_interval);
        cadence_due.min(sweep_due)
    }

    fn failure_backoff(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return self.config.failure_backoffs[0];
        }
        self.config
            .failure_backoffs
            .get(self.consecutive_failures.saturating_sub(1))
            .copied()
            .unwrap_or_else(|| {
                *self
                    .config
                    .failure_backoffs
                    .last()
                    .expect("failure backoff config cannot be empty")
            })
    }
}

fn remaining_after(interval: Duration, elapsed: Option<Duration>) -> Duration {
    match elapsed {
        Some(elapsed) if elapsed >= interval => Duration::ZERO,
        Some(elapsed) => interval - elapsed,
        None => Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_events_make_source_hot_then_success_warms_it() {
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::default());

        cadence.record_file_event(start);
        assert_eq!(cadence.state(), LocalCollectorState::Hot);
        assert_eq!(cadence.next_scan_after(start), Duration::ZERO);

        cadence.record_scan_success(start, 1);
        assert_eq!(cadence.state(), LocalCollectorState::Warm);
        assert_eq!(
            cadence.next_scan_after(start + Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn backend_activity_hint_warms_only_enabled_sources() {
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::default());

        cadence.record_backend_hint(start, 2, false, true);
        assert_eq!(cadence.state(), LocalCollectorState::Warm);

        cadence.record_backend_hint(start, 2, true, false);
        assert_eq!(cadence.state(), LocalCollectorState::Disabled);
    }

    #[test]
    fn failures_back_off_with_cap() {
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::default());

        cadence.record_scan_failure(start);
        assert_eq!(cadence.state(), LocalCollectorState::Failing);
        assert_eq!(
            cadence.next_scan_after(start + Duration::from_secs(10)),
            Duration::from_secs(50)
        );

        cadence.record_scan_failure(start + Duration::from_secs(60));
        assert_eq!(
            cadence.next_scan_after(start + Duration::from_secs(70)),
            Duration::from_secs(110)
        );
    }

    #[test]
    fn full_sweep_caps_idle_wait() {
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::default());
        cadence.record_full_sweep(start);
        cadence.record_scan_success(start, 0);

        assert_eq!(cadence.state(), LocalCollectorState::Idle);
        assert_eq!(
            cadence.next_scan_after(start + Duration::from_secs(6 * 60 * 60)),
            Duration::ZERO
        );
    }
}
