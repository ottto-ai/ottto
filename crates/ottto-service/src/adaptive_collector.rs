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

impl CadenceConfig {
    /// The cost-first tiers, which is the posture the snapshot sync loop uses.
    ///
    /// The difference from [`CadenceConfig::default`] is the point of the whole
    /// exercise: the **idle and cold tiers are the win** (a machine nobody is
    /// coding on today gets scanned every 30 minutes instead of every 5), while
    /// the hot 10-second freshness tier is deliberately NOT enabled. Freshness is
    /// already inside the product promise at the five-minute floor, and a
    /// ten-second tier multiplies request volume against a server whose accept
    /// path is the thing being redesigned.
    ///
    /// `hot_min_interval` and `warm_interval` are therefore both pinned to
    /// `floor`, so file activity restores the existing cadence and never beats it.
    /// The floor is a hard guarantee, not a default: it is what makes a 2-second
    /// filesystem debounce incapable of producing a per-event upload.
    pub fn cost_first(floor: Duration) -> Self {
        let default = Self::default();
        Self {
            hot_min_interval: floor,
            warm_interval: floor,
            idle_interval: default.idle_interval.max(floor),
            cold_interval: default.cold_interval.max(floor),
            ..default
        }
    }
}

/// How closely a cursor continuation page may follow the page before it.
///
/// The gap after a page is at least `idle_per_work` times that page's measured
/// work and never shorter than `min_gap`, so a run of continuation pages keeps
/// one thread busy at most `1 / (1 + idle_per_work)` of wall time. This bounds
/// wall-clock duty only; it is not a process CPU, IO or foreground-impact bound.
/// There is deliberately no upper clamp: a page slow enough that its gap reaches
/// the ordinary scan simply gets no continuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationPacing {
    pub min_gap: Duration,
    pub idle_per_work: u32,
}

/// A continuation asked for by a page that paused a still-valid job only
/// because its byte budget ran out. `work` is all of that page's measured work.
#[derive(Debug, Clone, Copy)]
struct ContinuationRequest {
    finished_at: Instant,
    work: Duration,
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
    server_min_interval: Option<Duration>,
    continuation: Option<ContinuationRequest>,
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
            server_min_interval: None,
            continuation: None,
        }
    }

    /// A server-requested minimum interval **between scans**, not a countdown.
    ///
    /// The distinction is the whole safety property. A relative "come back in five
    /// minutes" that is re-read on every cycle never elapses — each cycle would
    /// push the deadline another five minutes out and the scan would never run
    /// again, silently, on a healthy machine. Anchored to the last scan instead,
    /// the same repeated directive simply means "one scan per five minutes".
    pub fn set_server_min_interval(&mut self, interval: Option<Duration>) {
        self.server_min_interval = interval;
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

    /// The Hot tier's floor: the shortest gap the ordinary cadence ever takes.
    pub fn hot_min_interval(&self) -> Duration {
        self.config.hot_min_interval
    }

    /// The gap the ordinary cadence wants between scans right now: the tier
    /// floor, or the failure backoff while failing, lengthened by any server
    /// directive. It is a per-page lower bound of ordinary accrual, not
    /// coverage: ordinary cycle and lock delays are unbounded, and coverage
    /// for same-revision admission is the guard's.
    pub fn ordinary_interval(&self) -> Duration {
        if self.disabled {
            return self.config.cold_interval;
        }
        let tier = match self.state {
            LocalCollectorState::Hot => self.config.hot_min_interval,
            LocalCollectorState::Warm => self.config.warm_interval,
            LocalCollectorState::Idle => self.config.idle_interval,
            LocalCollectorState::Cold => self.config.cold_interval,
            LocalCollectorState::Failing => self.failure_backoff(),
            LocalCollectorState::Disabled => self.config.cold_interval,
        };
        // The server may ask for a longer gap between scans, never a shorter one:
        // it is a cost directive, and a server that could shorten it would be
        // asking the fleet to pay for the server's own load.
        match self.server_min_interval {
            Some(requested) => tier.max(requested),
            None => tier,
        }
    }

    /// Ask for a continuation page after a page that paused a still-valid,
    /// budget-exhausted job. Only that page may call this: refusal, busy or
    /// unknown outcomes clear instead, so they can never manufacture urgency.
    /// Returns whether the request stands; a disabled source takes none.
    pub fn request_continuation(&mut self, finished_at: Instant, work: Duration) -> bool {
        self.continuation = (!self.disabled).then_some(ContinuationRequest { finished_at, work });
        self.continuation.is_some()
    }

    pub fn clear_continuation(&mut self) {
        self.continuation = None;
    }

    /// The measured work of the page that asked for the pending continuation.
    pub fn continuation_work(&self) -> Option<Duration> {
        self.continuation.map(|request| request.work)
    }

    /// When the pending continuation page may run, or `None` when it should not
    /// run before the ordinary scan.
    ///
    /// The interval is `max(server minimum, failure backoff if failing,
    /// continuation gap)`, anchored to the later of the asking page and the last
    /// ordinary scan. The continuation therefore replaces only the Hot/Warm/Idle
    /// floor; a directive or a backoff still wins. Any overflow refuses the
    /// continuation rather than saturating into an early deadline. This never
    /// changes [`SourceCadence::next_scan_after`]: a continuation page is not an
    /// ordinary scan and does not move the ordinary eligibility clock. Neither
    /// does a continuation job's EOF completion: its caller saves the clock
    /// before the unchanged completion upload and restores it afterwards.
    pub fn continuation_due(&self, pacing: ContinuationPacing) -> Option<Instant> {
        if self.disabled {
            return None;
        }
        let request = self.continuation?;
        // An unscanned source is already due on the ordinary cadence.
        let last_scan = self.last_scan_at?;
        let gap = request
            .work
            .checked_mul(pacing.idle_per_work)?
            .max(pacing.min_gap);
        let mut interval = gap;
        if let Some(requested) = self.server_min_interval {
            interval = interval.max(requested);
        }
        if self.state == LocalCollectorState::Failing {
            interval = interval.max(self.failure_backoff());
        }
        let due = request.finished_at.max(last_scan).checked_add(interval)?;
        let ordinary_due = last_scan.checked_add(self.ordinary_interval())?;
        (due < ordinary_due).then_some(due)
    }

    pub fn next_scan_after(&self, now: Instant) -> Duration {
        if self.disabled {
            return self.config.cold_interval;
        }
        let interval = self.ordinary_interval();
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
    fn cost_first_disables_the_hot_tier_and_keeps_the_cheap_ones() {
        let floor = Duration::from_secs(5 * 60);
        let config = CadenceConfig::cost_first(floor);
        // No tier may ever ask for a cycle more often than the floor.
        assert_eq!(config.hot_min_interval, floor);
        assert_eq!(config.warm_interval, floor);
        assert!(config.idle_interval >= floor);
        assert!(config.cold_interval >= floor);
        // The cheap tiers are where the saving is, so they must stay LONGER than
        // the floor or this buys nothing.
        assert!(config.idle_interval > floor);
        assert!(config.cold_interval > config.idle_interval);
        // The sweep is untouched by the cost posture.
        assert_eq!(
            config.full_sweep_interval,
            CadenceConfig::default().full_sweep_interval
        );
    }

    #[test]
    fn cost_first_file_activity_restores_the_floor_and_never_beats_it() {
        let floor = Duration::from_secs(5 * 60);
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(floor));

        // An inactive source falls to the cheap tiers.
        let quiet = start + Duration::from_secs(20 * 60);
        cadence.record_scan_success(start, 0);
        cadence.record_scan_success(quiet, 0);
        assert_eq!(cadence.state(), LocalCollectorState::Idle);
        assert_eq!(
            cadence.next_scan_after(quiet),
            CadenceConfig::cost_first(floor).idle_interval
        );

        // A burst of filesystem events makes it hot — and hot still means the
        // floor, so no debounce can turn a busy transcript into per-event uploads.
        for offset in 0..50 {
            cadence.record_file_event(quiet + Duration::from_secs(offset));
        }
        assert_eq!(cadence.state(), LocalCollectorState::Hot);
        assert_eq!(
            cadence.next_scan_after(quiet + Duration::from_secs(60)),
            floor - Duration::from_secs(60),
            "a hot source is due at the floor, not before it"
        );
    }

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
    fn a_repeated_server_directive_cannot_starve_the_scan() {
        // The regression this guards: a relative directive re-read every cycle
        // pushes its own deadline forward forever, so the scan never runs again
        // and nothing looks wrong. Anchored to the last scan, a repeated
        // "come back in 10 minutes" just means one scan per 10 minutes.
        let start = Instant::now();
        let interval = Duration::from_secs(10 * 60);
        let mut cadence =
            SourceCadence::new(CadenceConfig::cost_first(Duration::from_secs(5 * 60)));
        cadence.record_scan_success(start, 1);

        for elapsed in [0u64, 60, 300, 599] {
            cadence.set_server_min_interval(Some(interval));
            let now = start + Duration::from_secs(elapsed);
            assert_eq!(
                cadence.next_scan_after(now),
                interval - Duration::from_secs(elapsed),
                "the directive must count down from the last scan"
            );
        }
        cadence.set_server_min_interval(Some(interval));
        assert_eq!(cadence.next_scan_after(start + interval), Duration::ZERO);

        // And it can only lengthen: a directive shorter than the tier is ignored.
        cadence.set_server_min_interval(Some(Duration::from_secs(1)));
        assert_eq!(
            cadence.next_scan_after(start),
            Duration::from_secs(5 * 60),
            "a short directive must not buy a faster scan"
        );
    }

    const PACING: ContinuationPacing = ContinuationPacing {
        min_gap: Duration::from_secs(30),
        idle_per_work: 9,
    };

    fn hot_scanned_at(start: Instant) -> SourceCadence {
        let mut cadence =
            SourceCadence::new(CadenceConfig::cost_first(Duration::from_secs(5 * 60)));
        cadence.record_scan_success(start, 1);
        cadence.record_file_event(start);
        cadence
    }

    #[test]
    fn a_continuation_request_never_moves_the_ordinary_cadence() {
        let start = Instant::now();
        let floor = Duration::from_secs(5 * 60);
        let mut cases = Vec::new();
        let mut hot = hot_scanned_at(start);
        cases.push(hot.clone());
        hot.set_server_min_interval(Some(Duration::from_secs(1800)));
        cases.push(hot);
        let mut idle = SourceCadence::new(CadenceConfig::cost_first(floor));
        idle.record_scan_success(start, 0);
        cases.push(idle);
        let mut failing = SourceCadence::new(CadenceConfig::cost_first(floor));
        failing.record_scan_failure(start);
        failing.record_scan_failure(start);
        cases.push(failing);
        cases.push(SourceCadence::new(CadenceConfig::cost_first(floor)));

        for ordinary in cases {
            let mut continued = ordinary.clone();
            continued.request_continuation(start + Duration::from_secs(5), Duration::from_secs(3));
            for offset in [0u64, 29, 30, 35, 120, 299, 300, 601, 1800, 7200] {
                let now = start + Duration::from_secs(offset);
                assert_eq!(
                    continued.next_scan_after(now),
                    ordinary.next_scan_after(now),
                    "a continuation must not change the ordinary schedule"
                );
                assert_eq!(continued.state(), ordinary.state());
            }
        }
    }

    #[test]
    fn the_continuation_replaces_only_the_tier_floor() {
        let start = Instant::now();
        let mut cadence = hot_scanned_at(start);
        assert_eq!(cadence.continuation_due(PACING), None, "nothing asked");

        // A 3 s page: the gap is the 30 s minimum, well inside the 300 s floor.
        let page_end = start + Duration::from_secs(4);
        cadence.request_continuation(page_end, Duration::from_secs(3));
        assert_eq!(
            cadence.continuation_due(PACING),
            Some(page_end + Duration::from_secs(30))
        );
        // A 10 s page: nine idle seconds per working second.
        cadence.request_continuation(page_end, Duration::from_secs(10));
        assert_eq!(
            cadence.continuation_due(PACING),
            Some(page_end + Duration::from_secs(90))
        );
        cadence.clear_continuation();
        assert_eq!(cadence.continuation_due(PACING), None);
    }

    #[test]
    fn a_server_directive_wins_over_the_continuation() {
        let start = Instant::now();
        let mut cadence = hot_scanned_at(start);
        cadence.request_continuation(start, Duration::from_secs(3));

        // 1800 s directive: the continuation can never run before the ordinary
        // scan, so there is none.
        cadence.set_server_min_interval(Some(Duration::from_secs(1800)));
        assert_eq!(cadence.continuation_due(PACING), None);

        // A directive shorter than the floor still lengthens the 30 s gap.
        cadence.set_server_min_interval(Some(Duration::from_secs(120)));
        assert_eq!(
            cadence.continuation_due(PACING),
            Some(start + Duration::from_secs(120))
        );
    }

    #[test]
    fn a_failure_backoff_wins_over_the_continuation() {
        let start = Instant::now();
        let mut cadence = hot_scanned_at(start);
        cadence.request_continuation(start, Duration::from_secs(3));
        // The ordinary pass after the continuation request failed.
        cadence.record_scan_failure(start + Duration::from_secs(10));
        assert_eq!(cadence.continuation_due(PACING), None);

        // Even a request made after the failure waits out the backoff.
        cadence.request_continuation(start + Duration::from_secs(20), Duration::from_secs(1));
        assert_eq!(cadence.continuation_due(PACING), None);
    }

    #[test]
    fn slow_pages_stay_inside_the_duty_bound_without_a_clamp() {
        let start = Instant::now();
        for work_secs in [1u64, 3, 10, 20, 30, 33, 34, 60, 600] {
            let mut cadence = hot_scanned_at(start);
            let work = Duration::from_secs(work_secs);
            let page_end = start + work;
            cadence.request_continuation(page_end, work);
            match cadence.continuation_due(PACING) {
                Some(due) => {
                    let gap = due - page_end;
                    assert!(gap >= PACING.min_gap);
                    assert!(
                        gap >= work * PACING.idle_per_work,
                        "{work_secs}s page: the gap must keep duty at or under 10 %"
                    );
                    assert!(due < start + Duration::from_secs(5 * 60));
                }
                // Here the duty gap reaches the ordinary scan; nothing is
                // clamped shorter to squeeze a continuation in.
                None => assert!(
                    page_end + work * PACING.idle_per_work >= start + Duration::from_secs(300)
                ),
            }
        }
    }

    #[test]
    fn continuation_arithmetic_overflow_refuses_instead_of_saturating() {
        let start = Instant::now();
        let mut cadence = hot_scanned_at(start);
        cadence.request_continuation(start, Duration::MAX);
        assert_eq!(cadence.continuation_due(PACING), None);

        // A never-scanned source is already due on the ordinary cadence.
        let mut fresh = SourceCadence::new(CadenceConfig::cost_first(Duration::from_secs(300)));
        fresh.request_continuation(start, Duration::from_secs(1));
        assert_eq!(fresh.continuation_due(PACING), None);

        // A disabled source takes no continuation at all.
        let mut disabled = hot_scanned_at(start);
        disabled.set_disabled(true);
        assert!(!disabled.request_continuation(start, Duration::from_secs(1)));
        assert_eq!(disabled.continuation_work(), None);
        assert_eq!(disabled.continuation_due(PACING), None);
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
