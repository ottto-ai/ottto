//! One collection/upload owner per source, independent of transcript scans.
//! Provider adapters still own acquisition budgets and observation timestamps.
use crate::agent_status::{
    collect_agent_status_collection, AgentStatusCollection, CodexHomeBinding,
};
use crate::{LocalApiError, LocalDaemon};
use ottto_protocol::SourceKind;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const INTERVAL: Duration = Duration::from_secs(300);
const RETRY_DELAY: Duration = Duration::from_secs(60);
const EVENT_MIN_INTERVAL: Duration = Duration::from_secs(60);
const MANUAL_COALESCE: Duration = Duration::from_secs(1);
static OWNER: OnceLock<Owner> = OnceLock::new();

struct Owner {
    lanes: [Arc<StatusLane>; 3],
}

/// All times are elapsed monotonic durations. A late tick performs one pass,
/// never a catch-up burst. Completion cannot add another five minutes to a
/// normal pass; overruns/failures leave a bounded recovery wait.
#[derive(Default)]
struct StatusSchedule {
    next_due: Duration,
    retry_not_before: Duration,
    last_started: Option<Duration>,
    pending: bool,
}
impl StatusSchedule {
    fn deadline(&self) -> Duration {
        let due = if self.pending {
            self.last_started
                .map(|at| at + EVENT_MIN_INTERVAL)
                .unwrap_or_default()
                .min(self.next_due)
        } else {
            self.next_due
        };
        due.max(self.retry_not_before)
    }
    fn start(&mut self, now: Duration) {
        self.pending = false;
        self.last_started = Some(now);
        self.next_due = now + INTERVAL;
    }
    fn finish(&mut self, now: Duration, success: bool) {
        if self.next_due <= now {
            self.next_due = now + RETRY_DELAY;
        }
        if !success {
            self.retry_not_before = now + RETRY_DELAY;
            self.next_due = self.next_due.min(self.retry_not_before);
        } else {
            self.retry_not_before = Duration::ZERO;
        }
    }
}
#[derive(Default)]
struct LaneState {
    schedule: StatusSchedule,
    running: bool,
    collecting: bool,
    manual: bool,
    stopped: bool,
    generation: u64,
    collection: Option<Arc<AgentStatusCollection>>,
}
struct StatusLane {
    origin: Instant,
    state: Mutex<LaneState>,
    changed: Condvar,
}
impl StatusLane {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            state: Mutex::new(LaneState::default()),
            changed: Condvar::new(),
        }
    }
    fn request(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.stopped {
            state.schedule.pending = true;
            self.changed.notify_all();
        }
    }
    fn wake_if_stale(&self, now: Duration, wall_now: OffsetDateTime) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            return;
        }
        let stale = state
            .collection
            .as_ref()
            .and_then(|collection| {
                OffsetDateTime::parse(&collection.source_health_snapshot.captured_at, &Rfc3339).ok()
            })
            .map_or(true, |captured| {
                wall_now - captured >= TimeDuration::seconds(INTERVAL.as_secs() as i64)
            });
        if stale {
            // macOS monotonic clocks can pause during suspend. Use the real
            // collection clock only to detect overdue work; never rewrite it.
            state.schedule.next_due = now;
            state.schedule.last_started = None;
            state.schedule.pending = true;
            self.changed.notify_all();
        }
    }
    fn stop(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.stopped = true;
        self.changed.notify_all();
    }
    fn collection(&self, manual: bool) -> Result<Arc<AgentStatusCollection>, LocalApiError> {
        self.collection_at(self.origin.elapsed(), manual)
    }
    fn collection_at(
        &self,
        now: Duration,
        manual: bool,
    ) -> Result<Arc<AgentStatusCollection>, LocalApiError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            return Err(LocalApiError::LocalOperationFailed(
                "agent status refresh stopped".into(),
            ));
        }
        let age = state.schedule.last_started.map(|at| now.saturating_sub(at));
        if !state.collecting
            && (state.running && !manual
                || age.is_some_and(|age| age < if manual { MANUAL_COALESCE } else { INTERVAL }))
        {
            if let Some(collection) = &state.collection {
                return Ok(collection.clone());
            }
        }
        let generation = state.generation;
        // Concurrent callers share the in-flight collection. No new thread,
        // unbounded request queue or independent uploader is created.
        if !state.collecting {
            state.manual = true;
            self.changed.notify_all();
        }
        while !state.stopped && state.generation == generation {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.stopped {
            return Err(LocalApiError::LocalOperationFailed(
                "agent status refresh stopped".into(),
            ));
        }
        Ok(state.collection.as_ref().unwrap().clone())
    }
    /// Production worker and deterministic tests execute this same ownership
    /// boundary. Collection results are visible before the bounded HTTP upload.
    fn pass(
        &self,
        now: Duration,
        automatic_enabled: bool,
        collect: impl FnOnce() -> AgentStatusCollection,
        publish: impl FnOnce(&AgentStatusCollection) -> bool,
        finished_at: impl FnOnce() -> Duration,
    ) -> bool {
        let reused = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.stopped
                || state.running
                || !(state.manual || automatic_enabled && state.schedule.deadline() <= now)
            {
                return false;
            }
            // Transport retries reuse the exact collected body until the next
            // normal acquisition. A lost response cannot multiply provider
            // reads or change observed_at/captured_at on the retried body.
            let reuse = !state.manual
                && !state.schedule.pending
                && state.schedule.retry_not_before != Duration::ZERO
                && state
                    .schedule
                    .last_started
                    .is_some_and(|at| now < at + INTERVAL);
            let reused = if reuse {
                state.collection.clone()
            } else {
                None
            };
            state.manual = false;
            state.running = true;
            state.collecting = reused.is_none();
            if reused.is_none() {
                state.schedule.start(now);
            } else {
                state.schedule.next_due = state.schedule.last_started.unwrap() + INTERVAL;
                state.schedule.retry_not_before = Duration::ZERO;
            }
            reused
        };
        let collection = if let Some(collection) = reused {
            collection
        } else {
            let collection = Arc::new(collect());
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.collection = Some(collection.clone());
            state.generation += 1;
            state.collecting = false;
            self.changed.notify_all();
            collection
        };
        let stopped = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stopped;
        let success = !stopped && publish(&collection);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.running = false;
        state.schedule.finish(finished_at(), success);
        self.changed.notify_all();
        true
    }
}
fn index(source: &SourceKind) -> usize {
    match source {
        SourceKind::Codex => 0,
        SourceKind::ClaudeCode => 1,
        SourceKind::Pi => 2,
    }
}

pub fn start(daemon: LocalDaemon) -> anyhow::Result<()> {
    let owner = Owner {
        lanes: std::array::from_fn(|_| Arc::new(StatusLane::new())),
    };
    if OWNER.set(owner).is_err() {
        return Ok(());
    }
    for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
        let lane = OWNER.get().unwrap().lanes[index(&source)].clone();
        let daemon = daemon.clone();
        if let Err(error) = std::thread::Builder::new()
            .name(format!("ottto-status-{}", index(&source)))
            .spawn(move || run(lane, source, daemon))
        {
            stop();
            return Err(error.into());
        }
    }
    Ok(())
}
fn run(lane: Arc<StatusLane>, source: SourceKind, daemon: LocalDaemon) {
    loop {
        // Re-read ordinary device grants each pass; a disabled source is not
        // polled automatically. Manual diagnostics retain their old behavior.
        let enabled = crate::snapshot_sync::agent_status_source_enabled(&source);
        let began = Instant::now();
        lane.pass(lane.origin.elapsed(), enabled,
            || {
                let captured = OffsetDateTime::now_utc();
                let collection = collect_agent_status_collection(&source,
                    captured.format(&Rfc3339).unwrap_or_default(),
                    (captured + TimeDuration::minutes(15)).format(&Rfc3339).unwrap_or_default());
                let _ = daemon.record_agent_status_health(collection.source_health_snapshot.clone());
                collection
            },
            |collection| {
                let result = crate::snapshot_sync::upload_agent_status_snapshots(&collection.snapshots);
                eprintln!("agent status refresh: source={source:?} outcome={} duration_ms={} snapshots={}",
                    if result.is_ok() { "ok" } else { "error" }, began.elapsed().as_millis(), collection.snapshots.len());
                if let Err(error) = &result {
                    eprintln!("agent status refresh skipped: {}", crate::snapshot_sync::safe_error(error));
                }
                result.is_ok()
            }, || lane.origin.elapsed());
        let mut state = lane
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.stopped {
                return;
            }
            if state.manual {
                break;
            }
            // Recheck grants at most once a minute while unavailable. The wait
            // is interruptible by manual refresh, wake, registry changes, stop.
            let wait = if enabled {
                state
                    .schedule
                    .deadline()
                    .saturating_sub(lane.origin.elapsed())
            } else {
                RETRY_DELAY
            };
            if wait.is_zero() {
                break;
            }
            let (next, timeout) = lane
                .changed
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() {
                break;
            }
        }
    }
}
/// Use the existing scan's full collection (including all account/home bindings)
/// without starting an additional acquisition path. Standalone native callers
/// without daemon workers keep their original, upload-free collection behavior.
pub(crate) fn collection(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
    manual: bool,
) -> Result<Arc<AgentStatusCollection>, LocalApiError> {
    match OWNER.get() {
        Some(owner) => owner.lanes[index(source)].collection(manual),
        None => Ok(Arc::new(collect_agent_status_collection(
            source,
            captured_at,
            expires_at,
        ))),
    }
}
/// Revalidate the existing local auth-file witness immediately before binding
/// scanned sessions. A cached provider reading cannot attest a later login.
/// Missing/changed witnesses withhold new ownership; persisted session ownership
/// remains with ScanIndex. No provider read or parser change is involved.
pub(crate) fn current_codex_home_bindings(
    collection: &AgentStatusCollection,
) -> Vec<CodexHomeBinding> {
    collection
        .codex_home_bindings
        .iter()
        .filter(|binding| {
            std::fs::metadata(binding.home.join("auth.json"))
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|at| at == binding.auth_modified_at)
        })
        .map(|binding| CodexHomeBinding {
            home: binding.home.clone(),
            account_identifier_hash: binding.account_identifier_hash.clone(),
            workspace_identifier_hash: binding.workspace_identifier_hash.clone(),
            auth_modified_at: binding.auth_modified_at,
        })
        .collect()
}

/// Preserve exact session and lineage evidence in the status input while
/// withholding only a current-login fallback whose home witness changed.
pub(crate) fn status_for_reconciliation(
    status: &ottto_protocol::AgentStatusSnapshot,
    current_homes: &[CodexHomeBinding],
    login_changed: bool,
) -> ottto_protocol::AgentStatusSnapshot {
    let mut status = status.clone();
    let still_current = status.account.as_ref().is_some_and(|account| {
        current_homes.iter().any(|home| {
            account.account_identifier_hash.as_deref()
                == Some(home.account_identifier_hash.as_str())
                && account.organization_identifier_hash.as_deref()
                    == Some(home.workspace_identifier_hash.as_str())
        })
    });
    if login_changed && !still_current {
        status.account = None;
    }
    status
}

pub(crate) fn active() -> bool {
    OWNER.get().is_some()
}
pub fn request(source: &SourceKind) {
    if let Some(owner) = OWNER.get() {
        owner.lanes[index(source)].request();
    }
}
pub fn request_all() {
    if let Some(owner) = OWNER.get() {
        for lane in &owner.lanes {
            lane.wake_if_stale(lane.origin.elapsed(), OffsetDateTime::now_utc());
        }
    }
}
pub(crate) fn stop() {
    if let Some(owner) = OWNER.get() {
        for lane in &owner.lanes {
            lane.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{AgentStatusCollectionMethod, AgentStatusSnapshot, AgentStatusState};
    use std::sync::mpsc;

    fn specimen(source: SourceKind) -> AgentStatusCollection {
        let snapshot = AgentStatusSnapshot {
            source,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::ManualFallback,
            captured_at: "2026-10-05T00:00:00Z".into(),
            expires_at: "2026-10-05T00:15:00Z".into(),
            account: None,
            model: None,
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        };
        AgentStatusCollection {
            snapshots: vec![snapshot.clone()],
            source_health_snapshot: snapshot,
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        }
    }
    fn seconds(n: u64) -> Duration {
        Duration::from_secs(n)
    }
    fn pass(lane: &StatusLane, at: u64, end: u64, success: bool) -> bool {
        lane.pass(
            seconds(at),
            true,
            || specimen(SourceKind::Codex),
            |_| success,
            || seconds(end),
        )
    }
    #[test]
    fn app_absent_twenty_minute_scan_does_not_delay_status() {
        // Hold the actual lock used by sync_once for the entire fake-clock
        // twenty-minute window. The production lane pass never needs it.
        let _scan = crate::snapshot_sync::status_test_scan_lock();
        let lane = StatusLane::new();
        let mut starts = Vec::new();
        for now in 0..=1200 {
            if pass(&lane, now, now + 7, true) {
                starts.push(now);
            }
        }
        assert_eq!(starts, vec![0, 300, 600, 900, 1200]);
        assert_eq!(lane.state.lock().unwrap().generation, 5);
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(1500));
    }
    #[test]
    fn late_tick_and_overrun_skip_catchup_without_busy_loop() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 1200, true));
        assert!(!pass(&lane, 1200, 1200, true));
        assert!(!pass(&lane, 1259, 1259, true));
        assert!(pass(&lane, 1260, 1267, true));
        assert!(pass(&lane, 9000, 9007, true));
        assert!(!pass(&lane, 9008, 9008, true));
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(9300));
    }
    #[test]
    fn slow_provider_and_upload_do_not_block_another_source() {
        let slow = Arc::new(StatusLane::new());
        let fast = StatusLane::new();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = slow.clone();
        let handle = std::thread::spawn(move || {
            worker.pass(
                Duration::ZERO,
                true,
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    specimen(SourceKind::ClaudeCode)
                },
                |_| false,
                || seconds(1200),
            )
        });
        started_rx.recv_timeout(seconds(2)).unwrap();
        for now in [0, 300, 600, 900, 1200] {
            assert!(pass(&fast, now, now + 3, true));
        }
        assert!(!pass(&slow, 1200, 1200, true), "one flight per source");
        release_tx.send(()).unwrap();
        assert!(handle.join().unwrap());
        assert_eq!(fast.state.lock().unwrap().generation, 5);
        assert_eq!(slow.state.lock().unwrap().generation, 1);
    }
    #[test]
    fn manual_and_timer_share_collection_and_upload() {
        let lane = Arc::new(StatusLane::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = lane.clone();
        let handle = std::thread::spawn(move || {
            worker.pass(
                Duration::ZERO,
                true,
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    specimen(SourceKind::Codex)
                },
                |_| true,
                || seconds(7),
            )
        });
        started_rx.recv_timeout(seconds(2)).unwrap();
        let manual_lane = lane.clone();
        let manual = std::thread::spawn(move || manual_lane.collection(true).unwrap());
        assert!(!pass(&lane, 0, 0, true));
        release_tx.send(()).unwrap();
        let observed = manual.join().unwrap();
        assert!(handle.join().unwrap());
        let again = lane.collection(true).unwrap();
        assert!(Arc::ptr_eq(&observed, &again));
        assert_eq!(lane.state.lock().unwrap().generation, 1);
        assert!(!lane.state.lock().unwrap().manual);
    }
    #[test]
    fn event_storm_is_one_trailing_pass_and_wake_is_interruptible() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 7, true));
        for _ in 0..10000 {
            lane.request();
        }
        assert!(!pass(&lane, 59, 59, true));
        assert!(pass(&lane, 60, 67, true));
        assert!(!pass(&lane, 68, 68, true));
        // A wake after a long suspend needs one ordinary pass, no missed-tick
        // replay. The monotonic deadline and existing provider budget survive.
        lane.request();
        assert!(pass(&lane, 3600, 3607, true));
        assert!(!pass(&lane, 3608, 3608, true));
    }
    #[test]
    fn failed_or_lost_upload_retries_at_most_once_per_minute() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 15, false));
        for now in 16..75 {
            assert!(!pass(&lane, now, now, false));
        }
        assert!(pass(&lane, 75, 90, false));
        assert!(!pass(&lane, 149, 149, false));
        assert!(pass(&lane, 150, 157, true));
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(300));
    }
    #[test]
    fn frozen_monotonic_sleep_catches_up_once_on_wall_clock_wake() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 7, true));
        let wall = OffsetDateTime::parse("2026-10-05T00:30:00Z", &Rfc3339).unwrap();
        lane.wake_if_stale(seconds(10), wall);
        assert!(pass(&lane, 10, 17, true));
        assert!(!pass(&lane, 18, 18, true));
        assert_eq!(lane.state.lock().unwrap().generation, 2);
    }
    #[test]
    fn transport_retry_keeps_body_and_acquisition_budget() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 15, false));
        let original = lane.state.lock().unwrap().collection.clone().unwrap();
        assert!(lane.pass(
            seconds(75),
            true,
            || panic!("transport retry must not poll provider"),
            |collection| {
                assert_eq!(
                    serde_json::to_value(&collection.snapshots).unwrap(),
                    serde_json::to_value(&original.snapshots).unwrap()
                );
                false
            },
            || seconds(90)
        ));
        assert!(lane.pass(
            seconds(150),
            true,
            || panic!("lost-response retry must reuse body"),
            |_| true,
            || seconds(157)
        ));
        assert_eq!(lane.state.lock().unwrap().generation, 1);
        assert!(pass(&lane, 300, 307, true));
        assert_eq!(lane.state.lock().unwrap().generation, 2);
    }
    #[test]
    fn cached_provider_observation_and_all_accounts_are_unchanged() {
        let lane = StatusLane::new();
        let mut collection = specimen(SourceKind::ClaudeCode);
        let quota = serde_json::from_value(serde_json::json!({
            "name":"five_hour", "scope":"account", "status":"ok",
            "freshness":"fresh", "observed_at":"2026-10-04T23:30:00Z",
            "window_seconds":18000,"resets_at":"2026-10-05T04:30:00Z",
            "quota":null,"remaining":null,"used_percent":25,"left_percent":75
        }))
        .unwrap();
        collection.snapshots[0].quota_windows.push(quota);
        collection.snapshots[0].account = Some(serde_json::from_value(serde_json::json!({"login_state":"signed_in","confidence":"high","account_identifier_hash":"account-a"})).unwrap());
        let mut second = collection.snapshots[0].clone();
        second.account.as_mut().unwrap().account_identifier_hash = Some("account-b".into());
        second.captured_at = "2026-10-05T00:00:01Z".into();
        collection.snapshots.push(second);
        let before = serde_json::to_value(&collection.snapshots).unwrap();
        assert!(lane.pass(
            Duration::ZERO,
            true,
            || collection,
            |result| {
                assert_eq!(serde_json::to_value(&result.snapshots).unwrap(), before);
                true
            },
            || seconds(7)
        ));
        let cached = lane.collection(false).unwrap();
        assert_eq!(cached.snapshots.len(), 2);
        assert_eq!(
            cached.snapshots[0].quota_windows[0].observed_at.as_deref(),
            Some("2026-10-04T23:30:00Z")
        );
        assert_eq!(serde_json::to_value(&cached.snapshots).unwrap(), before);
    }
    #[test]
    fn disabled_source_is_not_polled_and_shutdown_cancels_waiters() {
        let lane = Arc::new(StatusLane::new());
        assert!(!lane.pass(
            Duration::ZERO,
            false,
            || panic!("disabled collection"),
            |_| panic!("disabled upload"),
            || seconds(1)
        ));
        let pending = lane.clone();
        let waiter = std::thread::spawn(move || pending.collection(true));
        lane.stop();
        assert!(waiter.join().unwrap().is_err());
        assert!(!pass(&lane, 300, 307, true));
    }
    #[test]
    fn stop_during_collection_prevents_upload() {
        let lane = Arc::new(StatusLane::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = lane.clone();
        let handle = std::thread::spawn(move || {
            worker.pass(
                Duration::ZERO,
                true,
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    specimen(SourceKind::Pi)
                },
                |_| panic!("shutdown must prevent a new upload"),
                || seconds(5),
            )
        });
        started_rx.recv_timeout(seconds(2)).unwrap();
        lane.stop();
        release_tx.send(()).unwrap();
        assert!(handle.join().unwrap());
        assert!(lane.collection(true).is_err());
    }

    #[test]
    fn cached_account_switch_withholds_old_binding_and_keeps_other_home() {
        let root = crate::test_scratch::ScratchDir::new("status-auth-switch");
        let home_a = root.join("a");
        let home_c = root.join("c");
        std::fs::create_dir(&home_a).unwrap();
        std::fs::create_dir(&home_c).unwrap();
        let binding = |home: &std::path::Path, account: &str| {
            let auth = home.join("auth.json");
            std::fs::write(&auth, account).unwrap();
            CodexHomeBinding {
                home: home.into(),
                account_identifier_hash: account.into(),
                workspace_identifier_hash: format!("{account}-workspace"),
                auth_modified_at: std::fs::metadata(auth).unwrap().modified().unwrap(),
            }
        };
        let mut collection = specimen(SourceKind::Codex);
        collection.codex_home_bindings =
            vec![binding(&home_a, "account-a"), binding(&home_c, "account-c")];
        assert_eq!(current_codex_home_bindings(&collection).len(), 2);
        std::thread::sleep(Duration::from_millis(2));
        std::fs::write(home_a.join("auth.json"), "account-b").unwrap();
        let valid = current_codex_home_bindings(&collection);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].account_identifier_hash, "account-c");
        std::fs::remove_file(home_c.join("auth.json")).unwrap();
        assert!(current_codex_home_bindings(&collection).is_empty());
    }
    #[test]
    fn startup_reconfirm_after_cold_collection_requests_new_generation() {
        let lane = Arc::new(StatusLane::new());
        assert!(lane.pass(
            Duration::ZERO,
            true,
            || {
                let mut cold = specimen(SourceKind::Codex);
                cold.source_health_snapshot.status = AgentStatusState::NotInstalled;
                cold
            },
            |_| true,
            || seconds(1)
        ));
        let requester = lane.clone();
        let result = std::thread::spawn(move || requester.collection_at(seconds(2), true).unwrap());
        let state = lane.state.lock().unwrap();
        let (state, timeout) = lane
            .changed
            .wait_timeout_while(state, seconds(2), |state| !state.manual)
            .unwrap();
        assert!(!timeout.timed_out());
        drop(state);
        assert!(pass(&lane, 2, 3, true));
        assert_eq!(
            result.join().unwrap().source_health_snapshot.status,
            AgentStatusState::Available
        );
        assert_eq!(lane.state.lock().unwrap().generation, 2);
    }
    #[test]
    fn aged_manual_request_during_upload_queues_one_fresh_collection() {
        let lane = Arc::new(StatusLane::new());
        let (uploaded_tx, uploaded_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = lane.clone();
        let handle = std::thread::spawn(move || {
            worker.pass(
                Duration::ZERO,
                true,
                || specimen(SourceKind::Codex),
                |_| {
                    uploaded_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    true
                },
                || seconds(7),
            )
        });
        uploaded_rx.recv_timeout(seconds(2)).unwrap();
        let requester = lane.clone();
        let request =
            std::thread::spawn(move || requester.collection_at(seconds(2), true).unwrap());
        let state = lane.state.lock().unwrap();
        let (state, timeout) = lane
            .changed
            .wait_timeout_while(state, seconds(2), |state| !state.manual)
            .unwrap();
        assert!(!timeout.timed_out());
        drop(state);
        release_tx.send(()).unwrap();
        assert!(handle.join().unwrap());
        assert!(pass(&lane, 8, 15, true));
        assert_eq!(
            request.join().unwrap().source_health_snapshot.status,
            AgentStatusState::Available
        );
        assert_eq!(lane.state.lock().unwrap().generation, 2);
        assert!(!pass(&lane, 16, 16, true));
    }
}
