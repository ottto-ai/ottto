//! One collection/upload owner per source, independent of transcript scans.
//! Provider adapters still own acquisition budgets and observation timestamps.
use crate::agent_status::{
    claude_next_reset_read_at, collect_agent_status_collection, AgentStatusCollection,
    CodexHomeBinding,
};
use crate::{LocalApiError, LocalDaemon};
use ottto_protocol::SourceKind;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const INTERVAL: Duration = Duration::from_secs(300);
const RETRY_DELAY: Duration = Duration::from_secs(60);
const EVENT_MIN_INTERVAL: Duration = Duration::from_secs(60);
const MANUAL_COALESCE: Duration = Duration::from_secs(1);
/// A reset-read pass starts this long after the read falls due, so the
/// binding's own due check (wall clock) has passed by then.
const RESET_READ_MARGIN: Duration = Duration::from_secs(5);
static OWNER: Mutex<Option<Arc<Owner>>> = Mutex::new(None);

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
    started: bool,
    running: bool,
    collecting: bool,
    collection_failed: bool,
    manual: bool,
    /// Start of the last saved-only pass an app's request ran
    /// ([`StatusLane::app_passes_saved_only`]); the schedule ignores it.
    last_app_pass: Option<Duration>,
    /// The lane ran its first provider-reading pass since daemon start.
    /// Unlike `schedule.last_started`, a wake never clears it.
    startup_pass_ran: bool,
    stopped: bool,
    generation: u64,
    collection: Option<Arc<AgentStatusCollection>>,
}
struct StatusLane {
    origin: Instant,
    /// Claude: a pass an app's request starts serves stored provider readings,
    /// leaves the timer alone and uploads nothing. Provider reads come from
    /// the lane's own passes, which also run without an upload grant.
    app_passes_saved_only: bool,
    state: Mutex<LaneState>,
    changed: Condvar,
}
impl StatusLane {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            app_passes_saved_only: false,
            state: Mutex::new(LaneState::default()),
            changed: Condvar::new(),
        }
    }
    fn for_source(source: &SourceKind) -> Self {
        Self {
            app_passes_saved_only: *source == SourceKind::ClaudeCode,
            ..Self::new()
        }
    }
    // Workers cannot acquire or publish until every source has spawned.
    fn wait_started(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = self
            .changed
            .wait_while(state, |state| !state.started && !state.stopped)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.stopped
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
    /// Bring the next pass forward to a Claude reset read due `due_in` from
    /// `now`, when that is sooner than the regular interval. Callers pass only
    /// a read still ahead, so an unread reset never turns into back-to-back
    /// passes; failure delays still apply through `deadline`.
    fn run_by(&self, now: Duration, due_in: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let at = now + due_in + RESET_READ_MARGIN;
        if at < state.schedule.next_due {
            state.schedule.next_due = at;
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
    /// A pure peek: never wait for a pass, notify a worker, or acquire evidence.
    fn cached(&self) -> Option<Arc<AgentStatusCollection>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            None
        } else {
            state.collection.clone()
        }
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
        // Automatic scans must not promote a failed scheduled acquisition to
        // a manual refresh that bypasses its failure delay. An explicit manual
        // caller can still request recovery, and callers share an active pass.
        if !manual
            && state.collection_failed
            && !state.collecting
            && now < state.schedule.retry_not_before
        {
            return Err(LocalApiError::LocalOperationFailed(
                "agent status acquisition failed".into(),
            ));
        }
        let age = state
            .schedule
            .last_started
            .max(state.last_app_pass)
            .map(|at| now.saturating_sub(at));
        if !state.collecting
            && !state.collection_failed
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
        if state.collection_failed {
            return Err(LocalApiError::LocalOperationFailed(
                "agent status acquisition failed".into(),
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
        let (reused, app_only, first_pass) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let due = automatic_enabled && state.schedule.deadline() <= now;
            if state.stopped || state.running || !(state.manual || due) {
                return false;
            }
            // Only an app's request: saved readings, and the timer keeps its
            // time. A request that meets a due pass is that pass.
            let app_only = self.app_passes_saved_only && !due;
            // Transport retries reuse the exact collected body until the next
            // normal acquisition. A lost response cannot multiply provider
            // reads or change observed_at/captured_at on the retried body.
            let reuse = !state.collection_failed
                && !state.manual
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
            let first_pass = !app_only && !state.startup_pass_ran;
            state.startup_pass_ran |= first_pass;
            if app_only {
                state.last_app_pass = Some(now);
            } else if reused.is_none() {
                state.schedule.start(now);
            } else {
                state.schedule.next_due = state.schedule.last_started.unwrap() + INTERVAL;
                state.schedule.retry_not_before = Duration::ZERO;
            }
            (reused, app_only, first_pass)
        };
        let collection = if let Some(collection) = reused {
            collection
        } else {
            let started_at = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0);
            let collect = || {
                let collect =
                    || crate::agent_status::with_claude_pass(app_only, started_at, collect);
                // The provider calls of the first pass after daemon start
                // are its startup burst, not its steady cadence.
                if first_pass {
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::Startup,
                        collect,
                    )
                } else {
                    collect()
                }
            };
            let collection = match catch_unwind(AssertUnwindSafe(collect)) {
                Ok(collection) => Arc::new(collection),
                Err(_) => {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.running = false;
                    state.collecting = false;
                    state.collection_failed = true;
                    // Release this acquisition's waiters without replacing or
                    // re-dating the last good collection. The existing worker
                    // reacquires after the ordinary failure delay.
                    state.generation += 1;
                    if !app_only {
                        state.schedule.finish(finished_at(), false);
                    }
                    self.changed.notify_all();
                    eprintln!("agent status acquisition panicked; retry deferred");
                    return true;
                }
            };
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.collection = Some(collection.clone());
            state.collection_failed = false;
            state.generation += 1;
            state.collecting = false;
            if app_only {
                // Served to the app; the lane's own passes upload.
                state.running = false;
                self.changed.notify_all();
                return true;
            }
            self.changed.notify_all();
            collection
        };
        let stopped = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stopped;
        // A publication unwind has the same uncertain outcome as a lost
        // response: retain this exact body and use the existing transport retry.
        let success =
            !stopped && catch_unwind(AssertUnwindSafe(|| publish(&collection))).unwrap_or(false);
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
    start_with(&OWNER, |lane, source| {
        let daemon = daemon.clone();
        std::thread::Builder::new()
            .name(format!("ottto-status-{}", index(&source)))
            .spawn(move || run(lane, source, daemon))
    })
}
fn start_with(
    slot: &Mutex<Option<Arc<Owner>>>,
    mut spawn: impl FnMut(Arc<StatusLane>, SourceKind) -> std::io::Result<std::thread::JoinHandle<()>>,
) -> anyhow::Result<()> {
    // Serialize concurrent startup and publish only a fully started owner.
    // A failed attempt leaves standalone callers and a later start available.
    let mut installed = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if installed.is_some() {
        return Ok(());
    }
    let owner = Arc::new(Owner {
        lanes: [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi]
            .map(|source| Arc::new(StatusLane::for_source(&source))),
    });
    let mut workers = Vec::new();
    for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
        let lane = owner.lanes[index(&source)].clone();
        match spawn(lane, source) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                for lane in &owner.lanes {
                    lane.stop();
                }
                // Started threads are still at their startup gate. Reap them
                // before permitting a retry to create any replacement worker.
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error.into());
            }
        }
    }
    *installed = Some(owner.clone());
    for lane in &owner.lanes {
        let mut state = lane
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.started = true;
        lane.changed.notify_all();
    }
    Ok(())
}
fn owner() -> Option<Arc<Owner>> {
    OWNER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn run(lane: Arc<StatusLane>, source: SourceKind, daemon: LocalDaemon) {
    if !lane.wait_started() {
        return;
    }
    loop {
        // Re-read ordinary device grants each pass; a disabled source is not
        // polled automatically. Manual diagnostics retain their old behavior.
        // Claude's own passes are its quota schedule (app requests read no
        // provider), so they run without the grant too and only skip the
        // upload.
        let enabled = crate::snapshot_sync::agent_status_source_enabled(&source);
        let automatic = enabled || lane.app_passes_saved_only;
        let began = Instant::now();
        lane.pass(lane.origin.elapsed(), automatic,
            || {
                let captured = OffsetDateTime::now_utc();
                let collection = collect_agent_status_collection(&source,
                    captured.format(&Rfc3339).unwrap_or_default(),
                    (captured + TimeDuration::minutes(15)).format(&Rfc3339).unwrap_or_default());
                let _ = daemon.record_agent_status_health(collection.source_health_snapshot.clone());
                collection
            },
            |collection| {
                if !enabled {
                    return true;
                }
                let result = crate::snapshot_sync::upload_agent_status_snapshots(&collection.snapshots);
                eprintln!("agent status refresh: source={source:?} outcome={} duration_ms={} snapshots={}",
                    if result.is_ok() { "ok" } else { "error" }, began.elapsed().as_millis(), collection.snapshots.len());
                if let Err(error) = &result {
                    eprintln!("agent status refresh skipped: {}", crate::snapshot_sync::safe_error(error));
                }
                result.is_ok()
            }, || lane.origin.elapsed());
        if source == SourceKind::ClaudeCode {
            let collection = lane
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .collection
                .clone();
            if let Some(due_in) = collection.as_deref().and_then(|collection| {
                let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).ok()?;
                Some(claude_next_reset_read_at(collection, now)? - now)
            }) {
                lane.run_by(lane.origin.elapsed(), Duration::from_secs(due_in));
            }
        }
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
            } else if automatic {
                state
                    .schedule
                    .deadline()
                    .saturating_sub(lane.origin.elapsed())
                    .min(RETRY_DELAY)
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
/// Process memory only. In particular, do not call `collection`: its no-owner
/// path acquires from disk, and a running owner may schedule a manual pass.
pub(crate) fn cached(source: Option<&SourceKind>) -> Vec<ottto_protocol::AgentStatusSnapshot> {
    cached_from_owner(owner().as_deref(), source)
}

fn cached_from_owner(
    owner: Option<&Owner>,
    source: Option<&SourceKind>,
) -> Vec<ottto_protocol::AgentStatusSnapshot> {
    let Some(owner) = owner else {
        return Vec::new();
    };
    [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi]
        .iter()
        .filter(|candidate| source.map_or(true, |source| source == *candidate))
        .filter_map(|source| owner.lanes[index(source)].cached())
        .flat_map(|collection| {
            let mut snapshots = collection.snapshots.clone();
            crate::desktop_recent::overlay(
                &mut snapshots,
                &collection.source_health_snapshot,
                OffsetDateTime::now_utc(),
            );
            snapshots
        })
        .collect::<Vec<_>>()
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
    #[cfg(test)]
    if let Some(collection) = SCOPED_COLLECTION.with(|slot| slot.borrow().clone()) {
        return Ok(collection);
    }
    match owner() {
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
    owner().is_some()
}

#[cfg(test)]
thread_local! {
    static SCOPED_COLLECTION: std::cell::RefCell<Option<Arc<AgentStatusCollection>>> =
        const { std::cell::RefCell::new(None) };
}

/// Scoped input for an isolated, synchronous snapshot cycle. Serve never installs
/// it. Keep the production owner/provider fallback below `collection` unchanged.
#[cfg(test)]
pub(crate) fn with_collection<T>(collection: AgentStatusCollection, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<Arc<AgentStatusCollection>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            SCOPED_COLLECTION.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(SCOPED_COLLECTION.with(|slot| slot.replace(Some(Arc::new(collection)))));
    run()
}

#[cfg(test)]
pub(crate) fn with_test_collection<T>(
    collection: AgentStatusCollection,
    run: impl FnOnce() -> T,
) -> T {
    with_collection(collection, run)
}
pub fn request(source: &SourceKind) {
    if let Some(owner) = owner() {
        owner.lanes[index(source)].request();
    }
}
pub fn request_all() {
    if let Some(owner) = owner() {
        for lane in &owner.lanes {
            lane.wake_if_stale(lane.origin.elapsed(), OffsetDateTime::now_utc());
        }
    }
}
pub(crate) fn stop() {
    if let Some(owner) = owner() {
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

    pub(super) fn specimen(source: SourceKind) -> AgentStatusCollection {
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
    /// Claude: a pass only an app's request starts serves stored readings
    /// (no provider call), uploads nothing and leaves the timer alone, so
    /// the daemon's own 5-min passes, which may read the provider, keep
    /// their time however often the app asks.
    #[test]
    fn claude_app_passes_serve_stored_readings_and_keep_the_timer() {
        let lane = StatusLane::for_source(&SourceKind::ClaudeCode);
        let uploads = std::cell::Cell::new(0);
        let run = |at: u64, saved_only: bool| {
            lane.pass(
                seconds(at),
                true,
                || {
                    assert_eq!(
                        crate::agent_status::claude_pass_saved_only(),
                        saved_only,
                        "pass at {at}"
                    );
                    specimen(SourceKind::ClaudeCode)
                },
                |_| {
                    uploads.set(uploads.get() + 1);
                    true
                },
                || seconds(at + 2),
            )
        };
        assert!(run(0, false));
        assert_eq!(uploads.get(), 1);
        for at in [120, 250, 299] {
            lane.state.lock().unwrap().manual = true;
            assert!(run(at, true));
        }
        assert_eq!(uploads.get(), 1, "app passes upload nothing");
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(300));
        assert_eq!(lane.state.lock().unwrap().generation, 4);
        assert!(!crate::agent_status::claude_pass_saved_only());
        // The timer pass reads; an app request that meets it is that pass.
        lane.state.lock().unwrap().manual = true;
        assert!(run(300, false));
        assert_eq!(uploads.get(), 2);
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(600));
        // An app request right after a pass shares it.
        let shared = lane.collection_at(seconds(300), true).unwrap();
        assert_eq!(lane.state.lock().unwrap().generation, 5);
        drop(shared);
        // Other sources keep their old manual passes.
        let codex = StatusLane::for_source(&SourceKind::Codex);
        assert!(pass(&codex, 0, 2, true));
        codex.state.lock().unwrap().manual = true;
        assert!(pass(&codex, 120, 122, true));
        assert_eq!(codex.state.lock().unwrap().schedule.next_due, seconds(420));
    }
    /// The provider calls of a lane's first pass after daemon start are
    /// labelled `startup`; an app-only pass before it does not count, and
    /// later passes, including the first one after a wake, keep their
    /// callers' labels.
    #[test]
    fn first_lane_pass_is_the_startup_trigger() {
        use crate::provider_calls::{current_trigger, Trigger};
        let lane = StatusLane::for_source(&SourceKind::ClaudeCode);
        let seen = std::cell::RefCell::new(Vec::new());
        let run = |at: u64| {
            lane.pass(
                seconds(at),
                true,
                || {
                    seen.borrow_mut().push(current_trigger());
                    specimen(SourceKind::ClaudeCode)
                },
                |_| true,
                || seconds(at + 2),
            )
        };
        lane.state.lock().unwrap().schedule.next_due = seconds(60);
        lane.state.lock().unwrap().manual = true;
        assert!(run(10));
        assert!(run(60));
        assert!(run(360));
        // A wake with a stale collection restarts the schedule, not the daemon.
        let wall = OffsetDateTime::parse("2026-10-05T01:00:00Z", &Rfc3339).unwrap();
        lane.wake_if_stale(seconds(370), wall);
        assert!(lane.state.lock().unwrap().schedule.last_started.is_none());
        assert!(run(370));
        assert_eq!(*seen.borrow(), [None, Some(Trigger::Startup), None, None]);
    }
    #[test]
    fn claude_reset_read_brings_the_next_pass_forward_only() {
        let lane = StatusLane::new();
        assert!(pass(&lane, 0, 7, true));
        lane.run_by(seconds(7), seconds(60));
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(72));
        // A later reset read never pushes the regular pass back.
        lane.run_by(seconds(8), seconds(600));
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(72));
        assert!(!pass(&lane, 71, 71, true));
        assert!(pass(&lane, 72, 79, true));
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(372));
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
        let publications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let published = publications.clone();
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
                |_| {
                    published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    true
                },
                || seconds(5),
            )
        });
        started_rx.recv_timeout(seconds(2)).unwrap();
        lane.stop();
        release_tx.send(()).unwrap();
        assert!(handle.join().unwrap());
        assert_eq!(publications.load(std::sync::atomic::Ordering::SeqCst), 0);
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
    #[test]
    fn failed_start_reaps_partial_workers_and_allows_retry() {
        for fail_at in 0..3 {
            let slot = Mutex::new(None);
            let (tx, rx) = mpsc::channel();
            let mut attempts = 0;
            assert!(start_with(&slot, |lane, _| {
                let at = attempts;
                attempts += 1;
                if at == fail_at {
                    return Err(std::io::Error::other("synthetic spawn failure"));
                }
                let tx = tx.clone();
                Ok(std::thread::spawn(move || {
                    tx.send(lane.wait_started()).unwrap()
                }))
            })
            .is_err());
            assert!(slot.lock().unwrap().is_none());
            assert_eq!(attempts, fail_at + 1);
            for _ in 0..fail_at {
                assert!(
                    !rx.recv_timeout(seconds(2)).unwrap(),
                    "partial worker must not acquire"
                );
            }
            let mut retry_spawns = 0;
            start_with(&slot, |lane, _| {
                retry_spawns += 1;
                let tx = tx.clone();
                Ok(std::thread::spawn(move || {
                    tx.send(lane.wait_started()).unwrap()
                }))
            })
            .unwrap();
            assert_eq!(retry_spawns, 3);
            for _ in 0..3 {
                assert!(rx.recv_timeout(seconds(2)).unwrap());
            }
            start_with(&slot, |_, _| panic!("installed owner must not spawn again")).unwrap();
            for lane in &slot.lock().unwrap().as_ref().unwrap().lanes {
                assert!(lane.state.lock().unwrap().started);
                lane.stop();
            }
        }
    }
    #[test]
    fn concurrent_starts_install_exactly_one_worker_per_source() {
        let slot = Arc::new(Mutex::new(None));
        let (tx, rx) = mpsc::channel();
        let mut starts = Vec::new();
        for _ in 0..2 {
            let slot = slot.clone();
            let tx = tx.clone();
            starts.push(std::thread::spawn(move || {
                start_with(&slot, |lane, source| {
                    let tx = tx.clone();
                    Ok(std::thread::spawn(move || {
                        if lane.wait_started() {
                            tx.send(index(&source)).unwrap();
                        }
                    }))
                })
                .unwrap()
            }));
        }
        for start in starts {
            start.join().unwrap();
        }
        drop(tx);
        let mut sources = (0..3)
            .map(|_| rx.recv_timeout(seconds(2)).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            rx.recv_timeout(seconds(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        sources.sort_unstable();
        assert_eq!(sources, vec![0, 1, 2]);
    }
    #[test]
    fn acquisition_panic_releases_waiter_and_reacquires_preserving_last_good() {
        let lane = Arc::new(StatusLane::new());
        assert!(pass(&lane, 0, 7, true));
        let last_good = lane.state.lock().unwrap().collection.clone().unwrap();
        let requester = lane.clone();
        let (tx, rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            tx.send(requester.collection_at(seconds(300), true))
                .unwrap()
        });
        let state = lane.state.lock().unwrap();
        let (state, timeout) = lane
            .changed
            .wait_timeout_while(state, seconds(2), |state| !state.manual)
            .unwrap();
        assert!(!timeout.timed_out());
        drop(state);
        let mut publications = 0;
        assert!(lane.pass(
            seconds(300),
            true,
            || panic!("synthetic acquisition panic"),
            |_| {
                publications += 1;
                true
            },
            || seconds(307)
        ));
        // Stop even if the regression returns, so a broken waiter never leaks
        // into later tests or leaves this synthetic test process hanging.
        let result = rx.recv_timeout(seconds(2));
        if result.is_err() {
            lane.stop();
        }
        waiter.join().unwrap();
        assert!(result.unwrap().is_err());
        assert_eq!(publications, 0);
        {
            let state = lane.state.lock().unwrap();
            assert!(!state.running && !state.collecting);
            assert!(Arc::ptr_eq(state.collection.as_ref().unwrap(), &last_good));
        }
        assert!(lane.collection_at(seconds(308), false).is_err());
        assert!(
            !lane.state.lock().unwrap().manual,
            "automatic caller must preserve backoff"
        );
        assert!(!pass(&lane, 308, 308, true));
        assert!(!pass(&lane, 366, 366, true));
        let mut acquisitions = 0;
        assert!(lane.pass(
            seconds(367),
            true,
            || {
                acquisitions += 1;
                specimen(SourceKind::Codex)
            },
            |_| true,
            || seconds(374)
        ));
        assert_eq!(
            acquisitions, 1,
            "acquisition failure cannot reuse stale last-good as a transport retry"
        );
        assert_eq!(lane.state.lock().unwrap().generation, 3);
        assert!(!Arc::ptr_eq(
            &lane.collection_at(seconds(375), false).unwrap(),
            &last_good
        ));
        assert_eq!(
            last_good.source_health_snapshot.captured_at,
            "2026-10-05T00:00:00Z"
        );
    }
    #[test]
    fn upload_panic_releases_lane_and_retries_the_exact_collection() {
        let lane = StatusLane::new();
        assert!(lane.pass(
            Duration::ZERO,
            true,
            || specimen(SourceKind::Pi),
            |_| panic!("synthetic upload panic"),
            || seconds(7)
        ));
        let original = lane.collection_at(seconds(8), false).unwrap();
        assert!(!lane.state.lock().unwrap().running);
        assert!(!pass(&lane, 66, 66, true));
        let mut acquisitions = 0;
        let mut retried = None;
        assert!(lane.pass(
            seconds(67),
            true,
            || {
                acquisitions += 1;
                specimen(SourceKind::Pi)
            },
            |collection| {
                retried = Some(serde_json::to_value(&collection.snapshots).unwrap());
                true
            },
            || seconds(74)
        ));
        assert_eq!(acquisitions, 0);
        assert_eq!(
            retried.unwrap(),
            serde_json::to_value(&original.snapshots).unwrap()
        );
        assert!(Arc::ptr_eq(
            &lane.collection_at(seconds(75), false).unwrap(),
            &original
        ));
        assert_eq!(lane.state.lock().unwrap().generation, 1);
        assert_eq!(lane.state.lock().unwrap().schedule.next_due, seconds(300));
    }
    #[test]
    fn explicit_manual_refresh_can_recover_acquisition_during_backoff() {
        let lane = Arc::new(StatusLane::new());
        assert!(lane.pass(
            Duration::ZERO,
            true,
            || panic!("synthetic acquisition panic"),
            |_| false,
            || seconds(7)
        ));
        assert!(lane.collection_at(seconds(8), false).is_err());
        let requester = lane.clone();
        let (tx, rx) = mpsc::channel();
        let waiter =
            std::thread::spawn(move || tx.send(requester.collection_at(seconds(8), true)).unwrap());
        let state = lane.state.lock().unwrap();
        let (state, timeout) = lane
            .changed
            .wait_timeout_while(state, seconds(2), |state| !state.manual)
            .unwrap();
        assert!(!timeout.timed_out());
        drop(state);
        assert!(pass(&lane, 8, 15, true));
        let result = rx.recv_timeout(seconds(2));
        if result.is_err() {
            lane.stop();
        }
        waiter.join().unwrap();
        assert!(result.unwrap().is_ok());
        assert_eq!(lane.state.lock().unwrap().generation, 2);
    }
}

#[cfg(test)]
mod cached_tests {
    use super::*;

    #[test]
    fn cached_status_never_refreshes_waits_or_falls_back() {
        assert!(cached_from_owner(None, Some(&SourceKind::ClaudeCode)).is_empty());
        let owner = Owner {
            lanes: std::array::from_fn(|_| Arc::new(StatusLane::new())),
        };
        let lane = &owner.lanes[index(&SourceKind::ClaudeCode)];
        assert!(cached_from_owner(Some(&owner), None).is_empty());
        assert!(!lane.state.lock().unwrap().manual);
        let collection = super::tests::specimen(SourceKind::ClaudeCode);
        {
            let mut state = lane.state.lock().unwrap();
            state.collection = Some(Arc::new(collection));
            state.collecting = true; // a refresh waiter would block indefinitely
            state.collection_failed = true;
            state.generation = 12;
        }
        for _ in 0..2 {
            assert_eq!(
                cached_from_owner(Some(&owner), Some(&SourceKind::ClaudeCode)).len(),
                1
            );
            assert!(cached_from_owner(Some(&owner), Some(&SourceKind::Codex)).is_empty());
        }
        let mut state = lane.state.lock().unwrap();
        assert!(!state.manual);
        assert!(!state.schedule.pending);
        assert_eq!(state.schedule.last_started, None);
        assert_eq!(state.generation, 12);
        assert!(state.collecting && state.collection_failed);
        state.stopped = true;
        drop(state);
        assert!(cached_from_owner(Some(&owner), None).is_empty());
    }
}
