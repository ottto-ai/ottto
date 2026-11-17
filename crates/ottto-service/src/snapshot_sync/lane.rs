//! move snapshot lane into lane.

use super::anyhow;
use super::cadence_phase_offset;
use super::codex_scan_diagnostics;
use super::continuation;
use super::continuation_finish_inputs;
use super::current_rfc3339;
use super::default_support_dir;
pub(super) use super::enabled_snapshot_sources;
pub(super) use super::ensure_snapshot_destination_current;
pub(super) use super::ensure_snapshot_scan_authority;
use super::finish_sync_source;
use super::heartbeat_source;
use super::home_dir;
use super::live_snapshot_retry;
use super::load_snapshot_device_credentials;
use super::local_health_upload_can_wait_quietly;
use super::paced_scan_due;
use super::prepare_sync_source;
use super::report_checkin_status_with_fresh_relay_token;
use super::resume_reconnected_sources;
use super::rfc3339_after_minutes;
use super::safe_error;
pub(super) use super::snapshot_api_base_url;
pub(super) use super::snapshot_machine_id;
use super::start_collection_health;
use super::upload_local_health_projection_now;
use super::upload_local_health_projection_reporting;
use super::with_source_cadence;
use super::BTreeMap;
use super::BTreeSet;
use super::Context;
use super::Duration;
use super::FileMachineStore;
use super::Instant;
use super::LocalDaemon;
use super::LocalDeviceBinding;
use super::Mutex;
use super::Path;
use super::Result;
use super::ScanIndex;
use super::SnapshotApiClient;
use super::SnapshotItem;
use super::SnapshotSource;
use super::SourceKind;
use super::SourcePreparation;
use super::SourcePreparationStep;
use super::SourceScanResult;
use super::SourcesFailed;
use super::StageWindow;
use super::AGENT_STATUS_SNAPSHOT_TTL_MINUTES;
use super::CADENCE_WAIT_SLICE;
use super::LOCAL_HEALTH_PROJECTION_INTERVAL;
use super::ONE_SHOT_SYNC_IN_FLIGHT;
use super::SNAPSHOT_SYNC_INTERVAL;
use super::SNAPSHOT_SYNC_LOCK;
use super::SNAPSHOT_SYNC_WORKER_STACK_BYTES;

pub fn spawn_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    let phase_offset = local_cadence_phase_offset(SNAPSHOT_SYNC_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
        .spawn(move || {
            // Spread the fleet's cycle phase deterministically before the first
            // cycle. Otherwise phase is set by install or restart time, and every
            // fleet-wide event re-aligns every machine onto the same tick.
            std::thread::sleep(phase_offset);
            // Nothing watched the transcripts while the daemon was down.
            crate::snapshot_watcher::request_listing_all(
                crate::snapshot_watcher::ListingTrigger::Start,
            );
            // Best effort, and deliberately so: the loop below is driven by the
            // cadence tiers and the unconditional sweep, and the watcher only ever
            // shortens a wait. A machine that cannot watch its transcripts (no
            // permission, exhausted descriptors, a root that does not exist yet)
            // collects on exactly the schedule it does today.
            let mut watcher = watch_snapshot_source_roots(&home);
            if watcher.is_none() {
                eprintln!(
                    "local snapshot sync: filesystem watch unavailable; cadence follows the scan tiers only"
                );
            }
            let mut account_switch = ClaudeAccountSwitchProbe::default();
            let mut retry = live_snapshot_retry::LiveRetryOwner::production();
            loop {
                let prior = watcher.as_ref().map_or(&[][..], |current| current.roots());
                if let Ok(roots) = crate::snapshot_roots::watcher_roots(&home, prior) {
                    if watcher.as_ref().map_or(true, |current| !current.matches_roots(&roots)) {
                        // Nothing watched the changed or new targets until now.
                        crate::snapshot_watcher::request_listing_all(
                            crate::snapshot_watcher::ListingTrigger::Watcher,
                        );
                        watcher = crate::snapshot_watcher::watch_snapshot_roots(roots)
                            .inspect_err(|error| {
                                eprintln!(
                                    "local snapshot sync: filesystem watch re-create failed: {}",
                                    safe_error(error)
                                );
                            })
                            .ok();
                    }
                }
                match sync_once_with_retry(&home, &support_dir, &daemon, &mut retry) {
                    Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                    Err(error) => {
                        eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                        crate::net_resilience::handle_sync_failure(&daemon);
                    }
                }
                // The cycle cadence itself is unchanged. What the tiers gate is the
                // expensive part — the local transcript scan and its upload — while
                // agent-status/quota freshness has an independent source owner.
                // Paced cursor continuation pages run inside the same ordinary
                // interval; the ordinary cycle keeps its deadline.
                continuation::wait_for_ordinary_cycle(
                    &mut ContinuationLoop {
                        watcher: watcher.as_ref(),
                        account_switch: &mut account_switch,
                        retry: &mut retry,
                        home: &home,
                        support_dir: &support_dir,
                        daemon: &daemon,
                    },
                    SNAPSHOT_SYNC_INTERVAL,
                );
            }
        })
        .context("spawn local snapshot sync")?;
    Ok(())
}

/// The delivery-only retry wake inside a cadence wait.
pub(super) fn delivery_wake<'a>(
    retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    home: &'a Path,
    support_dir: &'a Path,
    daemon: &'a LocalDaemon,
) -> impl FnMut(Instant) -> Instant + 'a {
    move |ordinary| {
        if !retry.enabled() {
            return ordinary;
        }
        // The native cycle lock also excludes the UI one-shot
        // path during a delivery-only turn. This wake never
        // starts a provider scan or resets ordinary cadence.
        let _guard = SNAPSHOT_SYNC_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        retry.boundary(home, support_dir, daemon);
        retry.wake_before(ordinary)
    }
}

/// The production loop host for continuation pages: real time, the watcher
/// wait and the delivery wake, with no network beyond what each already does.
pub(super) struct ContinuationLoop<'a> {
    pub(super) watcher: Option<&'a crate::snapshot_watcher::SnapshotWatcher>,
    pub(super) account_switch: &'a mut ClaudeAccountSwitchProbe,
    pub(super) retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    pub(super) home: &'a Path,
    pub(super) support_dir: &'a Path,
    pub(super) daemon: &'a LocalDaemon,
}

impl continuation::LoopHost for ContinuationLoop<'_> {
    fn now(&mut self) -> Instant {
        crate::scan_clock::now()
    }
    fn wait(&mut self, wait: Duration) -> bool {
        collect_file_activity_for(
            wait,
            self.watcher,
            self.account_switch,
            delivery_wake(self.retry, self.home, self.support_dir, self.daemon),
        )
    }
    fn pending(&mut self) -> Option<(Instant, Duration)> {
        continuation::production_pending()
    }
    fn paced_due(&mut self) -> Option<Instant> {
        paced_scan_due()
    }
    fn page(&mut self, deadline: Instant) -> continuation::Outcome {
        continuation::run_production_page(self.home, self.support_dir, self.daemon, deadline)
    }
}

/// Watch every enabled source's transcript roots, if the platform allows it.
pub(super) fn watch_snapshot_source_roots(
    home: &Path,
) -> Option<crate::snapshot_watcher::SnapshotWatcher> {
    let roots = crate::snapshot_roots::watcher_roots(home, &[]).ok()?;
    crate::snapshot_watcher::watch_snapshot_roots(roots).ok()
}

/// Sleep for `wait`, folding any filesystem activity into the cadence tiers.
///
/// This is where the watcher earns its place, and it is deliberately the only
/// thing it does: an event **promotes a tier**, it never triggers a scan. A
/// promoted source becomes due at its floor on a later tick, so a transcript being
/// written continuously cannot produce an upload per event — and a machine whose
/// watcher never fires still collects on the tiers and the ceiling.
///
/// The one exception that ends a wait early is a Claude account switch (see
/// [`ClaudeAccountSwitchProbe`]): the next cycle then re-reads agent status and
/// re-attributes active sessions right away instead of up to a full interval
/// later. The transcript scan itself stays on its cadence. Returns `true` when
/// the wait ended early for that reason.
pub(super) fn collect_file_activity_for(
    wait: Duration,
    watcher: Option<&crate::snapshot_watcher::SnapshotWatcher>,
    account_switch: &mut ClaudeAccountSwitchProbe,
    retry_boundary: impl FnMut(Instant) -> Instant,
) -> bool {
    collect_file_activity_with_retry(
        wait,
        watcher,
        account_switch,
        retry_boundary,
        crate::agent_status::claude_default_account_fingerprint,
    )
}

pub(super) fn collect_file_activity_with_retry(
    wait: Duration,
    watcher: Option<&crate::snapshot_watcher::SnapshotWatcher>,
    account_switch: &mut ClaudeAccountSwitchProbe,
    mut retry_boundary: impl FnMut(Instant) -> Instant,
    mut read_account: impl FnMut() -> Option<String>,
) -> bool {
    let deadline = crate::scan_clock::now() + wait;
    let mut watcher = watcher;
    loop {
        // A delivery retry may share the ordinary deadline. Service it before
        // returning to collection, which can replace its retained checkpoint.
        let wake = retry_boundary(deadline).min(deadline);
        let now = crate::scan_clock::now();
        if now >= deadline {
            return false;
        }
        let slice = wake.saturating_duration_since(now).min(CADENCE_WAIT_SLICE);
        match watcher.map(|watcher| watcher.events.recv_timeout(slice)) {
            None => std::thread::sleep(slice),
            Some(Ok(event)) => {
                let _stage = StageWindow::begin(event.source.api_slug(), "offpass_hint");
                with_source_cadence(event.source, |cadence| {
                    cadence.record_file_event(crate::scan_clock::now())
                });
            }
            Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => {}
            // The watcher thread is gone. Keep waiting plainly rather than
            // spinning: collection is not gated on the watcher.
            Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) => {
                watcher = None;
            }
        }
        if account_switch.observe(crate::scan_clock::now(), &mut read_account) {
            eprintln!("local snapshot sync: Claude account switch detected; refreshing now");
            with_source_cadence(SnapshotSource::ClaudeCode, |cadence| {
                cadence.record_account_switch(crate::scan_clock::now())
            });
            return true;
        }
    }
}

/// How often the default Claude account is re-read while the loop waits.
pub(super) const CLAUDE_ACCOUNT_SWITCH_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Notices when this Mac's default Claude account changes — the Claude Desktop
/// app signing into another account, or `claude /login` in a terminal.
///
/// Neither touches a watched transcript root, so without this the switch waited
/// for the next scheduled cycle (up to a full interval plus a slow cycle) before
/// the new account's sessions stopped showing under the old one. The first
/// observation only records a baseline; an unreadable fingerprint is never a
/// switch.
#[derive(Default)]
pub(super) struct ClaudeAccountSwitchProbe {
    pub(super) last_fingerprint: Option<String>,
    pub(super) checked_at: Option<Instant>,
}

impl ClaudeAccountSwitchProbe {
    pub(super) fn observe(&mut self, now: Instant, read: impl FnOnce() -> Option<String>) -> bool {
        if self.checked_at.is_some_and(|checked| {
            now.saturating_duration_since(checked) < CLAUDE_ACCOUNT_SWITCH_CHECK_INTERVAL
        }) {
            return false;
        }
        let _stage = StageWindow::begin("unknown", "offpass_account_check");
        self.checked_at = Some(now);
        let Some(current) = read() else {
            return false;
        };
        let switched = self
            .last_fingerprint
            .as_ref()
            .is_some_and(|previous| previous != &current);
        self.last_fingerprint = Some(current);
        switched
    }
}

/// This machine's cadence phase offset inside `interval`.
///
/// Derived from the durable machine id when there is one. A machine that has not
/// been claimed yet has no stable id, and inventing a random one would re-scatter
/// the phase on every launch — so an unclaimed machine simply starts on time.
pub(super) fn local_cadence_phase_offset(interval: Duration) -> Duration {
    match FileMachineStore::default().load() {
        Ok(Some(machine)) if !machine.machine_id.is_empty() => {
            cadence_phase_offset(&machine.machine_id, interval)
        }
        _ => Duration::ZERO,
    }
}

pub fn spawn_local_health_projection_sync(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-local-health-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = upload_local_health_projection_now(&daemon) {
                if !local_health_upload_can_wait_quietly(&error) {
                    eprintln!(
                        "local health projection upload skipped: {}",
                        safe_error(&error)
                    );
                }
            }
            crate::control::reconcile_setup_scan_in_background(&daemon);
            std::thread::sleep(LOCAL_HEALTH_PROJECTION_INTERVAL);
        })
        .context("spawn local health projection sync")?;
    Ok(())
}

/// A freshly restarted daemon seeds registered sources as `verifying` (see
/// [`LocalDaemon::with_registered_device_sources`]) so a connected account never
/// momentarily shows zero sources while the first agent scan is pending. Nothing
/// else proactively runs that scan, so without this burst the seeded rows can
/// dwell in `verifying` for tens of seconds until a client polls with refresh or
/// the next session emits telemetry — a transient that can read as "not working"
/// to a customer right after a daemon restart. Reconfirm them shortly after
/// boot, retrying a few times so a cold CLI that is not yet ready on the first
/// pass still settles quickly. Honest by construction: this runs the same
/// agent-status scan a GUI/CLI refresh runs and only promotes `Available`
/// sources (see `LocalDaemon::reconfirm_verifying_sources_for_trusted_client`),
/// so it never reports `healthy` before the scan actually finds the source ready.
pub(super) const STARTUP_REVERIFY_SCHEDULE: &[Duration] = &[
    Duration::from_secs(2),
    Duration::from_secs(6),
    Duration::from_secs(15),
];

pub fn spawn_startup_source_reverify(daemon: LocalDaemon) {
    let spawn_result = std::thread::Builder::new()
        .name("ottto-startup-reverify".to_string())
        .spawn(move || {
            for delay in STARTUP_REVERIFY_SCHEDULE {
                std::thread::sleep(*delay);
                let captured_at = current_rfc3339();
                let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
                    .unwrap_or_else(|| captured_at.clone());
                match daemon.reconfirm_verifying_sources_for_trusted_client(captured_at, expires_at)
                {
                    // All seeded rows reconfirmed (or none seeded / not
                    // connected) — nothing left to do.
                    Ok(0) => break,
                    // Some sources were not `Available` yet (cold CLI); retry on
                    // the next, longer tick once they have had time to warm up.
                    Ok(_) => continue,
                    Err(error) => {
                        eprintln!("startup source re-verify skipped: {error}");
                        break;
                    }
                }
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("startup source re-verify unavailable: {error}");
    }
}

/// Startup/wake/upkeep share the source owner; transcript scans hold no
/// status lock and no hook starts a competing upload thread.
pub fn spawn_claude_agent_status_refresh(_opportunity: &'static str) {
    crate::agent_status_refresh::request(&SourceKind::ClaudeCode);
}

/// Cadence for the blocking-verification retry loop below: how often it checks
/// for sources stuck in a failed verification, and the exponential backoff for
/// actual re-verify attempts. Each attempt runs a real smoke session (a small
/// LLM call), so a fixed short interval would burn provider quota exactly when
/// the machine is quota-starved; exponential backoff recovers transient
/// failures (network blip, brief provider outage) within minutes while capping
/// steady-state cost at one smoke per source per half hour until it heals.
pub(super) const FAILED_VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(60);

pub(super) const FAILED_VERIFY_RETRY_INITIAL: Duration = Duration::from_secs(2 * 60);

pub(super) const FAILED_VERIFY_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// Exponential backoff for background re-verify attempts: 2m, 4m, 8m, 16m,
/// then capped at 30m for as long as the source stays failed. The counter
/// resets whenever the source leaves the failed state (a successful retry,
/// a manual Verify, or a fresh sign-in).
pub(super) fn reverify_backoff_delay(completed_attempts: u32) -> Duration {
    let factor = 1u32.checked_shl(completed_attempts).unwrap_or(u32::MAX);
    FAILED_VERIFY_RETRY_INITIAL
        .saturating_mul(factor)
        .min(FAILED_VERIFY_RETRY_MAX)
}

pub(super) struct ReverifySchedule {
    pub(super) source: SourceKind,
    pub(super) completed_attempts: u32,
    pub(super) next_attempt_at: Option<Instant>,
    // Outer None is a transient failure; Some holds the last nonsecret auth marker.
    pub(super) reauth_marker: Option<Option<String>>,
    pub(super) verification_baseline: Option<Option<String>>,
}

impl ReverifySchedule {
    pub(super) fn new(source: SourceKind, now: Instant) -> Self {
        Self {
            source,
            completed_attempts: 0,
            next_attempt_at: Some(now + reverify_backoff_delay(0)),
            reauth_marker: None,
            verification_baseline: None,
        }
    }

    pub(super) fn observe_verification_baseline(&mut self, baseline: Option<Option<String>>) {
        if self.verification_baseline != baseline {
            self.reauth_marker = baseline.clone();
            self.verification_baseline = baseline;
            self.next_attempt_at = None;
        }
    }

    pub(super) fn is_due(
        &mut self,
        now: Instant,
        requires_reauth: bool,
        marker: Option<String>,
    ) -> bool {
        if requires_reauth {
            let Some(previous) = self.reauth_marker.as_mut() else {
                self.reauth_marker = Some(marker);
                self.next_attempt_at = None;
                return false;
            };
            if marker.is_none() {
                // Keep both the last known marker and any unconsumed retry.
                // Unavailable reads neither create a retry nor discard one.
                return false;
            }
            if *previous != marker {
                // A new marker gets one attempt after the quiet window,
                // even if that attempt still fails auth.
                self.next_attempt_at = Some(now + reverify_backoff_delay(0));
                *previous = marker;
                return false;
            }
        } else if self.reauth_marker.take().is_some() {
            self.completed_attempts = 0;
            self.next_attempt_at = Some(now + reverify_backoff_delay(0));
        }
        if self.next_attempt_at.is_some_and(|deadline| now >= deadline) {
            self.next_attempt_at = None;
            true
        } else {
            false
        }
    }

    pub(super) fn record_attempt(&mut self, now: Instant) {
        self.completed_attempts = self.completed_attempts.saturating_add(1);
        if self.reauth_marker.is_none() {
            self.next_attempt_at = Some(now + reverify_backoff_delay(self.completed_attempts));
        }
    }
}

/// A blocking verification failure (`Failed` + `TelemetryNotVerified`) is
/// sticky by design: data refreshes only re-pin it and nothing re-runs the
/// smoke, so before this loop existed a transient failure sat on "needs
/// attention / Critical" until the customer pressed Verify by hand — even
/// though pressing Verify immediately healed it. Retry those sources
/// automatically with exponential backoff so the state converges on its own;
/// the companion app already self-heals once the daemon reports healthy.
/// Provider sign-in failures stay quiet until the Default Claude credential's
/// nonsecret modification marker changes. Other sources keep their existing backoff.
pub fn spawn_failed_verification_reverify(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-failed-verify-retry".to_string())
        .spawn(move || {
            let mut schedules: Vec<ReverifySchedule> = Vec::new();
            loop {
                std::thread::sleep(FAILED_VERIFY_POLL_INTERVAL);
                let failed = match daemon.blocking_verification_retry_states() {
                    Ok(failed) => failed,
                    Err(_) => continue,
                };
                // A source that healed (retry success, manual Verify, sign-in)
                // drops its schedule so a future failure restarts the backoff
                // from the initial delay.
                schedules
                    .retain(|schedule| failed.iter().any(|(source, _)| source == &schedule.source));
                for (source, requires_reauth) in failed {
                    let now = crate::scan_clock::now();
                    let index = schedules
                        .iter()
                        .position(|schedule| schedule.source == source)
                        .unwrap_or_else(|| {
                            schedules.push(ReverifySchedule::new(source.clone(), now));
                            schedules.len() - 1
                        });
                    let schedule = &mut schedules[index];
                    let marker = if requires_reauth && source == SourceKind::ClaudeCode {
                        let Ok(baseline) = daemon.claude_verification_auth_marker() else {
                            continue;
                        };
                        schedule.observe_verification_baseline(baseline);
                        crate::agent_status::claude_credential_modified_marker(
                            &ottto_core::ClaudeConfigDirSlot::Default,
                        )
                    } else {
                        None
                    };
                    if !schedule.is_due(now, requires_reauth, marker) {
                        continue;
                    }
                    match crate::control::reverify_failed_source(&daemon, source.clone()) {
                        Ok(result) => eprintln!(
                            "background re-verify for {} finished: {}",
                            crate::source_slug(&source),
                            result.message.code
                        ),
                        Err(error) => eprintln!(
                            "background re-verify for {} skipped: {error}",
                            crate::source_slug(&source)
                        ),
                    }
                    schedule.record_attempt(crate::scan_clock::now());
                }
            }
        })
        .context("spawn failed-verification re-verify loop")?;
    Ok(())
}

pub fn spawn_one_shot_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    if !claim_one_shot_sync_slot() {
        return Ok(());
    }
    let spawn_result = std::thread::Builder::new()
        .name("ottto-snapshot-sync-now".to_string())
        .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
        .spawn(move || {
            match sync_once(&home, &support_dir, &daemon) {
                Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                Err(error) => {
                    eprintln!(
                        "local snapshot sync after setup skipped: {}",
                        safe_error(&error)
                    );
                    crate::net_resilience::handle_sync_failure(&daemon);
                }
            }
            set_one_shot_sync_in_flight(false);
        });
    if let Err(error) = spawn_result {
        set_one_shot_sync_in_flight(false);
        return Err(error).context("spawn immediate local snapshot sync");
    }
    Ok(())
}

pub(super) fn claim_one_shot_sync_slot() -> bool {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    match lock.lock() {
        Ok(mut in_flight) => {
            if *in_flight {
                false
            } else {
                *in_flight = true;
                true
            }
        }
        Err(_) => true,
    }
}

pub(super) fn set_one_shot_sync_in_flight(value: bool) {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    if let Ok(mut in_flight) = lock.lock() {
        *in_flight = value;
    }
}

pub(super) fn sync_once(home: &Path, support_dir: &Path, daemon: &LocalDaemon) -> Result<()> {
    // Manual one-shot collection never owns the long-lived background queue.
    sync_once_with_retry(
        home,
        support_dir,
        daemon,
        &mut live_snapshot_retry::LiveRetryOwner::closed(),
    )
}

pub(super) fn sync_once_with_retry(
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    retry: &mut live_snapshot_retry::LiveRetryOwner,
) -> Result<()> {
    // The periodic loop and setup/UI one-shot path can otherwise scan and save
    // the same per-source index concurrently. Serialize the full cycle so a
    // one-shot rescan cannot race the background loop or publish an older
    // incremental index after it.
    let _sync_guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Before credentials: a re-enabled source resumes even with no live device.
    resume_reconnected_sources(support_dir);
    crate::claude_local_otel::close_append_handles();
    // Declared after the guard, so it settles before the lock is released.
    let mut continuation_cycle = continuation::CycleSettlement::default();
    let (device, device_secret) = load_snapshot_device_credentials()?;
    daemon
        .record_source_grants(&device)
        .map_err(|_| anyhow!("source grants unavailable"))?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let account_witness = daemon
        .snapshot_scan_account_witness()
        .map_err(|_| anyhow!("snapshot account authority unavailable"))?;
    let client = snapshot_cycle_client(support_dir, daemon)?;
    let enabled_sources = cycle_heartbeat(&client, &device, &device_secret, &machine_id, daemon);
    for source in enabled_sources.iter().copied() {
        start_collection_health(source);
    }

    // Cycle-start scan receipts: one cheap non-terminal status per enabled
    // source before any scanning. Sources late in the sequential cycle would
    // otherwise hold receipts from the PREVIOUS cycle for this whole cycle, and
    // a backlog drain (e.g. after a daemon restart) stretches that well past
    // the backend's five-minute freshness promise even though uploads are
    // healthy. Best-effort: a failed receipt must never block the actual sync.
    let cycle_started_at = current_rfc3339();
    for source in enabled_sources.iter().copied() {
        if let Err(error) = report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            Some(&cycle_started_at),
        ) {
            eprintln!(
                "local snapshot cycle-start receipt skipped for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
    }

    // Transport-layer outage evidence is folded here, in the per-source loop,
    // because this is the last point where each failure still carries the
    // typed `UploadFailureDiagnostics` (the aggregate error below collapses
    // to a count). One folded verdict per cycle feeds the streak.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    let mut failed_sources = Vec::new();
    let mut owner = SnapshotCycleOwner {
        client: &client,
        device: &device,
        device_secret: &device_secret,
        machine_id: &machine_id,
        home,
        support_dir,
        daemon,
        transport_cycle: &mut transport_cycle,
        failed_sources: &mut failed_sources,
        started: crate::scan_clock::now(),
        codex_started: None,
        paced_qos: None,
        account_witness,
        retry,
    };
    crate::source_rotation::run(
        &mut owner,
        &enabled_sources,
        crate::source_rotation::PARKED_BUDGET,
    );
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);
    crate::local_resource_diagnostics::rotate_service_log_if_due();
    if !failed_sources.is_empty() {
        return Err(SourcesFailed(failed_sources).into());
    }
    continuation_cycle.succeeded(enabled_sources.contains(&SnapshotSource::Codex));
    Ok(())
}

/// The cycle's heartbeat, then the sources this cycle collects: an OFF its
/// reply carries stops that source in this same cycle.
pub(super) fn cycle_heartbeat(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Vec<SnapshotSource> {
    if let Some(source) = heartbeat_source(device) {
        if let Err(error) = upload_local_health_projection_reporting(
            client,
            device,
            device_secret,
            source,
            machine_id,
            daemon,
        ) {
            eprintln!(
                "local health projection upload skipped: {}",
                safe_error(&error)
            );
        }
    }
    enabled_snapshot_sources(device)
}

/// The cycle's API client, with the receipt state and context every cycle uses.
pub(super) fn snapshot_cycle_client(
    support_dir: &Path,
    daemon: &LocalDaemon,
) -> Result<SnapshotApiClient> {
    let device_label = daemon
        .machine_for_trusted_client()
        .ok()
        .map(|machine| machine.display_name);
    let account_binding = daemon
        .account_for_trusted_client()
        .ok()
        .map(|account| account.state);
    Ok(SnapshotApiClient::new(snapshot_api_base_url()?)
        .with_receipt_state_dir(support_dir)
        .with_receipt_context(device_label, account_binding))
}

pub(super) fn retry_ordinary_owned(item: &SnapshotItem) -> Option<SnapshotItem> {
    if item.cache_observations.is_some() || item.cache_base_head_etag.is_some() {
        return None;
    }
    Some(SnapshotItem {
        evidence_basis: None,
        request_evidence: Vec::new(),
        request_identity_refusals: 0,
        claude_org_markers: None,
        claude_account_withheld_reason: None,
        claude_account_display: None,
        session_account_evidence: item.session_account_evidence.clone(),
        source_session_id: item.source_session_id.clone(),
        snapshot_fingerprint: item.snapshot_fingerprint.clone(),
        status: item.status.clone(),
        input_tokens: item.input_tokens,
        output_tokens: item.output_tokens,
        cache_read_tokens: item.cache_read_tokens,
        cache_creation_5m_tokens: item.cache_creation_5m_tokens,
        cache_creation_1h_tokens: item.cache_creation_1h_tokens,
        reasoning_output_tokens: item.reasoning_output_tokens,
        unattributed_total_tokens: item.unattributed_total_tokens,
        request_count: item.request_count,
        usage_accounting_contract: item.usage_accounting_contract.clone(),
        removed_request_count: item.removed_request_count,
        removed_usage: item.removed_usage,
        telemetry_owned_complete: item.telemetry_owned_complete,
        resolver_conflict_count: item.resolver_conflict_count,
        copy_unproven_counts: item.copy_unproven_counts,
        claude_money: None,
        claude_usage_request_ids: BTreeSet::new(),
        claude_usage_occurrences: BTreeMap::new(),
        cache_observations: item.cache_observations.clone(),
        cache_observations_state: None,
        cache_base_head_etag: None,
        cache_conflict_answer: None,
        cache_requests: Vec::new(),
        cache_requests_complete: false,
        avg_duration_ms: item.avg_duration_ms,
        avg_time_to_first_token_ms: item.avg_time_to_first_token_ms,
        max_duration_ms: item.max_duration_ms,
        max_time_to_first_token_ms: item.max_time_to_first_token_ms,
        peak_context_fill_tokens: item.peak_context_fill_tokens,
        first_turn_context_tokens: item.first_turn_context_tokens,
        last_turn_context_tokens: item.last_turn_context_tokens,
        // Copied, never dropped: a retry that lost the windows would settle as
        // UNCHANGED (they are outside every hash) and never deliver them.
        first_turn_context_window_tokens: item.first_turn_context_window_tokens,
        peak_context_fill_window_tokens: item.peak_context_fill_window_tokens,
        last_turn_context_window_tokens: item.last_turn_context_window_tokens,
        compaction_count: item.compaction_count,
        compaction_timestamps: item.compaction_timestamps.clone(),
        compaction_events: item.compaction_events.clone(),
        first_own_request_at: item.first_own_request_at.clone(),
        local_context_points: Vec::new(),
        compaction_total_pre_tokens: item.compaction_total_pre_tokens,
        compaction_total_post_tokens: item.compaction_total_post_tokens,
        compaction_total_cumulative_dropped_tokens: item.compaction_total_cumulative_dropped_tokens,
        compaction_total_duration_ms: item.compaction_total_duration_ms,
        context_curve: item.context_curve.clone(),
        claude_context_curve_boundaries: Vec::new(),
        claude_context_curve_identity_complete: false,
        claude_context_curve_request_index_complete: false,
        claude_context_curve_owned_start_proven: false,
        claude_file_birth: item.claude_file_birth,
        claude_file_birth_verdict: item.claude_file_birth_verdict(),
        activity_summary: item.activity_summary.clone(),
        tool_usage: item.tool_usage.clone(),
        tool_usage_truncated: item.tool_usage_truncated,
        session_start: item.session_start.clone(),
        model_usage: item.model_usage.clone(),
        usage_buckets: item.usage_buckets.clone(),
        cost: item.cost.clone(),
        session_display_name: item.session_display_name.clone(),
        session_display_name_source: item.session_display_name_source.clone(),
        source_started_at: item.source_started_at.clone(),
        source_ended_at: item.source_ended_at.clone(),
        source_last_activity_at: item.source_last_activity_at.clone(),
        collected_at: item.collected_at.clone(),
        workspace_hash: item.workspace_hash.clone(),
        workspace_display_label: item.workspace_display_label.clone(),
        workspace_label_source: item.workspace_label_source.clone(),
        repository_hash: item.repository_hash.clone(),
        repository_label: item.repository_label.clone(),
        repository_label_source: item.repository_label_source.clone(),
        repository_identity_source: item.repository_identity_source.clone(),
        workspace_kind: item.workspace_kind.clone(),
        source_file_fingerprint: item.source_file_fingerprint.clone(),
        session_artifacts: item.session_artifacts.clone(),
        provenance: item.provenance.clone(),
        origin: item
            .origin
            .as_ref()
            .map(|o| crate::snapshots::SnapshotOrigin {
                thread_source: o.thread_source.clone(),
                source: o.source.clone(),
                source_subagent: o.source_subagent,
                originator: o.originator.clone(),
                agent_role: o.agent_role.clone(),
                entrypoint: o.entrypoint.clone(),
                is_sidechain: o.is_sidechain,
                session_kind: o.session_kind.clone(),
                used_workflow_orchestration: o.used_workflow_orchestration,
                parent_session_ref: None,
            }),
        originator: item.originator.clone(),
        attribution_facts: item.attribution_facts.clone(),
    })
}

pub(super) struct SnapshotCycleOwner<'a> {
    pub(super) retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    pub(super) account_witness: [u8; 32],
    pub(super) client: &'a SnapshotApiClient,
    pub(super) device: &'a LocalDeviceBinding,
    pub(super) device_secret: &'a str,
    pub(super) machine_id: &'a str,
    pub(super) home: &'a Path,
    pub(super) support_dir: &'a Path,
    pub(super) daemon: &'a LocalDaemon,
    pub(super) transport_cycle: &'a mut crate::net_resilience::TransportCycleOutcome,
    pub(super) failed_sources: &'a mut Vec<&'static str>,
    pub(super) started: Instant,
    /// When this cycle's Codex preparation began, for a continuation ticket's
    /// measured work. Only written while continuation pages are enabled.
    pub(super) codex_started: Option<Instant>,
    /// Background QoS for the one source whose paced scan is due, held from
    /// its prepare through its finish; its outcome (or unwind) restores.
    pub(super) paced_qos: Option<continuation::MacPlatformSignals>,
}

impl SnapshotCycleOwner<'_> {
    pub(super) fn finish_completed(
        &mut self,
        (preparation, index, scan): (SourcePreparation, ScanIndex, SourceScanResult),
    ) -> Result<()> {
        use crate::source_rotation::Owner as _;
        codex_scan_diagnostics::observe_existing_outer_census_fence(
            preparation.source,
            self.support_dir,
            || {
                self.validate(&preparation)?;
                ensure_snapshot_destination_current(&preparation.upload_destination_namespace)
            },
        )?;
        let source = preparation.source;
        finish_sync_source(
            preparation,
            index,
            scan,
            self.client,
            self.device,
            self.device_secret,
            source,
            self.machine_id,
            self.home,
            self.support_dir,
            self.daemon,
            self.transport_cycle,
            self.retry,
        )
    }
}

impl crate::source_rotation::Owner for SnapshotCycleOwner<'_> {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        _remaining: Option<usize>,
    ) -> Result<Option<SourcePreparation>> {
        continuation::enter_source_qos(&mut self.paced_qos, source);
        if source == SnapshotSource::Codex {
            self.codex_started = Some(crate::scan_clock::now());
            // K2: this prepare's policy replaces any older cached inputs.
            continuation::invalidate_on_ordinary_prepare();
        }
        ensure_snapshot_scan_authority(
            self.device,
            source,
            self.client,
            &self.account_witness,
            self.daemon,
        )?;
        prepare_sync_source(
            self.client,
            self.device,
            self.device_secret,
            source,
            self.machine_id,
            self.home,
            self.support_dir,
            self.daemon,
            self.transport_cycle,
            self.account_witness,
            self.retry.enabled(),
        )
    }
    fn validate(&mut self, frame: &SourcePreparation) -> Result<()> {
        ensure_snapshot_scan_authority(
            self.device,
            frame.source,
            &frame.receipt_client,
            &frame.account_witness,
            self.daemon,
        )
    }
    fn step(
        &mut self,
        frame: SourcePreparation,
        _remaining: Option<usize>,
    ) -> crate::source_rotation::Step<SourcePreparation, Self::Completed> {
        match frame.step() {
            SourcePreparationStep::Pending(frame) => crate::source_rotation::Step::Pending(frame),
            SourcePreparationStep::Refused(frame, reason) => {
                drop(frame);
                crate::source_rotation::Step::Refused(reason)
            }
            SourcePreparationStep::Complete {
                preparation,
                index,
                scan,
            } => crate::source_rotation::Step::Complete((preparation, index, scan)),
        }
    }
    fn finish(&mut self, mut completed: Self::Completed, remaining: Option<usize>) -> Result<()> {
        let source = completed.0.source;
        // Read before the scan is consumed; kept only if the finish succeeds.
        let continuation_ticket = (source == SnapshotSource::Codex
            && completed.2.continuation_ticket().is_some())
        .then(|| {
            let endpoint = snapshot_api_base_url().ok()?;
            let authority =
                continuation::current_authority(self.device, &endpoint, &self.account_witness)
                    .filter(|_| self.client.matches_api_base(&endpoint));
            continuation::ordinary_ticket(
                &continuation::CodexContinuation::new(
                    &self.daemon.transcript_cache,
                    self.home,
                    self.support_dir,
                ),
                &completed.2,
                &completed.0.upload_destination_namespace,
                authority,
                continuation::ticket_lifetime(self.codex_started),
            )
            .and_then(continuation_finish_inputs(
                &mut completed.0,
                &mut completed.2,
                remaining,
                &self.daemon.codex_preludes,
                self.daemon.codex_versions.clone(),
            ))
        });
        let v2_active = crate::snapshots::state_v2_growth_retention_active(&completed.1);
        let exposure = completed.1.refusal_exposure;
        let finished = crate::local_resource_diagnostics::source_finish_with_refusals(
            source.api_slug(),
            v2_active,
            exposure,
            || self.finish_completed(completed),
        );
        if let Some(ticket) = continuation_ticket {
            continuation::after_ordinary_codex_page(ticket, self.codex_started, finished.is_ok());
        }
        finished
    }
    fn outcome(&mut self, source: SnapshotSource, result: Result<()>) {
        continuation::leave_source_qos(&mut self.paced_qos);
        crate::local_resource_diagnostics::pass_ended(source.api_slug());
        if result.is_err() {
            continuation::after_ordinary_source_failure(source);
        }
        match result {
            Ok(()) => self.transport_cycle.note_success(),
            Err(error) => {
                if error
                    .downcast_ref::<crate::source_rotation::LocalRefusal>()
                    .is_none()
                {
                    self.transport_cycle.note_error(&error);
                }
                eprintln!(
                    "local snapshot sync skipped for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
                crate::snapshots::money_freshness::report_failed_pass(source);
                self.failed_sources.push(source.api_slug());
            }
        }
    }
    fn monotonic(&self) -> Duration {
        self.started.elapsed()
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        retained_with_withheld(
            &self.daemon.transcript_cache.withheld_memo,
            limit,
            |limit| {
                let versions = crate::heap_layout_bound::bound(&self.daemon.codex_versions, limit)?;
                let continuation = continuation::retained_bound(limit.checked_sub(versions)?)?;
                versions.checked_add(continuation)
            },
        )
    }
    fn retained_budget_unavailable(&mut self) {
        self.daemon
            .transcript_cache
            .withheld_memo
            .discard_retained();
        self.discard_retained();
    }
    fn discard_retained(&mut self) {
        continuation::discard_retained();
        self.daemon
            .transcript_cache
            .withheld_memo
            .discard_if_refused();
    }
    fn boundary(&mut self) {
        self.retry
            .boundary(self.home, self.support_dir, self.daemon);
    }
}

// Existing retained graphs have priority over the advisory memo. Refusing only
// the memo must not trigger the rotation's discard of admitted sibling graphs.
pub(crate) fn retained_with_withheld(
    memo: &crate::snapshots::withheld_account::Memo,
    limit: usize,
    other: impl FnOnce(usize) -> Option<usize>,
) -> Option<usize> {
    let owned = other(limit);
    // Even when siblings are unsupported, price the portable memo against the
    // available allowance so their discard preserves it only if it fits.
    let remaining = limit.checked_sub(owned.unwrap_or(0))?;
    match memo.retained_bound(remaining) {
        Some(withheld) => owned?.checked_add(withheld),
        None => {
            // Frees all memo allocations; held population remains disclosed
            // with unavailable details and no optional memo storage to charge.
            memo.discard_if_refused();
            owned
        }
    }
}
