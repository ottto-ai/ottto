//! move snapshot lane into lane.

use super::anyhow;
use super::cadence_phase_offset;
use super::codex_scan_diagnostics;
use super::continuation;
use super::continuation_finish_inputs;
use super::current_rfc3339;
use super::default_support_dir;

use super::finish_sync_source;

use super::load_snapshot_device_credentials;
use super::local_health_upload_can_wait_quietly;
use super::paced_scan_due;
use super::prepare_sync_source;
use super::report_checkin_status_with_fresh_relay_token;

use super::rfc3339_after_minutes;
use super::safe_error;

use super::start_collection_health;
use super::upload_local_health_projection_now;
use super::upload_local_health_projection_reporting;
use super::with_source_cadence;
use super::BTreeMap;
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

#[cfg(test)]
use super::is_snapshot_fingerprint;
use super::reset_collection_health;
use super::sync_progress_parent;
#[cfg(test)]
use super::Deserialize;
use super::Digest;
use super::ErrorKind;
use super::FileConnectionStore;
use super::PathBuf;
use super::Sha256;
use super::SnapshotLocalStateRejected;
use super::SnapshotProgressLock;
use super::SnapshotUploadPolicy;
use super::DEFAULT_API_BASE_URL;
#[cfg(test)]
use super::SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION;

pub fn spawn_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    let phase_offset = local_cadence_phase_offset(SNAPSHOT_SYNC_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
        .spawn(move || {
            // A journal left by a crash or stop is replayed before anything
            // reads the per-session files.
            drain_relay_journal(&support_dir);
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
            loop {
                let prior = watcher.as_ref().map_or(&[][..], |current| current.roots());
                let listed = crate::snapshot_roots::watcher_roots(&home, prior);
                let listed_ok = listed.is_ok();
                if let Ok(roots) = listed {
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
                // The walk gate idles only roots a live, current watcher hints.
                crate::snapshot_watcher::cover(watcher.as_ref().filter(|_| listed_ok));
                match sync_once(&home, &support_dir, &daemon, false) {
                    Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                    Err(error) => {
                        eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                        crate::net_resilience::handle_sync_failure(&daemon);
                    }
                }
                // Between passes: report what the process holds at rest.
                crate::local_resource_diagnostics::rest_heap::emit();
                // The cycle cadence itself is unchanged. What the tiers gate is the
                // expensive part — the local transcript scan and its upload — while
                // agent-status/quota freshness has an independent source owner.
                // Paced cursor continuation pages run inside the same ordinary
                // interval; the ordinary cycle keeps its deadline.
                continuation::wait_for_ordinary_cycle(
                    &mut ContinuationLoop {
                        watcher: watcher.as_ref(),
                        account_switch: &mut account_switch,
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

/// The production loop host for continuation pages and watcher waits.
pub(super) struct ContinuationLoop<'a> {
    pub(super) watcher: Option<&'a crate::snapshot_watcher::SnapshotWatcher>,
    pub(super) account_switch: &'a mut ClaudeAccountSwitchProbe,
    pub(super) home: &'a Path,
    pub(super) support_dir: &'a Path,
    pub(super) daemon: &'a LocalDaemon,
}

impl continuation::LoopHost for ContinuationLoop<'_> {
    fn now(&mut self) -> Instant {
        crate::scan_clock::now()
    }
    fn wait(&mut self, wait: Duration) -> bool {
        collect_file_activity_for(wait, self.watcher, self.account_switch)
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
) -> bool {
    let deadline = crate::scan_clock::now() + wait;
    let mut watcher = watcher;
    loop {
        let now = crate::scan_clock::now();
        if now >= deadline {
            return false;
        }
        let slice = deadline
            .saturating_duration_since(now)
            .min(CADENCE_WAIT_SLICE);
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
        if account_switch.observe(
            crate::scan_clock::now(),
            crate::agent_status::claude_default_account_fingerprint,
        ) {
            eprintln!("local snapshot sync: Claude account switch detected; refreshing now");
            crate::snapshots::walk_idle::clear(SnapshotSource::ClaudeCode, "account_switch");
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
            match sync_once(&home, &support_dir, &daemon, true) {
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

/// `walk_all`: a requested sync walks every source (cleared under the lock).
/// An armed source may idle: its cycle-start beat carries no scan start, so the
/// server keeps the window the walk's manifest is paired with.
pub(super) fn cycle_start_scan_started_at(source: SnapshotSource, at: &str) -> Option<&str> {
    (!crate::snapshots::walk_idle::armed(source)).then_some(at)
}

fn drain_relay_journal(support_dir: &Path) {
    if let Err(error) = crate::claude_local_otel::drain_relay_journal(support_dir) {
        eprintln!(
            "local snapshot sync: relay journal drain deferred: {}",
            safe_error(&error)
        );
    }
}

pub(super) fn sync_once(
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    walk_all: bool,
) -> Result<()> {
    // The periodic loop and setup/UI one-shot path can otherwise scan and save
    // the same per-source index concurrently. Serialize the full cycle so a
    // one-shot rescan cannot race the background loop or publish an older
    // incremental index after it.
    let _sync_guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for source in SNAPSHOT_SOURCES.into_iter().filter(|_| walk_all) {
        crate::snapshots::walk_idle::clear(source, "walk_all");
    }
    // Before credentials: a re-enabled source resumes even with no live device.
    resume_reconnected_sources(support_dir);
    // Before any reader: relay rows accepted since the last drain move to
    // their per-session files, which this cycle then reads as before.
    drain_relay_journal(support_dir);
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
    continuation_cycle.collecting(&enabled_sources);
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
            cycle_start_scan_started_at(source, &cycle_started_at),
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

pub(super) struct SnapshotCycleOwner<'a> {
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
        finish_sync_source(
            preparation,
            index,
            scan,
            self.device,
            self.device_secret,
            self.machine_id,
            self.home,
            self.support_dir,
            self.daemon,
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
            // This prepare's policy replaces any older cached inputs.
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
            crate::snapshots::walk_idle::clear(source, "failure");
        }
        match result {
            Ok(()) => self.transport_cycle.note_success(),
            Err(error) => {
                crate::snapshots::scan_index_health::observe_failure(source, &error);
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

pub(super) const SNAPSHOT_SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::Codex,
    SnapshotSource::ClaudeCode,
    SnapshotSource::Pi,
];

pub(crate) fn enabled_snapshot_sources(device: &LocalDeviceBinding) -> Vec<SnapshotSource> {
    enabled_snapshot_sources_in(device, &default_support_dir())
}

/// A source with a removal marker is off at every boundary, whatever its grant.
pub(crate) fn enabled_snapshot_sources_in(
    device: &LocalDeviceBinding,
    support_dir: &Path,
) -> Vec<SnapshotSource> {
    SNAPSHOT_SOURCES
        .into_iter()
        .filter(|source| source_granted(device, *source))
        .filter(|source| source_marker(support_dir, *source).is_none())
        .collect()
}

pub(super) fn source_granted(device: &LocalDeviceBinding, source: SnapshotSource) -> bool {
    device.sources.iter().any(|slug| slug == source.api_slug())
}

/// The heartbeat's relay-token source: the first enabled one, else the first
/// granted one, so a device with every source paused still hears an ON.
pub(super) fn heartbeat_source(device: &LocalDeviceBinding) -> Option<SnapshotSource> {
    enabled_snapshot_sources(device)
        .first()
        .copied()
        .or_else(|| {
            SNAPSHOT_SOURCES
                .into_iter()
                .find(|source| source_granted(device, *source))
        })
}

/// Consecutive resume failures per marker. Held across each resume turn, so a
/// concurrent control-thread marker change cannot be overwritten by that
/// turn's completion.
static SOURCE_ERASURE_TURN: Mutex<BTreeMap<PathBuf, u32>> = Mutex::new(BTreeMap::new());

pub(super) fn source_erasure_turn() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, u32>> {
    SOURCE_ERASURE_TURN
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Any content but `reconnect` means paused (`pending`; `done` from older
/// builds). Nothing local is erased while a source is off.
pub(super) fn source_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    snapshot_index_path(support_dir, source)
        .with_file_name(format!("{}.source-disabled", source.api_slug()))
}

/// `None` only when clearly absent. An unreadable marker stays paused.
pub(crate) fn source_marker(support_dir: &Path, source: SnapshotSource) -> Option<String> {
    match std::fs::read_to_string(source_marker_path(support_dir, source)) {
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        marker => Some(marker.unwrap_or_default()),
    }
}

/// This source alone is paused: a marker that is not already resuming.
pub(crate) fn source_paused(support_dir: &Path, source: SnapshotSource) -> bool {
    source_marker(support_dir, source).is_some_and(|marker| marker != "reconnect")
}

pub(super) fn write_source_marker(path: &Path, state: &str) -> Result<()> {
    ottto_core::write_owner_only_file_atomic(path, state.as_bytes())?;
    sync_progress_parent(path)
}

/// Stops collection now and keeps every local file. Claude's legacy relay
/// closes after the marker is written and the guard is dropped.
pub(crate) fn disable_snapshot_source(support_dir: &Path, source: SnapshotSource) -> Result<()> {
    {
        let _turn = source_erasure_turn();
        write_source_marker(&source_marker_path(support_dir, source), "pending")?;
        reset_collection_health(source);
    }
    if source == SnapshotSource::ClaudeCode {
        crate::otlp_relay::legacy::revoke_now();
    }
    Ok(())
}

/// Applies the web's per-source OFF/ON from a heartbeat reply. Revisions are
/// per device and source; each newer one applies once, recorded in
/// `snapshots/<slug>.source-control` after its marker (a crash between them
/// re-applies the same revision). A missing or another device's record reads
/// as revision 0. OFF pauses like a local disable; ON resumes a paused source
/// and changes nothing for a running one. A block for another device, an
/// unknown source or a malformed entry is ignored.
pub(crate) fn apply_source_control(support_dir: &Path, reply: &serde_json::Value) {
    let block = &reply["source_control"];
    let (Some("source_control:v1"), Some(device_id), Some(entries)) = (
        block["contract"].as_str(),
        block["device_id"].as_str(),
        block["sources"]
            .as_array()
            .filter(|entries| !entries.is_empty()),
    ) else {
        return;
    };
    // Identity, then source: the marker writers take the erasure turn.
    let _binding = crate::control::lock_setup_run_binding();
    let current = ottto_core::FileDeviceStore::default().load().ok().flatten();
    if !current.is_some_and(|current| current.device_id == device_id) {
        return;
    }
    for entry in entries {
        let source = SNAPSHOT_SOURCES
            .into_iter()
            .find(|source| entry["source"].as_str() == Some(source.api_slug()));
        let (Some(source), Some(revision @ 1..), Some(state @ ("enabled" | "disabled"))) = (
            source,
            entry["revision"].as_u64(),
            entry["desired_state"].as_str(),
        ) else {
            continue;
        };
        let record = source_marker_path(support_dir, source)
            .with_file_name(format!("{}.source-control", source.api_slug()));
        let last = std::fs::read(&record)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(|record| record["device_id"] == device_id)
            .and_then(|record| record["revision"].as_u64())
            .unwrap_or(0);
        if revision <= last {
            continue;
        }
        let applied = match state {
            "disabled" => disable_snapshot_source(support_dir, source),
            _ => reconnect_snapshot_source(support_dir, source),
        };
        let body = serde_json::json!({"device_id": device_id, "revision": revision});
        let _ = applied.and_then(|()| write_source_marker(&record, &body.to_string()));
    }
}

/// The explicit way back. A source that was never paused has nothing to resume.
pub(crate) fn reconnect_snapshot_source(support_dir: &Path, source: SnapshotSource) -> Result<()> {
    let _turn = source_erasure_turn();
    match source_marker(support_dir, source) {
        Some(_) => write_source_marker(&source_marker_path(support_dir, source), "reconnect"),
        None => Ok(()),
    }
}

/// A credential generation that drops a source pauses it like an explicit disable.
pub(crate) fn disable_sources_dropped_from_grant(
    support_dir: &Path,
    current: &LocalDeviceBinding,
    next: &LocalDeviceBinding,
) -> Result<()> {
    SNAPSHOT_SOURCES
        .into_iter()
        .filter(|source| source_granted(current, *source) && !source_granted(next, *source))
        .try_for_each(|source| disable_snapshot_source(support_dir, source))
}

/// One attempt per re-enabled source, under the cycle lock. Only the marker
/// goes: the kept index, Tail rows, backfill progress and upload witnesses
/// make its next pass a warm Tail that re-sends nothing already sent (the
/// server keeps data while a source is off). A failure keeps the source
/// paused for the next cycle. Errors can name paths, so only counts are
/// logged.
pub(crate) fn resume_reconnected_sources(support_dir: &Path) {
    for source in SNAPSHOT_SOURCES {
        let mut turn = source_erasure_turn();
        if source_marker(support_dir, source).as_deref() != Some("reconnect") {
            continue;
        }
        let marker = source_marker_path(support_dir, source);
        let resumed = std::fs::remove_file(&marker)
            .map_err(anyhow::Error::from)
            .and_then(|()| {
                // The source is eligible now, even if the later directory sync fails.
                // A prepare hint in flight at pause may have re-armed its pulse.
                reset_collection_health(source);
                crate::snapshots::walk_idle::clear(source, "resumed");
                sync_progress_parent(&marker)
            });
        let failures = turn.entry(marker).or_default();
        *failures = if resumed.is_ok() { 0 } else { *failures + 1 };
        if *failures > 3 {
            crate::snapshots::state_v2::source_erasure_alarm(*failures);
        }
    }
}

pub(crate) fn snapshot_api_base_url() -> Result<String> {
    snapshot_api_base_url_from(
        FileConnectionStore::default().load(),
        std::env::var("OTTTO_API_BASE_URL").ok(),
    )
}

pub(super) fn snapshot_api_base_url_from(
    connection: Result<Option<ottto_core::LocalConnectionBinding>>,
    env_value: Option<String>,
) -> Result<String> {
    // Read/parse/cap errors are not an absent binding: never redirect secrets
    // to the environment/default destination after a persisted binding fails.
    let connection = crate::local_resource_diagnostics::connection_binding_read(connection)?;
    let api_base_url =
        normalize_api_base_url(connection.map(|binding| binding.api_base_url), env_value);
    // Uploads carry this Mac's device credential, so they go only to a backend
    // the control path also trusts.
    if !crate::control::is_trusted_api_base_url(&api_base_url) {
        return Err(anyhow!(
            "connection binding names an untrusted Ottto backend"
        ));
    }
    Ok(api_base_url)
}

pub(super) fn normalize_api_base_url(
    connection_value: Option<String>,
    env_value: Option<String>,
) -> String {
    connection_value
        .or(env_value)
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

pub(crate) fn snapshot_machine_id(device: &LocalDeviceBinding) -> Result<Option<String>> {
    if let Some(machine_id) = device.machine_id.as_ref().filter(|value| !value.is_empty()) {
        return Ok(Some(machine_id.clone()));
    }
    Ok(FileMachineStore::default()
        .load()?
        .map(|machine| machine.machine_id)
        .filter(|value| !value.is_empty()))
}

pub(super) fn snapshot_upload_context_fingerprint(
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:snapshot-upload-context:v1\0");
    digest.update(serde_json::to_vec(&upload_policy).expect("upload policy is serializable"));
    digest.update(b"\0");
    digest.update(
        attribution_checkpoint_namespace
            .unwrap_or("none")
            .as_bytes(),
    );
    format!("{:x}", digest.finalize())
}

/// Evidence probe only: decoding, migration and custody checks remain with the
/// locked source loaders. Never inspect a different destination for ownership.
pub(crate) fn snapshot_namespace_has_store(support: &Path, namespace: &str) -> Result<bool> {
    anyhow::ensure!(
        crate::hex::is_sha256_lower(namespace),
        "invalid snapshot namespace"
    );
    let dir = support.join("snapshots/destinations").join(namespace);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(&dir) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                _ => anyhow::bail!("uncertain snapshot namespace directory"),
            };
        }
        Err(_) => anyhow::bail!("inspect snapshot namespace"),
    };
    anyhow::ensure!(
        std::fs::symlink_metadata(&dir)?.is_dir(),
        "uncertain snapshot namespace directory"
    );
    let mut present = false;
    for entry in entries {
        let entry = entry.context("inspect snapshot namespace entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let relevant = [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ]
        .iter()
        .any(|source| name.starts_with(&format!("{}-scan-index", source.api_slug())));
        if !relevant {
            continue;
        }
        let sharded = name.ends_with(".json.shards") || name.ends_with(".json.v1-readonly.shards");
        let checkpoint = [
            ".v1-readonly.shards",
            ".shards",
            ".v1-readonly",
            ".v2-ack-receipt",
            ".v2.sqlite.import",
            ".v2.sqlite",
        ]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
        if checkpoint.ends_with(".json")
            && !checkpoint.contains("-upload-progress")
            && !checkpoint.contains(".tmp")
            && !checkpoint.contains(".backup")
        {
            let metadata = std::fs::symlink_metadata(entry.path())
                .context("inspect snapshot namespace custody")?;
            anyhow::ensure!(
                (sharded && metadata.is_dir()) || (!sharded && metadata.is_file()),
                "uncertain snapshot namespace custody"
            );
            present = true;
        }
    }
    Ok(present)
}

/// One destination-scoped index is shared by every privacy policy. A policy
/// change applies to bodies acquired from then on; exact entity proofs retain
/// their original upload context.
pub(super) fn snapshot_index_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("snapshots")
        .join(format!("{}-scan-index.json", source.api_slug()))
}

/// Test access to a source's progress path under its progress owner.
#[cfg(test)]
pub(crate) fn with_state_v2_progress_lock<T>(
    index_path: &Path,
    action: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    with_state_v2_progress_owner(index_path, None, |_, path| action(path))
}

/// A borrowed owner cannot outlive its flock. Verify its path before reusing it;
/// partial settlement retains this same owner from subset CAS through COMMIT.
pub(crate) fn with_state_v2_progress_owner<T>(
    index_path: &Path,
    owner: Option<&SnapshotProgressLock>,
    action: impl FnOnce(&SnapshotProgressLock, &Path) -> Result<T>,
) -> Result<T> {
    let path = snapshot_upload_progress_path(index_path);
    match owner {
        Some(owner) => {
            anyhow::ensure!(
                owner.path.as_deref() == Some(path.as_path()),
                "state_v2_progress_owner_path"
            );
            action(owner, &path)
        }
        None => {
            let owner = SnapshotProgressLock::acquire(&path)?.for_v2(&path);
            action(&owner, &path)
        }
    }
}

/// The removed upload-progress bound, (64 MiB - 16 KiB) / 6 bytes.
#[cfg(test)]
pub(crate) const OLD_PROGRESS_BOUND_FOR_TEST: usize = 11_182_080;

#[cfg(test)]
pub(crate) fn validate_state_v2_original_progress(bytes: &[u8], namespace: &str) -> Result<()> {
    // Unknown payload slots are carried byte-exactly. Decode only the owner
    // headers; Serde rejects duplicate headers and consumes the entire object.
    #[derive(Deserialize)]
    struct Owner {
        schema_version: u16,
        destination_namespace_hash: String,
        #[serde(default)]
        generation: u64,
    }
    let owner: Owner = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        owner.schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && is_snapshot_fingerprint(namespace)
            && owner.destination_namespace_hash == namespace
            && owner.generation < u64::MAX,
        "state_v2_original_progress_owner"
    );
    Ok(())
}

pub(super) fn snapshot_upload_progress_path(index_path: &Path) -> PathBuf {
    let stem = index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    index_path.with_file_name(format!("{stem}-upload-progress.json"))
}

pub(super) fn snapshot_v3_index_path(destination_index_path: &Path) -> PathBuf {
    let stem = destination_index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    destination_index_path.with_file_name(format!("{stem}-v3.json"))
}

pub(super) fn snapshot_destination_scoped_index_path(
    policy_index_path: &Path,
    destination_namespace_hash: &str,
) -> PathBuf {
    let parent = policy_index_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = policy_index_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("snapshot-scan-index.json"));
    parent
        .join("destinations")
        .join(destination_namespace_hash)
        .join(file_name)
}

/// Namespaces carried by the credentials `load_snapshot_device_credentials`
/// read, keyed by device id and sha256(secret): an entry only ever applies to
/// its exact credential, so resolving needs no second `device.json` read.
static CARRIED_NAMESPACES: Mutex<BTreeMap<(String, String), String>> = Mutex::new(BTreeMap::new());

/// Called by the credential loader on every load. It overwrites this exact
/// credential's entry with what it resolves now: the alias only when its
/// commitment is sha256(secret), else the raw hash. A reload after a legacy
/// writer stripped the alias therefore resolves raw, as a fresh process does.
pub(crate) fn carry_snapshot_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
    alias: Option<&ottto_core::SnapshotNamespaceAlias>,
) {
    let key = (
        device.device_id.clone(),
        crate::control::secret_sha256(device_secret),
    );
    let namespace = snapshot_destination_namespace(device, device_secret, alias);
    let mut carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    carried.insert(key, namespace);
}

/// Test-only: forget what earlier loads carried for these devices.
#[cfg(test)]
pub(crate) fn forget_carried_namespaces_for_test(device_ids: &[&str]) {
    let mut carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    carried.retain(|(device_id, _), _| !device_ids.contains(&device_id.as_str()));
}

/// Destination namespace of a loaded relay credential.
pub(crate) fn snapshot_upload_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> String {
    let key = (
        device.device_id.clone(),
        crate::control::secret_sha256(device_secret),
    );
    let carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    match carried.get(&key) {
        Some(namespace) => namespace.clone(),
        None => snapshot_destination_namespace(device, device_secret, None),
    }
}

/// Test-only: `links` same-account re-logins from a credential resolving to
/// `canonical`. Each successor carries the namespace as promotion writes it
/// and the loader reads it; returns what the last successor resolves to.
#[cfg(test)]
pub(crate) fn relogin_namespace(canonical: &str, links: usize) -> String {
    let mut namespace = canonical.to_string();
    for link in 1..=links {
        let device = LocalDeviceBinding {
            device_id: format!("relogin-{canonical}-{link}"),
            machine_id: Some("otm_test".into()),
            sources: Vec::new(),
        };
        let secret = format!("relogin-secret-{link}");
        let alias = ottto_core::SnapshotNamespaceAlias {
            namespace,
            secret_commitment_sha256: crate::control::secret_sha256(&secret),
        };
        carry_snapshot_namespace(&device, &secret, Some(&alias));
        namespace = snapshot_upload_destination_namespace(&device, &secret);
        assert_ne!(
            namespace,
            snapshot_destination_namespace(&device, &secret, None)
        );
    }
    namespace
}

/// The one namespace derivation: a confirmed same-account successor's alias
/// while the secret matches its commitment, else hash(device id, secret).
pub(crate) fn snapshot_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
    alias: Option<&ottto_core::SnapshotNamespaceAlias>,
) -> String {
    if let Some(alias) = alias.filter(|alias| {
        crate::hex::is_sha256_lower(&alias.namespace)
            && crate::control::secret_commitment_matches(
                &alias.secret_commitment_sha256,
                device_secret,
            )
    }) {
        return alias.namespace.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:snapshot-delivery-destination:relay-device:v1\0");
    hasher.update(device.device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(super) fn ensure_snapshot_scan_authority(
    expected_device: &LocalDeviceBinding,
    source: SnapshotSource,
    client: &SnapshotApiClient,
    expected_account: &[u8; 32],
    daemon: &LocalDaemon,
) -> Result<()> {
    let rejected = || {
        anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "source authority changed during owned scan",
        })
    };
    let current = crate::local_resource_diagnostics::credential_file_read(
        ottto_core::FileDeviceStore::default().load(),
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    let account = daemon
        .snapshot_scan_account_witness()
        .map_err(|_| rejected())?;
    validate_snapshot_scan_authority(
        expected_device,
        &current,
        source,
        client.matches_api_base(&snapshot_api_base_url().map_err(|_| rejected())?),
        expected_account,
        &account,
    )
}

pub(super) fn validate_snapshot_scan_authority(
    expected_device: &LocalDeviceBinding,
    current: &LocalDeviceBinding,
    source: SnapshotSource,
    endpoint_matches: bool,
    expected_account: &[u8; 32],
    current_account: &[u8; 32],
) -> Result<()> {
    if current.device_id != expected_device.device_id
        || current.machine_id != expected_device.machine_id
        || !enabled_snapshot_sources(current).contains(&source)
        || !endpoint_matches
        || expected_account != current_account
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "source authority changed during owned scan",
        }));
    }
    Ok(())
}

pub(super) fn ensure_snapshot_destination_current(expected_namespace_hash: &str) -> Result<()> {
    let (current_device, current_device_secret) =
        load_snapshot_device_credentials().map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "revalidate relay destination",
            })
        })?;
    validate_snapshot_destination(
        expected_namespace_hash,
        &current_device,
        &current_device_secret,
    )
}

pub(super) fn validate_snapshot_destination(
    expected_namespace_hash: &str,
    current_device: &LocalDeviceBinding,
    current_device_secret: &str,
) -> Result<()> {
    if snapshot_upload_destination_namespace(current_device, current_device_secret)
        != expected_namespace_hash
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "relay destination changed during snapshot sync",
        }));
    }
    Ok(())
}

pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}
