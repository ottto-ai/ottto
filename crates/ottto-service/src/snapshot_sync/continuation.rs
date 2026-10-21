//! Paced cursor continuation pages (FC1 Stage 1, sync-loop hunks B/C/F).
//!
//! A Codex page that pauses a still-valid cursor job only because its byte
//! budget ran out may ask for the next page sooner than the ordinary cadence.
//! That next page runs through [`run_page`], a dedicated entry point that is not
//! `sync_once`: it makes no network call (no relay token, activity hint,
//! receipt, status or health upload) unless the job reaches EOF, and then only
//! the existing authorized completion upload, after rechecking the scan
//! authority, the destination and the upload backoff. Ordinary cycles keep
//! their own deadline, so other sources' due work and network cadence are
//! unchanged, and an EOF completion does not move the ordinary Codex cadence.
//!
//! Everything here is compiled in and **inert**: [`ENABLED`] is false, the
//! cursor side is the [`NoCursorContinuation`] stub (c22 owns hunks A/D/E and
//! the guard, after #660), and the platform gates are [`NoPlatformSignals`],
//! whose unknown state falls back to the ordinary cadence. Inert parity rests
//! on that constant gate and on review: the loop takes today's path before it
//! reaches anything in this module.

use super::live_snapshot_retry::LiveRetryOwner;
use super::{
    complete_continuation_eof, enabled_snapshot_sources, load_snapshot_device_credentials,
    snapshot_api_base_url, snapshot_upload_destination_namespace, source_upload_backoff_remaining,
    with_source_cadence, ScanIndex, SnapshotSource, SourcePreparation, SourceScanResult,
    SNAPSHOT_SYNC_LOCK,
};
use crate::adaptive_collector::{ContinuationPacing, SourceCadence};
use crate::LocalDaemon;
use anyhow::{anyhow, Result};
use ottto_core::LocalDeviceBinding;
use ottto_protocol::LocalCollectorState;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Off until c22's cursor protocol (A/D/E/guard after #660), the platform
/// hunks and the exact integration are reviewed. While false, the sync loop
/// takes exactly today's path and no continuation state is written.
pub(super) const ENABLED: bool = false;

/// At least 30 s and nine idle seconds per working second between pages.
pub(super) const PACING: ContinuationPacing = ContinuationPacing {
    min_gap: Duration::from_secs(30),
    idle_per_work: 9,
};

/// A page whose measured work exceeds this is read as contention (a loaded
/// machine, a slow disk or a long lock wait): the next page waits for the
/// ordinary cadence instead. It is also the page's cooperative deadline; an
/// in-progress record, finalization and scheduling can overrun it.
pub(super) const CONTENTION_WORK: Duration = Duration::from_secs(20);

/// c22's cursor binding for one paused attempt (hunk A: namespace, rotation
/// key, `stamp_open`, `started`), minted only at the single pause site. The
/// scaffolding carries no cursor fields, and nothing in production mints one.
#[allow(dead_code)] // Minted only by c22's pause site (hunk A, after #660).
pub(super) struct CursorTicket {
    _sealed: (),
}

/// What c22's EOF page hands back: the committed job's preparation, index and
/// scan. StateMissing settles it ([`Host::complete_eof`] or
/// [`Host::defer_eof`]) through the same completion an ordinary Codex finish
/// runs. Nothing in production builds one until c22 wires its EOF page.
pub(super) struct EofCompletion(EofParts);

enum EofParts {
    Scan(Box<(SourcePreparation, ScanIndex, SourceScanResult)>),
    /// A stand-in for the fakes, which have no real scan to complete.
    #[cfg(test)]
    Synthetic,
}

impl EofCompletion {
    #[allow(dead_code)] // Built only by c22's EOF page (after #660).
    pub(super) fn new(
        preparation: SourcePreparation,
        index: ScanIndex,
        scan: SourceScanResult,
    ) -> Self {
        Self(EofParts::Scan(Box::new((preparation, index, scan))))
    }

    #[cfg(test)]
    pub(super) fn synthetic() -> Self {
        Self(EofParts::Synthetic)
    }

    /// The committed job's preparation, index and scan.
    pub(super) fn into_parts(self) -> Option<(SourcePreparation, ScanIndex, SourceScanResult)> {
        match self.0 {
            EofParts::Scan(parts) => Some(*parts),
            #[cfg(test)]
            EofParts::Synthetic => None,
        }
    }
}

/// The permission a finished Codex page leaves for the next continuation page.
/// Both bindings are fixed-size digests, so the slot never allocates.
pub(super) struct ContinuationTicket {
    /// SHA-256 of the destination namespace the asking page ran under.
    destination: [u8; 32],
    /// The scan authority the asking page ran under ([`current_authority`]).
    authority: [u8; 32],
    cursor: CursorTicket,
}

/// How one continuation page ended on the cursor side.
#[allow(dead_code)] // Only c22's cursor port (after #660) produces these outside tests.
pub(super) enum PageEnd {
    /// Saved `Ok` with its C15 callback, and the job paused again at its byte
    /// budget: the only end that may ask for another page.
    Paused(CursorTicket),
    /// Saved at a deadline or contention boundary, without exhausting the byte
    /// budget. No ticket or continuation request may follow this pause.
    PausedContended,
    /// The resume was refused or not `Active`; the job's paths stay pending for
    /// the next ordinary pass.
    Deferred,
    /// The job reached EOF and committed; its upload obligation remains.
    Eof(EofCompletion),
    /// The lease was lost, the page was dropped, or the process is stopping.
    /// Nothing was saved.
    Cancelled,
    /// A local error, such as a failed or CAS-refused save.
    Failed(anyhow::Error),
}

/// The cursor side of a continuation page. c22 implements it after #660.
/// None of its methods may make a network call; the EOF completion upload is
/// StateMissing's ([`Host::complete_eof`]).
pub(super) trait CursorContinuation {
    /// Hunk A: the ticket of a just-finished ordinary Codex page, only for a
    /// valid, budget-exhausted, accelerated pause.
    fn ticket_for(&self, scan: &SourceScanResult) -> Option<CursorTicket>;
    /// `cursor_continuation_ready`: under the cursor lock, with no IO.
    fn ready(&mut self, ticket: &CursorTicket) -> bool;
    /// One resume-only page: `ScanIndex::load`, then
    /// `begin_codex_side_pass(Continuation)`, the scan, the C15 mark, the save
    /// and `note_codex_side_saved` on `Ok`. Once `deadline` passes, the page
    /// stops at the next record boundary, saves and returns `PausedContended`.
    /// The deadline is cooperative: the in-progress record, local finalization
    /// and scheduling may overrun it; it is not a hard lock-hold bound.
    fn page(&mut self, ticket: CursorTicket, deadline: Instant) -> PageEnd;
}

/// The production cursor side until c22's hunks land: there is never a
/// continuation.
pub(super) struct NoCursorContinuation;

impl CursorContinuation for NoCursorContinuation {
    fn ticket_for(&self, _scan: &SourceScanResult) -> Option<CursorTicket> {
        None
    }
    fn ready(&mut self, _ticket: &CursorTicket) -> bool {
        false
    }
    fn page(&mut self, _ticket: CursorTicket, _deadline: Instant) -> PageEnd {
        PageEnd::Deferred
    }
}

/// A platform answer. Anything but `Allowed` falls back to the ordinary
/// cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `Refused` comes from the platform hunk under review.
pub(super) enum PlatformState {
    Allowed,
    Refused,
    Unknown,
}

/// Mandatory platform gates for a continuation page (hunk F).
pub(super) trait PlatformGates {
    /// On mains power with Low Power Mode off.
    fn power(&mut self) -> PlatformState;
    /// Lower this thread to background QoS for the page. `Allowed` means it
    /// was applied, and [`PlatformGates::restore_qos`] then runs after the page.
    fn enter_background_qos(&mut self) -> PlatformState;
    fn restore_qos(&mut self);
}

/// The service has no power, Low Power Mode or QoS call today. The proposed
/// APIs wait for review, so every answer is unknown and no page runs.
pub(super) struct NoPlatformSignals;

impl PlatformGates for NoPlatformSignals {
    fn power(&mut self) -> PlatformState {
        PlatformState::Unknown
    }
    fn enter_background_qos(&mut self) -> PlatformState {
        PlatformState::Unknown
    }
    fn restore_qos(&mut self) {}
}

/// Codex's cadence, for short critical sections.
pub(super) trait CadenceAccess {
    /// `None` when the cadence is unavailable.
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T>;
}

/// The state a continuation page reads, and StateMissing's settlement of an
/// EOF page. Only [`Host::complete_eof`] touches the network.
pub(super) trait Host: CadenceAccess {
    fn now(&mut self) -> Instant;
    /// Whether the server's upload backoff for Codex is still running.
    fn upload_backoff(&mut self) -> bool;
    /// SHA-256 of the current destination namespace, from local credentials.
    fn destination(&mut self) -> Option<[u8; 32]>;
    /// The current scan authority ([`current_authority`]) from the local device
    /// record, endpoint and account witness; `None` when Codex is no longer
    /// granted or an input is unavailable.
    fn authority(&mut self) -> Option<[u8; 32]>;
    /// The existing authorized completion upload, attempted once: the same
    /// census fence, authority and destination validation and unchanged
    /// `finish_sync_source` an ordinary Codex finish runs.
    fn complete_eof(&mut self, completion: EofCompletion) -> Result<()>;
    /// Completion cannot proceed now: the job's obligations stay owed to the
    /// next ordinary pass. Never a whole-index save of the un-uploaded commit.
    fn defer_eof(&mut self, completion: EofCompletion);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Skip {
    NoTicket,
    NotDue,
    Failing,
    Backoff,
    Platform,
    LockBusy,
    Authority,
    Destination,
    NotReady,
    CadenceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Skipped(Skip),
    Paused,
    /// Paused, but too slow to ask for another page: ordinary cadence next.
    PausedContended,
    /// Paused and saved, but the cadence took no request (unavailable, or the
    /// source is now disabled): ordinary cadence next.
    PausedWithoutRequest,
    Deferred,
    EofCompleted,
    EofDeferred,
    EofFailed,
    Cancelled,
    Failed,
}

impl Outcome {
    pub(super) fn label(self) -> &'static str {
        match self {
            Outcome::Skipped(skip) => match skip {
                Skip::NoTicket => "skipped_no_ticket",
                Skip::NotDue => "skipped_not_due",
                Skip::Failing => "skipped_failing",
                Skip::Backoff => "skipped_upload_backoff",
                Skip::Platform => "skipped_platform",
                Skip::LockBusy => "skipped_lock_busy",
                Skip::Authority => "skipped_authority",
                Skip::Destination => "skipped_destination",
                Skip::NotReady => "skipped_not_ready",
                Skip::CadenceUnavailable => "skipped_cadence_unavailable",
            },
            Outcome::Paused => "paused",
            Outcome::PausedContended => "paused_contended",
            Outcome::PausedWithoutRequest => "paused_without_request",
            Outcome::Deferred => "deferred",
            Outcome::EofCompleted => "eof_completed",
            Outcome::EofDeferred => "eof_deferred",
            Outcome::EofFailed => "eof_failed",
            Outcome::Cancelled => "cancelled",
            Outcome::Failed => "failed",
        }
    }
}

/// Run at most one continuation page.
///
/// `slot` holds the ticket. Only a `Paused` page under the contention limit
/// leaves a ticket and a cadence request behind; every other end clears both,
/// so the next page is ordinary. `lock` is held for the whole page (c22 R0) and
/// released before return, so it is never held while waiting between pages.
/// The ticket is taken and any new ticket written only while `lock` is held,
/// as an ordinary Codex finish writes its own, so a page can never overwrite a
/// newer ordinary decision with an older ticket. Clearing needs no lock: it
/// can only lose a continuation.
///
/// The page receives the earlier of `ordinary_deadline` and
/// [`CONTENTION_WORK`] after entry as a cooperative deadline. Measured work
/// runs from entry to just before the lock is released, so preparation, any EOF
/// completion and finalization all count.
pub(super) fn run_page<H: Host, P: CursorContinuation, G: PlatformGates>(
    host: &mut H,
    port: &mut P,
    gates: &mut G,
    lock: &Mutex<()>,
    slot: &Mutex<Option<ContinuationTicket>>,
    ordinary_deadline: Instant,
) -> Outcome {
    let started = host.now();
    if lock_slot(slot).is_none() {
        return Outcome::Skipped(Skip::NoTicket);
    }
    let skip = |host: &mut H, skip: Skip| {
        clear(host, slot);
        Outcome::Skipped(skip)
    };
    let check_due = |host: &mut H, now| match page_due(host, now) {
        Ok(true) => None,
        // An early wake keeps the ticket and request without moving either.
        Ok(false) => Some(Outcome::Skipped(Skip::NotDue)),
        Err(reason) => Some(skip(host, reason)),
    };
    if let Some(outcome) = check_due(host, started) {
        return outcome;
    }
    if gates.power() != PlatformState::Allowed {
        return skip(host, Skip::Platform);
    }
    let guard = match lock.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        // A one-shot or ordinary cycle owns the index now; it decides.
        Err(TryLockError::WouldBlock) => return skip(host, Skip::LockBusy),
    };
    if lock_slot(slot).is_none() {
        return Outcome::Skipped(Skip::NoTicket);
    }
    // An ordinary one-shot may have replaced both the ticket and its request
    // after the cheap precheck. Check the current policy under the same lock
    // that protects ticket replacement, before consuming that ticket.
    let now = host.now();
    if let Some(outcome) = check_due(host, now) {
        return outcome;
    }
    let Some(ticket) = lock_slot(slot).take() else {
        // An ordinary pass cleared it after the check above.
        return Outcome::Skipped(Skip::NoTicket);
    };
    // The same authority an ordinary pass checks at every prepare and finish:
    // device, machine, Codex grant, endpoint and account.
    if host.authority() != Some(ticket.authority) {
        return skip(host, Skip::Authority);
    }
    if host.destination() != Some(ticket.destination) {
        return skip(host, Skip::Destination);
    }
    if gates.enter_background_qos() != PlatformState::Allowed {
        return skip(host, Skip::Platform);
    }
    let ContinuationTicket {
        destination,
        authority,
        cursor,
    } = ticket;
    let deadline = started
        .checked_add(CONTENTION_WORK)
        .map_or(ordinary_deadline, |limit| limit.min(ordinary_deadline));
    let qos = RestoreQos(gates);
    let ended = if port.ready(&cursor) {
        Some(port.page(cursor, deadline))
    } else {
        None
    };
    // Back to the thread's own QoS before any EOF network work.
    drop(qos);
    let (outcome, next) = match ended {
        None => (Outcome::Skipped(Skip::NotReady), None),
        Some(PageEnd::Paused(cursor)) => (
            Outcome::Paused,
            Some(ContinuationTicket {
                destination,
                authority,
                cursor,
            }),
        ),
        Some(PageEnd::PausedContended) => (Outcome::PausedContended, None),
        Some(PageEnd::Deferred) => (Outcome::Deferred, None),
        Some(PageEnd::Cancelled) => (Outcome::Cancelled, None),
        Some(PageEnd::Failed(_)) => (Outcome::Failed, None),
        Some(PageEnd::Eof(completion)) => {
            (settle_eof(host, completion, destination, authority), None)
        }
    };
    let finished = host.now();
    let outcome = match next {
        Some(next) => match finished.checked_duration_since(started) {
            Some(work) if work <= CONTENTION_WORK => {
                match host.cadence(|cadence| cadence.request_continuation(finished, work)) {
                    Some(true) => {
                        *lock_slot(slot) = Some(next);
                        outcome
                    }
                    _ => {
                        clear(host, slot);
                        Outcome::PausedWithoutRequest
                    }
                }
            }
            _ => {
                clear(host, slot);
                Outcome::PausedContended
            }
        },
        None => {
            clear(host, slot);
            outcome
        }
    };
    drop(guard);
    outcome
}

/// `Ok(false)` preserves a future request; any error clears it. Called both
/// before and under the sync lock, so a replacement ticket uses its own policy.
fn page_due(host: &mut impl Host, now: Instant) -> std::result::Result<bool, Skip> {
    let (state, due) = host
        .cadence(|cadence| (cadence.state(), cadence.continuation_due(PACING)))
        .ok_or(Skip::CadenceUnavailable)?;
    if state == LocalCollectorState::Failing {
        return Err(Skip::Failing);
    }
    if host.upload_backoff() {
        return Err(Skip::Backoff);
    }
    due.map(|due| now >= due).ok_or(Skip::NotDue)
}

/// Restores the thread's QoS when dropped, including on a panic in the page.
struct RestoreQos<'a, G: PlatformGates>(&'a mut G);

impl<G: PlatformGates> Drop for RestoreQos<'_, G> {
    fn drop(&mut self) {
        self.0.restore_qos();
    }
}

/// Settle an EOF page, still under the sync lock. The authority, destination
/// and upload backoff are rechecked before the first network call of the page.
/// The completion upload is attempted once and never retried here.
///
/// An EOF completion is not an ordinary scan: the unchanged
/// `finish_sync_source` records its cadence as one, so the ordinary Codex clock
/// (tier, last scan, failures, full sweep) is saved first and put back after.
/// The ordinary Codex cadence is therefore exactly what it was before the page.
/// Without a saved clock the completion is deferred to the ordinary pass.
fn settle_eof<H: Host>(
    host: &mut H,
    completion: EofCompletion,
    destination: [u8; 32],
    authority: [u8; 32],
) -> Outcome {
    let current = !host.upload_backoff()
        && host.destination() == Some(destination)
        && host.authority() == Some(authority);
    let clock = if current {
        host.cadence(|cadence| cadence.ordinary_clock())
    } else {
        None
    };
    let Some(clock) = clock else {
        host.defer_eof(completion);
        return Outcome::EofDeferred;
    };
    let completed = host.complete_eof(completion);
    host.cadence(|cadence| cadence.restore_ordinary_clock(clock));
    if completed.is_ok() {
        Outcome::EofCompleted
    } else {
        Outcome::EofFailed
    }
}

fn lock_slot(
    slot: &Mutex<Option<ContinuationTicket>>,
) -> MutexGuard<'_, Option<ContinuationTicket>> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// No continuation: neither the ticket nor the cadence request survives.
fn clear(cadence: &mut impl CadenceAccess, slot: &Mutex<Option<ContinuationTicket>>) {
    *lock_slot(slot) = None;
    cadence.cadence(SourceCadence::clear_continuation);
}

/// What the sync loop does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wake {
    /// Wait this long, then run the ordinary cycle.
    Ordinary(Duration),
    /// Wait this long, then try one continuation page.
    Continuation(Duration),
}

/// Choose the next wake. A continuation page is offered only if, judged by the
/// asking page's work, it would finish before the ordinary deadline, so the
/// ordinary cycle keeps its slot.
pub(super) fn plan_wake(
    now: Instant,
    ordinary_deadline: Instant,
    pending: Option<(Instant, Duration)>,
) -> Wake {
    let ordinary = Wake::Ordinary(ordinary_deadline.saturating_duration_since(now));
    let Some((due, work)) = pending else {
        return ordinary;
    };
    match due.max(now).checked_add(work) {
        Some(end) if end <= ordinary_deadline => {
            Wake::Continuation(due.saturating_duration_since(now))
        }
        _ => ordinary,
    }
}

/// The loop's view of time, waiting and pages, so the schedule can be tested.
pub(super) trait LoopHost {
    fn now(&mut self) -> Instant;
    /// Wait up to `wait`; `true` when something (a Claude account switch) asks
    /// for the ordinary cycle now.
    fn wait(&mut self, wait: Duration) -> bool;
    fn pending(&mut self) -> Option<(Instant, Duration)>;
    /// One continuation page, which should end by `deadline`.
    fn page(&mut self, deadline: Instant) -> Outcome;
}

/// Wait out one ordinary interval, running due continuation pages inside it.
/// The ordinary deadline is fixed when the wait starts, and each page is given
/// it as its own deadline. A page can still push the ordinary cycle out by
/// the record it was reading when the deadline passed, required local
/// finalization and scheduling, plus any EOF completion upload. There is no
/// hard elapsed-time guarantee.
pub(super) fn wait_for_ordinary_cycle(host: &mut impl LoopHost, interval: Duration) {
    let start = host.now();
    let Some(deadline) = start.checked_add(interval) else {
        host.wait(interval);
        return;
    };
    loop {
        let now = host.now();
        let pending = host.pending();
        match plan_wake(now, deadline, pending) {
            Wake::Ordinary(wait) => {
                host.wait(wait);
                return;
            }
            Wake::Continuation(wait) => {
                if host.wait(wait) {
                    return;
                }
                let outcome = host.page(deadline);
                if matches!(outcome, Outcome::EofFailed | Outcome::Failed) {
                    eprintln!(
                        "local snapshot continuation page ended: {}",
                        outcome.label()
                    );
                }
            }
        }
    }
}

static TICKET: Mutex<Option<ContinuationTicket>> = Mutex::new(None);

/// Codex's production cadence.
struct CodexCadence;

impl CadenceAccess for CodexCadence {
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        with_source_cadence(SnapshotSource::Codex, apply)
    }
}

fn destination_digest(namespace: &str) -> [u8; 32] {
    Sha256::digest(namespace.as_bytes()).into()
}

/// The scan authority a Codex page may run under, as one fixed-size digest:
/// exactly the inputs `validate_snapshot_scan_authority` compares (device id,
/// machine id, the Codex grant, the API endpoint and the account witness).
/// `None` once the device record no longer grants Codex.
pub(super) fn current_authority(
    device: &LocalDeviceBinding,
    endpoint: &str,
    account: &[u8; 32],
) -> Option<[u8; 32]> {
    if !enabled_snapshot_sources(device).contains(&SnapshotSource::Codex) {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"ottto:continuation-scan-authority:v1\0");
    for field in [
        Some(device.device_id.as_str()),
        device.machine_id.as_deref(),
        Some(endpoint),
    ] {
        match field {
            Some(value) => {
                digest.update([1u8]);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
            None => digest.update([0u8]),
        }
    }
    digest.update(account);
    Some(digest.finalize().into())
}

/// The ticket an ordinary Codex page's pause minted, bound to the destination
/// and the scan authority it ran under. Read before the finish consumes the
/// scan. No authority, no ticket.
pub(super) fn ordinary_ticket(
    port: &impl CursorContinuation,
    scan: &SourceScanResult,
    destination_namespace: &str,
    authority: Option<[u8; 32]>,
) -> Option<ContinuationTicket> {
    let authority = authority?;
    port.ticket_for(scan).map(|cursor| ContinuationTicket {
        destination: destination_digest(destination_namespace),
        authority,
        cursor,
    })
}

/// After an ordinary Codex finish, under `SNAPSHOT_SYNC_LOCK`: keep the page's
/// ticket (with its measured work, from preparation to the end of the finish)
/// only if the finish succeeded, the page was not contended and the cadence
/// took the request; otherwise clear any older one.
pub(super) fn after_ordinary_codex_page(
    ticket: Option<ContinuationTicket>,
    started: Option<Instant>,
    finished_ok: bool,
) {
    let finished = Instant::now();
    let ticket = finished_ok
        .then_some(ticket)
        .flatten()
        .zip(started.and_then(|started| finished.checked_duration_since(started)))
        .filter(|(_, work)| *work <= CONTENTION_WORK);
    if let Some((ticket, work)) = ticket {
        let requested = with_source_cadence(SnapshotSource::Codex, |cadence| {
            cadence.request_continuation(finished, work)
        });
        if requested == Some(true) {
            *lock_slot(&TICKET) = Some(ticket);
            return;
        }
    }
    clear(&mut CodexCadence, &TICKET);
}

/// An ordinary Codex pass failed: no continuation follows it.
pub(super) fn after_ordinary_codex_failure() {
    clear(&mut CodexCadence, &TICKET);
}

/// How an ordinary cycle ended, for the continuation it leaves behind. A cycle
/// that failed, including before rotation, or ran without the Codex grant
/// leaves none.
pub(super) fn settle_cycle(
    cadence: &mut impl CadenceAccess,
    slot: &Mutex<Option<ContinuationTicket>>,
    succeeded_with_codex: bool,
) {
    if !succeeded_with_codex {
        clear(cadence, slot);
    }
}

/// Settles the continuation when an ordinary cycle ends ([`settle_cycle`]).
/// Created right after `SNAPSHOT_SYNC_LOCK` is taken, so it drops, and settles,
/// before the lock is released on every return path, including `?`.
#[derive(Default)]
pub(super) struct CycleSettlement {
    succeeded_with_codex: bool,
}

impl CycleSettlement {
    /// The cycle succeeded; `codex_granted` is whether it ran with Codex.
    pub(super) fn succeeded(&mut self, codex_granted: bool) {
        self.succeeded_with_codex = codex_granted;
    }
}

impl Drop for CycleSettlement {
    fn drop(&mut self) {
        if ENABLED {
            settle_cycle(&mut CodexCadence, &TICKET, self.succeeded_with_codex);
        }
    }
}

/// The pending page for the loop planner, or `None` while inert.
pub(super) fn production_pending() -> Option<(Instant, Duration)> {
    if !ENABLED {
        return None;
    }
    if lock_slot(&TICKET).is_none() {
        return None;
    }
    with_source_cadence(SnapshotSource::Codex, |cadence| {
        cadence
            .continuation_due(PACING)
            .zip(cadence.continuation_work())
    })
    .flatten()
}

/// The production host: local reads, plus the EOF completion inputs.
struct ProductionHost<'a> {
    home: &'a Path,
    support_dir: &'a Path,
    daemon: &'a LocalDaemon,
    retry: &'a mut LiveRetryOwner,
}

impl CadenceAccess for ProductionHost<'_> {
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        with_source_cadence(SnapshotSource::Codex, apply)
    }
}

impl Host for ProductionHost<'_> {
    fn now(&mut self) -> Instant {
        Instant::now()
    }
    fn upload_backoff(&mut self) -> bool {
        source_upload_backoff_remaining(SnapshotSource::Codex).is_some()
    }
    fn destination(&mut self) -> Option<[u8; 32]> {
        let (device, mut secret) = load_snapshot_device_credentials().ok()?;
        let namespace = snapshot_upload_destination_namespace(&device, &secret);
        secret.zeroize();
        Some(destination_digest(&namespace))
    }
    fn authority(&mut self) -> Option<[u8; 32]> {
        let current = ottto_core::FileDeviceStore::default().load().ok()??;
        let account = self.daemon.snapshot_scan_account_witness().ok()?;
        current_authority(&current, &snapshot_api_base_url(), &account)
    }
    fn complete_eof(&mut self, completion: EofCompletion) -> Result<()> {
        let completed = completion
            .into_parts()
            .ok_or_else(|| anyhow!("continuation completion has no scan"))?;
        complete_continuation_eof(
            self.home,
            self.support_dir,
            self.daemon,
            self.retry,
            completed,
        )
    }
    fn defer_eof(&mut self, completion: EofCompletion) {
        // Nothing is uploaded or saved: the committed job stays owed to the
        // next ordinary pass, which re-reads at most this page.
        drop(completion);
    }
}

/// One production continuation page, or a skip while inert.
pub(super) fn run_production_page(
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    retry: &mut LiveRetryOwner,
    ordinary_deadline: Instant,
) -> Outcome {
    if !ENABLED {
        return Outcome::Skipped(Skip::NoTicket);
    }
    run_page(
        &mut ProductionHost {
            home,
            support_dir,
            daemon,
            retry,
        },
        &mut NoCursorContinuation,
        &mut NoPlatformSignals,
        SNAPSHOT_SYNC_LOCK.get_or_init(|| Mutex::new(())),
        &TICKET,
        ordinary_deadline,
    )
}

/// Ordinary-page coverage for c22's same-revision guard and E2 accounting.
/// `None` means no acceleration: neither elapsed continuation work nor an
/// observed loop maximum proves when the unaccelerated attempt would finish.
/// Ordinary cycles and lock waits have no enforced duration bound, and policy
/// can change during an attempt. This scaffold supplies no coverage witness,
/// so it always refuses coverage, regardless of ENABLED or cadence history.
/// A future integration must preserve the actual ordinary eligibility clock
/// through final admission, including directive and upload-backoff changes,
/// before returning any credit here.
#[allow(dead_code)] // c22's guard (after #660) is the first production caller.
pub(super) fn production_ordinary_equivalent() -> Option<Duration> {
    None
}

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;
