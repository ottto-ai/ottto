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
//! Everything here is compiled in and **inert**: [`ENABLED`] is false, and the
//! platform gates are [`NoPlatformSignals`], whose unknown state falls back to
//! the ordinary cadence. The cursor side is [`CodexContinuation`], the adapter
//! over c22's `CodexCursorPort` (hunks A/D/E and the guard). It runs each page
//! on a short-lived, explicitly joined worker (Option W) and is reached only
//! behind [`ENABLED`]. Inert parity rests on that constant gate and on review:
//! the loop takes today's path before it reaches anything in this module.

use super::live_snapshot_retry::LiveRetryOwner;
use super::{
    complete_continuation_eof, enabled_snapshot_sources, load_snapshot_device_credentials,
    run_continuation_scan, safe_error, snapshot_api_base_url,
    snapshot_upload_destination_namespace, source_upload_backoff_remaining, with_source_cadence,
    ContinuationInputs, ContinuationScan, ScanIndex, SnapshotSource, SourcePreparation,
    SourceScanResult, SNAPSHOT_SYNC_INTERVAL, SNAPSHOT_SYNC_LOCK,
};
use crate::adaptive_collector::{ContinuationPacing, SourceCadence};
use crate::snapshots::sampled_scan::SharedCache;
use crate::snapshots::{CodexCursorPort, CodexCursorTicket};
use crate::LocalDaemon;
use anyhow::{anyhow, Result};
use ottto_core::LocalDeviceBinding;
use ottto_protocol::LocalCollectorState;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
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
/// key, `stamp_open`, `started`), minted only at the single pause site, with
/// the same-cycle inputs its continuation pages run on.
pub(super) struct CursorTicket(CursorParts);

enum CursorParts {
    Codex(Box<CodexPage>),
    /// A stand-in for the fakes, which have no cursor state.
    #[cfg(test)]
    Synthetic,
}

/// One paused attempt's ticket and the inputs its pages run on (`None` until
/// the minting finish attaches them; a ticket without inputs is never ready).
/// The inputs move to the worker with the page and back with a re-pause,
/// never copied (K2).
struct CodexPage {
    cursor: CodexCursorTicket,
    inputs: Option<ContinuationInputs>,
}

crate::heap_layout_bound::fields!(CodexPage; cursor, inputs);

impl CursorTicket {
    fn codex(cursor: CodexCursorTicket) -> Self {
        Self(CursorParts::Codex(Box::new(CodexPage {
            cursor,
            inputs: None,
        })))
    }

    #[cfg(test)]
    pub(super) fn synthetic() -> Self {
        Self(CursorParts::Synthetic)
    }

    /// Process-retained bytes of this ticket's boxed page and inputs, through
    /// the existing requested-layout admission (`None`: unknown, refused).
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        match &self.0 {
            CursorParts::Codex(page) => crate::heap_layout_bound::bound(page, limit),
            #[cfg(test)]
            CursorParts::Synthetic => Some(0),
        }
    }
}

/// What an EOF page hands back: the committed job's preparation, index and
/// scan, built only from a page whose `continuation_committed()` is true.
/// StateMissing settles it ([`Host::complete_eof`] or [`Host::defer_eof`])
/// through the same completion an ordinary Codex finish runs.
pub(super) struct EofCompletion(EofParts);

enum EofParts {
    Scan(Box<(SourcePreparation, ScanIndex, SourceScanResult)>),
    /// A stand-in for the fakes, which have no real scan to complete.
    #[cfg(test)]
    Synthetic,
}

impl EofCompletion {
    /// The committed page's parts, moved from the worker unchanged.
    fn of(parts: Box<(SourcePreparation, ScanIndex, SourceScanResult)>) -> Self {
        Self(EofParts::Scan(parts))
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
/// Both bindings are fixed-size digests; the cursor side's boxed inputs are
/// charged as process-retained memory ([`retained_bound`]).
pub(super) struct ContinuationTicket {
    /// SHA-256 of the destination namespace the asking page ran under.
    destination: [u8; 32],
    /// The scan authority the asking page ran under ([`current_authority`]).
    authority: [u8; 32],
    cursor: CursorTicket,
    /// The fixed lifetime of the cached inputs (K2/P-1, [`ticket_lifetime`]):
    /// valid from `issued` until before `expires`. A page or EOF upload
    /// outside it never runs, and nothing renews it.
    issued: Instant,
    expires: Instant,
}

impl ContinuationTicket {
    /// Attach the minting page's inputs (K2: moved from its preparation).
    pub(super) fn with_inputs(mut self, inputs: ContinuationInputs) -> Self {
        match &mut self.cursor.0 {
            CursorParts::Codex(page) => page.inputs = Some(inputs),
            #[cfg(test)]
            CursorParts::Synthetic => drop(inputs),
        }
        self
    }

    fn valid_at(&self, now: Instant) -> bool {
        lifetime_holds(self.issued, self.expires, now)
    }
}

/// `issued <= now < expires` on the monotonic clock: an earlier `now` (a
/// rolled-back test clock) is as invalid as a later one.
fn lifetime_holds(issued: Instant, expires: Instant, now: Instant) -> bool {
    issued <= now && now < expires
}

/// How one continuation page ended on the cursor side. No end but `Eof`
/// saves anything (K7): the job's progress lives in the cursor slot.
pub(super) enum PageEnd {
    /// The job paused again at its byte budget: the only end that may ask for
    /// another page.
    Paused(CursorTicket),
    /// Paused at the deadline, without exhausting the byte budget. No ticket
    /// or continuation request may follow this pause.
    PausedContended,
    /// The resume was refused or not `Active`, the page refused before any
    /// read (K1.1), or it ended with debt or a disclosure it does not save
    /// (K7.2); the job's paths stay pending for the next ordinary pass.
    Deferred,
    /// The job reached EOF and committed; its upload obligation remains.
    Eof(EofCompletion),
    /// The lease was lost, the page was dropped, or the process is stopping.
    /// Nothing was saved.
    #[allow(dead_code)] // No stop signal reaches a page yet; the fakes use it.
    Cancelled,
    /// A local error (a failed load, a worker that panicked or could not
    /// keep its invariants). Nothing was saved.
    Failed(anyhow::Error),
}

/// The cursor side of a continuation page ([`CodexContinuation`] over c22's
/// `CodexCursorPort`). None of its methods may make a network call; the EOF
/// completion upload is StateMissing's ([`Host::complete_eof`]).
pub(super) trait CursorContinuation {
    /// Hunk A: the ticket of a just-finished ordinary Codex page, only for a
    /// valid, budget-exhausted, accelerated pause.
    fn ticket_for(&self, scan: &SourceScanResult) -> Option<CursorTicket>;
    /// `cursor_continuation_ready`: under the cursor lock, with no IO.
    fn ready(&mut self, ticket: &CursorTicket) -> bool;
    /// One resume-only page: `ScanIndex::load`, the continuation-local
    /// prepare (K1), `begin_codex_continuation_side_pass`, the scan. No end
    /// but EOF saves (K7); an EOF page's index and scan go to the parent's
    /// unchanged finish. Once `deadline` passes, the job pauses at the next
    /// `step()` return without a ticket (`PausedContended`, K6). The deadline
    /// is cooperative: the in-progress record, C14, local finalization and
    /// scheduling may overrun it; it is not a hard lock-hold bound.
    /// `ordinary_equivalent` is the interval this page stands for (K4).
    fn page(
        &mut self,
        ticket: CursorTicket,
        deadline: Instant,
        ordinary_equivalent: Option<Duration>,
    ) -> PageEnd;
}

/// A cursor side with no continuation, for the inert controls.
#[cfg(test)]
pub(super) struct NoCursorContinuation;

#[cfg(test)]
impl CursorContinuation for NoCursorContinuation {
    fn ticket_for(&self, _scan: &SourceScanResult) -> Option<CursorTicket> {
        None
    }
    fn ready(&mut self, _ticket: &CursorTicket) -> bool {
        false
    }
    fn page(
        &mut self,
        _ticket: CursorTicket,
        _deadline: Instant,
        _ordinary_equivalent: Option<Duration>,
    ) -> PageEnd {
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
    /// The ticket's fixed lifetime ended (K2/P-1).
    Expired,
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
                Skip::Expired => "skipped_expired",
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
    // K2/P-1: the cached inputs' fixed lifetime, before anything reads them.
    // An expired ticket is dropped here (its context zeroized), so a later
    // earlier-looking clock cannot revive it.
    if !ticket.valid_at(now) {
        return skip(host, Skip::Expired);
    }
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
        issued,
        expires,
    } = ticket;
    let deadline = started
        .checked_add(CONTENTION_WORK)
        .map_or(ordinary_deadline, |limit| limit.min(ordinary_deadline));
    // K4: computed here, on this thread, under the lock and after every
    // recheck above; `None` (unknown) ends the attempt's acceleration.
    let backoff = host.upload_backoff();
    let ordinary = host
        .cadence(|cadence| ordinary_equivalent(cadence, backoff))
        .flatten();
    let qos = RestoreQos(gates);
    let ended = if port.ready(&cursor) {
        Some(port.page(cursor, deadline, ordinary))
    } else {
        None
    };
    // Back to the thread's own QoS before any EOF network work.
    drop(qos);
    let (outcome, next) = match ended {
        None => (Outcome::Skipped(Skip::NotReady), None),
        // The same lifetime: a page never renews it.
        Some(PageEnd::Paused(cursor)) => (
            Outcome::Paused,
            Some(ContinuationTicket {
                destination,
                authority,
                cursor,
                issued,
                expires,
            }),
        ),
        Some(PageEnd::PausedContended) => (Outcome::PausedContended, None),
        Some(PageEnd::Deferred) => (Outcome::Deferred, None),
        Some(PageEnd::Cancelled) => (Outcome::Cancelled, None),
        Some(PageEnd::Failed(error)) => {
            // The sync phase only, never raw details (as an ordinary pass).
            eprintln!(
                "local snapshot continuation page failed: {}",
                safe_error(&error)
            );
            (Outcome::Failed, None)
        }
        Some(PageEnd::Eof(completion)) => (
            settle_eof(host, completion, destination, authority, (issued, expires)),
            None,
        ),
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

/// Settle an EOF page, still under the sync lock. The ticket's lifetime
/// (K2/P-1), the authority, destination and upload backoff are rechecked
/// immediately before the first network call of the page. The completion
/// upload is attempted once and never retried here. A deferred completion can
/// cost a re-read of the whole attempt, not one page.
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
    (issued, expires): (Instant, Instant),
) -> Outcome {
    let now = host.now();
    let current = lifetime_holds(issued, expires, now)
        && !host.upload_backoff()
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
/// and the scan authority it ran under, with its fixed lifetime. Read before
/// the finish consumes the scan. No authority or no finite lifetime, no
/// ticket (K2: no attribution-bearing continuation without a bound).
pub(super) fn ordinary_ticket(
    port: &impl CursorContinuation,
    scan: &SourceScanResult,
    destination_namespace: &str,
    authority: Option<[u8; 32]>,
    lifetime: Option<(Instant, Instant)>,
) -> Option<ContinuationTicket> {
    let authority = authority?;
    let (issued, expires) = lifetime?;
    port.ticket_for(scan).map(|cursor| ContinuationTicket {
        destination: destination_digest(destination_namespace),
        authority,
        cursor,
        issued,
        expires,
    })
}

/// K2/P-1: the fixed lifetime of a ticket's cached inputs, from the start of
/// the ordinary Codex prepare whose policy they carry (`prepared_at`). It
/// ends at the earliest of the capture-time `ordinary_interval`, the Hot
/// floor and the loop interval. The next ordinary prepare starts no earlier
/// than the loop interval after this cycle ends, so the bound never reaches
/// it; the activity hint carries no key or grant expiry to add. Fixed here:
/// no later page, failure, backoff or missing prepare extends it. `None` (no
/// prepare time, a zero bound or an overflow) mints no ticket.
pub(super) fn lifetime_from(
    prepared_at: Option<Instant>,
    cadence: &SourceCadence,
) -> Option<(Instant, Instant)> {
    let prepared_at = prepared_at?;
    let bound = cadence
        .ordinary_interval()
        .min(cadence.hot_min_interval())
        .min(SNAPSHOT_SYNC_INTERVAL);
    if bound.is_zero() {
        return None;
    }
    Some((prepared_at, prepared_at.checked_add(bound)?))
}

/// [`lifetime_from`] on Codex's production cadence.
pub(super) fn ticket_lifetime(prepared_at: Option<Instant>) -> Option<(Instant, Instant)> {
    with_source_cadence(SnapshotSource::Codex, |cadence| {
        lifetime_from(prepared_at, cadence)
    })
    .flatten()
}

/// An ordinary Codex prepare is starting: whatever it learns (a disable, a
/// new key epoch, another destination) replaces the cached inputs, so the
/// older ticket and its context are dropped now. Only while enabled.
pub(super) fn invalidate_on_ordinary_prepare() {
    if ENABLED {
        clear(&mut CodexCadence, &TICKET);
    }
}

/// K2 accounting: the held ticket's inputs (context inventories, strings,
/// cached policy) as process-retained memory, outside every rotation frame.
/// `None` (unsupported layout, unknown size) makes the rotation discard it.
pub(super) fn retained_bound(limit: usize) -> Option<usize> {
    if !ENABLED {
        return Some(0);
    }
    match lock_slot(&TICKET).as_ref() {
        None => Some(0),
        Some(ticket) => ticket.cursor.retained_bound(limit),
    }
}

/// The rotation refused the retained charge: drop the ticket and its inputs.
pub(super) fn discard_retained() {
    if ENABLED {
        clear(&mut CodexCadence, &TICKET);
    }
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
        let current = crate::local_resource_diagnostics::credential_file_read(
            ottto_core::FileDeviceStore::default().load(),
        )
        .ok()??;
        let account = self.daemon.snapshot_scan_account_witness().ok()?;
        current_authority(&current, &snapshot_api_base_url().ok()?, &account)
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
        // next ordinary pass. Its attempt was consumed when it committed, so
        // this can cost a re-read of the whole attempt; it is counted.
        let deferred = EOF_DEFERRALS.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!(
            "local snapshot continuation EOF deferred to the ordinary pass ({deferred} so far); its attempt may be re-read"
        );
        drop(completion);
    }
}

/// EOF completions deferred to the ordinary pass, process lifetime.
static EOF_DEFERRALS: AtomicU64 = AtomicU64::new(0);

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
        &mut CodexContinuation::new(&daemon.transcript_cache, home, support_dir),
        &mut NoPlatformSignals,
        SNAPSHOT_SYNC_LOCK.get_or_init(|| Mutex::new(())),
        &TICKET,
        ordinary_deadline,
    )
}

/// K4 (amended W12): the interval a continuation page stands for in c22's
/// E2 accounting (`max(elapsed, ordinary)`), read once per page by
/// [`run_page`] under the sync lock after its rechecks, so only while
/// enabled. It is exactly `ordinary_interval`: the tier floor, or the failure
/// backoff while failing, lengthened only by the server directive, with no
/// clamp, floor or historical estimate. It is a per-page lower bound of what
/// ordinary scheduling would have taken, not coverage: cycle and lock delays
/// are unbounded, so acceleration can start a later same-revision attempt
/// earlier by that overhead (accepted Stage 1 design; the guard is c22's).
/// `None` (unknown) while disabled, failing or in upload backoff; an
/// unreadable cadence reaches the caller as `None` too.
pub(super) fn ordinary_equivalent(
    cadence: &SourceCadence,
    upload_backoff: bool,
) -> Option<Duration> {
    let state = cadence.state();
    if upload_backoff
        || state == LocalCollectorState::Failing
        || state == LocalCollectorState::Disabled
    {
        return None;
    }
    Some(cadence.ordinary_interval())
}

/// Set after any continuation worker panicked, or broke a page invariant
/// (W8): no further ticket is minted or readied for the process lifetime.
static WORKER_LATCHED: AtomicBool = AtomicBool::new(false);

/// W1: everything that crosses the worker join, and the port the worker
/// builds, is `Send` by its own types (checked here at compile time; no
/// `unsafe impl`). The closure itself is bounded by [`on_worker`].
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<PageEnd>();
    assert_send::<EofCompletion>();
    assert_send::<WorkerEnd>();
    assert_send::<CodexPage>();
    assert_send::<ContinuationInputs>();
    assert_send::<SourcePreparation>();
    assert_send::<ScanIndex>();
    assert_send::<SourceScanResult>();
    assert_send::<CodexCursorPort>();
    assert_send::<CodexCursorTicket>();
    assert_send::<Arc<SharedCache>>();
};

/// Why the worker did not return its page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerFailure {
    /// The thread could not start: nothing ran.
    Spawn,
    /// The page panicked on the worker.
    Panicked,
}

/// Option W: run `body` on one named, short-lived worker and join it
/// explicitly, so a panic comes back as `Err` instead of unwinding the
/// caller. The caller holds `SNAPSHOT_SYNC_LOCK` through the join and touches
/// nothing else; the worker never takes that lock and makes no callback,
/// channel send or wait toward the caller (W2). Thread-locals are the
/// worker's own: none is inherited (W10).
fn on_worker<T: Send>(body: impl FnOnce() -> T + Send) -> std::result::Result<T, WorkerFailure> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("ottto-codex-continuation".to_string())
            .spawn_scoped(scope, body)
            .map_err(|_| WorkerFailure::Spawn)?;
        worker.join().map_err(|_| WorkerFailure::Panicked)
    })
}

/// W11: the worker's own background QoS, applied inside the worker. The
/// platform call is hunk F, still under its parent decision, so production
/// answers `Unknown` and the page reads nothing.
fn no_worker_qos() -> PlatformState {
    PlatformState::Unknown
}

/// How the page ended on the worker. Everything here is `Send` (W1) and
/// moves to the parent; nothing is shared.
enum WorkerEnd {
    /// The job paused again at its byte budget: the page, with its new
    /// cursor ticket and the inputs it moved to the worker.
    Paused(Box<CodexPage>),
    /// Completed without committing and without a ticket (K6 deadline, or
    /// debt / a disclosure that is not saved, K7.2).
    Stopped,
    /// Nothing ran past the worker's own gates (QoS, members).
    Deferred,
    /// The continuation-local prepare refused before any read (K1.1).
    Refused(&'static str),
    /// The job committed: the parts the parent's unchanged finish uploads.
    Eof(Box<(SourcePreparation, ScanIndex, SourceScanResult)>),
    /// A non-EOF end produced snapshots (K7.1): nothing is saved, and the
    /// worker latch is set.
    Unexpected,
    Failed(anyhow::Error),
}

/// The production cursor side: c22's `CodexCursorPort`, with each page run
/// on an explicitly joined worker (Option W, W1–W12).
pub(super) struct CodexContinuation<'a> {
    cache: &'a Arc<SharedCache>,
    home: &'a Path,
    support_dir: &'a Path,
    /// The worker's QoS (W11): [`no_worker_qos`] in production.
    worker_qos: fn() -> PlatformState,
    /// The process latch (W8): [`WORKER_LATCHED`] in production.
    latch: &'static AtomicBool,
}

impl<'a> CodexContinuation<'a> {
    pub(super) fn new(cache: &'a Arc<SharedCache>, home: &'a Path, support_dir: &'a Path) -> Self {
        Self {
            cache,
            home,
            support_dir,
            worker_qos: no_worker_qos,
            latch: &WORKER_LATCHED,
        }
    }

    fn port(&self) -> CodexCursorPort {
        CodexCursorPort::new(Arc::clone(self.cache))
    }

    fn latched(&self) -> bool {
        self.latch.load(Ordering::SeqCst)
    }
}

impl CursorContinuation for CodexContinuation<'_> {
    fn ticket_for(&self, scan: &SourceScanResult) -> Option<CursorTicket> {
        if self.latched() {
            return None;
        }
        self.port().ticket_for(scan).map(CursorTicket::codex)
    }

    fn ready(&mut self, ticket: &CursorTicket) -> bool {
        match &ticket.0 {
            CursorParts::Codex(page) => {
                !self.latched() && page.inputs.is_some() && self.port().ready(&page.cursor)
            }
            #[cfg(test)]
            CursorParts::Synthetic => false,
        }
    }

    fn page(
        &mut self,
        ticket: CursorTicket,
        deadline: Instant,
        ordinary_equivalent: Option<Duration>,
    ) -> PageEnd {
        // One variant outside tests: the fakes' synthetic ticket is the other.
        #[allow(clippy::infallible_destructuring_match)]
        let page = match ticket.0 {
            CursorParts::Codex(page) => page,
            #[cfg(test)]
            CursorParts::Synthetic => return PageEnd::Deferred,
        };
        let (cache, home, support_dir, qos) =
            (self.cache, self.home, self.support_dir, self.worker_qos);
        let ended = on_worker(move || {
            page_on_worker(
                cache,
                home,
                support_dir,
                page,
                deadline,
                ordinary_equivalent,
                qos,
            )
        });
        page_end(ended, deadline, Instant::now(), self.latch)
    }
}

/// The parent's mapping of a joined worker's end (W7, W8, K7).
fn page_end(
    ended: std::result::Result<WorkerEnd, WorkerFailure>,
    deadline: Instant,
    now: Instant,
    latch: &AtomicBool,
) -> PageEnd {
    match ended {
        // Nothing ran: the ticket and request are cleared by `run_page`.
        Err(WorkerFailure::Spawn) => PageEnd::Deferred,
        Err(WorkerFailure::Panicked) => {
            latch.store(true, Ordering::SeqCst);
            PageEnd::Failed(anyhow!("continuation worker panicked"))
        }
        Ok(WorkerEnd::Paused(page)) => PageEnd::Paused(CursorTicket(CursorParts::Codex(page))),
        Ok(WorkerEnd::Stopped) if now >= deadline => PageEnd::PausedContended,
        Ok(WorkerEnd::Stopped | WorkerEnd::Deferred) => PageEnd::Deferred,
        Ok(WorkerEnd::Refused(label)) => {
            eprintln!("local snapshot continuation page refused: {label}");
            PageEnd::Deferred
        }
        Ok(WorkerEnd::Eof(parts)) => PageEnd::Eof(EofCompletion::of(parts)),
        Ok(WorkerEnd::Unexpected) => {
            latch.store(true, Ordering::SeqCst);
            PageEnd::Failed(anyhow!("continuation page produced snapshots before EOF"))
        }
        Ok(WorkerEnd::Failed(error)) => PageEnd::Failed(error),
    }
}

/// The whole page on one thread (W4): the worker's QoS, the members, then
/// the continuation-local prepare and scan. Nothing is saved before EOF (K7),
/// and no cursor credit, lease or active file outlives this call (W3).
#[allow(clippy::too_many_arguments)]
fn page_on_worker(
    cache: &Arc<SharedCache>,
    home: &Path,
    support_dir: &Path,
    mut page: Box<CodexPage>,
    deadline: Instant,
    ordinary_equivalent: Option<Duration>,
    qos: fn() -> PlatformState,
) -> WorkerEnd {
    if qos() != PlatformState::Allowed {
        return WorkerEnd::Deferred;
    }
    let Some(members) = CodexCursorPort::new(Arc::clone(cache)).members(&page.cursor) else {
        return WorkerEnd::Deferred;
    };
    let Some(inputs) = page.inputs.as_mut() else {
        return WorkerEnd::Deferred;
    };
    match run_continuation_scan(
        home,
        support_dir,
        cache,
        inputs,
        &members,
        ordinary_equivalent,
        deadline,
    ) {
        Err(error) => WorkerEnd::Failed(error),
        Ok(ContinuationScan::Refused(reason)) => WorkerEnd::Refused(reason.label()),
        Ok(ContinuationScan::StepRefused) => WorkerEnd::Deferred,
        Ok(ContinuationScan::Committed(parts)) => WorkerEnd::Eof(parts),
        Ok(ContinuationScan::Uncommitted { snapshots, .. }) if snapshots != 0 => {
            WorkerEnd::Unexpected
        }
        Ok(ContinuationScan::Uncommitted {
            ticket: Some(cursor),
            ..
        }) => {
            page.cursor = cursor;
            WorkerEnd::Paused(page)
        }
        Ok(ContinuationScan::Uncommitted { ticket: None, .. }) => WorkerEnd::Stopped,
    }
}

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;
