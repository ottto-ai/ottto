//! Paced cursor continuation pages (FC1 Stage 1, sync-loop hunks B/C/F).
//!
//! A Codex page that pauses a still-valid cursor job only because its byte
//! budget ran out may ask for the next page sooner than the ordinary cadence.
//! That next page runs through [`run_page`], a dedicated entry point that is not
//! `sync_once`: it makes no network call (no relay token, activity hint,
//! receipt, status or health upload) unless the job reaches EOF, and then only
//! the existing authorized completion upload, after rechecking the destination
//! and the upload backoff. Ordinary cycles keep their own deadline, so other
//! sources' due work and network cadence are unchanged.
//!
//! Everything here is compiled in and **inert**: [`ENABLED`] is false, the
//! cursor side is the [`NoCursorContinuation`] stub (c22 owns hunks A/D/E and
//! the guard, after #660), and the platform gates are [`NoPlatformSignals`],
//! whose unknown state falls back to the ordinary cadence.

use super::{
    load_snapshot_device_credentials, snapshot_upload_destination_namespace,
    source_upload_backoff_remaining, with_source_cadence, SnapshotSource, SourceScanResult,
    MAX_CYCLE_INTERVAL, SNAPSHOT_SYNC_INTERVAL, SNAPSHOT_SYNC_LOCK,
};
use crate::adaptive_collector::{ContinuationPacing, SourceCadence};
use anyhow::{anyhow, Result};
use ottto_protocol::LocalCollectorState;
use sha2::{Digest, Sha256};
use std::sync::{Mutex, TryLockError};
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
/// ordinary cadence instead.
pub(super) const CONTENTION_WORK: Duration = Duration::from_secs(20);

/// c22's cursor binding for one paused attempt (hunk A: namespace, rotation
/// key, `stamp_open`, `started`), minted only at the single pause site. The
/// scaffolding carries no cursor fields, and nothing in production mints one.
#[allow(dead_code)] // Minted only by c22's pause site (hunk A, after #660).
pub(super) struct CursorTicket {
    _sealed: (),
}

/// What c22's EOF page hands back for the existing completion upload: the
/// committed job's preparation, index and scan for the unchanged
/// `finish_sync_source`. Unconstructible in production until c22 wires it.
#[allow(dead_code)] // Built only by c22's EOF page (after #660).
pub(super) struct EofCompletion {
    _sealed: (),
}

/// The permission a finished Codex page leaves for the next continuation page.
pub(super) struct ContinuationTicket {
    /// SHA-256 of the destination namespace the asking page ran under. Fixed
    /// size, so the slot never allocates.
    destination: [u8; 32],
    cursor: CursorTicket,
}

/// How one continuation page ended on the cursor side.
#[allow(dead_code)] // Only c22's cursor port (after #660) produces these outside tests.
pub(super) enum PageEnd {
    /// Saved `Ok` with its C15 callback, and the job paused again at its byte
    /// budget: the only end that may ask for another page.
    Paused(CursorTicket),
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
/// Every method except `complete_eof` must make no network call.
pub(super) trait CursorContinuation {
    /// Hunk A: the ticket of a just-finished ordinary Codex page, only for a
    /// valid, budget-exhausted, accelerated pause.
    fn ticket_for(&self, scan: &SourceScanResult) -> Option<CursorTicket>;
    /// `cursor_continuation_ready`: under the cursor lock, with no IO.
    fn ready(&mut self, ticket: &CursorTicket) -> bool;
    /// One resume-only page: `ScanIndex::load`, then
    /// `begin_codex_side_pass(Continuation)`, the scan, the C15 mark, the save
    /// and `note_codex_side_saved` on `Ok`.
    fn page(&mut self, ticket: CursorTicket) -> PageEnd;
    /// The existing authorized completion upload: the unchanged
    /// `finish_sync_source` for the completed job's own obligations, preceded
    /// by the same authority and destination validation an ordinary finish
    /// runs. It is attempted once; a failure is never retried here.
    fn complete_eof(&mut self, completion: EofCompletion) -> Result<()>;
    /// The existing safe partial-checkpoint / owed path when completion cannot
    /// proceed now. Never a whole-index save of the un-uploaded commit.
    fn defer_eof(&mut self, completion: EofCompletion);
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
    fn page(&mut self, _ticket: CursorTicket) -> PageEnd {
        PageEnd::Deferred
    }
    fn complete_eof(&mut self, _completion: EofCompletion) -> Result<()> {
        Err(anyhow!("continuation completion is not wired"))
    }
    fn defer_eof(&mut self, _completion: EofCompletion) {}
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

/// The local state a continuation page reads. None of it touches the network.
pub(super) trait Host {
    fn now(&mut self) -> Instant;
    /// Whether the server's upload backoff for Codex is still running.
    fn upload_backoff(&mut self) -> bool;
    /// SHA-256 of the current destination namespace, from local credentials.
    fn destination(&mut self) -> Option<[u8; 32]>;
    /// Short critical sections on Codex's cadence; `None` when unavailable.
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Skip {
    NoTicket,
    NotDue,
    Failing,
    Backoff,
    Platform,
    LockBusy,
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
                Skip::Destination => "skipped_destination",
                Skip::NotReady => "skipped_not_ready",
                Skip::CadenceUnavailable => "skipped_cadence_unavailable",
            },
            Outcome::Paused => "paused",
            Outcome::PausedContended => "paused_contended",
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
/// The measured work runs from entry to after the lock is released, so lock
/// wait, preparation, the page, any EOF completion and finalization all count.
pub(super) fn run_page<H: Host, P: CursorContinuation, G: PlatformGates>(
    host: &mut H,
    port: &mut P,
    gates: &mut G,
    lock: &Mutex<()>,
    slot: &mut Option<ContinuationTicket>,
) -> Outcome {
    let started = host.now();
    let Some(ticket) = slot.take() else {
        return Outcome::Skipped(Skip::NoTicket);
    };
    let skip = |host: &mut H, skip: Skip| {
        host.cadence(SourceCadence::clear_continuation);
        Outcome::Skipped(skip)
    };
    let Some((state, due)) = host.cadence(|cadence| {
        let state = cadence.state();
        (state, cadence.continuation_due(PACING))
    }) else {
        return skip(host, Skip::CadenceUnavailable);
    };
    if state == LocalCollectorState::Failing {
        return skip(host, Skip::Failing);
    }
    if host.upload_backoff() {
        return skip(host, Skip::Backoff);
    }
    match due {
        Some(due) if started >= due => {}
        Some(_) => {
            *slot = Some(ticket);
            return Outcome::Skipped(Skip::NotDue);
        }
        None => return skip(host, Skip::NotDue),
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
    if host.destination() != Some(ticket.destination) {
        drop(guard);
        return skip(host, Skip::Destination);
    }
    if gates.enter_background_qos() != PlatformState::Allowed {
        drop(guard);
        return skip(host, Skip::Platform);
    }
    let destination = ticket.destination;
    let ended = if port.ready(&ticket.cursor) {
        Some(port.page(ticket.cursor))
    } else {
        None
    };
    let (outcome, next) = match ended {
        None => (Outcome::Skipped(Skip::NotReady), None),
        Some(PageEnd::Paused(cursor)) => (
            Outcome::Paused,
            Some(ContinuationTicket {
                destination,
                cursor,
            }),
        ),
        Some(PageEnd::Deferred) => (Outcome::Deferred, None),
        Some(PageEnd::Cancelled) => (Outcome::Cancelled, None),
        Some(PageEnd::Failed(_)) => (Outcome::Failed, None),
        Some(PageEnd::Eof(completion)) => {
            // Recheck before the first network call of the page.
            if host.upload_backoff() || host.destination() != Some(destination) {
                port.defer_eof(completion);
                (Outcome::EofDeferred, None)
            } else if port.complete_eof(completion).is_ok() {
                (Outcome::EofCompleted, None)
            } else {
                (Outcome::EofFailed, None)
            }
        }
    };
    gates.restore_qos();
    drop(guard);
    let finished = host.now();
    match next {
        Some(next) => match finished.checked_duration_since(started) {
            Some(work) if work <= CONTENTION_WORK => {
                if host
                    .cadence(|cadence| cadence.request_continuation(finished, work))
                    .is_some()
                {
                    *slot = Some(next);
                    outcome
                } else {
                    Outcome::Skipped(Skip::CadenceUnavailable)
                }
            }
            _ => {
                host.cadence(SourceCadence::clear_continuation);
                Outcome::PausedContended
            }
        },
        None => {
            host.cadence(SourceCadence::clear_continuation);
            outcome
        }
    }
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
    fn page(&mut self) -> Outcome;
}

/// Wait out one ordinary interval, running due continuation pages inside it.
/// The ordinary deadline is fixed when the wait starts, so pages never push
/// the ordinary cycle out except by the overrun of a page that ran longer than
/// the one before it.
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
                let outcome = host.page();
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

fn destination_digest(namespace: &str) -> [u8; 32] {
    Sha256::digest(namespace.as_bytes()).into()
}

/// The ticket an ordinary Codex page's pause minted, bound to the destination
/// it ran under. Read before the finish consumes the scan.
pub(super) fn ordinary_ticket(
    port: &impl CursorContinuation,
    scan: &SourceScanResult,
    destination_namespace: &str,
) -> Option<ContinuationTicket> {
    port.ticket_for(scan).map(|cursor| ContinuationTicket {
        destination: destination_digest(destination_namespace),
        cursor,
    })
}

/// After an ordinary Codex finish: keep the page's ticket (with its measured
/// work, from preparation to the end of the finish) only if the finish
/// succeeded and the page was not contended; otherwise clear any older one.
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
    let mut slot = TICKET.lock().unwrap_or_else(|p| p.into_inner());
    match ticket {
        Some((ticket, work)) => {
            let requested = with_source_cadence(SnapshotSource::Codex, |cadence| {
                cadence.request_continuation(finished, work)
            });
            *slot = requested.map(|()| ticket);
        }
        None => clear_production(&mut slot),
    }
}

/// An ordinary Codex pass failed: no continuation follows it.
pub(super) fn after_ordinary_codex_failure() {
    let mut slot = TICKET.lock().unwrap_or_else(|p| p.into_inner());
    clear_production(&mut slot);
}

fn clear_production(slot: &mut Option<ContinuationTicket>) {
    *slot = None;
    with_source_cadence(SnapshotSource::Codex, SourceCadence::clear_continuation);
}

/// The pending page for the loop planner, or `None` while inert.
pub(super) fn production_pending() -> Option<(Instant, Duration)> {
    if !ENABLED {
        return None;
    }
    if TICKET.lock().ok()?.is_none() {
        return None;
    }
    with_source_cadence(SnapshotSource::Codex, |cadence| {
        cadence
            .continuation_due(PACING)
            .zip(cadence.continuation_work())
    })
    .flatten()
}

struct ProductionHost;

impl Host for ProductionHost {
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
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        with_source_cadence(SnapshotSource::Codex, apply)
    }
}

/// One production continuation page, or a skip while inert.
pub(super) fn run_production_page() -> Outcome {
    if !ENABLED {
        return Outcome::Skipped(Skip::NoTicket);
    }
    // Take the ticket out so its mutex is never held across the page.
    let mut slot = TICKET.lock().unwrap_or_else(|p| p.into_inner()).take();
    let outcome = run_page(
        &mut ProductionHost,
        &mut NoCursorContinuation,
        &mut NoPlatformSignals,
        SNAPSHOT_SYNC_LOCK.get_or_init(|| Mutex::new(())),
        &mut slot,
    );
    *TICKET.lock().unwrap_or_else(|p| p.into_inner()) = slot;
    outcome
}

/// The ordinary-equivalent duration of one page gap for c22's guard and E2
/// accounting: the interval the ordinary cadence would actually have applied,
/// never less than the loop's own interval and never more than the ceiling
/// the loop clamps a wait to. A lower bound: the real ordinary period also
/// includes the cycle's own duration.
#[allow(dead_code)] // c22's guard (after #660) is the first production caller.
pub(super) fn ordinary_equivalent(cadence: &SourceCadence) -> Duration {
    cadence
        .ordinary_interval()
        .min(MAX_CYCLE_INTERVAL)
        .max(SNAPSHOT_SYNC_INTERVAL)
}

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;
