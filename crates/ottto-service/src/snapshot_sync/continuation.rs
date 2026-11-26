//! Enabled Codex cursor pages: AC only, background QoS, EOF parked for ordinary cadence.
use super::enabled_snapshot_sources;
use super::load_snapshot_device_credentials;
use super::safe_error;
use super::snapshot_api_base_url;
use super::snapshot_upload_destination_namespace;
use super::source_paced_due;
use super::source_upload_backoff_remaining;
use super::with_source_cadence;
use super::ScanIndex;
use super::SnapshotSource;
use super::SnapshotUploadPolicy;
use super::SourcePreparation;
use super::SourceScanResult;
use super::SNAPSHOT_SYNC_INTERVAL;
use super::SNAPSHOT_SYNC_LOCK;
use super::SNAPSHOT_SYNC_WORKER_STACK_BYTES;
use crate::adaptive_collector::{ContinuationPacing, SourceCadence};
use crate::snapshots::sampled_scan::SharedCache;
use crate::snapshots::{CodexCursorPort, CodexCursorTicket};
use crate::LocalDaemon;
use anyhow::anyhow;
use ottto_core::LocalDeviceBinding;
use ottto_protocol::LocalCollectorState;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub(super) type RuntimeContext = [Option<([u8; 32], [u8; 32])>; 2];
static UPLOAD_CONTEXT: Mutex<RuntimeContext> = Mutex::new([None; 2]);
pub(super) fn runtime_context() -> RuntimeContext {
    #[cfg(test)]
    if let Some(context) = tests::runtime_context_override() {
        return context;
    }
    *UPLOAD_CONTEXT.lock().unwrap_or_else(|p| p.into_inner())
}
pub(super) fn observe(source: SnapshotSource, context: &str, policy: SnapshotUploadPolicy) {
    let slot = match source {
        SnapshotSource::ClaudeCode => 0,
        SnapshotSource::Codex => 1,
        SnapshotSource::Pi => return,
    };
    let value = (
        Sha256::digest(context.as_bytes()).into(),
        Sha256::digest(serde_json::to_vec(&policy).expect("upload policy is serializable")).into(),
    );
    #[cfg(test)]
    if tests::observe_context(slot, value) {
        return;
    }
    UPLOAD_CONTEXT.lock().unwrap_or_else(|p| p.into_inner())[slot] = Some(value);
}

/// At least 30 s and nine idle seconds per working second between pages.
pub(super) const PACING: ContinuationPacing = ContinuationPacing {
    min_gap: Duration::from_secs(30),
    idle_per_work: 9,
};

/// Ordinary resident-paced passes reuse cadence requests, without the cursor's
/// contention cutoff: each pass repeats prepare and commits its queued work.
pub(super) const PACED_AC: ContinuationPacing = ContinuationPacing {
    min_gap: Duration::from_secs(30),
    idle_per_work: 0,
};
pub(super) const PACED_BATTERY: ContinuationPacing = ContinuationPacing {
    min_gap: Duration::from_secs(180),
    idle_per_work: 0,
};
pub(super) fn session_power_stretch(power: PlatformState) -> u32 {
    match power {
        PlatformState::Battery | PlatformState::Refused => 3,
        PlatformState::Allowed | PlatformState::Unknown => 1,
    }
}
/// The fixed diagnostics key for a power state.
pub(super) fn power_label(power: PlatformState) -> &'static str {
    match power {
        PlatformState::Allowed => "power_allowed",
        PlatformState::Battery => "power_battery",
        PlatformState::Refused => "power_refused",
        PlatformState::Unknown => "power_unknown",
    }
}
fn resident_pacing(power: PlatformState) -> Option<ContinuationPacing> {
    match power {
        PlatformState::Allowed => Some(PACED_AC),
        PlatformState::Battery => Some(PACED_BATTERY),
        PlatformState::Refused | PlatformState::Unknown => None,
    }
}
/// The QoS a due paced pass runs at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PassQos {
    Background,
    /// The thread's default QoS: a first-import pass on AC.
    Default,
    /// Refused or unknown power: the source's paced request is cleared.
    Cleared,
}
/// The one rule: only a first-import request on AC skips background QoS.
pub(super) fn paced_pass_qos(power: PlatformState, first_import: bool) -> PassQos {
    match power {
        PlatformState::Allowed if first_import => PassQos::Default,
        PlatformState::Allowed | PlatformState::Battery => PassQos::Background,
        PlatformState::Refused | PlatformState::Unknown => PassQos::Cleared,
    }
}
thread_local! {
    /// This owner thread's current pass took [`PassQos::Default`]; diagnostics only.
    static FIRST_IMPORT_DEFAULT_QOS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(crate) fn first_import_default_qos() -> bool {
    FIRST_IMPORT_DEFAULT_QOS.get()
}
/// Background QoS for one source's ordinary pass, only while THAT source's
/// paced scan is due; a refused entry clears only that source's request.
pub(super) fn paced_source_qos(
    source: SnapshotSource,
    power: impl FnOnce() -> PlatformState,
    background: impl FnOnce() -> Option<MacPlatformSignals>,
) -> Option<MacPlatformSignals> {
    FIRST_IMPORT_DEFAULT_QOS.set(false);
    if !source_paced_due(source).is_some_and(|due| due <= crate::scan_clock::now()) {
        return None;
    }
    let first_import = with_source_cadence(source, |c| c.paced_first_import()) == Some(true);
    let qos = match paced_pass_qos(power(), first_import) {
        PassQos::Default => {
            FIRST_IMPORT_DEFAULT_QOS.set(true);
            return None;
        }
        PassQos::Background => background(),
        PassQos::Cleared => None,
    };
    if qos.is_none() {
        with_source_cadence(source, SourceCadence::clear_continuation);
    }
    qos
}
/// Shared ordinary-owner entry seam; preserve drop-before-enter ordering.
pub(super) fn enter_source_qos(slot: &mut Option<MacPlatformSignals>, source: SnapshotSource) {
    drop(slot.take());
    let power = || MacPlatformSignals::default().power();
    *slot = paced_source_qos(source, power, MacPlatformSignals::background);
}
/// The ordinary-owner exit seam: drop the pass's QoS and its row flag.
pub(super) fn leave_source_qos(slot: &mut Option<MacPlatformSignals>) {
    drop(slot.take());
    FIRST_IMPORT_DEFAULT_QOS.set(false);
}
/// A spent byte budget or first-read progress asks only during the source's
/// first backfill. Progress asks only while the census is unfinished and not
/// a routine re-census; a page that read and listed nothing new never asks.
pub(super) fn resident_scan_requested(scan: &SourceScanResult, first_read_bootstrap: bool) -> bool {
    scan.charge_deferred
        || (scan.census_status.pending_work
            && ((scan.page_file_limit_hit && !scan.routine_recensus)
                || (first_read_bootstrap && scan.page_byte_budget_hit)
                || (first_read_bootstrap
                    && scan.first_read_progress
                    && !scan.routine_recensus
                    && !scan.census_complete)))
}
/// An AC request can wake once after unplugging; battery cannot renew this reason.
/// Every request made during the source's first import carries the
/// first-import flag, so its pages run at the import QoS on AC; battery and
/// steady-state passes stay at background QoS (`paced_pass_qos`).
pub(super) fn resident_scan_request_after_settlement(
    scan: &SourceScanResult,
    bootstrap: bool,
    power: PlatformState,
    runnable: bool,
) -> Option<bool> {
    let existing = resident_scan_requested(scan, bootstrap);
    (existing || (bootstrap && power == PlatformState::Allowed && runnable)).then_some(bootstrap)
}
#[cfg(not(test))]
fn with_last_destinations<T>(f: impl FnOnce(&mut [Option<[u8; 32]>; 3]) -> T) -> T {
    static LAST: Mutex<[Option<[u8; 32]>; 3]> = Mutex::new([None; 3]);
    f(&mut LAST.lock().unwrap_or_else(|p| p.into_inner()))
}
#[cfg(test)]
fn with_last_destinations<T>(f: impl FnOnce(&mut [Option<[u8; 32]>; 3]) -> T) -> T {
    thread_local! {
        static LAST: std::cell::RefCell<[Option<[u8; 32]>; 3]> = const { std::cell::RefCell::new([None; 3]) };
    }
    LAST.with(|last| f(&mut last.borrow_mut()))
}
/// When a source first sees a destination (an account switch, or the first
/// cycle of this process) and still owes its first import there, it asks for a
/// paced scan at once instead of waiting out the tier it carried from before.
/// AC requests carry the first-import flag; battery keeps its own pacing. An
/// unchanged destination, or nothing owed, requests nothing. Returns whether a
/// request was made.
pub(super) fn request_on_destination_change(
    source: SnapshotSource,
    destination: &str,
    power: PlatformState,
    bootstrap_pending: impl FnOnce() -> bool,
) -> bool {
    let digest: [u8; 32] = Sha256::digest(destination.as_bytes()).into();
    let changed = with_last_destinations(|last| {
        let slot = &mut last[source.slot()];
        let changed = *slot != Some(digest);
        *slot = Some(digest);
        changed
    });
    if !changed || resident_pacing(power).is_none() || !bootstrap_pending() {
        return false;
    }
    request_resident_scan_on_power(source, power == PlatformState::Allowed, power);
    true
}
#[cfg(test)]
pub(super) fn request_resident_scan(source: SnapshotSource, first_import: bool) {
    request_resident_scan_on_power(source, first_import, MacPlatformSignals::default().power());
}
pub(super) fn request_resident_scan_on_power(
    source: SnapshotSource,
    first_import: bool,
    power: PlatformState,
) {
    if let Some(pacing) = resident_pacing(power) {
        with_source_cadence(source, |cadence| {
            let now = crate::scan_clock::now();
            cadence.request_paced_scan(now, Duration::ZERO, pacing, first_import)
        });
    }
}

/// A page whose measured work exceeds this is read as contention (a loaded
/// machine, a slow disk or a long lock wait): the next page waits for the
/// ordinary cadence instead. It is also the page's cooperative deadline; an
/// in-progress record, finalization and scheduling can overrun it.
pub(super) const CONTENTION_WORK: Duration = Duration::from_secs(20);

/// The cursor binding for one paused attempt (namespace, rotation
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
/// never copied.
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

/// The permission a finished Codex page leaves for the next continuation page.
/// Both bindings are fixed-size digests; the cursor side's boxed inputs are
/// charged as process-retained memory ([`retained_bound`]).
pub(super) struct ContinuationTicket {
    /// SHA-256 of the destination namespace the asking page ran under.
    destination: [u8; 32],
    /// The scan authority the asking page ran under ([`current_authority`]).
    authority: [u8; 32],
    cursor: CursorTicket,
    issued: Instant,
    expires: Instant,
}

impl ContinuationTicket {
    /// Attach the minting page's inputs (moved from its preparation).
    pub(super) fn with_inputs(mut self, inputs: ContinuationInputs, limit: usize) -> Option<Self> {
        match &mut self.cursor.0 {
            CursorParts::Codex(page) => page.inputs = Some(inputs),
            #[cfg(test)]
            CursorParts::Synthetic => drop(inputs),
        }
        self.cursor.retained_bound(limit)?;
        Some(self)
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

pub(super) enum PageEnd {
    /// The job paused again at its byte budget: the only end that may ask for
    /// another page.
    Paused(CursorTicket),
    /// Paused at the deadline, without exhausting the byte budget. No ticket
    /// or continuation request may follow this pause.
    PausedContended,
    /// The resume was refused or not `Active`, the page refused before any
    /// read, or it ended with debt or a disclosure it does not save;
    /// the job's paths stay pending for the next ordinary pass.
    Deferred,
    /// The lease was lost, the page was dropped, or the process is stopping.
    /// Nothing was saved.
    #[allow(dead_code, reason = "no stop signal reaches pages yet; fakes use it")]
    Cancelled,
    /// A local error (a failed load, a worker that panicked or could not
    /// keep its invariants). Nothing was saved.
    Failed(anyhow::Error),
}

/// Resume only: no network calls or EOF completion.
pub(super) trait CursorContinuation {
    /// Hunk A: the ticket of a just-finished ordinary Codex page, only for a
    /// valid, budget-exhausted, accelerated pause.
    fn ticket_for(&self, scan: &SourceScanResult) -> Option<CursorTicket>;
    /// `cursor_continuation_ready`: under the cursor lock, with no IO.
    fn ready(&mut self, ticket: &CursorTicket) -> bool;
    fn page(
        &mut self,
        ticket: CursorTicket,
        deadline: Instant,
        ordinary_equivalent: Option<Duration>,
    ) -> PageEnd;
}

/// Cursor pages require `Allowed`; resident-paced ordinary passes also
/// accept `Battery`. Refused and unknown power keep the ordinary cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformState {
    Allowed,
    Battery,
    Refused,
    Unknown,
}

/// Mandatory platform gates for a continuation page.
pub(crate) trait PlatformGates {
    /// On mains power with Low Power Mode off.
    fn power(&mut self) -> PlatformState;
    /// Lower this thread to background QoS for the page. `Allowed` means it
    /// was applied, and [`PlatformGates::restore_qos`] then runs after the page.
    fn enter_background_qos(&mut self) -> PlatformState;
    fn restore_qos(&mut self);
}

#[derive(Default)]
pub(crate) struct MacPlatformSignals {
    saved: Option<(u32, i32)>,
    #[cfg(test)]
    setter: Option<fn(u32, i32) -> bool>,
}
fn power_state(answer: i32) -> PlatformState {
    match answer {
        1 => PlatformState::Allowed,
        2 => PlatformState::Battery,
        0 => PlatformState::Refused,
        _ => PlatformState::Unknown,
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn ottto_power_state() -> i32;
    fn pthread_get_qos_class_np(thread: libc::pthread_t, class: *mut u32, rel: *mut i32) -> i32;
    fn pthread_set_qos_class_self_np(class: u32, rel: i32) -> i32;
}
fn query_qos() -> Option<(u32, i32)> {
    #[cfg(target_os = "macos")]
    unsafe {
        let (mut class, mut rel) = (0, 0);
        (pthread_get_qos_class_np(libc::pthread_self(), &mut class, &mut rel) == 0)
            .then_some((class, rel))
    }
    #[cfg(not(target_os = "macos"))]
    None
}
fn set_qos(_class: u32, _rel: i32) -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        pthread_set_qos_class_self_np(_class, _rel) == 0
    }
    #[cfg(not(target_os = "macos"))]
    false
}
impl MacPlatformSignals {
    fn enter(&mut self, saved: Option<(u32, i32)>, set: fn(u32, i32) -> bool) -> PlatformState {
        if let Some(saved) = saved.filter(|_| set(0x09, 0)) {
            self.saved = Some(saved);
            PlatformState::Allowed
        } else {
            PlatformState::Unknown
        }
    }
    pub(crate) fn background() -> Option<Self> {
        let mut signals = Self::default();
        (signals.enter_background_qos() == PlatformState::Allowed).then_some(signals)
    }
}
impl PlatformGates for MacPlatformSignals {
    fn power(&mut self) -> PlatformState {
        #[cfg(all(test, unix))]
        if let Some(power) = super::resource_schedule::test_power() {
            return power;
        }
        #[cfg(target_os = "macos")]
        let answer = unsafe { ottto_power_state() };
        #[cfg(not(target_os = "macos"))]
        let answer = -1;
        power_state(answer)
    }
    fn enter_background_qos(&mut self) -> PlatformState {
        self.enter(query_qos(), set_qos)
    }
    fn restore_qos(&mut self) {
        if let Some((class, rel)) = self.saved.take() {
            // macOS has no "clear explicit QoS": unspecified restores DEFAULT.
            let class = if class == 0 { 0x15 } else { class };
            let set = set_qos;
            #[cfg(test)]
            let set = self.setter.unwrap_or(set);
            static LOGGED: AtomicBool = AtomicBool::new(false);
            if !set(class, rel) && !LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!("local snapshot continuation QoS restore failed");
            }
        }
    }
}
impl Drop for MacPlatformSignals {
    fn drop(&mut self) {
        self.restore_qos();
    }
}

/// Codex's cadence, for short critical sections.
pub(super) trait CadenceAccess {
    /// `None` when the cadence is unavailable.
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T>;
}

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
    /// The ticket's fixed lifetime ended.
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
            Outcome::Cancelled => "cancelled",
            Outcome::Failed => "failed",
        }
    }
}

/// Run at most one continuation page.
///
/// `slot` holds the ticket. Only a `Paused` page under the contention limit
/// leaves a ticket and a cadence request behind; every other end clears both,
/// so the next page is ordinary. `lock` is held for the whole page and
/// released before return, so it is never held while waiting between pages.
/// The ticket is taken and any new ticket written only while `lock` is held,
/// as an ordinary Codex finish writes its own, so a page can never overwrite a
/// newer ordinary decision with an older ticket. Clearing needs no lock: it
/// can only lose a continuation.
///
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
    // The cached inputs' fixed lifetime, before anything reads them.
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
    let qos = RestoreQos(gates);
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
    // Computed here, on this thread, under the lock and after every
    // recheck above; `None` (unknown) ends the attempt's acceleration.
    let backoff = host.upload_backoff();
    let ordinary = host
        .cadence(|cadence| ordinary_equivalent(cadence, backoff))
        .flatten();
    let ended = if port.ready(&cursor) {
        Some(port.page(cursor, deadline, ordinary))
    } else {
        None
    };
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

fn lock_slot(
    slot: &Mutex<Option<ContinuationTicket>>,
) -> MutexGuard<'_, Option<ContinuationTicket>> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Clear the cursor ticket and its request; a resident-paced ordinary request survives.
fn clear(cadence: &mut impl CadenceAccess, slot: &Mutex<Option<ContinuationTicket>>) {
    *lock_slot(slot) = None;
    cadence.cadence(SourceCadence::clear_cursor_continuation);
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
    fn paced_due(&mut self) -> Option<Instant> {
        None
    }
    /// One continuation page, which should end by `deadline`.
    fn page(&mut self, deadline: Instant) -> Outcome;
}

pub(super) fn wait_for_ordinary_cycle(host: &mut impl LoopHost, interval: Duration) {
    let start = host.now();
    let Some(deadline) = start.checked_add(interval) else {
        host.wait(interval);
        return;
    };
    loop {
        let now = host.now();
        let pending = host.pending();
        let ordinary_deadline = host.paced_due().map_or(deadline, |due| due.min(deadline));
        match plan_wake(now, ordinary_deadline, pending) {
            Wake::Ordinary(wait) => {
                host.wait(wait);
                return;
            }
            Wake::Continuation(wait) => {
                if host.wait(wait) {
                    return;
                }
                let outcome = host.page(ordinary_deadline);
                if matches!(outcome, Outcome::Failed) {
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
/// ticket (no attribution-bearing continuation without a bound).
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

/// The fixed lifetime of a ticket's cached inputs, from the start of
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

pub(super) fn invalidate_on_ordinary_prepare() {
    clear(&mut CodexCadence, &TICKET);
}

/// Accounting: the held ticket's inputs (context inventories, strings,
/// cached policy) as process-retained memory, outside every rotation frame.
/// `None` (unsupported layout, unknown size) makes the rotation discard it.
pub(super) fn retained_bound(limit: usize) -> Option<usize> {
    match lock_slot(&TICKET).as_ref() {
        None => Some(0),
        Some(ticket) => ticket.cursor.retained_bound(limit),
    }
}

/// The rotation refused the retained charge: drop the ticket and its inputs.
pub(super) fn discard_retained() {
    clear(&mut CodexCadence, &TICKET);
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
    if with_source_cadence(SnapshotSource::Codex, |cadence| {
        cadence.paced_scan_due().is_some()
    }) == Some(true)
    {
        clear(&mut CodexCadence, &TICKET);
        return;
    }
    let finished = crate::scan_clock::now();
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

/// A failed source pass leaves no paced request or cursor continuation.
pub(super) fn after_ordinary_source_failure(source: SnapshotSource) {
    drop_paced_request(source);
    if source == SnapshotSource::Codex {
        clear(&mut CodexCadence, &TICKET);
    }
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

/// A source with no pass to retire its paced request (paused, ungranted, or
/// stopped by a window-0 tombstone) drops it. Kept, its past deadline would
/// end every cycle wait at once.
pub(super) fn drop_paced_request(source: SnapshotSource) {
    with_source_cadence(source, SourceCadence::clear_continuation);
}

/// Settles the continuation when an ordinary cycle ends ([`settle_cycle`]).
/// Created right after `SNAPSHOT_SYNC_LOCK` is taken, so it drops, and settles,
/// before the lock is released on every return path, including `?`.
#[derive(Default)]
pub(super) struct CycleSettlement {
    succeeded_with_codex: bool,
    /// The sources this cycle collects; none until the cycle knows them.
    collecting: Vec<SnapshotSource>,
}

impl CycleSettlement {
    /// The cycle succeeded; `codex_granted` is whether it ran with Codex.
    pub(super) fn succeeded(&mut self, codex_granted: bool) {
        self.succeeded_with_codex = codex_granted;
    }

    /// The cycle collects `sources`; every other source's paced request
    /// drops when it ends.
    pub(super) fn collecting(&mut self, sources: &[SnapshotSource]) {
        self.collecting = sources.to_vec();
    }
}

impl Drop for CycleSettlement {
    fn drop(&mut self) {
        for source in super::SNAPSHOT_SOURCES {
            if !self.collecting.contains(&source) {
                drop_paced_request(source);
            }
        }
        settle_cycle(&mut CodexCadence, &TICKET, self.succeeded_with_codex);
    }
}

pub(super) fn production_pending() -> Option<(Instant, Duration)> {
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

struct ProductionHost<'a> {
    daemon: &'a LocalDaemon,
}

impl CadenceAccess for ProductionHost<'_> {
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        with_source_cadence(SnapshotSource::Codex, apply)
    }
}

impl Host for ProductionHost<'_> {
    fn now(&mut self) -> Instant {
        crate::scan_clock::now()
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
}

pub(super) fn run_production_page(
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    ordinary_deadline: Instant,
) -> Outcome {
    run_page(
        &mut ProductionHost { daemon },
        &mut CodexContinuation::new(&daemon.transcript_cache, home, support_dir),
        &mut MacPlatformSignals::default(),
        SNAPSHOT_SYNC_LOCK.get_or_init(|| Mutex::new(())),
        &TICKET,
        ordinary_deadline,
    )
}

/// The interval a continuation page stands for in the cursor's
/// `e2` accounting (`max(elapsed, ordinary)`), read once per page by
/// [`run_page`] under the sync lock after its rechecks, so only while
/// enabled. It is exactly `ordinary_interval`: the tier floor, or the failure
/// backoff while failing, lengthened only by the server directive, with no
/// clamp, floor or historical estimate. It is a per-page lower bound of what
/// ordinary scheduling would have taken, not coverage: cycle and lock delays
/// are unbounded, so acceleration can start a later same-revision attempt
/// earlier by that overhead (the guard is the cursor's).
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

/// Set after any continuation worker panicked, or broke a page invariant:
/// no further ticket is minted or readied for the process lifetime.
static WORKER_LATCHED: AtomicBool = AtomicBool::new(false);

/// W1: everything that crosses the worker join, and the port the worker
/// builds, is `Send` by its own types (checked here at compile time; no
/// `unsafe impl`). The closure itself is bounded by [`on_worker`].
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<PageEnd>();
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

/// Run `body` on one named, short-lived worker and join it
/// explicitly, so a panic comes back as `Err` instead of unwinding the
/// caller. The caller holds `SNAPSHOT_SYNC_LOCK` through the join and touches
/// nothing else; the worker never takes that lock and makes no callback,
/// channel send or wait toward the caller. Thread-locals are the
/// worker's own: none is inherited.
fn on_worker<T: Send>(body: impl FnOnce() -> T + Send) -> std::result::Result<T, WorkerFailure> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("ottto-codex-continuation".to_string())
            .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
            .spawn_scoped(scope, body)
            .map_err(|_| WorkerFailure::Spawn)?;
        worker.join().map_err(|_| WorkerFailure::Panicked)
    })
}

/// How the page ended on the worker. Everything here is `Send` (W1) and
/// moves to the parent; nothing is shared.
enum WorkerEnd {
    /// The job paused again at its byte budget: the page, with its new
    /// cursor ticket and the inputs it moved to the worker.
    Paused(Box<CodexPage>),
    /// Completed without committing and without a ticket (deadline, or
    /// debt / a disclosure that is not saved).
    Stopped,
    /// Nothing ran past the worker's own gates (QoS, members).
    Deferred,
    /// The continuation-local prepare refused before any read.
    Refused(&'static str),
    /// A non-EOF end produced snapshots: nothing is saved, and the
    /// worker latch is set.
    Unexpected,
    Failed(anyhow::Error),
}

/// The production cursor side: `CodexCursorPort`, with each page run
/// on an explicitly joined worker.
pub(super) struct CodexContinuation<'a> {
    cache: &'a Arc<SharedCache>,
    home: &'a Path,
    support_dir: &'a Path,
    worker_qos: fn() -> Option<MacPlatformSignals>,
    /// The process latch: [`WORKER_LATCHED`] in production.
    latch: &'static AtomicBool,
}

impl<'a> CodexContinuation<'a> {
    pub(super) fn new(cache: &'a Arc<SharedCache>, home: &'a Path, support_dir: &'a Path) -> Self {
        Self {
            cache,
            home,
            support_dir,
            worker_qos: MacPlatformSignals::background,
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
        #[allow(clippy::infallible_destructuring_match, reason = "fakes add a variant")]
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
        page_end(ended, deadline, crate::scan_clock::now(), self.latch)
    }
}

/// The parent's mapping of a joined worker's end.
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
        Ok(WorkerEnd::Unexpected) => {
            latch.store(true, Ordering::SeqCst);
            PageEnd::Failed(anyhow!("continuation page produced snapshots before EOF"))
        }
        Ok(WorkerEnd::Failed(error)) => PageEnd::Failed(error),
    }
}

fn page_on_worker(
    cache: &Arc<SharedCache>,
    home: &Path,
    support_dir: &Path,
    mut page: Box<CodexPage>,
    deadline: Instant,
    ordinary_equivalent: Option<Duration>,
    qos: fn() -> Option<MacPlatformSignals>,
) -> WorkerEnd {
    let Some(_qos) = qos() else {
        return WorkerEnd::Deferred;
    };
    if !CodexCursorPort::new(Arc::clone(cache)).ready(&page.cursor) {
        return WorkerEnd::Deferred;
    }
    let Some(inputs) = page.inputs.as_mut() else {
        return WorkerEnd::Deferred;
    };
    match run_continuation_scan(
        home,
        support_dir,
        cache,
        inputs,
        ordinary_equivalent,
        deadline,
    ) {
        Err(error) => WorkerEnd::Failed(error),
        Ok(ContinuationScan::Refused(reason)) => WorkerEnd::Refused(reason.label()),
        Ok(ContinuationScan::StepRefused) => WorkerEnd::Deferred,
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
#[path = "tests/continuation_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
pub(super) fn resource_qos() -> Option<(u32, i32)> {
    query_qos()
}
#[cfg(all(test, unix))]
pub(super) fn resource_set_qos(class: u32, relative: i32) -> bool {
    set_qos(class, relative)
}

use super::activate_source_upload_context;
use super::backfill_replay_pending;
use super::continuation;
use super::current_rfc3339;
use super::cycle_body_witness_revision;
use super::cycle_replay_generation;
use super::cycle_sampled_scope;
use super::cycle_upload_context;
use super::load_backfill_state;
use super::prepare_upload_progress_for_cycle_with_reoffer;
use super::reason_reoffer;
use super::scan_request_window_days;
use super::stale_owed;
use super::PathBuf;
use super::Result;
use super::SessionAttributionContext;
use super::SnapshotApiClient;
use super::SnapshotUploadProgress;
use super::SourcePreparationStep;
use super::MAX_BACKFILL_FILES_PER_SOURCE;

/// What a Codex continuation page needs from the
/// ordinary prepare of the cycle that minted its ticket. The attribution
/// context is that cycle's own, moved out of its preparation, never copied
/// or re-decoded; the policy copies (hint, upload policy, receipt client)
/// carry no raw key. A ticket holds these for at most its fixed lifetime
/// (`continuation::ticket_lifetime`) and drops them, zeroizing the key, on
/// every other end. Charged as process-retained memory
/// (`continuation::retained_bound`).
pub(super) struct ContinuationInputs {
    pub(super) codex_preludes: std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    pub(super) codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
    pub(super) account_witness: [u8; 32],
    pub(super) activity_hint: crate::snapshot_client::ActivityHintResponse,
    pub(super) receipt_window_days: u64,
    pub(super) cache_observations_enabled: bool,
    /// The one status input a continuation page reads: its finish never runs.
    pub(super) codex_scan_homes: Vec<PathBuf>,
    pub(super) attribution_context: Option<SessionAttributionContext>,
    pub(super) upload_policy: SnapshotUploadPolicy,
    pub(super) upload_destination_namespace: String,
    pub(super) receipt_client: SnapshotApiClient,
    pub(super) index_path: PathBuf,
    pub(super) upload_progress_path: PathBuf,
    pub(super) evidence: Option<crate::snapshots::CodexContinuationEvidence>,
    pub(super) runtime_context: continuation::RuntimeContext,
}

crate::heap_layout_bound::fields!(ContinuationInputs; codex_preludes, account_witness, activity_hint,
    receipt_window_days, cache_observations_enabled,
    codex_scan_homes, attribution_context, upload_policy,
    upload_destination_namespace, receipt_client, index_path, upload_progress_path, evidence, runtime_context; shared codex_versions);

impl ContinuationInputs {
    /// Whether the moved attribution context is present (tests read this
    /// instead of the context itself).
    #[cfg(test)]
    pub(super) fn holds_attribution(&self) -> bool {
        self.attribution_context.is_some()
    }
}

pub(super) fn continuation_finish_inputs<'a>(
    preparation: &'a mut SourcePreparation,
    scan: &'a mut SourceScanResult,
    remaining: Option<usize>,
    codex_preludes: &'a std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
) -> impl FnOnce(continuation::ContinuationTicket) -> Option<continuation::ContinuationTicket> + 'a
{
    move |ticket| {
        let evidence = scan.take_continuation_evidence()?;
        let mut inputs = take_continuation_inputs(preparation, codex_preludes, codex_versions);
        inputs.evidence = Some(evidence);
        let refusal = remaining.map_or("no_remaining", |_| "over_bound");
        let ticket = remaining.and_then(|limit| ticket.with_inputs(inputs, limit));
        crate::local_resource_diagnostics::codex_continuation_mint(
            ticket.as_ref().map_or(refusal, |_| "minted"),
        );
        ticket
    }
}

/// The continuation inputs of a just-finished ordinary Codex
/// page, taken before its finish. `finish_sync_source` never reads the
/// attribution context, so moving it out changes nothing for the finish.
/// Called only while continuation pages are enabled and a ticket was minted.
pub(super) fn take_continuation_inputs(
    preparation: &mut SourcePreparation,
    codex_preludes: &std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
) -> ContinuationInputs {
    let mut activity_hint = preparation.activity_hint.clone();
    // The prepare took the raw key out of its hint already; never keep one.
    if let Some(mut key) = activity_hint.session_attribution_hmac_key.take() {
        key.zeroize();
    }
    ContinuationInputs {
        codex_preludes: std::sync::Arc::clone(codex_preludes),
        codex_versions,
        evidence: None,
        runtime_context: continuation::runtime_context(),
        account_witness: preparation.account_witness,
        activity_hint,
        receipt_window_days: preparation.receipt_window_days,
        cache_observations_enabled: preparation.cache_observations_enabled,
        codex_scan_homes: preparation
            .scan_agent_status_collection
            .as_ref()
            .map(|collection| collection.codex_scan_homes.clone())
            .unwrap_or_default(),
        attribution_context: preparation.attribution_context.take(),
        upload_policy: preparation.upload_policy,
        upload_destination_namespace: preparation.upload_destination_namespace.clone(),
        receipt_client: preparation.receipt_client.clone(),
        index_path: preparation.index_path.clone(),
        upload_progress_path: preparation.upload_progress_path.clone(),
    }
}

/// Why a continuation page refused before reading any
/// transcript. Each state changes only through an ordinary prepare, so the
/// paused job waits in its slot for the ordinary pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContinuationRefusal {
    HistoricalReplay,
    AdmissionReoffer,
    UploadClaim,
    ReasonReoffer,
    EvidenceChanged,
}

impl ContinuationRefusal {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::HistoricalReplay => "historical_replay_pending",
            Self::AdmissionReoffer => "admission_reoffer_pending",
            Self::UploadClaim => "upload_progress_claim_needed",
            Self::ReasonReoffer => "reason_reoffer_active",
            Self::EvidenceChanged => "continuation_evidence_changed",
        }
    }
}

/// Whether this cycle's ordinary prepare would claim
/// an upload-progress generation or lease a retry or re-offer (and save that
/// claim). Pure: it runs the ordinary selection on a copy, so its answer is
/// the mutating function's by construction, and nothing is persisted.
pub(super) fn continuation_upload_claim_needed(
    upload_progress: &SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    reoffer: &reason_reoffer::Scope<'_>,
) -> bool {
    let mut probe = upload_progress.clone();
    prepare_upload_progress_for_cycle_with_reoffer(
        &mut probe,
        index,
        replay_generation,
        false,
        Some(reoffer),
    )
}

/// How a continuation page's scan ended, on the worker.
pub(super) enum ContinuationScan {
    /// Refused before any transcript read: nothing was stepped or saved.
    Refused(ContinuationRefusal),
    /// The scan's own local admission refused a step.
    StepRefused,
    /// Completed without committing its job. `ticket` is the byte-budget
    /// pause's new ticket; `snapshots` how many snapshots the page produced
    /// (zero on every valid non-EOF end). Nothing was saved.
    Uncommitted {
        ticket: Option<crate::snapshots::CodexCursorTicket>,
        snapshots: usize,
    },
}

pub(super) fn run_continuation_scan(
    home: &Path,
    support_dir: &Path,
    cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    inputs: &mut ContinuationInputs,
    ordinary_equivalent: Option<Duration>,
    deadline: Instant,
) -> Result<ContinuationScan> {
    let current = continuation::runtime_context();
    let contexts = |value: continuation::RuntimeContext| value.map(|slot| slot.map(|v| v.0));
    let held = if contexts(inputs.runtime_context) != contexts(current) {
        "context_changed"
    } else if inputs.runtime_context != current {
        "policy_changed"
    } else if inputs.evidence.is_none() {
        "other"
    } else {
        "roster_changed"
    };
    if inputs.runtime_context != current
        || !inputs
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.content_unchanged())
    {
        crate::local_resource_diagnostics::codex_continuation(Some(held));
        return Ok(ContinuationScan::Refused(
            ContinuationRefusal::EvidenceChanged,
        ));
    }
    let mut preparation = match prepare_continuation_source(
        home,
        support_dir,
        cache,
        inputs,
        ordinary_equivalent,
        deadline,
    )
    .inspect_err(|_| crate::local_resource_diagnostics::codex_continuation(Some("other")))?
    {
        Ok(preparation) => preparation,
        Err(reason) => {
            crate::local_resource_diagnostics::codex_continuation(Some("other"));
            return Ok(ContinuationScan::Refused(reason));
        }
    };
    crate::local_resource_diagnostics::codex_continuation(None);
    loop {
        match preparation.step() {
            SourcePreparationStep::Pending(next) => preparation = next,
            SourcePreparationStep::Refused(mut refused, _) => {
                crate::local_resource_diagnostics::codex_continuation(Some("other"));
                inputs.attribution_context = refused.attribution_context.take();
                return Ok(ContinuationScan::StepRefused);
            }
            SourcePreparationStep::Complete {
                mut preparation,
                index: _,
                mut scan,
            } => {
                inputs.evidence = scan.take_continuation_evidence();
                inputs.attribution_context = preparation.attribution_context.take();
                return Ok(ContinuationScan::Uncommitted {
                    ticket: scan.continuation_ticket().cloned(),
                    snapshots: scan.snapshots.len(),
                });
            }
        }
    }
}

/// The continuation-local prepare. It is not
/// `prepare_sync_source`'s tail: it takes no watcher hint, spends no
/// per-cycle budget, saves nothing and never resets the index. Every state
/// that would need one of those refuses first, before scan setup or any transcript
/// read. The rest follows the ordinary prepare's order on the freshly
/// loaded index and upload progress, with the same-cycle cached inputs. On
/// `Ok(Ok(..))` the attribution context has moved into the preparation; on a
/// refusal it is still in `inputs`.
pub(super) fn prepare_continuation_source(
    home: &Path,
    support_dir: &Path,
    cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    inputs: &mut ContinuationInputs,
    ordinary_equivalent: Option<Duration>,
    deadline: Instant,
) -> Result<std::result::Result<SourcePreparation, ContinuationRefusal>> {
    let source = SnapshotSource::Codex;
    let scan_started_at = current_rfc3339();
    let checkpoint_namespace = inputs
        .attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let upload_context = cycle_upload_context(
        inputs.upload_policy,
        checkpoint_namespace.as_deref(),
        inputs.cache_observations_enabled,
    );
    let (mut index, _) =
        ScanIndex::load_for_snapshot_source_with_origin(&inputs.index_path, source, support_dir)?;
    index.require_persistence_available()?;
    let mut upload_progress = SnapshotUploadProgress::load_for_index(
        &index,
        &inputs.index_path,
        &inputs.upload_progress_path,
        &inputs.upload_destination_namespace,
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &upload_context),
    )?;
    upload_progress.configure_ack_capacity(&index);
    let backfill_state = load_backfill_state(support_dir);
    let replay_generation = cycle_replay_generation(source, &inputs.upload_destination_namespace);
    if backfill_replay_pending(
        source,
        &backfill_state,
        &inputs.upload_destination_namespace,
    ) {
        return Ok(Err(ContinuationRefusal::HistoricalReplay));
    }
    if index.snapshot_admission_reoffer_pending() {
        return Ok(Err(ContinuationRefusal::AdmissionReoffer));
    }
    let reoffer_now = reason_reoffer::now_unix_seconds();
    let claim_needed = continuation_upload_claim_needed(
        &upload_progress,
        &index,
        &replay_generation,
        &reason_reoffer::Scope {
            index: &index,
            now: reoffer_now,
            window_start_unix_seconds: reoffer_now
                .saturating_sub(inputs.receipt_window_days.saturating_mul(86_400)),
        },
    );
    if claim_needed {
        return Ok(Err(ContinuationRefusal::UploadClaim));
    }
    activate_source_upload_context(source, upload_context, &mut index, &mut upload_progress);
    // The ordinary selection's in-memory effects, on this page's own copy;
    // the probe above found no claim, so there is nothing to save.
    let claimed = prepare_upload_progress_for_cycle_with_reoffer(
        &mut upload_progress,
        &index,
        &replay_generation,
        false,
        Some(&reason_reoffer::Scope {
            index: &index,
            now: reoffer_now,
            window_start_unix_seconds: reoffer_now
                .saturating_sub(inputs.receipt_window_days.saturating_mul(86_400)),
        }),
    );
    if claimed {
        return Ok(Err(ContinuationRefusal::UploadClaim));
    }
    if !upload_progress.active_reason_reoffers.is_empty() {
        return Ok(Err(ContinuationRefusal::ReasonReoffer));
    }
    index.activate_effective_upload_body_witness_revision(cycle_body_witness_revision(source));
    // K3: as the ordinary prepare, before the scan advances it. It is dropped
    // here unless the page commits, and crosses to the parent only by move.
    crate::local_resource_diagnostics::index_clone_start(source.api_slug());
    let committed_index = index.clone();
    // No lease is active (refused above), so this only installs the empty
    // set, as the ordinary prepare does; there are no hint paths to take.
    let leased_paths =
        index.activate_reason_reoffer_retries(upload_progress.active_reason_reoffers.clone());
    debug_assert!(leased_paths.is_empty());
    index.activate_reason_reoffer_cooldowns(upload_progress.reason_reoffer_cooldowns(reoffer_now));
    stale_owed::rearm_held_probe_once(source, &upload_progress, &mut index);
    upload_progress.reselect_pending_cache_heads(&mut index, inputs.cache_observations_enabled);
    let roots = crate::snapshot_roots::scan_roots(source, home, &inputs.codex_scan_homes)?;
    // Reuse the ordinary page's namespace and durable pass, including GC/breaker state.
    let sampled_scope = cycle_sampled_scope(
        &inputs.account_witness,
        &inputs.upload_destination_namespace,
        &inputs.index_path,
        false,
    );
    let scan = crate::snapshots::OwnedSourceScan::new_continuation(
        &roots,
        index,
        &scan_started_at,
        scan_request_window_days(inputs.receipt_window_days, false),
        MAX_BACKFILL_FILES_PER_SOURCE,
        ordinary_equivalent,
        inputs.evidence.take(),
    )
    .with_continuation_deadline(deadline)
    .with_sampled_acquisition(std::sync::Arc::clone(cache), sampled_scope)
    .with_launch_events(home)
    .with_line_observer("codex_prelude", inputs.codex_preludes.observer(&roots))
    .with_codex_versions(inputs.codex_versions.clone());
    Ok(Ok(SourcePreparation {
        source,
        walk_idle_pass: None,
        claude_scan_roots: None,
        account_witness: inputs.account_witness,
        scan_started_at,
        activity_hint: inputs.activity_hint.clone(),
        receipt_window_days: inputs.receipt_window_days,
        cache_observations_enabled: inputs.cache_observations_enabled,
        scan_agent_status_collection: None,
        attribution_context: inputs.attribution_context.take(),
        upload_policy: inputs.upload_policy,
        upload_destination_namespace: inputs.upload_destination_namespace.clone(),
        receipt_client: inputs.receipt_client.clone(),
        index_path: inputs.index_path.clone(),
        upload_progress_path: inputs.upload_progress_path.clone(),
        upload_progress,
        committed_index,
        backfill_state,
        backfill_pending: false,
        scan: Some(scan),
    }))
}
