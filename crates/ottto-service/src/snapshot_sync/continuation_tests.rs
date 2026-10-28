// CI controls for paced continuation. The cursor side and the
// platform are fakes standing in for c22's hunks and the platform hunk; the
// clock is simulated, so nothing here sleeps, reads a transcript or opens a
// socket.

use super::super::{validate_snapshot_scan_authority, SNAPSHOT_SYNC_INTERVAL};
use super::*;
use crate::adaptive_collector::CadenceConfig;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::PathBuf;

/// An ordinary Codex scan of an empty root: no cursor, no ticket.
fn empty_scan() -> SourceScanResult {
    let root = crate::test_scratch::unique_path("ottto-continuation-empty-root");
    std::fs::create_dir_all(&root).unwrap();
    crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut ScanIndex::default(),
        "2026-10-24T00:00:00Z",
        30,
        10,
        false,
    )
    .unwrap()
}

const DESTINATION: [u8; 32] = [7; 32];
const OTHER_DESTINATION: [u8; 32] = [9; 32];
const AUTHORITY: [u8; 32] = [3; 32];
const OTHER_AUTHORITY: [u8; 32] = [4; 32];
/// How far a page reads past its deadline: to the end of the current record.
const RECORD: Duration = Duration::from_secs(1);
/// The fakes' ticket lifetime unless a control sets its own: long enough
/// that only the K2/P-1 expiry controls reach it.
const LIFETIME: Duration = Duration::from_secs(24 * 3600);

struct World {
    now: Cell<Instant>,
    backoff: Cell<bool>,
    destination: Cell<Option<[u8; 32]>>,
    authority: Cell<Option<[u8; 32]>>,
    cadence: RefCell<SourceCadence>,
    slot: Mutex<Option<ContinuationTicket>>,
    /// Every call that would reach the network. Only `complete_eof` counts.
    network: Cell<u32>,
    /// What the unchanged completion upload records on the cadence: `Some`
    /// accepted count for a success, `None` for a retryable deferral.
    lock: Mutex<()>,
    lock_held_in_page: Cell<Option<bool>>,
    qos_lowered: Cell<bool>,
    /// The lifetime of the tickets ordinary pages mint here.
    lifetime: Cell<Duration>,
}

impl World {
    fn new() -> Self {
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.record_scan_success(start, 1);
        Self {
            now: Cell::new(start),
            backoff: Cell::new(false),
            destination: Cell::new(Some(DESTINATION)),
            authority: Cell::new(Some(AUTHORITY)),
            cadence: RefCell::new(cadence),
            slot: Mutex::new(None),
            network: Cell::new(0),
            lock: Mutex::new(()),
            lock_held_in_page: Cell::new(None),
            qos_lowered: Cell::new(false),
            lifetime: Cell::new(LIFETIME),
        }
    }

    fn advance(&self, by: Duration) {
        self.now.set(self.now.get() + by);
    }

    /// An ordinary Codex page that paused at its budget after `work`.
    fn ordinary_page_asks(&self, work: Duration) {
        self.advance(work);
        let mut cadence = self.cadence.borrow_mut();
        cadence.record_scan_success(self.now.get(), 1);
        assert!(cadence.request_continuation(self.now.get(), work));
        *lock_slot(&self.slot) = Some(self.ticket(DESTINATION));
    }

    /// A ticket minted now, with this world's lifetime.
    fn ticket(&self, destination: [u8; 32]) -> ContinuationTicket {
        let issued = self.now.get();
        ticket_at(destination, issued, issued + self.lifetime.get())
    }

    fn held_lifetime(&self) -> Option<(Instant, Instant)> {
        lock_slot(&self.slot)
            .as_ref()
            .map(|ticket| (ticket.issued, ticket.expires))
    }

    fn held(&self) -> bool {
        lock_slot(&self.slot).is_some()
    }

    fn held_destination(&self) -> Option<[u8; 32]> {
        lock_slot(&self.slot)
            .as_ref()
            .map(|ticket| ticket.destination)
    }

    fn due(&self) -> Option<Instant> {
        self.cadence.borrow().continuation_due(PACING)
    }

    fn advance_to_due(&self) {
        let due = self.due().expect("a continuation is due");
        if due > self.now.get() {
            self.now.set(due);
        }
    }
}

fn ticket_at(destination: [u8; 32], issued: Instant, expires: Instant) -> ContinuationTicket {
    ContinuationTicket {
        destination,
        authority: AUTHORITY,
        cursor: CursorTicket::synthetic(),
        issued,
        expires,
    }
}

struct FakeHost<'a>(&'a World);

impl CadenceAccess for FakeHost<'_> {
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        Some(apply(&mut self.0.cadence.borrow_mut()))
    }
}

impl Host for FakeHost<'_> {
    fn now(&mut self) -> Instant {
        self.0.now.get()
    }
    fn upload_backoff(&mut self) -> bool {
        self.0.backoff.get()
    }
    fn destination(&mut self) -> Option<[u8; 32]> {
        self.0.destination.get()
    }
    fn authority(&mut self) -> Option<[u8; 32]> {
        self.0.authority.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Paused,
    Deferred,
    ParkedEof,
    Cancelled,
    Failed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Calls {
    ready: u32,
    page: u32,
}

struct FakePort<'a> {
    world: &'a World,
    ready: bool,
    ends: VecDeque<End>,
    work: Duration,
    /// Something changes while the page runs, before the EOF recheck.
    backoff_during_page: bool,
    destination_during_page: Option<[u8; 32]>,
    authority_during_page: Option<Option<[u8; 32]>>,
    /// The deadline each page was given, and whether it was cut short there.
    deadlines: Vec<(Instant, bool)>,
    /// The ordinary equivalent each page was given (K4).
    equivalents: Vec<Option<Duration>>,
    calls: Calls,
}

impl<'a> FakePort<'a> {
    fn new(world: &'a World, ends: &[End]) -> Self {
        Self {
            world,
            ready: true,
            ends: ends.iter().copied().collect(),
            work: Duration::from_secs(4),
            backoff_during_page: false,
            destination_during_page: None,
            authority_during_page: None,
            deadlines: Vec::new(),
            equivalents: Vec::new(),
            calls: Calls::default(),
        }
    }
}

impl CursorContinuation for FakePort<'_> {
    fn ticket_for(&self, _scan: &SourceScanResult) -> Option<CursorTicket> {
        None
    }
    fn ready(&mut self, _ticket: &CursorTicket) -> bool {
        self.calls.ready += 1;
        self.ready
    }
    fn page(
        &mut self,
        _ticket: CursorTicket,
        deadline: Instant,
        ordinary_equivalent: Option<Duration>,
    ) -> PageEnd {
        self.calls.page += 1;
        self.equivalents.push(ordinary_equivalent);
        self.world
            .lock_held_in_page
            .set(Some(self.world.lock.try_lock().is_err()));
        assert!(!self.world.held(), "the page's ticket is out of the slot");
        // Past the deadline, stop at the next record boundary and pause.
        let end = self.world.now.get() + self.work;
        let cut = end > deadline;
        self.deadlines.push((deadline, cut));
        self.world
            .now
            .set(if cut { deadline + RECORD } else { end });
        if self.backoff_during_page {
            self.world.backoff.set(true);
        }
        if let Some(destination) = self.destination_during_page {
            self.world.destination.set(Some(destination));
        }
        if let Some(authority) = self.authority_during_page {
            self.world.authority.set(authority);
        }
        let planned = self.ends.pop_front().unwrap_or(End::Paused);
        if cut {
            return PageEnd::PausedContended;
        }
        match planned {
            End::Paused => PageEnd::Paused(CursorTicket::synthetic()),
            End::Deferred => PageEnd::Deferred,
            End::ParkedEof => PageEnd::Deferred,
            End::Cancelled => PageEnd::Cancelled,
            End::Failed => PageEnd::Failed(anyhow!("synthetic save CAS refusal")),
        }
    }
}

struct FakeGates<'a> {
    world: &'a World,
    power: PlatformState,
    qos: PlatformState,
    /// An ordinary pass that runs between the due check and the sync lock.
    on_power: Option<fn(&World)>,
    entered: u32,
    restored: u32,
}

impl<'a> FakeGates<'a> {
    fn allowed(world: &'a World) -> Self {
        Self {
            world,
            power: PlatformState::Allowed,
            qos: PlatformState::Allowed,
            on_power: None,
            entered: 0,
            restored: 0,
        }
    }
}

impl PlatformGates for FakeGates<'_> {
    fn power(&mut self) -> PlatformState {
        if let Some(ordinary_pass) = self.on_power {
            ordinary_pass(self.world);
        }
        self.power
    }
    fn enter_background_qos(&mut self) -> PlatformState {
        self.entered += 1;
        if self.qos == PlatformState::Allowed {
            self.world.qos_lowered.set(true);
        }
        self.qos
    }
    fn restore_qos(&mut self) {
        self.restored += 1;
        self.world.qos_lowered.set(false);
    }
}

/// A deadline no page in these controls reaches.
fn far(world: &World) -> Instant {
    world.now.get() + Duration::from_secs(3600)
}

fn run(world: &World, port: &mut FakePort<'_>, gates: &mut FakeGates<'_>) -> Outcome {
    let deadline = far(world);
    run_page(
        &mut FakeHost(world),
        port,
        gates,
        &world.lock,
        &world.slot,
        deadline,
    )
}

#[test]
fn a_paused_page_asks_for_the_next_page_after_the_duty_gap() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);

    let started = world.now.get();
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
    let finished = world.now.get();
    assert!(world.held());
    assert_eq!(world.network.get(), 0);
    assert_eq!(
        world.lock_held_in_page.get(),
        Some(true),
        "R0: the page runs under the snapshot sync lock"
    );
    assert!(
        world.lock.try_lock().is_ok(),
        "the lock is released before the wait between pages"
    );
    assert_eq!((gates.entered, gates.restored), (1, 1));
    // 4 s of measured work: the 30 s minimum still dominates 9 × 4 s.
    assert_eq!(finished - started, Duration::from_secs(4));
    assert_eq!(world.due(), Some(finished + Duration::from_secs(36)));
}

#[test]
fn cancelled_failed_and_deferred_pages_leave_no_continuation() {
    for (end, expected) in [
        (End::Cancelled, Outcome::Cancelled),
        (End::Failed, Outcome::Failed),
        (End::Deferred, Outcome::Deferred),
    ] {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let mut port = FakePort::new(&world, &[end]);
        let mut gates = FakeGates::allowed(&world);
        assert_eq!(run(&world, &mut port, &mut gates), expected);
        assert!(!world.held(), "{end:?}");
        assert_eq!(world.due(), None, "{end:?}");
        assert_eq!(world.network.get(), 0, "{end:?}");
        assert_eq!((gates.entered, gates.restored), (1, 1), "{end:?}");
        assert!(world.lock.try_lock().is_ok(), "{end:?}");
    }
}

#[test]
fn refused_busy_or_unknown_inputs_cannot_manufacture_urgency() {
    type Setup = fn(&World, &mut FakePort<'_>, &mut FakeGates<'_>);
    let cases: [(&str, Setup, Skip); 11] = [
        (
            "failing",
            |w, _, _| {
                w.cadence.borrow_mut().record_scan_failure(w.now.get());
            },
            Skip::Failing,
        ),
        ("backoff", |w, _, _| w.backoff.set(true), Skip::Backoff),
        (
            "power unknown",
            |_, _, g| g.power = PlatformState::Unknown,
            Skip::Platform,
        ),
        (
            "power refused",
            |_, _, g| g.power = PlatformState::Refused,
            Skip::Platform,
        ),
        (
            "qos unknown",
            |_, _, g| g.qos = PlatformState::Unknown,
            Skip::Platform,
        ),
        (
            "qos refused",
            |_, _, g| g.qos = PlatformState::Refused,
            Skip::Platform,
        ),
        // The device no longer grants Codex, or a device, machine, endpoint
        // or account input is unavailable.
        (
            "grant revoked",
            |w, _, _| w.authority.set(None),
            Skip::Authority,
        ),
        (
            "account changed",
            |w, _, _| w.authority.set(Some(OTHER_AUTHORITY)),
            Skip::Authority,
        ),
        (
            "destination",
            |w, _, _| w.destination.set(Some(OTHER_DESTINATION)),
            Skip::Destination,
        ),
        (
            "credentials",
            |w, _, _| w.destination.set(None),
            Skip::Destination,
        ),
        ("not ready", |_, p, _| p.ready = false, Skip::NotReady),
    ];
    for (name, setup, skip) in cases {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let reference = world.cadence.borrow().clone();
        let mut port = FakePort::new(&world, &[End::Paused]);
        let mut gates = FakeGates::allowed(&world);
        setup(&world, &mut port, &mut gates);
        assert_eq!(
            run(&world, &mut port, &mut gates),
            Outcome::Skipped(skip),
            "{name}"
        );
        assert_eq!(port.calls.page, 0, "{name}: no page ran");
        assert!(!world.held(), "{name}: the ticket is gone");
        assert_eq!(world.due(), None, "{name}: back to the ordinary cadence");
        assert_eq!(world.network.get(), 0, "{name}");
        let restored = if name.starts_with("qos") {
            0
        } else {
            gates.entered
        };
        assert_eq!(
            gates.restored, restored,
            "{name}: QoS is restored exactly when it was applied"
        );
        if name != "failing" {
            let now = world.now.get();
            assert_eq!(
                world.cadence.borrow().next_scan_after(now),
                reference.next_scan_after(now),
                "{name}: the ordinary schedule is untouched"
            );
        }
        assert!(world.lock.try_lock().is_ok(), "{name}");
    }

    // A busy lock: the other cycle owns the index and decides.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    let held = world.lock.lock().expect("hold the lock");
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::LockBusy)
    );
    drop(held);
    assert_eq!(port.calls.page, 0);
    assert!(!world.held());
    assert_eq!(world.due(), None);

    // No ticket at all.
    let world = World::new();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NoTicket)
    );
    assert_eq!(port.calls.ready, 0);
}

#[test]
fn a_failed_cycle_or_a_lost_codex_grant_leaves_no_continuation() {
    // A cycle that ends `Err`, including before rotation (machine identity
    // missing, account authority unavailable), or ran without the Codex grant.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    settle_cycle(&mut FakeHost(&world), &world.slot, false);
    assert!(!world.held());
    assert_eq!(world.due(), None);
    world.advance(Duration::from_secs(60));
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NoTicket)
    );
    assert_eq!(port.calls.page, 0);

    // A successful cycle with the grant keeps a ticket whose Codex scan was
    // not due this cycle.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    settle_cycle(&mut FakeHost(&world), &world.slot, true);
    assert!(world.held());
    assert!(world.due().is_some());
}

fn ordinary_pass_clears(world: &World) {
    settle_cycle(&mut FakeHost(world), &world.slot, false);
}

fn ordinary_pass_mints_newer(world: &World) {
    let _guard = world.lock.lock().unwrap();
    world.ordinary_page_asks(Duration::from_secs(4));
    world.destination.set(Some(OTHER_DESTINATION));
    *lock_slot(&world.slot) = Some(world.ticket(OTHER_DESTINATION));
}

#[test]
fn the_ticket_is_taken_and_written_only_under_the_sync_lock() {
    // An ordinary pass between the due check and the lock clears the ticket:
    // no page runs on the older one.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    gates.on_power = Some(ordinary_pass_clears as fn(&World));
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NoTicket)
    );
    assert_eq!(port.calls.page, 0);
    assert!(!world.held());

    // An ordinary pass that minted a newer ticket (here under a rotated
    // destination) also installs its own cadence request. Its new 36 s gap
    // must elapse before even ready() is called.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    gates.on_power = Some(ordinary_pass_mints_newer as fn(&World));
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NotDue)
    );
    let due = world.due().unwrap();
    assert_eq!(due - world.now.get(), Duration::from_secs(36));
    assert_eq!(world.held_destination(), Some(OTHER_DESTINATION));
    assert_eq!(port.calls, Calls::default());
    assert_eq!(gates.entered, 0);
    gates.on_power = None;
    world.now.set(due - Duration::from_secs(1));
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NotDue)
    );
    assert_eq!(world.due(), Some(due));
    assert_eq!(port.calls, Calls::default());
    world.now.set(due);
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
    assert_eq!(port.calls.page, 1);
    assert_eq!(world.held_destination(), Some(OTHER_DESTINATION));
}

#[test]
fn policy_changes_between_precheck_and_lock_apply_to_the_current_ticket() {
    type Change = fn(&World);
    let rows: [(Change, Skip, bool); 4] = [
        (
            |w| {
                w.cadence
                    .borrow_mut()
                    .set_server_min_interval(Some(Duration::from_secs(120)))
            },
            Skip::NotDue,
            true,
        ),
        (
            |w| {
                w.cadence
                    .borrow_mut()
                    .set_server_min_interval(Some(Duration::from_secs(1800)))
            },
            Skip::NotDue,
            false,
        ),
        (
            |w| w.cadence.borrow_mut().record_scan_failure(w.now.get()),
            Skip::Failing,
            false,
        ),
        (|w| w.backoff.set(true), Skip::Backoff, false),
    ];
    for (change, reason, kept) in rows {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(4));
        world.advance_to_due();
        let mut port = FakePort::new(&world, &[End::Paused]);
        let mut gates = FakeGates::allowed(&world);
        gates.on_power = Some(change);
        assert_eq!(run(&world, &mut port, &mut gates), Outcome::Skipped(reason));
        assert_eq!(world.held(), kept);
        assert_eq!(world.due().is_some(), kept);
        assert_eq!(port.calls, Calls::default());
        assert_eq!(gates.entered, 0);
    }
}

#[test]
fn qos_is_restored_after_every_page_that_entered_it() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    port.ready = false;
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NotReady)
    );
    assert_eq!((gates.entered, gates.restored), (1, 1));
    assert!(!world.qos_lowered.get());
}

#[test]
fn a_ticket_that_is_not_yet_due_waits_without_a_page() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NotDue)
    );
    assert!(world.held(), "an early wake keeps the ticket");
    assert!(world.due().is_some());
    assert_eq!(port.calls.ready, 0);
    assert_eq!(gates.entered, 0);
}

#[test]
fn a_server_directive_or_failure_backoff_wins_over_a_due_ticket() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    world
        .cadence
        .borrow_mut()
        .set_server_min_interval(Some(Duration::from_secs(1800)));
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(
        run(&world, &mut port, &mut gates),
        Outcome::Skipped(Skip::NotDue)
    );
    assert!(!world.held(), "the 1800 s directive wins: no continuation");
    assert_eq!(port.calls.page, 0);
}

#[test]
fn slow_pages_fall_back_to_the_ordinary_cadence() {
    // A page cut at its 20 s deadline still counts its lock wait and
    // finalization, so it is contended and does not ask again.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    port.work = CONTENTION_WORK + Duration::from_secs(1);
    let mut gates = FakeGates::allowed(&world);
    let started = world.now.get();
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::PausedContended);
    assert_eq!(port.deadlines, vec![(started + CONTENTION_WORK, true)]);
    assert_eq!(world.now.get(), started + CONTENTION_WORK + RECORD);
    assert!(!world.held());
    assert_eq!(world.due(), None);

    // An ordinary page that took too long never asks either.
    let world = World::new();
    let mut cadence = world.cadence.borrow_mut();
    cadence.request_continuation(world.now.get(), Duration::from_secs(40));
    assert_eq!(
        cadence.continuation_due(PACING),
        None,
        "9 × 40 s reaches the ordinary scan: no clamp squeezes a page in"
    );
}

#[test]
fn a_page_stops_at_the_ordinary_deadline() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    port.work = Duration::from_secs(15);
    let mut gates = FakeGates::allowed(&world);
    let started = world.now.get();
    let ordinary = started + Duration::from_secs(6);
    let outcome = run_page(
        &mut FakeHost(&world),
        &mut port,
        &mut gates,
        &world.lock,
        &world.slot,
        ordinary,
    );
    assert_eq!(port.deadlines, vec![(ordinary, true)]);
    assert_eq!(
        world.now.get(),
        ordinary + RECORD,
        "the overrun is at most the record being read"
    );
    assert_eq!(outcome, Outcome::PausedContended);
    assert!(!world.held());
    assert_eq!(world.due(), None);
    // No request survives into this or a later wait: ordinary next.
    let pending = world.due().zip(world.cadence.borrow().continuation_work());
    assert!(matches!(
        plan_wake(world.now.get(), ordinary, pending),
        Wake::Ordinary(_)
    ));
}

#[test]
fn byte_budget_exhaustion_before_the_deadline_still_requests() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(4));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    let deadline = world.now.get() + Duration::from_secs(6);
    assert_eq!(
        run_page(
            &mut FakeHost(&world),
            &mut port,
            &mut gates,
            &world.lock,
            &world.slot,
            deadline
        ),
        Outcome::Paused
    );
    assert_eq!(port.deadlines, vec![(deadline, false)]);
    assert!(world.held());
    assert!(world.due().is_some());
}

#[test]
fn plan_wake_keeps_the_ordinary_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(300);
    assert_eq!(
        plan_wake(now, deadline, None),
        Wake::Ordinary(Duration::from_secs(300))
    );
    assert_eq!(
        plan_wake(
            now,
            deadline,
            Some((now + Duration::from_secs(40), Duration::from_secs(4)))
        ),
        Wake::Continuation(Duration::from_secs(40))
    );
    // A page that would still be running at the deadline waits for the
    // ordinary cycle instead.
    assert_eq!(
        plan_wake(
            now,
            deadline,
            Some((now + Duration::from_secs(297), Duration::from_secs(4)))
        ),
        Wake::Ordinary(Duration::from_secs(300))
    );
    // An overdue page runs now.
    assert_eq!(
        plan_wake(
            now + Duration::from_secs(50),
            deadline,
            Some((now + Duration::from_secs(40), Duration::from_secs(4)))
        ),
        Wake::Continuation(Duration::ZERO)
    );
}

/// The loop against a fixed per-page work and gap, for schedule-only checks.
struct ScheduleLoop {
    now: Instant,
    due: Option<Instant>,
    work: Duration,
    gap: Duration,
    waits: Vec<Duration>,
    pages: Vec<(Instant, Instant)>,
    switch_on_wait: Option<usize>,
}

impl ScheduleLoop {
    fn new(first_due: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            now,
            due: first_due.map(|offset| now + offset),
            work: Duration::from_secs(4),
            gap: Duration::from_secs(36),
            waits: Vec::new(),
            pages: Vec::new(),
            switch_on_wait: None,
        }
    }
}

impl LoopHost for ScheduleLoop {
    fn now(&mut self) -> Instant {
        self.now
    }
    fn wait(&mut self, wait: Duration) -> bool {
        self.waits.push(wait);
        if self.switch_on_wait == Some(self.waits.len()) {
            return true;
        }
        self.now += wait;
        false
    }
    fn pending(&mut self) -> Option<(Instant, Duration)> {
        self.due.map(|due| (due, self.work))
    }
    fn page(&mut self, _deadline: Instant) -> Outcome {
        let start = self.now;
        self.now += self.work;
        self.pages.push((start, self.now));
        self.due = Some(self.now + self.gap);
        Outcome::Paused
    }
}

#[test]
fn an_account_switch_still_starts_the_ordinary_cycle_at_once() {
    let mut host = ScheduleLoop::new(Some(Duration::from_secs(40)));
    host.switch_on_wait = Some(1);
    wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
    assert!(host.pages.is_empty());
    assert_eq!(host.waits.len(), 1);
}

/// The whole loop: ordinary cycles on today's interval, with real
/// `run_page` continuation pages against the fakes in between.
struct WorldLoop<'a> {
    world: &'a World,
    port: FakePort<'a>,
    gates: FakeGates<'a>,
    pages: Vec<(Instant, Instant, Outcome)>,
}

impl LoopHost for WorldLoop<'_> {
    fn now(&mut self) -> Instant {
        self.world.now.get()
    }
    fn wait(&mut self, wait: Duration) -> bool {
        self.world.advance(wait);
        false
    }
    fn pending(&mut self) -> Option<(Instant, Duration)> {
        if !self.world.held() {
            return None;
        }
        let cadence = self.world.cadence.borrow();
        cadence
            .continuation_due(PACING)
            .zip(cadence.continuation_work())
    }
    fn page(&mut self, deadline: Instant) -> Outcome {
        let start = self.world.now.get();
        let outcome = run_page(
            &mut FakeHost(self.world),
            &mut self.port,
            &mut self.gates,
            &self.world.lock,
            &self.world.slot,
            deadline,
        );
        self.pages.push((start, self.world.now.get(), outcome));
        outcome
    }
}

struct Simulation {
    ordinary_starts: Vec<Instant>,
    pages: Vec<(Instant, Instant, Outcome)>,
    end: Instant,
    network: u32,
}

/// Run `cycles` ordinary cycles of `cycle` wall each; the Codex page of each
/// ordinary cycle asks for a continuation after `codex_work`.
fn simulate(
    enabled: bool,
    cycles: usize,
    cycle: Duration,
    codex_work: Duration,
    page_work: Duration,
) -> Simulation {
    let world = World::new();
    let mut port = FakePort::new(&world, &[]);
    port.work = page_work;
    let mut host = WorldLoop {
        world: &world,
        port,
        gates: FakeGates::allowed(&world),
        pages: Vec::new(),
    };
    let mut ordinary_starts = Vec::new();
    for _ in 0..cycles {
        ordinary_starts.push(world.now.get());
        world.advance(cycle - codex_work);
        world.ordinary_page_asks(codex_work);
        if enabled {
            wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
        } else {
            settle_cycle(&mut FakeHost(&world), &world.slot, false);
            world.advance(SNAPSHOT_SYNC_INTERVAL);
        }
    }
    Simulation {
        ordinary_starts,
        pages: host.pages,
        end: world.now.get(),
        network: world.network.get(),
    }
}

#[test]
fn ordinary_cycles_keep_todays_cadence_and_order_with_continuation_pages() {
    let cycle = Duration::from_secs(30);
    let codex = Duration::from_secs(3);
    let page = Duration::from_secs(4);
    let today = simulate(false, 12, cycle, codex, page);
    let staged = simulate(true, 12, cycle, codex, page);
    assert!(today.pages.is_empty());
    let (pages, network) = (&staged.pages, staged.network);
    let today_end = today.end;
    let staged_end = staged.end;
    let today = today.ordinary_starts;
    let staged = staged.ordinary_starts;
    assert_eq!(
        staged.iter().map(|at| *at - staged[0]).collect::<Vec<_>>(),
        today.iter().map(|at| *at - today[0]).collect::<Vec<_>>(),
        "ordinary cycles start exactly when they do today"
    );
    assert_eq!(staged_end - staged[0], today_end - today[0]);
    assert!(pages.len() >= 12 * 5, "pages ran between ordinary cycles");
    assert_eq!(network, 0, "continuation pages made no network call");
    // No page runs into an ordinary cycle.
    for (start, end, _) in pages {
        assert!(staged
            .iter()
            .all(|ordinary| end <= ordinary || start >= &(*ordinary + cycle)));
    }
}

#[test]
fn the_duty_bound_holds_for_slow_pages() {
    for page_secs in [2u64, 5, 9, 15, 19] {
        let page = Duration::from_secs(page_secs);
        let Simulation {
            ordinary_starts: ordinary,
            pages,
            ..
        } = simulate(
            true,
            6,
            Duration::from_secs(30),
            Duration::from_secs(3),
            page,
        );
        let mut busy = Duration::ZERO;
        let mut span = Duration::ZERO;
        for pair in pages.windows(2) {
            let (_, end, _) = pair[0];
            let (next_start, next_end, _) = pair[1];
            if ordinary.iter().any(|at| *at > end && *at < next_start) {
                continue;
            }
            let gap = next_start - end;
            assert!(gap >= PACING.min_gap, "{page_secs}s");
            assert!(
                gap >= page * PACING.idle_per_work,
                "{page_secs}s pages: duty above 10 %"
            );
            busy += next_end - next_start;
            span += next_end - end;
        }
        if !span.is_zero() {
            assert!(busy.as_secs_f64() / span.as_secs_f64() <= 0.1 + 1e-9);
        }
    }
}

#[test]
fn other_sources_and_the_ordinary_eligibility_clock_are_untouched() {
    let world = World::new();
    let claude = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    let claude_before = format!("{claude:?}");
    world.ordinary_page_asks(Duration::from_secs(3));
    let reference = world.cadence.borrow().clone();
    let mut port = FakePort::new(&world, &[End::Paused, End::Paused, End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    for _ in 0..3 {
        world.advance_to_due();
        assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
        let now = world.now.get();
        assert_eq!(
            world.cadence.borrow().next_scan_after(now),
            reference.next_scan_after(now),
            "a continuation page is not an ordinary scan"
        );
        assert_eq!(world.cadence.borrow().state(), reference.state());
    }
    assert_eq!(format!("{claude:?}"), claude_before);
}

#[test]
fn the_ordinary_equivalent_is_the_ordinary_interval_with_no_historical_estimate() {
    let start = Instant::now();
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(start, 0);
    assert_eq!(cadence.ordinary_interval(), Duration::from_secs(600));
    // Two earlier cycles observed tick=330 s and cycle=30 s. The withdrawn
    // formula would credit 960 s, and a later cycle/lock wait can last longer.
    let historical_estimate = cadence.ordinary_interval() + Duration::from_secs(330 + 30);
    let delayed_scan = start + Duration::from_secs(1500);
    assert!(cadence.next_scan_after(delayed_scan).is_zero());
    assert!(delayed_scan - start > historical_estimate);
    // K4 (amended W12): exactly `ordinary_interval`, no clamp, floor or
    // historical estimate. It is a per-page lower bound of what ordinary
    // scheduling took (the delayed scan above took longer, as disclosed);
    // coverage stays the guard's.
    let clock = format!("{:?}", cadence);
    assert_eq!(
        ordinary_equivalent(&cadence, false),
        Some(Duration::from_secs(600))
    );
    assert!(ordinary_equivalent(&cadence, false) < Some(historical_estimate));
    assert_eq!(format!("{:?}", cadence), clock, "a read");
}

#[test]
fn the_ordinary_equivalent_is_unknown_while_failing_disabled_or_in_backoff() {
    type Policy = fn(&World);
    let directive = Duration::from_secs(1800);
    let rows: [(&str, Policy, Option<Option<Duration>>); 6] = [
        // `None` expected: the cadence's own interval.
        ("unchanged", |_| {}, None),
        (
            "directive",
            |w| {
                w.cadence
                    .borrow_mut()
                    .set_server_min_interval(Some(Duration::from_secs(1800)))
            },
            Some(Some(directive)),
        ),
        (
            "failing",
            |w| {
                for _ in 0..5 {
                    w.cadence.borrow_mut().record_scan_failure(w.now.get());
                }
            },
            Some(None),
        ),
        ("backoff", |w| w.backoff.set(true), Some(None)),
        (
            "disabled",
            |w| w.cadence.borrow_mut().set_disabled(true),
            Some(None),
        ),
        (
            "cleared",
            |w| {
                w.cadence.borrow_mut().set_server_min_interval(None);
                w.backoff.set(false);
            },
            None,
        ),
    ];
    for (name, change, expected) in rows {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(4));
        change(&world);
        let cadence = world.cadence.borrow();
        let expected = expected.unwrap_or(Some(cadence.ordinary_interval()));
        let clock = format!("{:?}", cadence);
        assert_eq!(
            ordinary_equivalent(&cadence, world.backoff.get()),
            expected,
            "{name}"
        );
        assert_eq!(format!("{:?}", cadence), clock, "{name}: a read");
        drop(cadence);
        assert!(world.held(), "{name}: reading it consumes no ticket");
    }
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(4));
    assert!(world.cadence.borrow().state() != LocalCollectorState::Failing);
    assert_ne!(
        world.cadence.borrow().ordinary_interval(),
        directive,
        "the directive row lengthens the tier"
    );
}

#[test]
fn run_page_hands_the_page_the_gated_ordinary_equivalent() {
    // A server directive leaves no continuation due at all (the directive
    // control above), so only the undirected cadence reaches a page here.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    let expected = world.cadence.borrow().ordinary_interval();
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
    assert_eq!(port.equivalents, vec![Some(expected)]);
}

/// K2/P-1: a ticket whose fixed lifetime ended before the page, or a clock
/// that reads earlier than its issue, never reaches the cursor side.
#[test]
fn an_expired_or_rolled_back_ticket_runs_no_page() {
    for (name, issued_offset, lifetime) in [
        ("expired", 0i64, Duration::from_secs(10)),
        ("at expiry", 0, Duration::ZERO),
        ("rolled back", 120, LIFETIME),
    ] {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let now = world.now.get();
        let issued = now
            .checked_sub(Duration::from_secs(60))
            .unwrap()
            .checked_add(Duration::from_secs(issued_offset as u64))
            .unwrap();
        let expires = if lifetime.is_zero() {
            now
        } else {
            issued + lifetime
        };
        *lock_slot(&world.slot) = Some(ticket_at(DESTINATION, issued, expires));
        let mut port = FakePort::new(&world, &[End::ParkedEof]);
        let mut gates = FakeGates::allowed(&world);
        assert_eq!(
            run(&world, &mut port, &mut gates),
            Outcome::Skipped(Skip::Expired),
            "{name}"
        );
        assert_eq!(port.calls, Calls::default(), "{name}: no ready, no page");
        assert_eq!(world.network.get(), 0, "{name}");
        assert!(!world.held(), "{name}: dropped, not kept for later");
        assert_eq!(world.due(), None, "{name}: the request is cleared");
        assert!(world.lock.try_lock().is_ok());
    }
}

/// A page crossing expiry still leaves EOF parked for the ordinary pass.
#[test]
fn an_eof_page_that_crosses_expiry_defers_its_upload() {
    let world = World::new();
    // Due 45 s after the mint (9 × 5 s), 15 s before the expiry.
    world.lifetime.set(Duration::from_secs(60));
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let (_, expires) = world.held_lifetime().unwrap();
    assert!(world.now.get() < expires, "valid when the page starts");
    let mut port = FakePort::new(&world, &[End::ParkedEof]);
    port.work = expires - world.now.get();
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::Deferred);
    assert_eq!(port.calls.page, 1);
    assert_eq!(world.network.get(), 0, "no upload under the expired policy");
    assert!(!world.held());
    assert_eq!(world.due(), None);
}

/// K2/P-1: nothing renews the lifetime: a re-paused page keeps the minting
/// page's `issued`/`expires`, so a run of pages ends at the fixed expiry
/// whatever its activity.
#[test]
fn continuation_pages_never_renew_the_lifetime() {
    let world = World::new();
    world.lifetime.set(Duration::from_secs(150));
    world.ordinary_page_asks(Duration::from_secs(5));
    let minted = world.held_lifetime().unwrap();
    let mut port = FakePort::new(&world, &[]);
    let mut gates = FakeGates::allowed(&world);
    let mut paused = 0;
    loop {
        world.advance_to_due();
        match run(&world, &mut port, &mut gates) {
            Outcome::Paused => {
                paused += 1;
                assert_eq!(world.held_lifetime(), Some(minted), "page {paused}");
            }
            Outcome::Skipped(Skip::Expired) => break,
            other => panic!("page {paused}: {other:?}"),
        }
        assert!(paused < 16, "the lifetime ends");
    }
    assert!(paused >= 2, "pages ran inside the lifetime: {paused}");
    assert!(world.now.get() >= minted.1);
    assert!(!world.held());
}

#[test]
fn the_lifetime_is_the_capture_time_minimum_or_none() {
    let start = Instant::now();
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(start, 0);
    let bound = cadence
        .ordinary_interval()
        .min(cadence.hot_min_interval())
        .min(SNAPSHOT_SYNC_INTERVAL);
    assert_eq!(bound, SNAPSHOT_SYNC_INTERVAL);
    assert_eq!(
        lifetime_from(Some(start), &cadence),
        Some((start, start + bound))
    );
    assert_eq!(lifetime_from(None, &cadence), None, "no prepare time");
    // A directive or a failure backoff lengthens the ordinary interval, never
    // the lifetime.
    cadence.set_server_min_interval(Some(Duration::from_secs(6 * 3600)));
    for _ in 0..5 {
        cadence.record_scan_failure(start);
    }
    assert_eq!(
        lifetime_from(Some(start), &cadence),
        Some((start, start + bound))
    );
    // A shorter Hot floor wins.
    let mut hot = SourceCadence::new(CadenceConfig::cost_first(Duration::from_secs(60)));
    hot.record_scan_success(start, 0);
    let (_, expires) = lifetime_from(Some(start), &hot).unwrap();
    assert!(expires - start <= Duration::from_secs(60));
    // A zero bound mints nothing.
    let zero = SourceCadence::new(CadenceConfig::cost_first(Duration::ZERO));
    assert!(zero.hot_min_interval().is_zero());
    assert_eq!(lifetime_from(Some(start), &zero), None);
}

#[test]
fn no_lifetime_or_authority_mints_no_ticket() {
    struct Mints;
    impl CursorContinuation for Mints {
        fn ticket_for(&self, _scan: &SourceScanResult) -> Option<CursorTicket> {
            Some(CursorTicket::synthetic())
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
    let scan = empty_scan();
    let now = Instant::now();
    let bounds = (now, now + LIFETIME);
    let lifetime = Some(bounds);
    assert!(ordinary_ticket(&Mints, &scan, "ns", Some(AUTHORITY), None).is_none());
    assert!(ordinary_ticket(&Mints, &scan, "ns", None, lifetime).is_none());
    let minted = ordinary_ticket(&Mints, &scan, "ns", Some(AUTHORITY), lifetime).unwrap();
    assert_eq!((minted.issued, minted.expires), bounds);
    assert_eq!(minted.destination, destination_digest("ns"));
    assert!(!minted.valid_at(now + LIFETIME));
    assert!(!minted.valid_at(now - Duration::from_secs(1)));
    assert!(minted.valid_at(now));
}

/// The loop never holds the page's lock while it waits between pages.
#[test]
fn the_sync_lock_is_free_while_the_loop_waits() {
    struct Checked<'a> {
        inner: WorldLoop<'a>,
        waits: Vec<bool>,
    }
    impl LoopHost for Checked<'_> {
        fn now(&mut self) -> Instant {
            self.inner.now()
        }
        fn wait(&mut self, wait: Duration) -> bool {
            self.waits.push(self.inner.world.lock.try_lock().is_ok());
            self.inner.wait(wait)
        }
        fn pending(&mut self) -> Option<(Instant, Duration)> {
            self.inner.pending()
        }
        fn page(&mut self, deadline: Instant) -> Outcome {
            self.inner.page(deadline)
        }
    }
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    let mut host = Checked {
        inner: WorldLoop {
            world: &world,
            port: FakePort::new(&world, &[End::Paused, End::Paused, End::ParkedEof]),
            gates: FakeGates::allowed(&world),
            pages: Vec::new(),
        },
        waits: Vec::new(),
    };
    wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
    assert!(host.inner.pages.len() >= 2, "{:?}", host.inner.pages);
    assert_eq!(
        world.lock_held_in_page.get(),
        Some(true),
        "held during a page"
    );
    assert!(host.waits.len() >= 3);
    assert!(host.waits.iter().all(|free| *free), "{:?}", host.waits);
}

// Option W (W1–W12): the worker, its join and the parent's mapping.

#[test]
fn the_worker_is_named_joined_and_returns_a_panic_as_failure() {
    assert_eq!(
        on_worker(|| std::thread::current().name().map(str::to_owned)),
        Ok(Some("ottto-codex-continuation".to_owned()))
    );
    let parent = std::thread::current().id();
    assert_eq!(
        on_worker(|| std::thread::current().id() != parent),
        Ok(true)
    );
    assert_eq!(
        on_worker(|| -> u8 { panic!("synthetic continuation worker panic") }),
        Err(WorkerFailure::Panicked),
        "W8: explicit join, no re-panic in the parent"
    );
}

/// W2: the parent holds the sync lock through the join; the worker sees it
/// held and never waits for it.
#[test]
fn the_parent_holds_the_sync_lock_through_the_join() {
    let lock = Mutex::new(());
    let guard = lock.lock().unwrap();
    assert_eq!(on_worker(|| lock.try_lock().is_err()), Ok(true));
    drop(guard);
    assert!(lock.try_lock().is_ok());
}

/// W10: test hooks are thread-locals the worker does not inherit; a test
/// must install them inside the worker.
#[test]
fn parent_test_hooks_are_not_seen_on_the_worker() {
    use crate::snapshots::{cursor_limit_for_test, with_test_limits_for_test};
    let production = cursor_limit_for_test();
    assert_ne!(production, 2048);
    with_test_limits_for_test(2048, 1024, 64, || {
        assert_eq!(cursor_limit_for_test(), 2048, "installed on the parent");
        assert_eq!(
            on_worker(cursor_limit_for_test),
            Ok(production),
            "not inherited by the worker"
        );
        assert_eq!(
            on_worker(|| with_test_limits_for_test(4096, 1024, 64, cursor_limit_for_test)),
            Ok(4096),
            "installed inside the worker"
        );
        assert_eq!(cursor_limit_for_test(), 2048, "the parent's own is kept");
    });
}

fn test_latch() -> &'static AtomicBool {
    Box::leak(Box::new(AtomicBool::new(false)))
}

/// W7/W8/K6/K7: every worker end maps to one page end; only a panic or a
/// broken invariant sets the latch.
#[test]
fn every_worker_end_maps_to_one_page_end() {
    let deadline = Instant::now();
    let before = deadline - Duration::from_secs(1);
    type Check = fn(&PageEnd) -> bool;
    type Ended = std::result::Result<WorkerEnd, WorkerFailure>;
    type Row = (&'static str, Ended, Instant, Check, bool);
    let rows: [Row; 10] = [
        (
            "spawn",
            Err(WorkerFailure::Spawn),
            before,
            |e| matches!(e, PageEnd::Deferred),
            false,
        ),
        (
            "panic",
            Err(WorkerFailure::Panicked),
            before,
            |e| matches!(e, PageEnd::Failed(_)),
            true,
        ),
        (
            "stopped",
            Ok(WorkerEnd::Stopped),
            before,
            |e| matches!(e, PageEnd::Deferred),
            false,
        ),
        (
            "stopped at the deadline",
            Ok(WorkerEnd::Stopped),
            deadline,
            |e| matches!(e, PageEnd::PausedContended),
            false,
        ),
        (
            "deferred",
            Ok(WorkerEnd::Deferred),
            deadline,
            |e| matches!(e, PageEnd::Deferred),
            false,
        ),
        (
            "refused",
            Ok(WorkerEnd::Refused("historical_replay_pending")),
            before,
            |e| matches!(e, PageEnd::Deferred),
            false,
        ),
        (
            "snapshots before EOF",
            Ok(WorkerEnd::Unexpected),
            before,
            |e| matches!(e, PageEnd::Failed(_)),
            true,
        ),
        (
            "failed",
            Ok(WorkerEnd::Failed(anyhow!("synthetic load failure"))),
            before,
            |e| matches!(e, PageEnd::Failed(_)),
            false,
        ),
        (
            "paused",
            Ok(WorkerEnd::Paused(Box::new(CodexPage {
                cursor: CodexCursorTicket::unready_for_test(),
                inputs: None,
            }))),
            before,
            |e| matches!(e, PageEnd::Paused(_)),
            false,
        ),
        (
            "paused past the deadline",
            Ok(WorkerEnd::Paused(Box::new(CodexPage {
                cursor: CodexCursorTicket::unready_for_test(),
                inputs: None,
            }))),
            deadline,
            // A byte-budget pause; `run_page` judges the contention.
            |e| matches!(e, PageEnd::Paused(_)),
            false,
        ),
    ];
    for (name, ended, now, check, latches) in rows {
        let latch = test_latch();
        let end = page_end(ended, deadline, now, latch);
        assert!(check(&end), "{name}");
        assert_eq!(latch.load(Ordering::SeqCst), latches, "{name}");
    }
}

/// W8(a), W9: a worker that panics while holding any of the cache's locks
/// comes back as `Failed`; the latch then refuses every further ticket and
/// readiness, and the poisoned or recovered lock fails closed.
#[test]
fn a_worker_panic_under_any_cache_lock_latches_and_fails_closed() {
    use crate::snapshots::sampled_scan::TestLock;
    for lock in [TestLock::Cursor, TestLock::Retained, TestLock::Side] {
        let cache = Arc::new(SharedCache::default());
        let dir = std::env::temp_dir();
        let mut port = CodexContinuation::new(&cache, &dir, &dir);
        port.latch = test_latch();
        let panicked = on_worker(|| cache.panic_under_lock_for_test(lock));
        assert_eq!(panicked, Err(WorkerFailure::Panicked), "{lock:?}");
        assert!(matches!(
            page_end(
                panicked.map(|()| WorkerEnd::Stopped),
                Instant::now(),
                Instant::now(),
                port.latch
            ),
            PageEnd::Failed(_)
        ));
        assert!(port.latched(), "{lock:?}");
        assert!(port.ticket_for(&empty_scan()).is_none());
        let page = CursorTicket::codex(CodexCursorTicket::unready_for_test());
        assert!(!port.ready(&page), "{lock:?}");
        match lock {
            // The cursor stays poisoned: nothing is admitted or readied.
            TestLock::Cursor => {
                assert!(cache.lock_poisoned_for_test(lock));
                assert!(!CodexCursorPort::new(Arc::clone(&cache))
                    .ready(&CodexCursorTicket::unready_for_test()));
            }
            TestLock::Retained => assert!(cache.lock_poisoned_for_test(lock)),
            // The side ledger recovers by clearing (a process start for
            // pacing) on its next use: the cursor-side W9 control.
            TestLock::Side => assert!(cache.lock_poisoned_for_test(lock)),
        }
    }
}

/// A production adapter page on a synthetic ticket, or on a Codex ticket
/// without inputs, never reaches the worker's scan.
#[test]
fn the_adapter_refuses_a_page_without_inputs() {
    let cache = Arc::new(SharedCache::default());
    let dir = std::env::temp_dir();
    let mut port = CodexContinuation::new(&cache, &dir, &dir);
    port.latch = test_latch();
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(!port.ready(&CursorTicket::synthetic()));
    assert!(matches!(
        port.page(CursorTicket::synthetic(), deadline, None),
        PageEnd::Deferred
    ));
    let codex = CursorTicket::codex(CodexCursorTicket::unready_for_test());
    assert!(!port.ready(&codex), "no inputs, and not paused here");
    // A ticket with no live job reads nothing regardless of platform QoS.
    assert!(matches!(
        port.page(codex, deadline, Some(Duration::from_secs(300))),
        PageEnd::Deferred
    ));
    port.worker_qos = || Some(MacPlatformSignals::default());
    // Allowed QoS, but the ticket names no paused job: no members.
    assert!(matches!(
        port.page(
            CursorTicket::codex(CodexCursorTicket::unready_for_test()),
            deadline,
            None
        ),
        PageEnd::Deferred
    ));
    assert!(!port.latched());
}

#[test]
fn the_retained_charge_is_zero_for_a_synthetic_ticket() {
    assert_eq!(CursorTicket::synthetic().retained_bound(0), Some(0));
    assert_eq!(retained_bound(usize::MAX), Some(0), "nothing held");
}

fn attach_inputs(mut ticket: ContinuationTicket, inputs: ContinuationInputs) -> ContinuationTicket {
    if let CursorParts::Codex(page) = &mut ticket.cursor.0 {
        page.inputs = Some(inputs);
    }
    ticket
}

/// A Codex ticket that carries real cached inputs (with the synthetic
/// attribution context), and the inputs' drop sentinel.
fn ticket_with_inputs(
    world: &World,
) -> (
    ContinuationTicket,
    Arc<crate::agent_status::AgentStatusCollection>,
) {
    let (inputs, sentinel) = super::super::tests::continuation_inputs_for_test(true);
    assert!(inputs.holds_attribution());
    let issued = world.now.get();
    let ticket = attach_inputs(
        ContinuationTicket {
            destination: DESTINATION,
            authority: AUTHORITY,
            cursor: CursorTicket::codex(CodexCursorTicket::unready_for_test()),
            issued,
            expires: issued + world.lifetime.get(),
        },
        inputs,
    );
    assert_eq!(Arc::strong_count(&sentinel), 2, "held by the ticket");
    (ticket, sentinel)
}

/// K2 (4): the moved context is dropped (its key zeroized by its own
/// `Zeroizing` storage) on every end that clears the ticket: expiry, an
/// authority or destination change, a ticket that is not ready, an ordinary
/// failure or prepare, a replacement, a rotation discard, and a worker
/// panic. The drop sentinel is the inputs' status collection.
#[test]
fn a_held_context_is_dropped_on_every_clear() {
    type Clear = fn(&World);
    let rows: [(&str, Clear); 6] = [
        ("expired", |w| {
            w.now.set(w.now.get() + LIFETIME);
            let mut port = FakePort::new(w, &[]);
            let outcome = run(w, &mut port, &mut FakeGates::allowed(w));
            assert_eq!(outcome, Outcome::Skipped(Skip::Expired));
        }),
        ("authority", |w| {
            w.authority.set(Some(OTHER_AUTHORITY));
            let mut port = FakePort::new(w, &[]);
            let outcome = run(w, &mut port, &mut FakeGates::allowed(w));
            assert_eq!(outcome, Outcome::Skipped(Skip::Authority));
        }),
        ("destination", |w| {
            w.destination.set(Some(OTHER_DESTINATION));
            let mut port = FakePort::new(w, &[]);
            let outcome = run(w, &mut port, &mut FakeGates::allowed(w));
            assert_eq!(outcome, Outcome::Skipped(Skip::Destination));
        }),
        ("not ready", |w| {
            let mut port = FakePort::new(w, &[]);
            port.ready = false;
            let outcome = run(w, &mut port, &mut FakeGates::allowed(w));
            assert_eq!(outcome, Outcome::Skipped(Skip::NotReady));
        }),
        ("failed cycle", |w| {
            settle_cycle(&mut FakeHost(w), &w.slot, false)
        }),
        ("replaced", |w| {
            *lock_slot(&w.slot) = Some(w.ticket(DESTINATION));
        }),
    ];
    for (name, clear) in rows {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let (ticket, sentinel) = ticket_with_inputs(&world);
        *lock_slot(&world.slot) = Some(ticket);
        clear(&world);
        assert_eq!(Arc::strong_count(&sentinel), 1, "{name}: dropped");
    }
    // A page that ends (here `Deferred`) drops the page it was given.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let (ticket, sentinel) = ticket_with_inputs(&world);
    *lock_slot(&world.slot) = Some(ticket);
    let mut port = FakePort::new(&world, &[End::Deferred]);
    assert_eq!(
        run(&world, &mut port, &mut FakeGates::allowed(&world)),
        Outcome::Deferred
    );
    assert_eq!(Arc::strong_count(&sentinel), 1, "page end: dropped");
    // A worker that panics with the page drops it while unwinding there.
    let world = World::new();
    let (ticket, sentinel) = ticket_with_inputs(&world);
    let ContinuationTicket { cursor, .. } = ticket;
    let panicked = on_worker(move || {
        let _page = cursor;
        panic!("synthetic continuation worker panic with a held context");
    });
    assert_eq!(panicked.err(), Some(WorkerFailure::Panicked));
    assert_eq!(
        Arc::strong_count(&sentinel),
        1,
        "panic: dropped on the worker"
    );
}

/// K2 (5): the held inputs are charged as process-retained memory through
/// the requested-layout admission, and an unsupported layout or a bound over
/// the limit refuses the charge (the rotation then discards the ticket).
#[test]
fn held_inputs_are_charged_and_an_unknown_charge_refuses() {
    let world = World::new();
    let (ticket, _sentinel) = ticket_with_inputs(&world);
    let charged = ticket.cursor.retained_bound(usize::MAX);
    if crate::heap_layout_bound::layout_supported() {
        let charged = charged.expect("a supported layout is bounded");
        let bare = CursorTicket::codex(CodexCursorTicket::unready_for_test())
            .retained_bound(usize::MAX)
            .expect("bounded");
        assert!(charged > bare, "the inputs are charged: {charged} > {bare}");
        assert_eq!(
            ticket.cursor.retained_bound(charged - 1),
            None,
            "over the limit"
        );
    } else {
        assert_eq!(charged, None, "unknown layout: refused, never zero");
    }
}

#[test]
fn the_authority_digest_follows_the_ordinary_validation() {
    let endpoint = "https://api.example.test";
    let account = [5u8; 32];
    let expected = LocalDeviceBinding {
        device_id: "device-1".to_string(),
        machine_id: Some("machine-1".to_string()),
        sources: vec!["codex".to_string(), "claude_code".to_string()],
    };
    let bound = current_authority(&expected, endpoint, &account).expect("Codex is granted");
    type Change = fn(&mut LocalDeviceBinding, &mut String, &mut [u8; 32]);
    let changes: [(&str, Change); 7] = [
        ("unchanged", |_, _, _| {}),
        ("device", |d, _, _| d.device_id = "device-2".to_string()),
        ("machine", |d, _, _| {
            d.machine_id = Some("machine-2".to_string())
        }),
        ("machine missing", |d, _, _| d.machine_id = None),
        ("grant", |d, _, _| d.sources.retain(|s| s != "codex")),
        ("endpoint", |_, e, _| e.push_str("/other")),
        ("account", |_, _, a| a[0] ^= 1),
    ];
    for (name, change) in changes {
        let mut current = expected.clone();
        let mut current_endpoint = endpoint.to_string();
        let mut current_account = account;
        change(&mut current, &mut current_endpoint, &mut current_account);
        let ordinary = validate_snapshot_scan_authority(
            &expected,
            &current,
            SnapshotSource::Codex,
            current_endpoint == endpoint,
            &account,
            &current_account,
        )
        .is_ok();
        let continuation =
            current_authority(&current, &current_endpoint, &current_account) == Some(bound);
        assert_eq!(continuation, ordinary, "{name}");
        assert_eq!(ordinary, name == "unchanged", "{name}");
    }
}

#[test]
fn the_non_eof_page_path_names_no_network_code() {
    // Structural control: the real page is c22's, so no real-boundary network
    // probe exists yet. This module reaches the network only through the one
    // EOF completion call, and imports nothing else that could.
    let source = include_str!("continuation.rs");
    for forbidden in [
        "SnapshotApiClient",
        "relay_token",
        "get_activity_hint",
        "report_",
        "upload_local_health",
        "finish_sync_source(",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
    assert!(!source.contains("complete_continuation_eof"));
    let imports = source
        .split("use super::{")
        .nth(1)
        .and_then(|rest| rest.split("};").next())
        .expect("one parent import list");
    let mut imports = imports
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    imports.sort_unstable();
    assert_eq!(
        imports,
        [
            "ContinuationInputs",
            "ContinuationScan",
            "SNAPSHOT_SYNC_INTERVAL",
            "SNAPSHOT_SYNC_LOCK",
            "SNAPSHOT_SYNC_WORKER_STACK_BYTES",
            "ScanIndex",
            "SnapshotSource",
            "SnapshotUploadPolicy",
            "SourcePreparation",
            "SourceScanResult",
            "enabled_snapshot_sources",
            "load_snapshot_device_credentials",
            "run_continuation_scan",
            "safe_error",
            "snapshot_api_base_url",
            "snapshot_upload_destination_namespace",
            "source_upload_backoff_remaining",
            "with_source_cadence",
        ]
    );
    assert_eq!(source.matches("super::").count(), 1, "no other parent path");
    assert_eq!(source.matches("run_continuation_scan(").count(), 1);
    // The worker's half in the parent module: the continuation-local
    // prepare and scan name no network or relay code either.
    let parent = include_str!("../snapshot_sync.rs");
    let worker = parent
        .split("fn run_continuation_scan(")
        .nth(1)
        .and_then(|rest| rest.split("fn capture_codex_recovery_evidence(").next())
        .expect("the continuation scan and prepare");
    assert!(worker.contains("fn prepare_continuation_source("));
    for forbidden in [
        "relay_token",
        "get_activity_hint",
        "report_",
        "upload_local_health",
        "finish_sync_source(",
        "take_pending_snapshot_paths",
        "LiveAuthority",
        ".save(",
        "prepare_historical_replay",
        "prepare_snapshot_admission_reoffer",
        "prepare_legacy_settlement_reconciliation",
        "issue_",
        "post_",
        ".send(",
    ] {
        assert!(!worker.contains(forbidden), "worker half: {forbidden}");
    }
}

#[test]
fn platform_power_mapping_and_fake_battery_lpm_unknown_skip() {
    for (answer, expected) in [
        (1, PlatformState::Allowed),
        (0, PlatformState::Refused),
        (-1, PlatformState::Unknown),
    ] {
        assert_eq!(power_state(answer), expected);
    }
    for (condition, state) in [
        ("battery", PlatformState::Refused),
        ("lpm", PlatformState::Refused),
        ("unknown", PlatformState::Unknown),
    ] {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(1));
        world.advance_to_due();
        let mut gates = FakeGates {
            power: state,
            ..FakeGates::allowed(&world)
        };
        let mut port = FakePort::new(&world, &[End::Paused]);
        assert_eq!(
            run(&world, &mut port, &mut gates),
            Outcome::Skipped(Skip::Platform),
            "{condition}"
        );
        assert_eq!(port.calls.page, 0);
        assert_eq!(gates.entered, 0);
    }
}

#[test]
fn parent_qos_is_restored_when_the_page_panics() {
    struct PanicPort;
    impl CursorContinuation for PanicPort {
        fn ticket_for(&self, _: &SourceScanResult) -> Option<CursorTicket> {
            None
        }
        fn ready(&mut self, _: &CursorTicket) -> bool {
            panic!("page panic");
        }
        fn page(&mut self, _: CursorTicket, _: Instant, _: Option<Duration>) -> PageEnd {
            unreachable!()
        }
    }
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(1));
    world.advance_to_due();
    let mut gates = FakeGates::allowed(&world);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_page(
            &mut FakeHost(&world),
            &mut PanicPort,
            &mut gates,
            &world.lock,
            &world.slot,
            far(&world),
        )
    }));
    assert!(result.is_err());
    assert_eq!(gates.restored, 1);
    assert!(!world.qos_lowered.get());
}

thread_local! { static QOS_WRITES: RefCell<Vec<(u32, i32)>> = const { RefCell::new(Vec::new()) }; }
fn record_qos(class: u32, rel: i32) -> bool {
    QOS_WRITES.with(|v| v.borrow_mut().push((class, rel)));
    true
}
fn saved_qos() -> Option<(u32, i32)> {
    Some((0x19, -7))
}

#[test]
fn exact_qos_pair_restores_on_parent_and_worker_panics_and_failed_query_is_untouched() {
    fn panic_with_guard() {
        QOS_WRITES.with(|v| v.borrow_mut().clear());
        let result = std::panic::catch_unwind(|| {
            let mut signals = MacPlatformSignals {
                setter: Some(record_qos),
                ..Default::default()
            };
            assert_eq!(
                signals.enter(saved_qos(), record_qos),
                PlatformState::Allowed
            );
            let _guard = signals;
            panic!("after QoS entry");
        });
        assert!(result.is_err());
        QOS_WRITES.with(|v| assert_eq!(*v.borrow(), [(0x09, 0), (0x19, -7)]));
    }
    panic_with_guard();
    assert_eq!(on_worker(panic_with_guard), Ok(()));
    QOS_WRITES.with(|v| v.borrow_mut().clear());
    let mut signals = MacPlatformSignals {
        setter: Some(record_qos),
        ..Default::default()
    };
    assert_eq!(signals.enter(None, record_qos), PlatformState::Unknown);
    signals.restore_qos();
    QOS_WRITES.with(|v| assert!(v.borrow().is_empty()));
    assert_eq!(
        signals.enter(Some((0, 0)), record_qos),
        PlatformState::Allowed
    );
    signals.restore_qos();
    QOS_WRITES.with(|v| assert_eq!(v.borrow().last(), Some(&(0x15, 0))));
}

#[test]
fn eof_park_and_middle_pages_never_upload_or_move_the_ordinary_clock() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(1));
    let reference = world.cadence.borrow().clone();
    let mut port = FakePort::new(&world, &[End::Paused, End::ParkedEof]);
    let mut gates = FakeGates::allowed(&world);
    for expected in [Outcome::Paused, Outcome::Deferred] {
        world.advance_to_due();
        assert_eq!(run(&world, &mut port, &mut gates), expected);
        assert_eq!(world.network.get(), 0);
        assert!(!world.qos_lowered.get());
        for offset in [0, 300, 900, 7200] {
            let now = world.now.get() + Duration::from_secs(offset);
            assert_eq!(
                world.cadence.borrow().next_scan_after(now),
                reference.next_scan_after(now)
            );
        }
    }
    assert!(!world.held());
    assert_eq!(world.due(), None);
}

fn inventory_inputs() -> (PathBuf, ContinuationInputs) {
    let root = crate::test_scratch::unique_path("continuation-carried-inventory");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("rollout-2026-10-24T00-00-00-019fa111-2222-7333-8444-555555555555.jsonl");
    std::fs::write(&path, br#"{"type":"session_meta","timestamp":"2026-10-24T00:00:00Z","payload":{"id":"019fa111-2222-7333-8444-555555555555","timestamp":"2026-10-24T00:00:00Z"}}
"#).unwrap();
    let evidence = crate::snapshots::CodexContinuationEvidence::certified_for_test(
        std::slice::from_ref(&root),
        &std::collections::BTreeSet::from([path.to_string_lossy().into_owned()]),
    );
    let (mut inputs, _) = super::super::tests::continuation_inputs_for_test(false);
    inputs.evidence = Some(evidence);
    assert!(inputs.evidence.as_ref().unwrap().content_unchanged());
    inputs.runtime_context = runtime_context();
    (root, inputs)
}

#[test]
fn changed_context_policy_or_inventory_holds_before_any_read() {
    for change in ["context", "policy", "content"] {
        let (root, mut inputs) = inventory_inputs();
        observe(SnapshotSource::Codex, "mint-context", inputs.upload_policy);
        inputs.runtime_context = runtime_context();
        match change {
            "context" => observe(
                SnapshotSource::Codex,
                "changed-context",
                inputs.upload_policy,
            ),
            "policy" => {
                let policy = super::super::SnapshotUploadPolicy {
                    session_titles_enabled: !inputs.upload_policy.session_titles_enabled,
                    ..inputs.upload_policy
                };
                observe(SnapshotSource::ClaudeCode, "changed-policy", policy);
            }
            _ => {
                let file = std::fs::read_dir(&root)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(file)
                    .unwrap()
                    .write_all(b"{}\n")
                    .unwrap();
                assert!(!inputs.evidence.as_ref().unwrap().content_unchanged());
            }
        }
        crate::snapshots::begin_continuation_read_ranges_for_test();
        let cache = Arc::new(SharedCache::default());
        let result = run_continuation_scan(
            &root,
            &root,
            &cache,
            &mut inputs,
            &std::collections::BTreeSet::new(),
            Some(Duration::from_secs(300)),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        assert!(
            matches!(
                result,
                ContinuationScan::Refused(super::super::ContinuationRefusal::EvidenceChanged)
            ),
            "{change}"
        );
        assert!(
            crate::snapshots::take_continuation_read_ranges_for_test().is_empty(),
            "{change}: zero bytes"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn carried_inventory_over_the_retained_limit_refuses_ticket_admission() {
    let (root, inputs) = inventory_inputs();
    let world = World::new();
    let issued = world.now.get();
    let mut ticket = attach_inputs(
        ContinuationTicket {
            destination: DESTINATION,
            authority: AUTHORITY,
            cursor: CursorTicket::codex(CodexCursorTicket::unready_for_test()),
            issued,
            expires: issued + LIFETIME,
        },
        inputs,
    );
    let limit = ticket
        .cursor
        .retained_bound(usize::MAX)
        .map_or(usize::MAX, |bytes| bytes - 1);
    let inputs = match &mut ticket.cursor.0 {
        CursorParts::Codex(page) => page.inputs.take().unwrap(),
        _ => unreachable!(),
    };
    assert!(
        ticket.with_inputs(inputs, limit).is_none(),
        "over-bound or unknown inventory never mints"
    );
    std::fs::remove_dir_all(root).unwrap();
}
