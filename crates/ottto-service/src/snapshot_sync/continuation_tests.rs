// CI controls for the inert continuation scaffolding. The cursor side and the
// platform are fakes standing in for c22's hunks and the platform hunk; the
// clock is simulated, so nothing here sleeps, reads a transcript or opens a
// socket.

use super::super::{
    negotiated_wait, record_finished_snapshot_cadence, validate_snapshot_scan_authority,
    MAX_CYCLE_INTERVAL, SNAPSHOT_SYNC_INTERVAL,
};
use super::*;
use crate::adaptive_collector::CadenceConfig;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

const DESTINATION: [u8; 32] = [7; 32];
const OTHER_DESTINATION: [u8; 32] = [9; 32];
const AUTHORITY: [u8; 32] = [3; 32];
const OTHER_AUTHORITY: [u8; 32] = [4; 32];
/// How far a page reads past its deadline: to the end of the current record.
const RECORD: Duration = Duration::from_secs(1);

struct World {
    now: Cell<Instant>,
    backoff: Cell<bool>,
    destination: Cell<Option<[u8; 32]>>,
    authority: Cell<Option<[u8; 32]>>,
    cadence: RefCell<SourceCadence>,
    slot: Mutex<Option<ContinuationTicket>>,
    /// Every call that would reach the network. Only `complete_eof` counts.
    network: Cell<u32>,
    complete_ok: Cell<bool>,
    /// What the unchanged completion upload records on the cadence: `Some`
    /// accepted count for a success, `None` for a retryable deferral.
    eof_records: Cell<Option<u64>>,
    defers: Cell<u32>,
    lock: Mutex<()>,
    lock_held_in_page: Cell<Option<bool>>,
    qos_lowered: Cell<bool>,
    qos_lowered_at_eof: Cell<Option<bool>>,
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
            complete_ok: Cell::new(true),
            eof_records: Cell::new(Some(0)),
            defers: Cell::new(0),
            lock: Mutex::new(()),
            lock_held_in_page: Cell::new(None),
            qos_lowered: Cell::new(false),
            qos_lowered_at_eof: Cell::new(None),
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
        *lock_slot(&self.slot) = Some(ticket(DESTINATION));
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

fn ticket(destination: [u8; 32]) -> ContinuationTicket {
    ContinuationTicket {
        destination,
        authority: AUTHORITY,
        cursor: CursorTicket { _sealed: () },
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
    fn complete_eof(&mut self, completion: EofCompletion) -> Result<()> {
        assert!(completion.into_parts().is_none(), "a synthetic completion");
        let world = self.0;
        world.network.set(world.network.get() + 1);
        world.qos_lowered_at_eof.set(Some(world.qos_lowered.get()));
        world.advance(Duration::from_secs(2));
        // The unchanged finish_sync_source records its cadence as an ordinary
        // scan, through this same function.
        let records = world.eof_records.get();
        record_finished_snapshot_cadence(
            &mut world.cadence.borrow_mut(),
            world.now.get(),
            records.unwrap_or(0),
            records.is_none(),
        );
        if world.complete_ok.get() {
            Ok(())
        } else {
            Err(anyhow!("synthetic upload refusal"))
        }
    }
    fn defer_eof(&mut self, _completion: EofCompletion) {
        self.0.defers.set(self.0.defers.get() + 1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Paused,
    Deferred,
    Eof,
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
    fn page(&mut self, _ticket: CursorTicket, deadline: Instant) -> PageEnd {
        self.calls.page += 1;
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
        match if cut { End::Paused } else { planned } {
            End::Paused => PageEnd::Paused(CursorTicket { _sealed: () }),
            End::Deferred => PageEnd::Deferred,
            End::Eof => PageEnd::Eof(EofCompletion::synthetic()),
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
fn the_inert_default_is_const_gated_and_its_stubs_refuse() {
    // Inert parity is by this constant and by review: the sync loop takes
    // today's path before it reaches anything here. This control covers the
    // gate and the stubs, not the loop itself.
    assert!(
        !std::hint::black_box(ENABLED),
        "Stage 1 stays inert until its integration is approved"
    );
    assert_eq!(production_pending(), None);
    assert!(!NoCursorContinuation.ready(&CursorTicket { _sealed: () }));
    assert!(matches!(
        NoCursorContinuation.page(CursorTicket { _sealed: () }, Instant::now()),
        PageEnd::Deferred
    ));
    assert_eq!(NoPlatformSignals.power(), PlatformState::Unknown);
    assert_eq!(
        NoPlatformSignals.enter_background_qos(),
        PlatformState::Unknown
    );

    // With nothing pending, the planner's wait is one uninterrupted ordinary
    // interval and no page.
    let mut host = ScheduleLoop::new(None);
    wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
    assert_eq!(host.waits, vec![SNAPSHOT_SYNC_INTERVAL]);
    assert!(host.pages.is_empty());
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
fn a_continuation_only_wake_makes_no_network_call_until_eof() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    let mut port = FakePort::new(
        &world,
        &[End::Paused, End::Paused, End::Paused, End::Paused, End::Eof],
    );
    let mut gates = FakeGates::allowed(&world);
    for _ in 0..4 {
        world.advance_to_due();
        assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
        assert_eq!(world.network.get(), 0, "a non-EOF page is zero-network");
    }
    world.advance_to_due();
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::EofCompleted);
    assert_eq!(
        world.network.get(),
        1,
        "only the existing completion upload, once"
    );
    assert_eq!(
        world.qos_lowered_at_eof.get(),
        Some(false),
        "the thread's own QoS is back before the upload"
    );
    assert!(!world.held());
    assert_eq!(world.due(), None, "a completed job asks for nothing more");
}

#[test]
fn eof_rechecks_authority_upload_backoff_and_destination_before_the_network() {
    for change in ["backoff", "destination", "grant", "account"] {
        let world = World::new();
        world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let mut port = FakePort::new(&world, &[End::Eof]);
        match change {
            "backoff" => port.backoff_during_page = true,
            "destination" => port.destination_during_page = Some(OTHER_DESTINATION),
            "grant" => port.authority_during_page = Some(None),
            _ => port.authority_during_page = Some(Some(OTHER_AUTHORITY)),
        }
        let mut gates = FakeGates::allowed(&world);
        assert_eq!(
            run(&world, &mut port, &mut gates),
            Outcome::EofDeferred,
            "{change}"
        );
        assert_eq!(world.network.get(), 0, "{change}");
        assert_eq!(world.defers.get(), 1, "{change}: the obligation stays owed");
        assert!(!world.held());
        assert_eq!(world.due(), None);
    }
}

#[test]
fn an_eof_upload_refusal_is_not_retried() {
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Eof]);
    world.complete_ok.set(false);
    world.eof_records.set(None);
    let mut gates = FakeGates::allowed(&world);
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::EofFailed);
    assert_eq!(world.network.get(), 1, "no hidden retry");
    assert!(!world.held());
    assert_eq!(world.due(), None, "the next attempt is the ordinary pass");
    assert!(world.lock.try_lock().is_ok());
}

#[test]
fn an_eof_completion_leaves_the_ordinary_codex_cadence_unchanged() {
    // With and without a server directive: the completion upload would
    // otherwise re-stamp the last scan and the sweep, drop the tier, or turn
    // the source Failing.
    for directive in [None, Some(Duration::from_secs(120))] {
        for records in [Some(0), Some(3), None] {
            let world = World::new();
            world
                .cadence
                .borrow_mut()
                .set_server_min_interval(directive);
            world.ordinary_page_asks(Duration::from_secs(5));
            let reference = world.cadence.borrow().clone();
            let scanned = world.now.get();
            world.advance_to_due();
            world.eof_records.set(records);
            let mut port = FakePort::new(&world, &[End::Eof]);
            let mut gates = FakeGates::allowed(&world);
            assert_eq!(run(&world, &mut port, &mut gates), Outcome::EofCompleted);
            assert_eq!(world.network.get(), 1);
            let cadence = world.cadence.borrow();
            assert_eq!(cadence.state(), reference.state(), "{records:?}");
            for offset in [0u64, 60, 299, 300, 600, 900, 1800, 7200, 6 * 3600] {
                let now = scanned + Duration::from_secs(offset);
                assert_eq!(
                    cadence.next_scan_after(now),
                    reference.next_scan_after(now),
                    "{directive:?} {records:?}: the ordinary Codex cadence did not move"
                );
            }
        }
    }
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
    world.destination.set(Some(OTHER_DESTINATION));
    *lock_slot(&world.slot) = Some(ticket(OTHER_DESTINATION));
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
    // destination): the page runs on that one, and the ticket it leaves is the
    // page's own, written before the lock is released.
    let world = World::new();
    world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed(&world);
    gates.on_power = Some(ordinary_pass_mints_newer as fn(&World));
    assert_eq!(run(&world, &mut port, &mut gates), Outcome::Paused);
    assert_eq!(world.held_destination(), Some(OTHER_DESTINATION));
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
    assert_eq!(outcome, Outcome::Paused);
    // The next page would end after this cycle's deadline: ordinary next.
    let pending = world.due().zip(world.cadence.borrow().continuation_work());
    assert!(matches!(
        plan_wake(world.now.get(), ordinary, pending),
        Wake::Ordinary(_)
    ));
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

fn loop_shape(tick: Duration, cycle: Duration) -> Option<LoopShape> {
    let start = Instant::now();
    let mut record = LoopRecord::new();
    record.observe(start, start + cycle);
    assert_eq!(record.shape(), None, "unknown until a tick is observed");
    record.observe(start + tick, start + tick + cycle);
    record.shape()
}

#[test]
fn the_ordinary_equivalent_follows_the_applicable_policy_unclamped() {
    let start = Instant::now();
    let shape = loop_shape(Duration::from_secs(330), Duration::from_secs(30));
    let slack = Duration::from_secs(330 + 30);
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(start, 1);
    assert_eq!(
        ordinary_equivalent(&cadence, shape),
        Some(Duration::from_secs(300) + slack)
    );
    cadence.record_scan_success(start + Duration::from_secs(20 * 60), 0);
    assert_eq!(
        ordinary_equivalent(&cadence, shape),
        Some(Duration::from_secs(600) + slack)
    );
    cadence.set_server_min_interval(Some(Duration::from_secs(1200)));
    assert_eq!(
        ordinary_equivalent(&cadence, shape),
        Some(Duration::from_secs(1200) + slack)
    );
    cadence.set_server_min_interval(None);
    for _ in 0..5 {
        cadence.record_scan_failure(start);
    }
    assert_eq!(
        ordinary_equivalent(&cadence, shape),
        Some(Duration::from_secs(3600) + slack),
        "the loop waits out a one-hour backoff in full: only the reported wait is clamped"
    );
    assert_eq!(negotiated_wait(&cadence, start), MAX_CYCLE_INTERVAL);

    // Unknown loop shape or overflow: no equivalent, so no acceleration.
    assert_eq!(ordinary_equivalent(&cadence, None), None);
    let huge = Some(LoopShape {
        longest_tick: Duration::MAX,
        longest_cycle: Duration::ZERO,
    });
    assert_eq!(ordinary_equivalent(&cadence, huge), None);
}

#[test]
fn the_ordinary_equivalent_is_never_shorter_than_the_real_ordinary_gap() {
    let floor = SNAPSHOT_SYNC_INTERVAL;
    type Policy = fn(&mut SourceCadence, Instant);
    let policies: [(&str, Policy); 5] = [
        ("warm", |c, at| c.record_scan_success(at, 1)),
        ("idle", |c, at| c.record_scan_success(at, 0)),
        ("directive", |c, at| {
            c.set_server_min_interval(Some(Duration::from_secs(1200)));
            c.record_scan_success(at, 1);
        }),
        ("cold directive", |c, at| {
            c.set_server_min_interval(Some(Duration::from_secs(1800)));
            c.record_scan_success(at, 0);
        }),
        ("one-hour backoff", |c, at| {
            for _ in 0..5 {
                c.record_scan_failure(at);
            }
        }),
    ];
    for (name, policy) in policies {
        for cycle_secs in [1u64, 30, 120, 290] {
            let cycle = Duration::from_secs(cycle_secs);
            let tick = floor + cycle;
            let base = Instant::now();
            // Loop cycles start one tick apart, and Codex's place inside each
            // cycle alternates between its start and its end.
            let scan_at = |k: u32| base + tick * k + cycle * (k % 2);
            let anchor = scan_at(1);
            let mut cadence = SourceCadence::new(CadenceConfig::cost_first(floor));
            policy(&mut cadence, anchor);
            let equivalent =
                ordinary_equivalent(&cadence, loop_shape(tick, cycle)).expect("a known loop shape");
            assert!(equivalent >= cadence.ordinary_interval(), "{name}");
            let next = (2..1000)
                .map(scan_at)
                .find(|at| cadence.next_scan_after(*at).is_zero())
                .expect("the ordinary path scans again");
            let gap = next - anchor;
            assert!(gap >= cadence.ordinary_interval(), "{name}");
            assert!(
                gap <= equivalent,
                "{name}, {cycle_secs}s cycles: real gap {gap:?} above {equivalent:?}"
            );
        }
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
    assert_eq!(source.matches("complete_continuation_eof(").count(), 1);
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
            "SNAPSHOT_SYNC_LOCK",
            "ScanIndex",
            "SnapshotSource",
            "SourcePreparation",
            "SourceScanResult",
            "complete_continuation_eof",
            "enabled_snapshot_sources",
            "load_snapshot_device_credentials",
            "snapshot_api_base_url",
            "snapshot_upload_destination_namespace",
            "source_upload_backoff_remaining",
            "with_source_cadence",
        ]
    );
    assert_eq!(source.matches("super::").count(), 2, "no other parent path");
}
