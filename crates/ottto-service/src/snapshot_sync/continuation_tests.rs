// CI controls for the inert continuation scaffolding. The cursor side and the
// platform are fakes standing in for c22's hunks and the platform hunk; the
// clock is simulated, so nothing here sleeps, reads a transcript or opens a
// socket.

use super::*;
use crate::adaptive_collector::CadenceConfig;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

const DESTINATION: [u8; 32] = [7; 32];
const OTHER_DESTINATION: [u8; 32] = [9; 32];

struct World {
    now: Cell<Instant>,
    backoff: Cell<bool>,
    destination: Cell<Option<[u8; 32]>>,
    cadence: RefCell<SourceCadence>,
    /// Every call that would reach the network. Only `complete_eof` counts.
    network: Cell<u32>,
    lock: Mutex<()>,
    lock_held_in_page: Cell<Option<bool>>,
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
            cadence: RefCell::new(cadence),
            network: Cell::new(0),
            lock: Mutex::new(()),
            lock_held_in_page: Cell::new(None),
        }
    }

    fn advance(&self, by: Duration) {
        self.now.set(self.now.get() + by);
    }

    /// An ordinary Codex page that paused at its budget after `work`.
    fn ordinary_page_asks(&self, work: Duration) -> Option<ContinuationTicket> {
        self.advance(work);
        let mut cadence = self.cadence.borrow_mut();
        cadence.record_scan_success(self.now.get(), 1);
        cadence.request_continuation(self.now.get(), work);
        Some(ticket(DESTINATION))
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
        cursor: CursorTicket { _sealed: () },
    }
}

struct FakeHost<'a>(&'a World);

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
    fn cadence<T>(&mut self, apply: impl FnOnce(&mut SourceCadence) -> T) -> Option<T> {
        Some(apply(&mut *self.0.cadence.borrow_mut()))
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
    complete: u32,
    defer: u32,
}

struct FakePort<'a> {
    world: &'a World,
    ready: bool,
    ends: VecDeque<End>,
    work: Duration,
    complete_ok: bool,
    /// Something changes while the page runs, before the EOF recheck.
    backoff_during_page: bool,
    destination_during_page: Option<[u8; 32]>,
    calls: Calls,
}

impl<'a> FakePort<'a> {
    fn new(world: &'a World, ends: &[End]) -> Self {
        Self {
            world,
            ready: true,
            ends: ends.iter().copied().collect(),
            work: Duration::from_secs(4),
            complete_ok: true,
            backoff_during_page: false,
            destination_during_page: None,
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
    fn page(&mut self, _ticket: CursorTicket) -> PageEnd {
        self.calls.page += 1;
        self.world
            .lock_held_in_page
            .set(Some(self.world.lock.try_lock().is_err()));
        self.world.advance(self.work);
        if self.backoff_during_page {
            self.world.backoff.set(true);
        }
        if let Some(destination) = self.destination_during_page {
            self.world.destination.set(Some(destination));
        }
        match self.ends.pop_front().unwrap_or(End::Paused) {
            End::Paused => PageEnd::Paused(CursorTicket { _sealed: () }),
            End::Deferred => PageEnd::Deferred,
            End::Eof => PageEnd::Eof(EofCompletion { _sealed: () }),
            End::Cancelled => PageEnd::Cancelled,
            End::Failed => PageEnd::Failed(anyhow!("synthetic save CAS refusal")),
        }
    }
    fn complete_eof(&mut self, _completion: EofCompletion) -> Result<()> {
        self.calls.complete += 1;
        self.world.network.set(self.world.network.get() + 1);
        if self.complete_ok {
            Ok(())
        } else {
            Err(anyhow!("synthetic upload refusal"))
        }
    }
    fn defer_eof(&mut self, _completion: EofCompletion) {
        self.calls.defer += 1;
    }
}

struct FakeGates {
    power: PlatformState,
    qos: PlatformState,
    entered: u32,
    restored: u32,
}

impl FakeGates {
    fn allowed() -> Self {
        Self {
            power: PlatformState::Allowed,
            qos: PlatformState::Allowed,
            entered: 0,
            restored: 0,
        }
    }
}

impl PlatformGates for FakeGates {
    fn power(&mut self) -> PlatformState {
        self.power
    }
    fn enter_background_qos(&mut self) -> PlatformState {
        self.entered += 1;
        self.qos
    }
    fn restore_qos(&mut self) {
        self.restored += 1;
    }
}

fn run(
    world: &World,
    port: &mut FakePort<'_>,
    gates: &mut FakeGates,
    slot: &mut Option<ContinuationTicket>,
) -> Outcome {
    run_page(&mut FakeHost(world), port, gates, &world.lock, slot)
}

#[test]
fn the_inert_default_takes_todays_path() {
    assert!(
        !std::hint::black_box(ENABLED),
        "Stage 1 stays inert until its integration is approved"
    );
    assert_eq!(production_pending(), None);
    assert_eq!(run_production_page(), Outcome::Skipped(Skip::NoTicket));
    assert!(!NoCursorContinuation.ready(&CursorTicket { _sealed: () }));
    assert!(matches!(
        NoCursorContinuation.page(CursorTicket { _sealed: () }),
        PageEnd::Deferred
    ));
    assert_eq!(NoPlatformSignals.power(), PlatformState::Unknown);
    assert_eq!(
        NoPlatformSignals.enter_background_qos(),
        PlatformState::Unknown
    );

    // With nothing pending, the wait is exactly today's: one uninterrupted
    // ordinary interval, and no page.
    let mut host = ScheduleLoop::new(None);
    wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
    assert_eq!(host.waits, vec![SNAPSHOT_SYNC_INTERVAL]);
    assert!(host.pages.is_empty());
}

#[test]
fn a_paused_page_asks_for_the_next_page_after_the_duty_gap() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed();

    let started = world.now.get();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::Paused
    );
    let finished = world.now.get();
    assert!(slot.is_some());
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
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    let mut port = FakePort::new(
        &world,
        &[End::Paused, End::Paused, End::Paused, End::Paused, End::Eof],
    );
    let mut gates = FakeGates::allowed();
    for _ in 0..4 {
        world.advance_to_due();
        assert_eq!(
            run(&world, &mut port, &mut gates, &mut slot),
            Outcome::Paused
        );
        assert_eq!(world.network.get(), 0, "a non-EOF page is zero-network");
    }
    world.advance_to_due();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::EofCompleted
    );
    assert_eq!(
        world.network.get(),
        1,
        "only the existing completion upload, once"
    );
    assert_eq!(port.calls.complete, 1);
    assert!(slot.is_none());
    assert_eq!(world.due(), None, "a completed job asks for nothing more");
}

#[test]
fn eof_rechecks_upload_backoff_and_destination_before_the_network() {
    for change in ["backoff", "destination"] {
        let world = World::new();
        let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let mut port = FakePort::new(&world, &[End::Eof]);
        match change {
            "backoff" => port.backoff_during_page = true,
            _ => port.destination_during_page = Some(OTHER_DESTINATION),
        }
        let mut gates = FakeGates::allowed();
        assert_eq!(
            run(&world, &mut port, &mut gates, &mut slot),
            Outcome::EofDeferred,
            "{change}"
        );
        assert_eq!(world.network.get(), 0, "{change}");
        assert_eq!(port.calls.complete, 0);
        assert_eq!(port.calls.defer, 1, "the owed path keeps the obligation");
        assert!(slot.is_none());
        assert_eq!(world.due(), None);
    }
}

#[test]
fn an_eof_upload_refusal_is_not_retried() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Eof]);
    port.complete_ok = false;
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::EofFailed
    );
    assert_eq!(port.calls.complete, 1, "no hidden retry");
    assert_eq!(world.network.get(), 1);
    assert!(slot.is_none());
    assert_eq!(world.due(), None, "the next attempt is the ordinary pass");
    assert!(world.lock.try_lock().is_ok());
}

#[test]
fn cancelled_failed_and_deferred_pages_leave_no_continuation() {
    for (end, expected) in [
        (End::Cancelled, Outcome::Cancelled),
        (End::Failed, Outcome::Failed),
        (End::Deferred, Outcome::Deferred),
    ] {
        let world = World::new();
        let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let mut port = FakePort::new(&world, &[end]);
        let mut gates = FakeGates::allowed();
        assert_eq!(run(&world, &mut port, &mut gates, &mut slot), expected);
        assert!(slot.is_none(), "{end:?}");
        assert_eq!(world.due(), None, "{end:?}");
        assert_eq!(world.network.get(), 0, "{end:?}");
        assert_eq!((gates.entered, gates.restored), (1, 1), "{end:?}");
        assert!(world.lock.try_lock().is_ok(), "{end:?}");
    }
}

#[test]
fn refused_busy_or_unknown_inputs_cannot_manufacture_urgency() {
    type Setup = fn(&World, &mut FakePort<'_>, &mut FakeGates);
    let cases: [(&str, Setup, Skip); 9] = [
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
        let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
        world.advance_to_due();
        let reference = world.cadence.borrow().clone();
        let mut port = FakePort::new(&world, &[End::Paused]);
        let mut gates = FakeGates::allowed();
        setup(&world, &mut port, &mut gates);
        assert_eq!(
            run(&world, &mut port, &mut gates, &mut slot),
            Outcome::Skipped(skip),
            "{name}"
        );
        assert_eq!(port.calls.page, 0, "{name}: no page ran");
        assert!(slot.is_none(), "{name}: the ticket is gone");
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
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed();
    let held = world.lock.lock().expect("hold the lock");
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::Skipped(Skip::LockBusy)
    );
    drop(held);
    assert_eq!(port.calls.page, 0);
    assert!(slot.is_none());
    assert_eq!(world.due(), None);

    // No ticket at all.
    let world = World::new();
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut None),
        Outcome::Skipped(Skip::NoTicket)
    );
    assert_eq!(port.calls.ready, 0);
}

#[test]
fn qos_is_restored_after_every_page_that_entered_it() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    port.ready = false;
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::Skipped(Skip::NotReady)
    );
    assert_eq!((gates.entered, gates.restored), (1, 1));
}

#[test]
fn a_ticket_that_is_not_yet_due_waits_without_a_page() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::Skipped(Skip::NotDue)
    );
    assert!(slot.is_some(), "an early wake keeps the ticket");
    assert!(world.due().is_some());
    assert_eq!(port.calls.ready, 0);
    assert_eq!(gates.entered, 0);
}

#[test]
fn a_server_directive_or_failure_backoff_wins_over_a_due_ticket() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    world
        .cadence
        .borrow_mut()
        .set_server_min_interval(Some(Duration::from_secs(1800)));
    let mut port = FakePort::new(&world, &[End::Paused]);
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::Skipped(Skip::NotDue)
    );
    assert!(slot.is_none(), "the 1800 s directive wins: no continuation");
    assert_eq!(port.calls.page, 0);
}

#[test]
fn slow_pages_fall_back_to_the_ordinary_cadence() {
    let world = World::new();
    let mut slot = world.ordinary_page_asks(Duration::from_secs(5));
    world.advance_to_due();
    let mut port = FakePort::new(&world, &[End::Paused]);
    port.work = CONTENTION_WORK + Duration::from_secs(1);
    let mut gates = FakeGates::allowed();
    assert_eq!(
        run(&world, &mut port, &mut gates, &mut slot),
        Outcome::PausedContended
    );
    assert!(slot.is_none());
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
    fn page(&mut self) -> Outcome {
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
    gates: FakeGates,
    slot: Option<ContinuationTicket>,
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
        self.slot.as_ref()?;
        let cadence = self.world.cadence.borrow();
        cadence
            .continuation_due(PACING)
            .zip(cadence.continuation_work())
    }
    fn page(&mut self) -> Outcome {
        let start = self.world.now.get();
        let outcome = run_page(
            &mut FakeHost(self.world),
            &mut self.port,
            &mut self.gates,
            &self.world.lock,
            &mut self.slot,
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
        gates: FakeGates::allowed(),
        slot: None,
        pages: Vec::new(),
    };
    let mut ordinary_starts = Vec::new();
    for _ in 0..cycles {
        ordinary_starts.push(world.now.get());
        world.advance(cycle - codex_work);
        let ticket = world.ordinary_page_asks(codex_work);
        if enabled {
            host.slot = ticket;
            wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
        } else {
            world.cadence.borrow_mut().clear_continuation();
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
        staged.iter().map(|at| *at - today[0]).collect::<Vec<_>>(),
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
    let mut slot = world.ordinary_page_asks(Duration::from_secs(3));
    let reference = world.cadence.borrow().clone();
    let mut port = FakePort::new(&world, &[End::Paused, End::Paused, End::Paused]);
    let mut gates = FakeGates::allowed();
    for _ in 0..3 {
        world.advance_to_due();
        assert_eq!(
            run(&world, &mut port, &mut gates, &mut slot),
            Outcome::Paused
        );
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
fn the_ordinary_equivalent_follows_the_applicable_policy() {
    let start = Instant::now();
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(start, 1);
    assert_eq!(ordinary_equivalent(&cadence), Duration::from_secs(300));
    cadence.record_scan_success(start + Duration::from_secs(20 * 60), 0);
    assert_eq!(ordinary_equivalent(&cadence), Duration::from_secs(600));
    cadence.set_server_min_interval(Some(Duration::from_secs(1200)));
    assert_eq!(ordinary_equivalent(&cadence), Duration::from_secs(1200));
    cadence.set_server_min_interval(None);
    for _ in 0..5 {
        cadence.record_scan_failure(start);
    }
    assert_eq!(
        ordinary_equivalent(&cadence),
        MAX_CYCLE_INTERVAL,
        "a one-hour backoff waits no longer than the loop's ceiling"
    );
}
