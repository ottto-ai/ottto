// CI controls for paced continuation. The cursor side and the
// platform are fakes standing in for c22's hunks and the platform hunk; the
// clock is simulated, so nothing here sleeps, reads a transcript or opens a
// socket.

use super::super::{validate_snapshot_scan_authority, SNAPSHOT_SYNC_INTERVAL};
use super::*;
use crate::adaptive_collector::CadenceConfig;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

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

/// W8(a), W9: a worker that panics while holding the cache's cursor lock
/// comes back as `Failed`; the latch then refuses every further ticket and
/// readiness, and the poisoned lock fails closed.
#[test]
fn a_worker_panic_under_the_cursor_lock_latches_and_fails_closed() {
    let cache = Arc::new(SharedCache::default());
    let dir = std::env::temp_dir();
    let mut port = CodexContinuation::new(&cache, &dir, &dir);
    port.latch = test_latch();
    let panicked = on_worker(|| cache.panic_under_cursor_lock_for_test());
    assert_eq!(panicked, Err(WorkerFailure::Panicked));
    assert!(matches!(
        page_end(
            panicked.map(|()| WorkerEnd::Stopped),
            Instant::now(),
            Instant::now(),
            port.latch
        ),
        PageEnd::Failed(_)
    ));
    assert!(port.latched());
    assert!(port.ticket_for(&empty_scan()).is_none());
    let page = CursorTicket::codex(CodexCursorTicket::unready_for_test());
    assert!(!port.ready(&page));
    // The cursor stays poisoned: nothing is admitted or readied.
    assert!(cache.cursor_poisoned_for_test());
    assert!(!CodexCursorPort::new(Arc::clone(&cache)).ready(&CodexCursorTicket::unready_for_test()));
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
    Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
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
/// panic. The drop sentinel is the inputs' prelude feed.
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

thread_local! {
    static TEST_CONTEXT: std::cell::Cell<Option<RuntimeContext>> = const { std::cell::Cell::new(None) };
}
pub(super) fn runtime_context_override() -> Option<RuntimeContext> {
    TEST_CONTEXT.with(std::cell::Cell::get)
}
pub(super) fn observe_context(slot: usize, value: ([u8; 32], [u8; 32])) -> bool {
    TEST_CONTEXT.with(|state| {
        let Some(mut context) = state.get() else {
            return false;
        };
        context[slot] = Some(value);
        state.set(Some(context));
        true
    })
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
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_CONTEXT.with(|v| v.set(None));
        }
    }
    let _reset = Reset;
    TEST_CONTEXT.with(|v| v.set(Some([None; 2])));
    for change in ["context", "policy", "content"] {
        let (root, mut inputs) = inventory_inputs();
        observe(SnapshotSource::Codex, "mint-context", inputs.upload_policy);
        observe(
            SnapshotSource::ClaudeCode,
            "mint-context",
            inputs.upload_policy,
        );
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
                observe(SnapshotSource::ClaudeCode, "mint-context", policy);
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
        let (result, records) = crate::local_resource_diagnostics::capture(|| {
            run_continuation_scan(
                &root,
                &root,
                &cache,
                &mut inputs,
                Some(Duration::from_secs(300)),
                Instant::now() + Duration::from_secs(20),
            )
            .unwrap()
        });
        let reason = match change {
            "context" => "context_changed",
            "policy" => "policy_changed",
            _ => "roster_changed",
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["stage"], "codex_continuation");
        assert_eq!(records[0]["counts"]["continuation_pages_run"], 0);
        assert_eq!(records[0]["counts"]["continuation_held"][reason], 1);
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
#[cfg(target_os = "macos")]
fn native_platform_qos_restores_on_a_spawned_thread_and_power_has_valid_range() {
    std::thread::spawn(|| {
        let prior = query_qos().expect("native QoS query");
        let guard = MacPlatformSignals::background().expect("native background entry");
        assert_eq!(query_qos(), Some((0x09, 0)));
        drop(guard);
        let restored = if prior.0 == 0 { (0x15, prior.1) } else { prior };
        assert_eq!(query_qos(), Some(restored));
        assert!(matches!(unsafe { ottto_power_state() }, -1..=2));
    })
    .join()
    .unwrap();
}

const MINT_SESSION: &str = "019fa111-2222-7333-8444-555555555555";

/// A real ordinary page that leaves one rollout's job paused and accelerated.
/// Run under `with_test_limits_for_test`.
/// A Codex rollout body: the session header and `turns` token counts.
fn rollout_body(session: &str, turns: u64) -> String {
    let mut body = format!(
        "{}\n",
        serde_json::json!({"type":"session_meta", "timestamp":"2026-10-24T00:00:00Z", "payload":{"id":session}})
    );
    for n in 1..=turns {
        body.push_str(&format!("{}\n", serde_json::json!({"type":"event_msg", "timestamp":"2026-10-24T00:30:00Z", "payload":{"type":"token_count", "info":{"model":"fixture-model", "total_token_usage":{"input_tokens":n*100,"cached_input_tokens":n*50,"output_tokens":n*10},"last_token_usage":{"input_tokens":100,"cached_input_tokens":50,"output_tokens":10}}}})));
    }
    body
}

fn paused_accelerated_scan(root: &Path, cache: &Arc<SharedCache>) -> SourceScanResult {
    let session = MINT_SESSION;
    std::fs::write(
        root.join(format!("rollout-2026-10-24T00-00-00-{session}.jsonl")),
        rollout_body(session, 80),
    )
    .unwrap();
    let mut owned = crate::snapshots::OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&root.to_path_buf()),
        ScanIndex::default(),
        "2026-10-24T12:00:00Z",
        30,
        10,
        None,
        &[],
        false,
    )
    .with_sampled_acquisition(
        Arc::clone(cache),
        crate::transcript_acquisition::Scope("mint-fixture".into()),
    );
    let scan = loop {
        match owned.step(None) {
            crate::snapshots::OwnedSourceScanStep::Pending(next) => owned = next,
            crate::snapshots::OwnedSourceScanStep::Complete { scan, .. } => break scan,
        }
    };
    assert!(scan.snapshots.is_empty());
    assert!(
        scan.continuation_ticket().is_some(),
        "real paused accelerated scan"
    );
    scan
}

#[test]
#[cfg(target_os = "macos")]
fn production_finish_closure_mints_a_paused_accelerated_page_with_evidence() {
    let mut preparation = super::super::tests::continuation_preparation_for_test();
    let root = preparation.index_path.parent().unwrap().join("sessions");
    std::fs::create_dir_all(&root).unwrap();
    let cache = Arc::new(SharedCache::default());
    crate::snapshots::with_test_limits_for_test(2048, 1024, 64, || {
        let mut scan = paused_accelerated_scan(&root, &cache);
        static LATCH: AtomicBool = AtomicBool::new(false);
        let mut port = CodexContinuation {
            cache: &cache,
            home: &root,
            support_dir: &root,
            worker_qos: MacPlatformSignals::background,
            latch: &LATCH,
        };
        let world = World::new();
        let ticket = ordinary_ticket(
            &port,
            &scan,
            &preparation.upload_destination_namespace,
            Some(AUTHORITY),
            Some((world.now.get(), world.now.get() + LIFETIME)),
        )
        .unwrap();
        let (ticket, records) = crate::local_resource_diagnostics::capture(|| {
            super::super::continuation_finish_inputs(
                &mut preparation,
                &mut scan,
                Some(8 * 1024 * 1024),
                &Arc::default(),
                Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
            )(ticket)
            .expect("real finish admits carried evidence under an 8 MiB retained allowance")
        });
        *world.slot.lock().unwrap() = Some(ticket);
        assert!(world.held());
        let mut held = world.slot.lock().unwrap();
        let ticket = held.as_mut().unwrap();
        assert!(port.ready(&ticket.cursor));
        match &ticket.cursor.0 {
            CursorParts::Codex(page) => {
                let inputs = page.inputs.as_ref().unwrap();
                assert!(inputs.evidence.as_ref().unwrap().content_unchanged());
                assert!(inputs.holds_attribution());
            }
            _ => panic!("a production Codex ticket"),
        }
        assert!(preparation.attribution_context.is_none(), "inputs moved");
        assert!(
            scan.take_continuation_evidence().is_none(),
            "evidence moved once"
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["counts"]["continuation_mint"]["minted"], 1);
    });
}

/// [regress] Every real mint was `over_bound`: the page's inputs exceeded the
/// ticket's walk. Realistic inputs (a status collection over the walk alone,
/// 2,500 lineage rows, scan homes, schedules) mint through the production
/// finish and `with_inputs`, under the walk with room to spare.
#[test]
fn realistic_inputs_mint_through_the_tickets_walk_with_headroom() {
    use crate::heap_layout_bound::{bound, layout_supported, Counter, HeapLayoutBound as _};
    if !layout_supported() {
        return;
    }
    let mut preparation = super::super::tests::continuation_realistic_preparation_for_test();
    let status = Arc::clone(preparation.scan_agent_status_collection.as_ref().unwrap());
    assert!(
        bound(&status, 8 << 20).is_none(),
        "the whole status collection exceeds the ticket's walk"
    );
    let root = preparation.index_path.parent().unwrap().join("sessions");
    std::fs::create_dir_all(&root).unwrap();
    let state = rusqlite::Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
    state
        .execute_batch(
            "CREATE TABLE threads (\
                id TEXT NOT NULL, title TEXT, tokens_used INTEGER NOT NULL,\
                thread_source TEXT, first_user_message TEXT, created_at_ms INTEGER,\
                rollout_path TEXT\
            );\
            CREATE TABLE thread_spawn_edges (\
                parent_thread_id TEXT NOT NULL, child_thread_id TEXT NOT NULL\
            );",
        )
        .unwrap();
    let rollout = root.join(format!("rollout-2026-10-24T00-00-00-{MINT_SESSION}.jsonl"));
    state
        .execute(
            "INSERT INTO threads VALUES (?1, 'Thread', 1, 'user', 'Summarize', ?2, ?3)",
            rusqlite::params![
                MINT_SESSION,
                1_792_800_000_000_i64,
                rollout.to_string_lossy().into_owned()
            ],
        )
        .unwrap();
    for n in 0..2_500 {
        state
            .execute(
                "INSERT INTO thread_spawn_edges VALUES (?1, ?2)",
                rusqlite::params![
                    format!("019fb000-0000-7000-8000-{n:012}"),
                    format!("019fc000-0000-7000-8000-{n:012}")
                ],
            )
            .unwrap();
    }
    drop(state);
    let cache = Arc::new(SharedCache::default());
    crate::snapshots::with_test_limits_for_test(2048, 1024, 64, || {
        let mut scan = paused_accelerated_scan(&root, &cache);
        static LATCH: AtomicBool = AtomicBool::new(false);
        let port = CodexContinuation {
            cache: &cache,
            home: &root,
            support_dir: &root,
            worker_qos: MacPlatformSignals::background,
            latch: &LATCH,
        };
        let world = World::new();
        let ticket = ordinary_ticket(
            &port,
            &scan,
            &preparation.upload_destination_namespace,
            Some(AUTHORITY),
            Some((world.now.get(), world.now.get() + LIFETIME)),
        )
        .unwrap();
        let (ticket, records) = crate::local_resource_diagnostics::capture(|| {
            super::super::continuation_finish_inputs(
                &mut preparation,
                &mut scan,
                Some(8 * 1024 * 1024),
                &Arc::default(),
                Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
            )(ticket)
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["counts"]["continuation_mint"]["minted"], 1);
        let ticket = ticket.expect("realistic inputs mint");
        match &ticket.cursor.0 {
            CursorParts::Codex(page) => {
                let inputs = page.inputs.as_ref().unwrap();
                assert_eq!(inputs.codex_scan_homes, status.codex_scan_homes);
                assert!(inputs.holds_attribution());
                let mut walk = Counter::new(8 << 20);
                page.heap_bound(&mut walk).expect("within the walk");
                assert!(
                    walk.visits_for_test() < 3072,
                    "headroom under the 4096-visit walk: {}",
                    walk.visits_for_test()
                );
            }
            _ => panic!("a production Codex ticket"),
        }
    });
}

/// [behaviour] Paced ordinary work picks its gap at request time, including
/// battery, without the cursor's 20-second contention cutoff.
#[test]
fn resident_pacing_selects_power_gap_and_preserves_cursor_ac_gate() {
    let now = Instant::now();
    for (answer, state, gap) in [
        (1, PlatformState::Allowed, Some(30)),
        (2, PlatformState::Battery, Some(180)),
        (0, PlatformState::Refused, None),
        (-1, PlatformState::Unknown, None),
        (3, PlatformState::Unknown, None),
    ] {
        assert_eq!(power_state(answer), state);
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.record_scan_success(now, 1);
        if let Some(pacing) = resident_pacing(state) {
            assert!(cadence.request_paced_scan(now, Duration::from_secs(103), pacing, false));
        }
        assert_eq!(
            cadence.paced_scan_due(),
            gap.map(|gap| now + Duration::from_secs(gap))
        );
        if let Some(gap) = gap {
            assert_eq!(cadence.next_scan_after(now), Duration::from_secs(gap));
            cadence.record_scan_success(now + Duration::from_secs(gap), 0);
            assert!(
                cadence.paced_scan_due().is_none(),
                "a quiet pass adds no wake"
            );
        }
    }
    // LPM on AC and on battery has the same shim answer: no pacing request.
    assert!(resident_pacing(power_state(0)).is_none());
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(now, 1);
    cadence.request_paced_scan(now, Duration::from_secs(103), PACED_AC, false);
    cadence.request_paced_scan(now, Duration::from_secs(103), PACED_BATTERY, false);
    assert_eq!(
        cadence.paced_scan_due(),
        Some(now + Duration::from_secs(180))
    );
    // Server minima and backoff still win; a new ordinary success resets its clock.
    cadence.set_server_min_interval(Some(Duration::from_secs(210)));
    assert_eq!(cadence.next_scan_after(now), Duration::from_secs(210));

    let w = World::new();
    let mut cursor = FakePort::new(&w, &[End::Paused]);
    let mut gates = FakeGates::allowed(&w);
    w.ordinary_page_asks(Duration::from_secs(1));
    w.advance_to_due();
    gates.power = PlatformState::Battery;
    let outcome = run_page(
        &mut FakeHost(&w),
        &mut cursor,
        &mut gates,
        &w.lock,
        &w.slot,
        w.now.get() + Duration::from_secs(300),
    );
    assert!(matches!(outcome, Outcome::Skipped(Skip::Platform)));
    assert_eq!(w.network.get(), 0);
}

/// [behaviour] A full file selection paces queued work through the same power
/// gates as a resident deferral; a drained or underfull selection adds no wake.
#[test]
fn file_limit_full_pages_request_pacing_only_with_queued_work_and_allowed_power() {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    let home = crate::test_scratch::private_dir("file-limit-pacing")
        .canonicalize()
        .unwrap();
    let now = Instant::now();
    for (case, (files, power, routine, charge, gap)) in [
        (3_usize, PlatformState::Allowed, false, false, Some(30)),
        (3, PlatformState::Battery, false, false, Some(180)),
        (2, PlatformState::Allowed, false, false, None),
        (1, PlatformState::Allowed, false, false, None),
        (3, power_state(0), false, false, None), // Low Power Mode on AC or battery.
        (3, PlatformState::Unknown, false, false, None),
        (3, PlatformState::Allowed, true, false, None),
        (3, PlatformState::Battery, true, false, None),
        (3, PlatformState::Allowed, true, true, Some(30)),
    ]
    .into_iter()
    .enumerate()
    {
        let root = home.join(case.to_string());
        std::fs::create_dir_all(&root).unwrap();
        for file in 0..files {
            std::fs::write(
                root.join(format!("session-{file}.jsonl")),
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{\"input\":1,\"output\":1}}}\n",
            )
            .unwrap();
        }
        let ((_, mut scan, _), rows) = crate::local_resource_diagnostics::capture(|| {
            E2ScanFixture::default().scan_other_page(
                SnapshotSource::Pi,
                &[root],
                &home,
                ScanIndex::default(),
                true,
                2,
                &[],
            )
        });
        let page = rows
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(page["counts"]["routine_recensus"], scan.routine_recensus);
        assert_eq!(
            page["counts"]["page_file_limit_hit"],
            scan.page_file_limit_hit
        );
        assert_eq!(
            page["counts"]["pending_work"],
            scan.census_status.pending_work
        );
        assert_eq!(scan.backfill_file_limit, 2);
        assert_eq!(scan.scanned_file_count, files.min(2));
        assert_eq!(scan.page_file_limit_hit, files >= 2);
        assert_eq!(scan.census_status.pending_work, files > 2);
        assert!(
            !scan.charge_deferred,
            "the file allowance is the only trigger"
        );
        assert!(
            !scan.routine_recensus,
            "a first walk in this process stays paced"
        );
        scan.routine_recensus = routine;
        scan.charge_deferred = charge;
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.record_scan_success(now, 1);
        if resident_scan_requested(&scan, false)
            && let Some(pacing) = resident_pacing(power)
        {
            assert!(cadence.request_paced_scan(now, Duration::ZERO, pacing, false));
        }
        assert_eq!(
            cadence.paced_scan_due(),
            gap.map(|gap| now + Duration::from_secs(gap))
        );
    }
    std::fs::remove_dir_all(home).unwrap();
}

/// [behaviour] A spent Codex byte budget asks for pacing with queued work
/// only during a first backfill, routine or not.
#[test]
fn byte_budget_pages_pace_only_during_a_first_backfill() {
    let mut scan = empty_scan();
    assert!(!scan.charge_deferred && !scan.page_file_limit_hit);
    for bits in 0..16_u8 {
        let [bootstrap, byte_hit, routine, pending] = [1, 2, 4, 8].map(|bit| bits & bit != 0);
        (scan.page_byte_budget_hit, scan.routine_recensus) = (byte_hit, routine);
        scan.census_status.pending_work = pending;
        let requested = resident_scan_requested(&scan, bootstrap);
        assert_eq!(requested, bootstrap && byte_hit && pending, "{bits:04b}");
    }
}

const WALK_NOW: &str = "2026-11-17T00:01:00Z";
const WALK_START: &str = "2026-11-17T00:00:00Z";

#[test]
fn slow_paced_prepare_limits_per_source() {
    let ms = Duration::from_millis(1);
    let codex = Duration::from_secs(10);
    for (source, limit) in [
        (SnapshotSource::ClaudeCode, CONTENTION_WORK),
        (SnapshotSource::Codex, codex),
    ] {
        assert!(slow_paced_prepare(source, limit + ms, true), "{source:?}");
        assert!(!slow_paced_prepare(source, limit, true), "{source:?}");
        // A slow utility pass never cuts.
        assert!(!slow_paced_prepare(source, limit * 3, false), "{source:?}");
    }
    assert!(!slow_paced_prepare(
        SnapshotSource::Pi,
        CONTENTION_WORK * 3,
        true
    ));
    assert!(!paced_background_pass());
}

#[test]
fn slow_paced_prepare_stops_only_file_limit_pacing() {
    use crate::local_resource_diagnostics::{capture, source_finish, source_prepare};

    let check = |scan: &SourceScanResult, bootstrap, cut_walk: bool, power, expected, cut: bool| {
        let source = scan.source.api_slug();
        let (request, rows) = capture(|| {
            source_prepare(source, || (), |_| false);
            source_finish(source, false, || {
                Ok(resident_scan_request_after_settlement(
                    scan,
                    bootstrap,
                    || cut_walk,
                    power,
                    true,
                ))
            })
            .unwrap()
        });
        assert_eq!(request, expected, "{source} {power:?}");
        let finish = rows
            .iter()
            .find(|row| row["stage"] == "source_finish")
            .unwrap();
        let pass = finish["counts"]["pass"].as_object().unwrap();
        assert_eq!(
            pass.get("paced_request_slow_prepare_cut"),
            cut.then(|| serde_json::json!(1)).as_ref(),
            "{source} {power:?}"
        );
    };
    let mut scan = empty_scan();
    scan.page_file_limit_hit = true;
    scan.census_status.pending_work = true;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        scan.source = source;
        for power in [PlatformState::Allowed, PlatformState::Battery] {
            // A full page on a non-routine walk: the cut wins and is counted.
            check(&scan, false, true, power, None, true);
            check(&scan, false, false, power, Some(false), false);
            check(&scan, true, true, power, Some(true), false);
            scan.charge_deferred = true;
            check(&scan, false, true, power, Some(false), false);
            scan.charge_deferred = false;
        }
    }
    // Bootstrap and charge deferral never consult, so never arm, the walk latch.
    let latch_untouched = || -> bool { panic!("walk latch consulted") };
    let request = |scan: &SourceScanResult, bootstrap| {
        resident_scan_request_after_settlement(
            scan,
            bootstrap,
            latch_untouched,
            PlatformState::Allowed,
            true,
        )
    };
    assert_eq!(request(&scan, true), Some(true));
    scan.charge_deferred = true;
    assert_eq!(request(&scan, false), Some(false));
    scan.charge_deferred = false;
    scan.routine_recensus = true;
    check(&scan, false, true, PlatformState::Allowed, None, false);
    scan.routine_recensus = false;
    scan.census_status.pending_work = false;
    check(&scan, false, true, PlatformState::Allowed, None, false);
    scan.census_status.pending_work = true;
    scan.page_file_limit_hit = false;
    check(&scan, false, true, PlatformState::Allowed, None, false);
}

fn pacing_index(queued: bool) -> ScanIndex {
    let key = "/synthetic/work.jsonl";
    let fp = "a".repeat(64);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.into(),
        crate::snapshots::ScanIndexEntry {
            last_snapshot_fingerprint: Some(fp.clone()),
            ..Default::default()
        },
    );
    let mut value = serde_json::to_value(index).unwrap();
    value["file_snapshot_fingerprints"] = serde_json::json!({key: [fp]});
    value["traversal"] = serde_json::json!({
        "context_fingerprint": "context", "census_window_end": WALK_START,
        "scan_roots": ["/synthetic"], "pending_directories": [],
        "pending_candidates": if queued { serde_json::json!([{
            "scan_root": "/synthetic", "path": key, "census_member": true
        }]) } else { serde_json::json!([]) },
        "observed_index_keys": [], "reconciliation_upper_bound": key,
        "reconciliation_after": null, "reconciliation_started": false, "counts": {}
    });
    serde_json::from_value(value).unwrap()
}

fn walk_request(scan: &SourceScanResult, index: &ScanIndex, power: PlatformState) -> Option<bool> {
    resident_scan_request_after_settlement(
        scan,
        true,
        || false,
        power,
        index.runnable_walk_or_followup(scan, &Default::default(), false, false, WALK_NOW),
    )
}

#[test]
fn first_import_open_walk_pacing_decision_table() {
    let mut scan = empty_scan();
    scan.routine_recensus = true;
    scan.census_status.pending_work = false;
    scan.census_status.reconciliation_incomplete = true;
    scan.state_census_complete = true;
    scan.sidecar_census_complete = true;
    let open = pacing_index(true);
    let empty = pacing_index(false);
    let mut followup = serde_json::to_value(&empty).unwrap();
    followup["traversal"] = serde_json::Value::Null;
    let clean: ScanIndex = serde_json::from_value(followup.clone()).unwrap();
    followup["bounded_sweep_had_unsettled_upload"] = serde_json::json!(true);
    let followup: ScanIndex = serde_json::from_value(followup).unwrap();
    let mut reconciliation = serde_json::to_value(&empty).unwrap();
    reconciliation["traversal"]["reconciliation_started"] = serde_json::json!(true);
    let reconciliation: ScanIndex = serde_json::from_value(reconciliation).unwrap();
    for source in ROTATION {
        scan.source = source;
        for (name, index, runnable) in [
            ("queued census", &open, true),
            ("owed clean followup", &followup, true),
            ("empty healthy/stalled finalization", &empty, false),
            ("executable reconciliation", &reconciliation, true),
            ("clean close", &clean, false),
        ] {
            for power in [
                PlatformState::Allowed,
                PlatformState::Battery,
                PlatformState::Refused,
                PlatformState::Unknown,
            ] {
                let requested = walk_request(&scan, index, power);
                assert_eq!(
                    requested,
                    (runnable && power == PlatformState::Allowed).then_some(true),
                    "{source:?} {name} {power:?}"
                );
                let runnable = index.runnable_walk_or_followup(
                    &scan,
                    &Default::default(),
                    false,
                    false,
                    WALK_NOW,
                );
                assert_eq!(
                    resident_scan_request_after_settlement(&scan, false, || false, power, runnable),
                    None,
                    "bootstrap complete {source:?} {name}"
                );
            }
        }
        for index in [&empty, &reconciliation, &followup] {
            scan.state_census_complete = false;
            assert_eq!(
                walk_request(&scan, index, PlatformState::Allowed),
                None,
                "metadata only"
            );
            scan.state_census_complete = true;
            scan.sidecar_census_complete = false;
            assert_eq!(
                walk_request(&scan, index, PlatformState::Allowed),
                None,
                "sidecar only"
            );
            scan.sidecar_census_complete = true;
        }
    }
}

#[test]
fn blocked_followup_debt_grants_no_new_request_but_queued_siblings_do() {
    use crate::snapshots::UnsettledUploadCause;
    let mut scan = empty_scan();
    scan.state_census_complete = true;
    scan.sidecar_census_complete = true;
    let mut index = pacing_index(false);
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::DeferredConflict);
    assert!(!index.runnable_walk_or_followup(&scan, &Default::default(), true, true, WALK_NOW));
    for cause in [
        UnsettledUploadCause::CompletedBlockingHolds,
        UnsettledUploadCause::RejectedWithHolds,
    ] {
        let mut held = index.clone();
        held.mark_bounded_sweep_unsettled_by(cause);
        assert!(!held.runnable_walk_or_followup(
            &scan,
            &Default::default(),
            false,
            false,
            WALK_NOW
        ));
    }
    let mut value = serde_json::to_value(&index).unwrap();
    value["quarantined_snapshot_fingerprints"] = serde_json::json!({
        "a".repeat(64): crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex)
    });
    let conflicted: ScanIndex = serde_json::from_value(value.clone()).unwrap();
    assert!(!conflicted.runnable_walk_or_followup(
        &scan,
        &Default::default(),
        false,
        false,
        WALK_NOW
    ));
    value["traversal"]["pending_candidates"] = serde_json::json!([{
        "scan_root": "/synthetic", "path": "/synthetic/work.jsonl", "census_member": true
    }]);
    let held: ScanIndex = serde_json::from_value(value.clone()).unwrap();
    assert!(!held.runnable_walk_or_followup(&scan, &Default::default(), false, false, WALK_NOW));
    value["traversal"]["pending_candidates"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "scan_root": "/synthetic", "path": "/synthetic/sibling.jsonl", "census_member": true
        }));
    let sibling: ScanIndex = serde_json::from_value(value).unwrap();
    assert!(sibling.runnable_walk_or_followup(&scan, &Default::default(), true, false, WALK_NOW));
    let local = std::collections::BTreeSet::from(["a".repeat(64)]);
    assert!(pacing_index(true).runnable_walk_or_followup(
        &scan,
        &Default::default(),
        true,
        false,
        WALK_NOW
    ));
    assert!(!pacing_index(true).runnable_walk_or_followup(&scan, &local, true, false, WALK_NOW));
}

#[test]
fn decode_held_followup_and_candidate_are_not_runnable() {
    let mut scan = empty_scan();
    let home = crate::test_scratch::private_dir("pacing-decode-hold");
    let path = home.join("index.json");
    let mut value = serde_json::to_value(pacing_index(true)).unwrap();
    value["bounded_sweep_had_unsettled_upload"] = serde_json::json!(true);
    value["files"]["/synthetic/work.jsonl"]["size_bytes"] = serde_json::json!("invalid");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let index = ScanIndex::load(&path).unwrap();
    assert!(index.decode_held_file_keys().next().is_some());
    scan.state_census_complete = true;
    scan.sidecar_census_complete = true;
    assert!(!index.runnable_walk_or_followup(&scan, &Default::default(), false, true, WALK_NOW));
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn terminal_retry_eligibility_dominates_followup_debt_and_nonmember_rereads() {
    let mut scan = empty_scan();
    let now = crate::snapshots::rfc3339_unix_seconds(WALK_NOW).unwrap();
    for source in ROTATION {
        scan.source = source;
        let mut index = ScanIndex::default();
        index.install_terminal_unhealthy_traversal_for_retry_test(source, &[], 30, now + 60);
        index.mark_bounded_sweep_unsettled();
        let mut value = serde_json::to_value(index).unwrap();
        value["traversal"]["census_window_end"] = serde_json::json!(WALK_START);
        value["traversal"]["pending_candidates"] = serde_json::json!([{
            "scan_root": "/synthetic", "path": "/synthetic/live.jsonl", "census_member": false
        }]);
        for (deadline, expected) in [
            (Some(now + 60), false),
            (Some(now), true),
            (None, true),
            (Some(now + 7200), true),
        ] {
            value["traversal"]["unhealthy_retry_not_before_unix_seconds"] =
                serde_json::json!(deadline);
            let index: ScanIndex = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(
                index.runnable_walk_or_followup(&scan, &Default::default(), false, true, WALK_NOW),
                expected,
                "{source:?} deadline {deadline:?}"
            );
        }
        value["traversal"]["unhealthy_retry_not_before_unix_seconds"] = serde_json::json!(now + 60);
        let mut mid_walk = value.clone();
        mid_walk["traversal"]["pending_candidates"][0]["census_member"] = serde_json::json!(true);
        let mid_walk: ScanIndex = serde_json::from_value(mid_walk).unwrap();
        assert!(mid_walk.runnable_walk_or_followup(
            &scan,
            &Default::default(),
            false,
            false,
            WALK_NOW
        ));
        let mut index: ScanIndex = serde_json::from_value(value).unwrap();
        index.insert_retry_pending_claude_authority_for_test("family");
        let mut value = serde_json::to_value(index).unwrap();
        value["claude_usage_authority_quarantine"]["family"]["retry_after_unix_seconds"] =
            serde_json::json!(now);
        let index: ScanIndex = serde_json::from_value(value).unwrap();
        assert_eq!(
            index.runnable_walk_or_followup(&scan, &Default::default(), false, true, WALK_NOW),
            source == SnapshotSource::ClaudeCode,
            "family override {source:?}"
        );
    }
}

#[test]
fn first_import_final_page_conflict_requests_followup_after_settlement() {
    let mut scan = empty_scan();
    scan.census_complete = true;
    scan.state_census_complete = true;
    scan.sidecar_census_complete = true;
    let mut index = ScanIndex::default();
    let requested = |index: &ScanIndex, fresh| {
        resident_scan_request_after_settlement(
            &scan,
            true,
            || true,
            PlatformState::Allowed,
            index.runnable_walk_or_followup(&scan, &Default::default(), false, fresh, WALK_NOW),
        )
    };
    assert_eq!(requested(&index, true), None);
    index.mark_bounded_sweep_unsettled_by(crate::snapshots::UnsettledUploadCause::DeferredConflict);
    let saved: ScanIndex = serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
    assert_eq!(requested(&saved, true), Some(true));
    assert_eq!(requested(&ScanIndex::default(), true), None, "clean close");
}

#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn first_import_open_walk_pacing_obeys_upload_shed_deadline_and_unplug() {
    use super::super::{defer_source_uploads, paced_scan_due};
    let _saved = OwnedCadences::install();
    super::super::clear_cadence_state_for_test();
    super::super::clear_source_upload_deadlines_for_test();
    let scan = empty_scan();
    let index = pacing_index(true);
    crate::scan_clock::with_clock(1000, || {
        let now = crate::scan_clock::now();
        for source in ROTATION {
            with_source_cadence(source, |cadence| cadence.record_scan_success(now, 0));
            let first_import = walk_request(&scan, &index, PlatformState::Allowed).unwrap();
            assert!(
                first_import,
                "every first-import request carries the import flag"
            );
            request_resident_scan_on_power(source, first_import, PlatformState::Allowed);
            with_source_cadence(source, |cadence| {
                assert_eq!(
                    cadence.paced_scan_due(),
                    Some(now + Duration::from_secs(30))
                );
                assert_eq!(
                    paced_pass_qos(PlatformState::Battery, cadence.paced_first_import()),
                    PassQos::Background
                );
                assert_eq!(
                    walk_request(&scan, &index, PlatformState::Battery),
                    None,
                    "no renewal"
                );
                cadence.set_server_min_interval(Some(Duration::from_secs(90)));
                assert!(cadence.next_scan_after(now) >= Duration::from_secs(90));
            });
            defer_source_uploads(source, Duration::from_secs(120));
        }
        assert_eq!(paced_scan_due(), Some(now + Duration::from_secs(120)));
        for source in ROTATION {
            assert!(source_paced_due(source).is_none());
            after_ordinary_source_failure(source);
        }
        assert_eq!(paced_scan_due(), None);
    });
    super::super::clear_source_upload_deadlines_for_test();
    super::super::clear_cadence_state_for_test();
}

/// `count` Codex rollouts of about 1.7 KiB each in `root`, numbered from `first`.
fn codex_rollouts(root: &Path, first: u64, count: u64) -> Vec<PathBuf> {
    (first..first + count)
        .map(|n| {
            let session = format!("019fa111-2222-7333-8444-{n:012}");
            let path = root.join(format!("rollout-2026-10-24T00-00-00-{session}.jsonl"));
            std::fs::write(&path, rollout_body(&session, 5)).unwrap();
            path
        })
        .collect()
}

/// [behaviour] Byte-bound Codex pages ask for paced passes during the first
/// backfill. Once census completion marks the backfill state, new large
/// files still spend the byte budget but ask for nothing. A pending replay
/// revision is not a first backfill.
#[test]
fn first_read_byte_pacing_stops_when_backfill_completes() {
    use super::super::backfill_replay_pending;
    use crate::backfill::{
        bootstrap_pending_for_destination, mark_backfill_complete_for_destination, BackfillState,
    };
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    const DESTINATION: &str = "first-read-destination";
    let codex = SnapshotSource::Codex;
    let bootstrap = |state: &BackfillState| {
        backfill_replay_pending(codex, state, DESTINATION)
            && bootstrap_pending_for_destination(state, codex, DESTINATION)
    };
    let home = crate::test_scratch::private_dir("first-read-byte-pacing")
        .canonicalize()
        .unwrap();
    let root = home.join(".codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    codex_rollouts(&root, 0, 6);
    let scanner = E2ScanFixture::default();
    let mut state = BackfillState::default();
    crate::snapshots::with_test_limits_for_test(1 << 20, 4096, 64, || {
        let page = |index, hints: &[PathBuf]| {
            let roots = std::slice::from_ref(&root);
            let (index, scan, _) =
                scanner.scan_other_page(codex, roots, &home, index, true, 100, hints);
            (index, scan)
        };
        let (mut index, mut paced, mut complete) = (ScanIndex::default(), 0, false);
        for _ in 0..16 {
            let (next, scan) = page(index, &[]);
            index = next;
            paced += usize::from(resident_scan_requested(&scan, bootstrap(&state)));
            complete = scan.census_complete;
            if complete {
                break;
            }
        }
        assert!(
            complete && paced > 0,
            "{paced} paced pages, complete {complete}"
        );
        mark_backfill_complete_for_destination(&mut state, codex, DESTINATION);
        assert!(!bootstrap(&state));
        let hints = codex_rollouts(&root, 100, 6);
        let mut byte_bound = 0;
        for _ in 0..16 {
            let (next, scan) = page(index, &hints);
            index = next;
            byte_bound += usize::from(scan.page_byte_budget_hit && scan.census_status.pending_work);
            assert!(!resident_scan_requested(&scan, bootstrap(&state)));
            if byte_bound > 0 {
                break;
            }
        }
        assert!(
            byte_bound > 0,
            "new large files still spend the byte budget"
        );
    });
    state
        .completed_destination_replays
        .get_mut("codex")
        .unwrap()
        .insert(DESTINATION.into(), "codex_replay:v0".into());
    assert!(backfill_replay_pending(codex, &state, DESTINATION));
    assert!(!bootstrap(&state), "a pending replay revision");
    std::fs::remove_dir_all(home).unwrap();
}

/// [behaviour] First-read progress asks for pacing with queued work only
/// during a first backfill, while the census is unfinished and the pass is not
/// a routine re-census. The charge, file-limit and byte-budget terms keep their
/// own rules, and a routine pass ignores progress.
#[test]
fn first_read_progress_pages_pace_only_during_a_first_backfill() {
    let mut scan = empty_scan();
    for bits in 0..=u8::MAX {
        let [bootstrap, pending, progress, byte_hit, file_hit, routine, charge, complete] =
            [1, 2, 4, 8, 16, 32, 64, 128].map(|bit| bits & bit != 0);
        scan.census_status.pending_work = pending;
        scan.first_read_progress = progress;
        scan.page_byte_budget_hit = byte_hit;
        scan.page_file_limit_hit = file_hit;
        scan.routine_recensus = routine;
        scan.charge_deferred = charge;
        scan.census_complete = complete;
        let existing = charge || (pending && ((file_hit && !routine) || (bootstrap && byte_hit)));
        let progress_term = bootstrap && pending && progress && !routine && !complete;
        let requested = resident_scan_requested(&scan, bootstrap);
        assert_eq!(requested, existing || progress_term, "{bits:08b}");
        for power in [
            PlatformState::Allowed,
            PlatformState::Battery,
            PlatformState::Refused,
            PlatformState::Unknown,
        ] {
            assert_eq!(
                resident_scan_request_after_settlement(&scan, bootstrap, || false, power, false),
                requested.then_some(bootstrap),
                "old predicate and QoS {bits:08b} {power:?}"
            );
        }
        if !bootstrap {
            scan.first_read_progress = !progress;
            assert_eq!(
                resident_scan_requested(&scan, false),
                requested,
                "{bits:08b}"
            );
        }
    }
    // The read that completes the census, with non-member work still queued,
    // asks for no further paced pass.
    let mut scan = empty_scan();
    (scan.census_status.pending_work, scan.first_read_progress) = (true, true);
    scan.census_complete = true;
    assert!(!resident_scan_requested(&scan, true));
}

/// One valid synthetic transcript of `source` in `dir`, numbered `n`.
fn first_read_file(source: SnapshotSource, dir: &Path, n: u64) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    match source {
        SnapshotSource::Codex => codex_rollouts(dir, n, 1).remove(0),
        SnapshotSource::ClaudeCode => {
            let session = format!("a0000000-0000-4000-8000-{n:012}");
            let path = dir.join(format!("{session}.jsonl"));
            std::fs::write(&path, claude_line(&session, n)).unwrap();
            path
        }
        SnapshotSource::Pi => {
            let path = dir.join(format!("session-{n}.jsonl"));
            std::fs::write(&path, pi_line(n)).unwrap();
            path
        }
    }
}

fn claude_line(session: &str, n: u64) -> String {
    let line = serde_json::json!({"type": "assistant", "version": "2.1.309",
        "sessionId": session, "timestamp": "2026-08-02T07:00:00Z",
        "requestId": format!("request-{n}"), "message": {"id": format!("message-{n}"),
        "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 1}}});
    format!("{line}\n")
}

fn pi_line(n: u64) -> String {
    let line = serde_json::json!({"type": "message_end", "message": {"model": "gpt-5.4",
        "timestamp": 1_793_088_001_000_u64 + n, "usage": {"input": 1, "output": 1}}});
    format!("{line}\n")
}

/// A fresh index; Claude also loads its (empty) re-emission exclusions.
fn first_read_index(source: SnapshotSource, home: &Path) -> ScanIndex {
    let mut index = ScanIndex::default();
    if source == SnapshotSource::ClaudeCode {
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(home, &[]);
        index.load_claude_reemission_exclusions(home);
    }
    index
}

/// The scan root of `source` under `home`.
fn first_read_root(source: SnapshotSource, home: &Path) -> PathBuf {
    home.join(match source {
        SnapshotSource::ClaudeCode => ".claude/projects",
        SnapshotSource::Codex => ".codex/sessions",
        SnapshotSource::Pi => ".pi/agent/sessions",
    })
}

/// One page of `source` over `root`: Claude through its own scan seam.
#[expect(clippy::too_many_arguments, reason = "test helper, 8 page inputs")]
fn first_read_page(
    scanner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    source: SnapshotSource,
    root: &Path,
    home: &Path,
    index: ScanIndex,
    limit: usize,
    sampled: bool,
    hints: &[PathBuf],
) -> (ScanIndex, SourceScanResult) {
    let roots = [root.to_path_buf()];
    let (index, scan, _) = if source == SnapshotSource::ClaudeCode {
        let births = std::collections::BTreeMap::new();
        scanner.scan(&roots, home, index, limit, sampled, &births, hints)
    } else {
        scanner.scan_other_page(source, &roots, home, index, sampled, limit, hints)
    };
    (index, scan)
}

/// [behaviour] During a first backfill, listing ticks and small-file pages
/// ask for paced passes although they fill no file allowance and spend no
/// byte budget. A page that reads nothing new and finishes its listing asks
/// for nothing, and once the backfill is marked complete no page asks.
#[test]
fn first_read_progress_paces_first_import_listing_and_small_file_pages() {
    use super::super::backfill_replay_pending;
    use crate::backfill::{
        bootstrap_pending_for_destination, mark_backfill_complete_for_destination, BackfillState,
    };
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use crate::snapshots::with_test_directory_entries;
    const DESTINATION: &str = "first-read-progress-destination";
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let bootstrap = |state: &BackfillState| {
            backfill_replay_pending(source, state, DESTINATION)
                && bootstrap_pending_for_destination(state, source, DESTINATION)
        };
        let home = crate::test_scratch::private_dir("first-read-progress")
            .canonicalize()
            .unwrap();
        let root = first_read_root(source, &home);
        // Codex rollouts sit in their file date's day directory.
        let dirs: &[&str] = match source {
            SnapshotSource::ClaudeCode => &["project-a", "project-b"],
            SnapshotSource::Codex => &["2026/10/24"],
            SnapshotSource::Pi => &["2026/10/23", "2026/10/24"],
        };
        for (d, dir) in (0_u64..).zip(dirs) {
            for n in 0..2 {
                first_read_file(source, &root.join(dir), d * 10 + n);
            }
        }
        let scanner = E2ScanFixture::default();
        let page =
            |index, limit| first_read_page(&scanner, source, &root, &home, index, limit, true, &[]);
        let mut state = BackfillState::default();
        assert!(bootstrap(&state), "{source:?}");
        // Walk one directory per tick until the census completes.
        let walk = |state: &BackfillState| {
            with_test_directory_entries(1, || {
                let mut index = first_read_index(source, &home);
                let (mut listing, mut reading) = (0, 0);
                for _ in 0..32 {
                    let (next, scan) = page(index, 100);
                    index = next;
                    let pending = scan.census_status.pending_work;
                    assert!(
                        !scan.page_file_limit_hit && !scan.page_byte_budget_hit,
                        "{source:?}"
                    );
                    assert!(!scan.charge_deferred, "{source:?}");
                    assert!(!resident_scan_requested(&scan, false), "{source:?}");
                    assert_eq!(
                        resident_scan_requested(&scan, bootstrap(state)),
                        bootstrap(state)
                            && pending
                            && scan.first_read_progress
                            && !scan.routine_recensus
                            && !scan.census_complete,
                        "{source:?}"
                    );
                    if pending && scan.first_read_progress {
                        if scan.scanned_file_count == 0 {
                            listing += 1;
                        } else {
                            reading += 1;
                        }
                    }
                    if scan.census_complete {
                        return (listing, reading);
                    }
                }
                panic!("{source:?} census did not complete");
            })
        };
        let (listing, reading) = walk(&state);
        assert!(listing > 0, "{source:?}: listing ticks ask");
        if source != SnapshotSource::Codex {
            assert!(reading > 0, "{source:?}: small-file pages ask");
        }

        // One full listing tick and no selection: queued work, no progress.
        let (index, stuck) = page(first_read_index(source, &home), 0);
        assert!(stuck.census_status.pending_work, "{source:?}");
        assert_eq!(stuck.scanned_file_count, 0, "{source:?}");
        assert!(!stuck.first_read_progress, "{source:?}");
        assert!(!resident_scan_requested(&stuck, bootstrap(&state)));
        let (index, stuck) = page(index, 0);
        assert!(stuck.census_status.pending_work && !stuck.first_read_progress);
        assert!(!resident_scan_requested(&stuck, bootstrap(&state)));
        // Reading the new census members is progress, even after listing ends.
        let (_, read) = page(index, 100);
        assert!(read.scanned_file_count > 0 && read.first_read_progress);

        mark_backfill_complete_for_destination(&mut state, source, DESTINATION);
        assert!(!bootstrap(&state), "{source:?}");
        let (listing, _) = walk(&state);
        assert!(listing > 0, "{source:?}: progress without a first backfill");
        std::fs::remove_dir_all(home).unwrap();
    }
}

/// [behaviour] A Codex freshness page reads up to 256 hinted first-read files,
/// fills no file allowance and spends no byte budget, yet asks for a paced
/// pass during a first backfill while census work stays queued.
#[test]
fn codex_small_file_pages_pace_during_a_first_import() {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    let home = crate::test_scratch::private_dir("codex-small-file-pacing")
        .canonicalize()
        .unwrap();
    let root = first_read_root(SnapshotSource::Codex, &home);
    std::fs::create_dir_all(&root).unwrap();
    let hints = codex_rollouts(&root, 0, 300);
    let scanner = E2ScanFixture::default();
    let (mut index, mut asked, mut complete) = (ScanIndex::default(), 0, false);
    for page in 0..8 {
        let hinted: &[PathBuf] = if page == 0 { &hints } else { &[] };
        let codex = SnapshotSource::Codex;
        let (next, scan) = first_read_page(&scanner, codex, &root, &home, index, 280, true, hinted);
        index = next;
        if scan.scanned_file_count > 0
            && scan.census_status.pending_work
            && !scan.page_file_limit_hit
            && !scan.page_byte_budget_hit
            && !scan.charge_deferred
            && !scan.census_complete
        {
            assert!(scan.first_read_progress, "page {page}");
            assert!(resident_scan_requested(&scan, true), "page {page}");
            assert!(!resident_scan_requested(&scan, false), "page {page}");
            asked += 1;
        }
        complete = scan.census_complete;
        if complete {
            break;
        }
    }
    assert!(complete && asked > 0, "{asked} small-file pages asked");
    std::fs::remove_dir_all(home).unwrap();
}

/// [regress] During a first backfill with census work still queued, a page
/// that only re-reads a recorded live session (a watcher hint), retries an
/// unreadable file or fails to parse one reports no first-read progress and
/// asks for nothing. Claude and Pi count every hint as a census member.
#[cfg(unix)]
#[test]
fn first_read_progress_ignores_rereads_and_stuck_tails() {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use crate::snapshots::with_test_directory_entries;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        let home = crate::test_scratch::private_dir("first-read-stuck")
            .canonicalize()
            .unwrap();
        let root = first_read_root(source, &home);
        let (a, b) = (root.join("a"), root.join("b"));
        let live = first_read_file(source, &a, 1);
        let unreadable = first_read_file(source, &a, 2);
        let broken = first_read_file(source, &a, 3);
        std::fs::write(&broken, "not json\n").unwrap();
        first_read_file(source, &b, 4);
        let mode = |mode| std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&unreadable, mode(0o000)).unwrap();
        let scanner = E2ScanFixture::default();
        let page = |index, budget, hints: &[PathBuf]| {
            with_test_directory_entries(budget, || {
                first_read_page(&scanner, source, &root, &home, index, 100, false, hints)
            })
        };
        // The root, then `a`: its readable session is a first read.
        let (index, listed) = page(first_read_index(source, &home), 1, &[]);
        assert!(listed.census_status.pending_work, "{source:?}");
        assert!(listed.first_read_progress, "{source:?}");
        let (index, read) = page(index, 1, &[]);
        assert!(read.census_status.pending_work, "{source:?}: b is queued");
        assert!(read.first_read_progress, "{source:?}");
        assert!(index.files.iter().next().is_some(), "{source:?}");
        // No listing budget: only the hinted live session and the stuck files.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&live)
            .unwrap();
        let line = match source {
            SnapshotSource::ClaudeCode => claude_line("a0000000-0000-4000-8000-000000000001", 5),
            _ => pi_line(5),
        };
        file.write_all(line.as_bytes()).unwrap();
        drop(file);
        let (index, reread) = page(index, 0, std::slice::from_ref(&live));
        assert!(
            reread.scanned_file_count > 0,
            "{source:?}: the live re-read"
        );
        assert!(reread.census_status.pending_work, "{source:?}");
        assert!(!reread.first_read_progress, "{source:?}: a re-read");
        assert!(!resident_scan_requested(&reread, true), "{source:?}");
        let (index, stuck) = page(index, 0, &[]);
        assert!(stuck.census_status.pending_work, "{source:?}");
        assert!(!stuck.first_read_progress, "{source:?}: a stuck tail");
        assert!(!resident_scan_requested(&stuck, true), "{source:?}");
        // Listing `b` reads its new session again as progress.
        let (_, other) = page(index, 1, &[]);
        assert!(other.first_read_progress, "{source:?}");
        std::fs::set_permissions(&unreadable, mode(0o600)).unwrap();
        std::fs::remove_dir_all(home).unwrap();
    }
}

/// [behaviour] A resident wake starts another ordinary pass, releases the
/// sync lock while waiting, and adds no wake after a quiet successful drain.
#[test]
fn resident_wake_advances_ordinary_cycle_without_a_cursor_timer() {
    struct OrdinaryLoop {
        now: Instant,
        cadence: SourceCadence,
        lock: Mutex<()>,
        waits: Vec<Duration>,
    }
    impl LoopHost for OrdinaryLoop {
        fn now(&mut self) -> Instant {
            self.now
        }
        fn wait(&mut self, wait: Duration) -> bool {
            assert!(self.lock.try_lock().is_ok());
            self.waits.push(wait);
            self.now += wait;
            false
        }
        fn pending(&mut self) -> Option<(Instant, Duration)> {
            None
        }
        fn paced_due(&mut self) -> Option<Instant> {
            self.cadence.paced_scan_due()
        }
        fn page(&mut self, _: Instant) -> Outcome {
            panic!("no cursor page requested")
        }
    }
    for pacing in [PACED_AC, PACED_BATTERY] {
        let now = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.record_scan_success(now, 1);
        cadence.request_paced_scan(now, Duration::from_secs(103), pacing, false);
        cadence.clear_cursor_continuation(); // ordinary prepare drops only a cursor.
        assert!(cadence.continuation_due(PACING).is_none());
        let mut host = OrdinaryLoop {
            now,
            cadence,
            lock: Mutex::new(()),
            waits: Vec::new(),
        };
        wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
        assert_eq!(host.waits, [pacing.min_gap]);
        assert_eq!(host.cadence.next_scan_after(host.now), Duration::ZERO);
        host.cadence.record_scan_success(host.now, 0);
        wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
        assert_eq!(host.waits, [pacing.min_gap, SNAPSHOT_SYNC_INTERVAL]);
        host.cadence
            .request_paced_scan(host.now, Duration::from_secs(103), pacing, false);
        host.cadence.record_scan_failure(host.now);
        assert!(host.cadence.paced_scan_due().is_none());
    }
}

/// [behaviour] An upload shed delays only an existing paced request. Planner
/// peeks preserve both deadlines; at the wake the ordinary source gate admits it.
#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn paced_shed_wake_obeys_both_deadlines_and_source_errors_do_not_spin() {
    use super::super::{
        defer_source_uploads, paced_scan_due, source_cadence_wait, source_upload_deadlines,
    };
    struct ShedLoop {
        seconds: u64,
        waits: Vec<Duration>,
    }
    impl LoopHost for ShedLoop {
        fn now(&mut self) -> Instant {
            crate::scan_clock::with_clock(self.seconds, crate::scan_clock::now)
        }
        fn wait(&mut self, wait: Duration) -> bool {
            self.waits.push(wait);
            self.seconds += wait.as_secs();
            false
        }
        fn pending(&mut self) -> Option<(Instant, Duration)> {
            None
        }
        fn paced_due(&mut self) -> Option<Instant> {
            crate::scan_clock::with_clock(self.seconds, paced_scan_due)
        }
        fn page(&mut self, _: Instant) -> Outcome {
            panic!("an ordinary paced wake must not run a cursor page")
        }
    }
    let _saved = OwnedCadences::install();
    for source in ROTATION {
        for (gap, backoff) in [(0, 60), (30, 60), (60, 60), (180, 60), (30, 180)] {
            super::super::clear_cadence_state_for_test();
            super::super::clear_source_upload_deadlines_for_test();
            let mut host = ShedLoop {
                seconds: 1000,
                waits: Vec::new(),
            };
            let start = host.now();
            with_source_cadence(source, |cadence| {
                cadence.record_scan_success(start, 1);
                assert!(cadence.request_paced_scan(
                    start,
                    Duration::ZERO,
                    crate::adaptive_collector::ContinuationPacing {
                        min_gap: Duration::from_secs(gap),
                        idle_per_work: 0,
                    },
                    false,
                ));
            });
            crate::scan_clock::with_clock(1000, || {
                defer_source_uploads(source, Duration::from_secs(backoff));
                let due = start + Duration::from_secs(gap.max(backoff));
                assert_eq!(paced_scan_due(), Some(due));
                assert_eq!(paced_scan_due(), Some(due), "a peek consumes nothing");
                assert_eq!(source_upload_deadlines().lock().unwrap().len(), 1);
                assert!(
                    source_paced_due(source).is_none(),
                    "QoS still obeys backoff"
                );
            });
            wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
            assert_eq!(host.waits, [Duration::from_secs(gap.max(backoff))]);
            crate::scan_clock::with_clock(host.seconds, || {
                assert!(super::super::source_upload_backoff_remaining(source).is_none());
                assert_eq!(source_cadence_wait(source), None);
                // Prepare, scan or finish can fail after the shed deadline.
                // This is the same boundary used by the rotation's outcome.
                after_ordinary_source_failure(source);
                assert_eq!(paced_scan_due(), None);
            });
            wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
            assert_eq!(host.waits[1], SNAPSHOT_SYNC_INTERVAL, "no Wake(0) on error");
        }
    }
    super::super::clear_cadence_state_for_test();
    super::super::clear_source_upload_deadlines_for_test();
    crate::scan_clock::with_clock(1000, || {
        let start = crate::scan_clock::now();
        defer_source_uploads(SnapshotSource::Codex, Duration::from_secs(60));
        assert_eq!(
            paced_scan_due(),
            None,
            "no request is manufactured by a shed"
        );
        let mut host = ShedLoop {
            seconds: 1000,
            waits: Vec::new(),
        };
        wait_for_ordinary_cycle(&mut host, SNAPSHOT_SYNC_INTERVAL);
        assert_eq!(host.waits, [SNAPSHOT_SYNC_INTERVAL]);
        for (source, gap, backoff) in [
            (SnapshotSource::Codex, 30, 120),
            (SnapshotSource::ClaudeCode, 180, 60),
            (SnapshotSource::Pi, 30, 60),
        ] {
            with_source_cadence(source, |cadence| {
                cadence.record_scan_success(start, 1);
                cadence.request_paced_scan(
                    start,
                    Duration::ZERO,
                    crate::adaptive_collector::ContinuationPacing {
                        min_gap: Duration::from_secs(gap),
                        idle_per_work: 0,
                    },
                    false,
                );
            });
            defer_source_uploads(source, Duration::from_secs(backoff));
        }
        assert_eq!(paced_scan_due(), Some(start + Duration::from_secs(60)));
        // A Codex hint shed during prepare is still an error: its paced
        // request clears even while the newly supplied deadline stands.
        after_ordinary_source_failure(SnapshotSource::Codex);
        assert!(OwnedCadences::due(SnapshotSource::Codex).is_none());
        assert!(source_upload_deadlines()
            .lock()
            .unwrap()
            .contains_key("codex"));
        assert!(OwnedCadences::due(SnapshotSource::ClaudeCode).is_some());
    });
}

const UTILITY: (u32, i32) = (0x11, 0);
const BACKGROUND: (u32, i32) = (0x09, 0);
thread_local! {
    /// The fake thread QoS that the fake setter writes and the owner reads.
    static FAKE_QOS: Cell<(u32, i32)> = const { Cell::new(UTILITY) };
}
fn fake_qos() -> (u32, i32) {
    FAKE_QOS.with(Cell::get)
}
fn fake_set(class: u32, rel: i32) -> bool {
    FAKE_QOS.with(|qos| qos.set((class, rel)));
    true
}
fn fake_background() -> Option<MacPlatformSignals> {
    let mut signals = MacPlatformSignals {
        saved: None,
        setter: Some(fake_set),
    };
    (signals.enter(Some(fake_qos()), fake_set) == PlatformState::Allowed).then_some(signals)
}
fn refused_background() -> Option<MacPlatformSignals> {
    None
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    None,
    PrepareNone,
    PrepareErr,
    ValidateErr,
    Refused,
    FinishErr,
    Panic,
}

/// A rotation owner holding the paced QoS exactly as `SnapshotCycleOwner`
/// does: entered in `prepare`, dropped in `outcome`. Faults hit Codex only.
struct PacedOwner {
    fault: Fault,
    background: fn() -> Option<MacPlatformSignals>,
    power: PlatformState,
    paced_qos: Option<MacPlatformSignals>,
    seen: Vec<(SnapshotSource, &'static str, (u32, i32))>,
}
impl PacedOwner {
    fn new(fault: Fault, background: fn() -> Option<MacPlatformSignals>) -> Self {
        Self {
            fault,
            background,
            power: PlatformState::Allowed,
            paced_qos: None,
            seen: Vec::new(),
        }
    }
    fn fault(&mut self, source: SnapshotSource, stage: &'static str) -> Fault {
        self.seen.push((source, stage, fake_qos()));
        if source == SnapshotSource::Codex {
            self.fault
        } else {
            Fault::None
        }
    }
}
impl crate::source_rotation::Owner for PacedOwner {
    type Source = SnapshotSource;
    type Frame = (SnapshotSource, u8);
    type Completed = SnapshotSource;
    fn prepare(
        &mut self,
        source: SnapshotSource,
        _: Option<usize>,
    ) -> anyhow::Result<Option<Self::Frame>> {
        drop(self.paced_qos.take());
        self.paced_qos = paced_source_qos(source, || self.power, self.background);
        match self.fault(source, "prepare") {
            Fault::PrepareNone => Ok(None),
            Fault::PrepareErr => Err(anyhow!("prepare")),
            _ => Ok(Some((source, 0))),
        }
    }
    fn validate(&mut self, frame: &Self::Frame) -> anyhow::Result<()> {
        match self.fault(frame.0, "validate") {
            Fault::ValidateErr => Err(anyhow!("validate")),
            _ => Ok(()),
        }
    }
    fn step(
        &mut self,
        (source, page): Self::Frame,
        _: Option<usize>,
    ) -> crate::source_rotation::Step<Self::Frame, SnapshotSource> {
        match self.fault(source, "page") {
            Fault::Refused => crate::source_rotation::Step::Refused(
                crate::source_rotation::LocalRefusal("fake refusal"),
            ),
            Fault::Panic => panic!("fake page panic"),
            _ if page < 2 => crate::source_rotation::Step::Pending((source, page + 1)),
            _ => crate::source_rotation::Step::Complete(source),
        }
    }
    fn finish(&mut self, source: SnapshotSource, _: Option<usize>) -> anyhow::Result<()> {
        match self.fault(source, "finish") {
            Fault::FinishErr => Err(anyhow!("finish")),
            _ => Ok(()),
        }
    }
    fn outcome(&mut self, source: SnapshotSource, _: anyhow::Result<()>) {
        self.fault(source, "outcome");
        drop(self.paced_qos.take());
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
}

/// Owns the three process cadence slots and upload deadlines for one control.
struct OwnedCadences(Vec<(&'static str, Option<SourceCadence>)>);
const ROTATION: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];
impl OwnedCadences {
    /// Codex has a due paced request, Claude a pending (not yet due) one and
    /// Pi none.
    fn install() -> Self {
        Self::install_with(false)
    }
    /// As [`OwnedCadences::install`], with each request's first-import reason.
    fn install_with(first_import: bool) -> Self {
        let mut cadences = super::super::source_cadences().lock().unwrap();
        let saved = ROTATION
            .iter()
            .map(|source| (source.api_slug(), cadences.remove(source.api_slug())))
            .collect();
        let now = Instant::now();
        let before = now.checked_sub(Duration::from_secs(40)).unwrap();
        for (source, last_scan) in [
            (SnapshotSource::ClaudeCode, now),
            (SnapshotSource::Codex, before),
            (SnapshotSource::Pi, before),
        ] {
            let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
            cadence.record_scan_success(last_scan, 1);
            if source != SnapshotSource::Pi {
                assert!(cadence.request_paced_scan(
                    last_scan,
                    Duration::ZERO,
                    PACED_AC,
                    first_import
                ));
            }
            cadences.insert(source.api_slug(), cadence);
        }
        drop(cadences);
        super::super::source_upload_deadlines()
            .lock()
            .unwrap()
            .clear();
        Self(saved)
    }
    fn due(source: SnapshotSource) -> Option<Instant> {
        with_source_cadence(source, |cadence| cadence.paced_scan_due()).flatten()
    }
}
impl Drop for OwnedCadences {
    fn drop(&mut self) {
        super::super::source_upload_deadlines()
            .lock()
            .unwrap()
            .clear();
        let mut cadences = super::super::source_cadences()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for (slug, cadence) in self.0.drain(..) {
            cadences.remove(slug);
            if let Some(cadence) = cadence {
                cadences.insert(slug, cadence);
            }
        }
    }
}

/// [behaviour] Only the source whose own paced scan is due runs its prepare,
/// pages and finish at background QoS; siblings in the same cycle keep the
/// original QoS, and every outcome, error, refusal and unwind restores it.
#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn paced_qos_covers_only_the_due_source_and_restores_on_every_exit() {
    for fault in [
        Fault::None,
        Fault::PrepareNone,
        Fault::PrepareErr,
        Fault::ValidateErr,
        Fault::Refused,
        Fault::FinishErr,
    ] {
        let _cadences = OwnedCadences::install();
        let mut owner = PacedOwner::new(fault, fake_background);
        crate::source_rotation::run(&mut owner, &ROTATION, usize::MAX);
        assert_eq!(fake_qos(), UTILITY, "{fault:?}: restored after the cycle");
        for (source, stage, qos) in &owner.seen {
            let expected = if *source == SnapshotSource::Codex {
                BACKGROUND
            } else {
                UTILITY
            };
            assert_eq!(*qos, expected, "{fault:?}: {source:?} {stage}");
        }
        let stages = |source| {
            owner
                .seen
                .iter()
                .filter(move |(seen, _, _)| *seen == source)
                .map(|(_, stage, _)| *stage)
        };
        assert!(stages(SnapshotSource::Pi)
            .eq(["prepare", "validate", "page", "page", "page", "finish", "outcome"]));
        if fault == Fault::None {
            assert!(stages(SnapshotSource::Codex)
                .eq(["prepare", "validate", "page", "page", "page", "finish", "outcome"]));
        }
        assert!(
            OwnedCadences::due(SnapshotSource::Codex).is_some(),
            "{fault:?}"
        );
        assert!(
            OwnedCadences::due(SnapshotSource::ClaudeCode).is_some(),
            "{fault:?}"
        );
    }

    // Unwind out of the due source's page drops the owner and restores.
    let _cadences = OwnedCadences::install();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut owner = PacedOwner::new(Fault::Panic, fake_background);
        crate::source_rotation::run(&mut owner, &ROTATION, usize::MAX);
    }));
    assert!(unwound.is_err());
    assert_eq!(fake_qos(), UTILITY, "restored on unwind");
    drop(_cadences);

    // A source under upload backoff is not paced, so it keeps its QoS.
    let _cadences = OwnedCadences::install();
    super::super::source_upload_deadlines()
        .lock()
        .unwrap()
        .insert(
            SnapshotSource::Codex.api_slug(),
            Instant::now() + Duration::from_secs(600),
        );
    let mut owner = PacedOwner::new(Fault::None, fake_background);
    crate::source_rotation::run(&mut owner, &ROTATION, usize::MAX);
    assert!(owner.seen.iter().all(|(_, _, qos)| *qos == UTILITY));
    assert!(OwnedCadences::due(SnapshotSource::Codex).is_some());
}

/// [behaviour] A refused QoS entry clears only the due source's paced request,
/// before its cadence gate; siblings keep theirs and nothing is lowered.
#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn refused_paced_qos_clears_only_that_sources_request() {
    let _cadences = OwnedCadences::install();
    let mut owner = PacedOwner::new(Fault::PrepareNone, refused_background);
    crate::source_rotation::run(&mut owner, &ROTATION, usize::MAX);
    assert!(owner.seen.iter().all(|(_, _, qos)| *qos == UTILITY));
    assert!(
        OwnedCadences::due(SnapshotSource::Codex).is_none(),
        "cleared"
    );
    assert!(
        OwnedCadences::due(SnapshotSource::ClaudeCode).is_some(),
        "a sibling's pending request survives"
    );
    assert_eq!(fake_qos(), UTILITY);
}

/// [behaviour] Only a paced request made during the first import, on AC,
/// runs its whole pass at the thread's default QoS and keeps its request; a
/// routine AC request stays background. First-import requests on battery stay
/// background and Low Power Mode still clears. Source isolation, restoration
/// and the routine power rows are pinned by the tests above.
#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn first_import_paced_passes_keep_default_qos_only_on_ac() {
    use PlatformState::{Allowed, Battery, Refused};
    for (power, first_import, expected, codex_qos) in [
        (Allowed, true, PassQos::Default, UTILITY),
        (Allowed, false, PassQos::Background, BACKGROUND),
        (Battery, true, PassQos::Background, BACKGROUND),
        (Refused, true, PassQos::Cleared, UTILITY),
    ] {
        let case = format!("{power:?} {first_import}");
        assert_eq!(paced_pass_qos(power, first_import), expected, "{case}");
        let _cadences = OwnedCadences::install_with(first_import);
        let mut owner = PacedOwner::new(Fault::None, fake_background);
        owner.power = power;
        crate::source_rotation::run(&mut owner, &ROTATION, usize::MAX);
        for (_, stage, qos) in owner
            .seen
            .iter()
            .filter(|(s, ..)| *s == SnapshotSource::Codex)
        {
            assert_eq!(*qos, codex_qos, "{case}: {stage}");
        }
        let kept = OwnedCadences::due(SnapshotSource::Codex).is_some();
        assert_eq!(kept, expected != PassQos::Cleared, "{case}");
        let qos = paced_source_qos(SnapshotSource::Codex, || power, fake_background);
        assert_eq!(first_import_default_qos(), expected == PassQos::Default);
        drop(qos);
        leave_source_qos(&mut None);
        assert!(
            !first_import_default_qos(),
            "the row flag ends with the pass"
        );
    }
}

/// [behaviour] Through the finish-site request: a paced pass asked for during
/// the first backfill runs at default QoS on AC; once the backfill state marks
/// the import complete, the next paced request is background again, and the
/// earlier first-import reason does not outlive its request.
#[cfg(unix)]
#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn first_import_default_qos_ends_when_backfill_completes() {
    use super::super::backfill_replay_pending;
    use crate::backfill::{
        bootstrap_pending_for_destination, mark_backfill_complete_for_destination, BackfillState,
    };
    const DESTINATION: &str = "first-import-qos-destination";
    let codex = SnapshotSource::Codex;
    let mut state = BackfillState::default();
    super::super::source_upload_deadlines()
        .lock()
        .unwrap()
        .clear();
    super::super::resource_schedule::with_power("ac", || {
        for (seconds, complete, expected) in [(1000, false, UTILITY), (2000, true, BACKGROUND)] {
            if complete {
                mark_backfill_complete_for_destination(&mut state, codex, DESTINATION);
            }
            let first_read_bootstrap = backfill_replay_pending(codex, &state, DESTINATION)
                && bootstrap_pending_for_destination(&state, codex, DESTINATION);
            assert_eq!(first_read_bootstrap, !complete);
            crate::scan_clock::with_clock(seconds, || {
                with_source_cadence(codex, |cadence| {
                    cadence.record_scan_success(crate::scan_clock::now(), 1)
                });
                request_resident_scan(codex, first_read_bootstrap);
            });
            crate::scan_clock::with_clock(seconds + 30, || {
                let power = || MacPlatformSignals::default().power();
                let qos = paced_source_qos(codex, power, fake_background);
                assert_eq!(fake_qos(), expected, "complete {complete}");
                assert_eq!(first_import_default_qos(), !complete);
                drop(qos);
            });
        }
    });
}

/// [behaviour] A Codex selecting page takes the first-import page total only
/// while Codex's first import for the destination is pending and no other
/// granted source is importing for it. Every source bootstrapping a new
/// destination keeps the ordinary total; once the other sources complete
/// (here mid-walk), the next page takes the larger total; Codex's own
/// completion returns the next page to the ordinary total; a Full replay of
/// a completed destination is not a first import. A source the device does
/// not grant never syncs, so it never counts as importing.
#[test]
fn first_import_page_total_binds_only_while_codex_alone_imports() {
    use super::super::backfill_replay_pending;
    use super::super::prepare::first_import_alone;
    use crate::backfill::{mark_backfill_complete_for_destination, BackfillState};
    const DESTINATION: &str = "first-import-total-destination";
    let codex = SnapshotSource::Codex;
    let device = |sources: &[&str]| LocalDeviceBinding {
        device_id: "device".to_string(),
        machine_id: Some("machine".to_string()),
        sources: sources.iter().map(|source| source.to_string()).collect(),
    };
    let all = device(&["claude_code", "codex", "pi"]);
    // What prepare sets on the index before the page is built.
    let first_import = |state: &BackfillState, device: &LocalDeviceBinding| {
        backfill_replay_pending(codex, state, DESTINATION)
            && first_import_alone(codex, device, state, DESTINATION)
    };
    for (other, last) in [
        (SnapshotSource::ClaudeCode, SnapshotSource::Pi),
        (SnapshotSource::Pi, SnapshotSource::ClaudeCode),
    ] {
        let mut state = BackfillState::default();
        assert!(!first_import(&state, &all), "every source bootstrapping");
        assert!(
            first_import(&state, &device(&["codex"])),
            "Codex alone granted"
        );
        mark_backfill_complete_for_destination(&mut state, other, DESTINATION);
        assert!(!first_import(&state, &all), "{last:?} still bootstrapping");
        let without_last = device(&[other.api_slug(), "codex"]);
        assert!(first_import(&state, &without_last), "{last:?} not granted");
        mark_backfill_complete_for_destination(&mut state, last, DESTINATION);
        assert!(first_import(&state, &all), "Codex alone imports");
        // Only Codex reads the flag; another source's own first import is
        // not "alone" while Codex still imports.
        assert!(!first_import_alone(other, &all, &state, DESTINATION));
        // A new destination: every source bootstraps again.
        assert!(!first_import_alone(
            codex,
            &all,
            &state,
            "first-import-total-other"
        ));
        mark_backfill_complete_for_destination(&mut state, codex, DESTINATION);
        assert!(!first_import(&state, &all), "Codex completed: ordinary");
        state
            .completed_destination_replays
            .get_mut("codex")
            .unwrap()
            .insert(DESTINATION.into(), "codex_replay:v0".into());
        assert!(backfill_replay_pending(codex, &state, DESTINATION));
        assert!(
            !first_import(&state, &all),
            "a replay keeps the ordinary total"
        );
    }
}

#[test]
fn first_import_recensus_and_no_progress_pages_take_import_qos_on_ac_only() {
    // A routine re-census page and a page that read nothing new during the
    // first import: no page reason asks, so only the AC bootstrap arm can.
    for routine in [true, false] {
        let mut scan = empty_scan();
        scan.routine_recensus = routine;
        scan.census_status.pending_work = true;
        scan.first_read_progress = false;
        scan.page_file_limit_hit = false;
        assert!(!resident_scan_requested(&scan, true), "routine={routine}");
        let ac = resident_scan_request_after_settlement(
            &scan,
            true,
            || false,
            PlatformState::Allowed,
            true,
        );
        assert_eq!(ac, Some(true), "routine={routine}");
        assert_eq!(
            paced_pass_qos(PlatformState::Allowed, true),
            PassQos::Default
        );
        assert_eq!(
            resident_scan_request_after_settlement(
                &scan,
                true,
                || false,
                PlatformState::Battery,
                true
            ),
            None,
            "battery keeps its own pacing, routine={routine}"
        );
        assert_eq!(
            paced_pass_qos(PlatformState::Battery, true),
            PassQos::Background
        );
        assert_eq!(
            resident_scan_request_after_settlement(
                &scan,
                false,
                || false,
                PlatformState::Allowed,
                true
            ),
            None,
            "steady state, routine={routine}"
        );
    }
}

#[test]
#[serial_test::serial(source_cadences, source_upload_deadlines)]
fn destination_change_requests_paced_scan_only_when_first_import_is_owed() {
    let _saved = OwnedCadences::install();
    super::super::clear_cadence_state_for_test();
    super::super::clear_source_upload_deadlines_for_test();
    crate::scan_clock::with_clock(1000, || {
        let now = crate::scan_clock::now();
        for source in ROTATION {
            with_source_cadence(source, |cadence| cadence.record_scan_success(now, 0));
            // First import owed on the new destination, AC: paced, import flag.
            assert!(request_on_destination_change(
                source,
                "destination-a",
                PlatformState::Allowed,
                || true
            ));
            with_source_cadence(source, |cadence| {
                assert_eq!(
                    cadence.paced_scan_due(),
                    Some(now + Duration::from_secs(30))
                );
                assert!(cadence.paced_first_import());
            });
            // The same destination again never reads the backfill state.
            assert!(!request_on_destination_change(
                source,
                "destination-a",
                PlatformState::Allowed,
                || panic!("unchanged destination")
            ));
            // A change with nothing owed leaves the cadence as it is.
            with_source_cadence(source, SourceCadence::clear_continuation);
            assert!(!request_on_destination_change(
                source,
                "destination-b",
                PlatformState::Allowed,
                || false
            ));
            assert_eq!(
                with_source_cadence(source, |c| c.paced_scan_due()),
                Some(None)
            );
            // Battery keeps its own pacing and the background flag.
            assert!(request_on_destination_change(
                source,
                "destination-c",
                PlatformState::Battery,
                || true
            ));
            with_source_cadence(source, |cadence| {
                assert_eq!(
                    cadence.paced_scan_due(),
                    Some(now + Duration::from_secs(180))
                );
                assert!(!cadence.paced_first_import());
                cadence.clear_continuation();
            });
            // Refused or unknown power requests nothing.
            for power in [PlatformState::Refused, PlatformState::Unknown] {
                assert!(!request_on_destination_change(
                    source,
                    if power == PlatformState::Refused {
                        "destination-d"
                    } else {
                        "destination-e"
                    },
                    power,
                    || true
                ));
                assert_eq!(
                    with_source_cadence(source, |c| c.paced_scan_due()),
                    Some(None)
                );
            }
        }
    });
    super::super::clear_source_upload_deadlines_for_test();
    super::super::clear_cadence_state_for_test();
}
