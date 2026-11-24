// The walk gate on the real runner. A simulated watcher covers the roots
// and owns this thread's hint queue; `age_for_test` stands for wall time
// going by between passes. Every input is synthetic.
use super::*;
use crate::snapshot_watcher::{
    request_listing_all, simulate_transcript_events, with_simulated_watch, ListingTrigger,
};
use crate::snapshots::walk_idle::{self, WALK_GAP};

/// One cadence step between passes, as the slowest cadence would space them.
const STEP: u64 = 1800;
const SECOND_CODEX_THREAD: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";

fn roots(home: &OracleHome) -> Vec<PathBuf> {
    home.source.default_roots(&home.fixture.home)
}

fn install(home: &OracleHome) {
    match home.source {
        SnapshotSource::ClaudeCode => {}
        SnapshotSource::Codex => install_created_thread(home, false, IDENTITY_PIPELINE_ROOT, false),
        SnapshotSource::Pi => home.write_rows(&pi_rows(false)),
    }
}

fn transcript(home: &OracleHome) -> PathBuf {
    if home.source == SnapshotSource::Codex {
        roots(home)[0].join(format!("rollout-{IDENTITY_PIPELINE_ROOT}.jsonl"))
    } else {
        home.transcript()
    }
}

/// New usage that no hint announces. Codex gains a second thread (a new
/// rollout and its state rows); its home side files are not gate inputs.
fn change(home: &OracleHome) {
    let at = "2026-11-01T07:03:00Z";
    let line = match home.source {
        SnapshotSource::ClaudeCode => json!({"timestamp":at,"type":"assistant",
            "sessionId":IDENTITY_PIPELINE_ROOT,"requestId":"req_3","message":{"id":"m3",
            "model":"claude-haiku-4-5","usage":{"input_tokens":5,"output_tokens":1}}}),
        SnapshotSource::Pi => json!({"type":"message","timestamp":at,"message":{
            "role":"assistant","model":"gpt-5","provider":"openai","responseId":"late",
            "timestamp":at,"usage":{"input":4,"output":1}}}),
        SnapshotSource::Codex => {
            install_created_thread(home, false, SECOND_CODEX_THREAD, false);
            return;
        }
    };
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(transcript(home))
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

fn hint(home: &OracleHome) {
    simulate_transcript_events(home.source, &roots(home), &[transcript(home)]);
}

thread_local! {
    /// Passes move the oracle's scan clock instead of aging the gate's record.
    static MOVING_CLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One pass `aged` seconds after the previous one. On a moving clock the scan
/// clock itself advances, so time-due states and the backstop age together.
fn pass(home: &mut OracleHome, server: &OracleServer, recording: &Recording, aged: u64) -> Cycle {
    if MOVING_CLOCK.with(std::cell::Cell::get) {
        home.now += aged;
    } else {
        walk_idle::age_for_test(home.source, aged);
    }
    home.cycle(server, recording)
}

fn walked(cycle: &Cycle) -> bool {
    assert!(cycle.finish.is_ok(), "{:?}", cycle.finish);
    cycle.gate["census_complete"] == true
}

fn assert_idle(cycle: &Cycle) {
    assert!(!walked(cycle), "{}", cycle.gate);
    assert_eq!(cycle.steps.len(), 1, "an idle page is one step");
    assert_eq!(cycle.gate["scanned_file_count"], 0);
    assert!(cycle.before.is_empty() && cycle.finalized.is_empty());
    assert!(cycle.batches.is_empty() && cycle.acknowledged.is_empty());
}

/// Walks until one completes its census and arms the gate (a cold walk may
/// take pages, or move an input the record binds).
fn settle(home: &mut OracleHome, server: &OracleServer, recording: &Recording) -> Vec<Cycle> {
    let mut cycles = Vec::new();
    loop {
        assert!(cycles.len() < 4, "the fixture walk did not settle");
        cycles.push(home.cycle(server, recording));
        if walked(cycles.last().unwrap()) && walk_idle::armed_for_test(home.source).is_some() {
            return cycles;
        }
    }
}

fn prepare_once(home: &mut OracleHome) -> Result<Option<SourcePreparation>> {
    home.cadence.due();
    let collection = home.collection();
    with_scan_clock(home.now, || {
        crate::agent_status_refresh::with_test_collection(collection, || {
            prepare_sync_source(
                &home.client,
                &home.device,
                "device-secret",
                home.source,
                "otm_test",
                &home.fixture.home,
                &home.support,
                &home.daemon,
                &mut home.transport,
                home.daemon.snapshot_scan_account_witness().unwrap(),
            )
        })
    })
}

fn amounts(cycle: &Cycle) -> Vec<Value> {
    cycle
        .finalized
        .iter()
        .map(|item| {
            json!([
                item.source_session_id,
                item.input_tokens,
                item.output_tokens,
                item.request_count
            ])
        })
        .collect()
}

/// The usage the backend holds per session, without placement metadata.
fn placement(server: &OracleServer) -> Value {
    let placed = server.placement.lock().unwrap();
    placed
        .iter()
        .map(|(session, body)| {
            let usage = json!({"request_evidence":body["request_evidence"],
                "session_account_evidence":body["session_account_evidence"],
                "model_usage":body["model_usage"],"usage_buckets":body["usage_buckets"]});
            (session.clone(), usage)
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// The source's cached terminal manifest: a complete census publishes it, and
/// an idle pass keeps the last walk's for check-in beats to refresh.
fn manifest(source: SnapshotSource) -> Option<crate::snapshots::SnapshotSourceManifest> {
    crate::snapshot_sync::finish::source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(key, _)| key.1 == source.api_slug())
        .map(|(_, manifest)| manifest.clone())
}

/// The last collector status body the server received.
fn last_status(server: &OracleServer) -> Value {
    server.statuses.lock().unwrap().last().cloned().unwrap()
}

fn status_count(server: &OracleServer) -> usize {
    server.statuses.lock().unwrap().len()
}

/// What the local cache and the server held after the last pass.
struct Seen {
    manifest: Option<crate::snapshots::SnapshotSourceManifest>,
    statuses: usize,
}

impl Seen {
    fn now(source: SnapshotSource, server: &OracleServer) -> Self {
        Self {
            manifest: manifest(source),
            statuses: status_count(server),
        }
    }
}

/// One pass that must walk or idle. A completed walk sends its terminal
/// receipt and publishes the manifest. An idle pass sends no receipt (the
/// server would read one as a new scan result) and keeps the walk's manifest.
fn expect_pass(
    source: SnapshotSource,
    row: &str,
    cycle: &Cycle,
    walk: bool,
    server: &OracleServer,
    seen: &mut Seen,
) {
    if walk {
        assert!(walked(cycle), "{row}: expected a walk: {}", cycle.gate);
    } else {
        assert_idle(cycle);
    }
    let now = Seen::now(source, server);
    assert!(now.manifest.is_some(), "{row}: manifest: {}", cycle.gate);
    if walk {
        assert!(now.statuses > seen.statuses, "{row}: the walk's receipt");
        let receipt = last_status(server);
        assert_eq!(receipt["report_kind"], "scan_status", "{row}: {receipt}");
    } else {
        assert_eq!(
            now.statuses, seen.statuses,
            "{row}: an idle pass sends no receipt"
        );
        assert_eq!(
            now.manifest, seen.manifest,
            "{row}: the walk's manifest stands"
        );
    }
    *seen = now;
}

fn unacked_lost(cycles: &[Cycle]) -> BTreeMap<String, u64> {
    let mut lost = BTreeMap::<String, u64>::new();
    for (name, count) in cycles.iter().flat_map(|cycle| &cycle.unacked_lost) {
        *lost.entry(name.clone()).or_default() += count;
    }
    lost
}

struct Lifecycle {
    amounts: Vec<Value>,
    acknowledged: usize,
    placement: Value,
    unacked_lost: BTreeMap<String, u64>,
    walks: usize,
    passes: usize,
}

impl Lifecycle {
    fn of(server: &OracleServer, cycles: &[Cycle], walks: usize) -> Self {
        Self {
            amounts: cycles.iter().flat_map(amounts).collect(),
            acknowledged: cycles.iter().map(|c| c.acknowledged.concat().len()).sum(),
            placement: placement(server),
            unacked_lost: unacked_lost(cycles),
            walks,
            passes: cycles.len(),
        }
    }

    /// The same money as today's back-to-back walks over the same inputs.
    fn assert_matches(&self, today: &Self, row: &str) {
        assert_eq!(self.passes, today.passes, "{row}");
        assert_eq!(today.walks, today.passes, "{row}");
        assert_eq!(
            self.amounts, today.amounts,
            "{row}: the same bodies, in order"
        );
        assert_eq!(self.acknowledged, today.acknowledged, "{row}");
        assert_eq!(self.placement, today.placement, "{row}");
        assert_eq!(self.unacked_lost, today.unacked_lost, "{row}");
    }
}

/// complete -> idle gap -> hint -> relist -> unannounced change -> backstop
/// -> restart -> idle. With `gated` false the gate stays off (nothing is
/// covered), which is today's back-to-back walks over the same inputs.
fn lifecycle(source: SnapshotSource, row: &'static str, gated: bool) -> Lifecycle {
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    install(&home);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        if !gated {
            crate::snapshot_watcher::cover_paths_for_test(None);
        }
        let mut cycles = settle(&mut home, &server, &recording);
        let mut walks = cycles.iter().filter(|cycle| walked(cycle)).count();
        let mut seen = Seen::now(source, &server);
        let mut expect = |cycle: Cycle, walk: bool, cycles: &mut Vec<Cycle>| {
            let walk = walk || !gated;
            expect_pass(source, row, &cycle, walk, &server, &mut seen);
            walks += usize::from(walk);
            cycles.push(cycle);
        };
        for _ in 0..2 {
            let cycle = pass(&mut home, &server, &recording, STEP);
            expect(cycle, false, &mut cycles);
        }
        hint(&home);
        let cycle = pass(&mut home, &server, &recording, STEP);
        expect(cycle, true, &mut cycles);
        request_listing_all(ListingTrigger::Rescan);
        let cycle = pass(&mut home, &server, &recording, STEP);
        expect(cycle, true, &mut cycles);
        // A dropped-event overflow walks the same way (FSEvents drop flags
        // arrive as the Rescan above).
        request_listing_all(ListingTrigger::Overflow);
        let cycle = pass(&mut home, &server, &recording, STEP);
        expect(cycle, true, &mut cycles);
        // An unannounced change waits for the backstop, Codex's moved state
        // store included.
        change(&home);
        let mut since_walk = 0;
        loop {
            since_walk += STEP;
            let backstop = since_walk >= WALK_GAP;
            let cycle = pass(&mut home, &server, &recording, STEP);
            expect(cycle, backstop, &mut cycles);
            if backstop {
                break;
            }
        }
        home.restart();
        walk_idle::restart_for_test();
        // A restart walks. On a moving clock that walk can drop a time-due
        // re-read for the next walk and not arm; a pass idles once armed.
        // Both runs take the same three passes, so their money compares.
        for after_restart in 0..3 {
            let armed = walk_idle::armed_for_test(source).is_some();
            let cycle = pass(&mut home, &server, &recording, STEP);
            expect(cycle, after_restart == 0 || !armed, &mut cycles);
        }
        assert!(
            walk_idle::armed_for_test(source).is_some(),
            "{row}: re-armed"
        );
        // Every completed walk takes its census once; an idle pass none.
        let censuses = cycles.iter().filter(|cycle| walked(cycle)).count();
        assert_eq!(censuses, walks, "{row}");
        Lifecycle::of(&server, &cycles, walks)
    })
}

fn walk_gate_lifecycle(source: SnapshotSource, row: &'static str, control: &'static str) {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let gated = lifecycle(source, row, true);
    let today = lifecycle(source, control, false);
    assert!(gated.walks < today.walks, "the gate skipped no walk");
    gated.assert_matches(&today, row);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_claude_matches_back_to_back_walks() {
    walk_gate_lifecycle(SnapshotSource::ClaudeCode, "w01_claude", "w01_claude_today");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_codex_matches_back_to_back_walks() {
    walk_gate_lifecycle(SnapshotSource::Codex, "w01_codex", "w01_codex_today");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_pi_matches_back_to_back_walks() {
    walk_gate_lifecycle(SnapshotSource::Pi, "w01_pi", "w01_pi_today");
}

/// The same lifecycle on a moving scan clock (growth claims, retry times and
/// the backstop all come due on it).
fn walk_gate_lifecycle_moving(source: SnapshotSource, row: &'static str, control: &'static str) {
    MOVING_CLOCK.with(|moving| moving.set(true));
    walk_gate_lifecycle(source, row, control);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_claude_on_a_moving_clock() {
    walk_gate_lifecycle_moving(SnapshotSource::ClaudeCode, "w12_claude", "w12_claude_today");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_codex_on_a_moving_clock() {
    walk_gate_lifecycle_moving(SnapshotSource::Codex, "w12_codex", "w12_codex_today");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn walk_gate_lifecycle_pi_on_a_moving_clock() {
    walk_gate_lifecycle_moving(SnapshotSource::Pi, "w12_pi", "w12_pi_today");
}

/// Writes one spawn edge into the Codex home's state store. The rollouts
/// stay byte-identical.
fn add_spawn_edge(home: &OracleHome, parent: &str, child: &str) {
    let state = roots(home)[0].parent().unwrap().join("state_5.sqlite");
    rusqlite::Connection::open(state)
        .unwrap()
        .execute(
            "INSERT INTO thread_spawn_edges VALUES (?1,?2)",
            [parent, child],
        )
        .unwrap();
}

/// Moves a thread's thread-history extent by `lag` bytes and ordinals behind
/// what the fixture wrote (0 catches it up again). The rollout is untouched.
fn set_extent_lag(home: &OracleHome, thread: &str, lag: i64) {
    let history = roots(home)[0]
        .parent()
        .unwrap()
        .join("thread_history_1.sqlite");
    let rows = std::fs::read_to_string(roots(home)[0].join(format!("rollout-{thread}.jsonl")))
        .unwrap()
        .lines()
        .count() as i64;
    let length = std::fs::metadata(roots(home)[0].join(format!("rollout-{thread}.jsonl")))
        .unwrap()
        .len() as i64;
    rusqlite::Connection::open(history)
        .unwrap()
        .execute(
            "UPDATE thread_history_projection_state SET next_rollout_byte_offset=?1,next_rollout_ordinal=?2 WHERE thread_id=?3",
            rusqlite::params![length - lag, rows - lag, thread],
        )
        .unwrap();
}

/// The side-only change a Codex row makes after its source settles.
#[derive(Clone, Copy)]
enum SideOnly {
    /// A spawn edge binds a created thread.
    SpawnEdge,
    /// The thread is held (its spawn edge is in place, its extent lags the
    /// rollout); thread history then catches up.
    ExtentCatchUp,
}

/// complete -> a side-only change for a created thread whose rollout never
/// changes -> passes to the backstop. With `gated` false every pass walks
/// (today's back-to-back walks over the same timeline). Also returns, per
/// pass after the change, whether the rollout's index entry or the server's
/// placement took it.
fn codex_side_only_lifecycle(
    row: &'static str,
    gated: bool,
    side: SideOnly,
) -> (Lifecycle, Vec<bool>) {
    let source = SnapshotSource::Codex;
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    install(&home);
    install_created_thread(&home, false, SECOND_CODEX_THREAD, false);
    if let SideOnly::ExtentCatchUp = side {
        add_spawn_edge(&home, SECOND_CODEX_THREAD, IDENTITY_PIPELINE_ROOT);
        set_extent_lag(&home, IDENTITY_PIPELINE_ROOT, 1);
    }
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        if !gated {
            crate::snapshot_watcher::cover_paths_for_test(None);
        }
        let mut cycles = settle(&mut home, &server, &recording);
        let mut walks = cycles.iter().filter(|cycle| walked(cycle)).count();
        let mut seen = Seen::now(source, &server);
        let key = transcript(&home).to_string_lossy().into_owned();
        let fingerprint = |cycle: &Cycle| {
            (cycle.index.files.get(&key)).map(|entry| entry.source_file_fingerprint.clone())
        };
        let before = fingerprint(cycles.last().unwrap());
        let placed = placement(&server);
        let rollout = std::fs::read(transcript(&home)).unwrap();
        match side {
            SideOnly::SpawnEdge => {
                add_spawn_edge(&home, SECOND_CODEX_THREAD, IDENTITY_PIPELINE_ROOT);
            }
            SideOnly::ExtentCatchUp => set_extent_lag(&home, IDENTITY_PIPELINE_ROOT, 0),
        }
        let mut applied = Vec::new();
        let mut since_walk = 0;
        loop {
            since_walk += STEP;
            let backstop = since_walk >= WALK_GAP;
            let cycle = pass(&mut home, &server, &recording, STEP);
            let walk = backstop || !gated;
            expect_pass(source, row, &cycle, walk, &server, &mut seen);
            walks += usize::from(walk);
            applied.push(fingerprint(&cycle) != before || placement(&server) != placed);
            cycles.push(cycle);
            if backstop {
                break;
            }
        }
        assert_eq!(
            std::fs::read(transcript(&home)).unwrap(),
            rollout,
            "{row}: the rollout never changed"
        );
        (Lifecycle::of(&server, &cycles, walks), applied)
    })
}

/// Runs one side-only row gated and with back-to-back walks: the change
/// wakes nothing, the backstop walk applies it, and the money matches.
fn codex_side_only_waits_for_the_backstop(
    side: SideOnly,
    row: &'static str,
    control: &'static str,
) {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (gated, rested) = codex_side_only_lifecycle(row, true, side);
    let (today, walked_each) = codex_side_only_lifecycle(control, false, side);
    assert!(walked_each[0], "{row}: the next walk applies the change");
    let (backstop, rests) = rested.split_last().unwrap();
    assert!(
        rests.iter().all(|applied| !applied),
        "{row}: a rest applies nothing"
    );
    assert!(*backstop, "{row}: the backstop walk applies the change");
    assert!(gated.walks < today.walks, "{row}: the change woke no walk");
    gated.assert_matches(&today, row);
}

/// A spawn edge for a created thread on an unchanged rollout.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn codex_side_only_change_waits_for_the_backstop_walk() {
    codex_side_only_waits_for_the_backstop(
        SideOnly::SpawnEdge,
        "w20_codex_side",
        "w20_codex_side_today",
    );
}

/// A created thread held while its thread-history extent lags: the extent
/// catching up (no rollout change) misses the hold's memo, so the backstop
/// walk re-reads it and binds the parent.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn codex_held_thread_extent_catch_up_waits_for_the_backstop_walk() {
    codex_side_only_waits_for_the_backstop(
        SideOnly::ExtentCatchUp,
        "w22_codex_extent",
        "w22_codex_extent_today",
    );
}

/// An unreadable Codex state store still walks an armed source: home side
/// files left the gate key, the scan's census health check did not.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn codex_unreadable_state_store_walks_an_armed_source() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w21_codex_health";
    install(&home);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        settle_idle(&mut home, &server, &recording);
        assert!(walk_idle::armed_for_test(source).is_some());
        let state = roots(&home)[0].parent().unwrap().join("state_5.sqlite");
        std::fs::write(state, b"not a state store").unwrap();
        let cycle = pass(&mut home, &server, &recording, STEP);
        assert!(cycle.finish.is_ok(), "{:?}", cycle.finish);
        assert!(
            walk_idle::armed_for_test(source).is_none(),
            "the pass walked: {}",
            cycle.gate
        );
    });
}

/// Settles `home` under the simulated watcher, with one idle pass behind it.
fn settle_idle(home: &mut OracleHome, server: &OracleServer, recording: &Recording) {
    walk_idle::restart_for_test();
    settle(home, server, recording);
    assert_idle(&pass(home, server, recording, STEP));
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn idle_pass_emits_no_body() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w02";
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        settle_idle(&mut home, &server, &recording);
        let placed = placement(&server);
        // New usage with no hint: the idle pass reads and sends nothing.
        change(&home);
        assert_idle(&pass(&mut home, &server, &recording, STEP));
        assert_eq!(placement(&server), placed);
        hint(&home);
        let served = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&served));
        assert!(!served.batches.is_empty(), "the hinted change is served");
        assert_ne!(placement(&server), placed);
    });
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn idle_page_that_starts_a_walk_finishes_ordinarily() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w03";
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        settle(&mut home, &server, &recording);
        walk_idle::age_for_test(source, STEP);
        let frame = prepare_once(&mut home).unwrap().expect("due pass");
        let SourcePreparationStep::Complete {
            preparation,
            mut index,
            scan,
        } = frame.step()
        else {
            panic!("an idle page completes in one step");
        };
        assert!(scan.walk_idle);
        walk_idle::start_walk_for_test(source, &watched, &mut index);
        let collection = home.collection();
        let finished = with_scan_clock(home.now, || {
            crate::agent_status_refresh::with_test_collection(collection, || {
                finish_sync_source(
                    preparation,
                    index,
                    scan,
                    &home.device,
                    "device-secret",
                    "otm_test",
                    &home.fixture.home,
                    &home.support,
                    &home.daemon,
                )
            })
        });
        assert!(finished.is_ok(), "{finished:?}");
        assert_eq!(
            walk_idle::armed_for_test(source),
            None,
            "the record is cleared"
        );
        let next = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&next), "the saved walk continues");
    });
}

fn collection_health_at(
    source: SnapshotSource,
    now: u64,
) -> ottto_protocol::SourceCollectionHealth {
    with_scan_clock(now, || {
        crate::snapshot_sync::collection_health(source, true, AT)
    })
    .expect("the collection pulse is started")
}

/// Collection health across an idle stretch on a moving clock, past the stall
/// threshold (1 h on these cadences) and the backstop. With `failing`, every
/// pass after the walk fails before the gate.
fn idle_collection_health(source: SnapshotSource, row: &'static str, failing: bool) {
    use ottto_protocol::SourceCollectionState::{Collecting, Stalled};
    MOVING_CLOCK.with(|moving| moving.set(true));
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    install(&home);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        crate::snapshot_sync::reset_collection_health(source);
        with_scan_clock(home.now, || {
            crate::snapshot_sync::start_collection_health(source)
        });
        walk_idle::restart_for_test();
        settle(&mut home, &server, &recording);
        let walked_at = collection_health_at(source, home.now).last_scan_at;
        assert!(walked_at.is_some(), "{row}: the walk is a completed scan");
        for step in 1..=7 {
            if failing {
                let _failure = SaveFailure::at("after_hint_take");
                home.now += STEP;
                assert!(prepare_once(&mut home).is_err(), "{row}: step {step}");
                let health = collection_health_at(source, home.now);
                assert_eq!(health.last_scan_at, walked_at, "{row}: step {step}");
            } else {
                let cycle = pass(&mut home, &server, &recording, STEP);
                if step <= 5 {
                    // Inside the backstop: the gate holds.
                    assert_idle(&cycle);
                }
                let health = collection_health_at(source, home.now);
                assert_eq!(health.state, Collecting, "{row}: step {step}");
            }
        }
        if failing {
            assert_eq!(
                collection_health_at(source, home.now).state,
                Stalled,
                "{row}"
            );
        }
    });
    crate::snapshot_sync::reset_collection_health(source);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn idle_gated_source_stays_collecting_past_the_stall_threshold() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    idle_collection_health(SnapshotSource::ClaudeCode, "w19_claude", false);
    idle_collection_health(SnapshotSource::Codex, "w19_codex", false);
    idle_collection_health(SnapshotSource::Pi, "w19_pi", false);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn failing_source_still_stalls_after_its_walk() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    idle_collection_health(SnapshotSource::Pi, "w20_pi", true);
}

/// Hint loss: a pass that took a hint and then failed leaves no record, so
/// the next pass walks and serves the hinted input.
fn hint_then_failure(source: SnapshotSource, row: &'static str, stage: &'static str) {
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    install(&home);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        settle_idle(&mut home, &server, &recording);
        let placed = placement(&server);
        let deletion = stage == "finish_cycle";
        if deletion {
            std::fs::remove_file(transcript(&home)).unwrap();
        } else {
            change(&home);
        }
        hint(&home);
        let failure = SaveFailure::at(stage);
        walk_idle::age_for_test(source, STEP);
        if stage == "after_hint_take" {
            assert!(prepare_once(&mut home).is_err());
        } else {
            let failed = home.cycle(&server, &recording);
            assert!(failed.finish.is_err());
            if stage == "selected_save" {
                // The index save precedes this failure point: a crash before
                // it is modeled by the committed state before the pass.
                home.restore_pre_cycle_index(&failed);
            }
        }
        drop(failure);
        assert_eq!(walk_idle::armed_for_test(source), None);
        let next = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&next), "{row}: the pass after a failure walks");
        if deletion {
            let key = transcript(&home).to_string_lossy().into_owned();
            assert!(next.index.files.get(&key).is_none(), "{row}: proven absent");
        } else {
            assert!(!next.before.is_empty(), "{row}: the hinted input is read");
            assert_ne!(placement(&server), placed, "{row}: and served");
        }
    });
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn hint_loss_failed_finish_walks_next() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    hint_then_failure(SnapshotSource::ClaudeCode, "w04_claude", "selected_save");
    hint_then_failure(SnapshotSource::Codex, "w04_codex", "selected_save");
    hint_then_failure(SnapshotSource::Pi, "w04_pi", "selected_save");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn hint_loss_failure_after_the_take_walks_next() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    hint_then_failure(SnapshotSource::ClaudeCode, "w05_claude", "after_hint_take");
    hint_then_failure(SnapshotSource::Codex, "w05_codex", "after_hint_take");
    hint_then_failure(SnapshotSource::Pi, "w05_pi", "after_hint_take");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn hint_loss_deleted_file_walks_next() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    hint_then_failure(SnapshotSource::ClaudeCode, "w06_claude", "finish_cycle");
    hint_then_failure(SnapshotSource::Codex, "w06_codex", "finish_cycle");
    hint_then_failure(SnapshotSource::Pi, "w06_pi", "finish_cycle");
}

/// When a no-hint arm acts: before the first walk, or in the idle gap.
#[derive(Clone, Copy, PartialEq)]
enum Moment {
    Install,
    Gap,
}

/// settle -> idle -> `arm` acts in the gap with no hint -> idle to the
/// backstop walk -> idle. With `gated` false every pass walks.
fn no_hint_arm(
    source: SnapshotSource,
    row: &'static str,
    gated: bool,
    owed: bool,
    arm: &dyn Fn(&OracleHome, &OracleServer, Moment),
) -> Lifecycle {
    let recording = Recording::start();
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    install(&home);
    arm(&home, &server, Moment::Install);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        if !gated {
            crate::snapshot_watcher::cover_paths_for_test(None);
        }
        // An owed source never arms: its walks stay back to back until the
        // deletion settles it, so its passes are observed, not predicted.
        let mut cycles = if owed {
            let cycle = home.cycle(&server, &recording);
            assert!(walked(&cycle), "{row}: {}", cycle.gate);
            assert_eq!(walk_idle::armed_for_test(source), None, "{row}: owed");
            vec![cycle]
        } else {
            settle(&mut home, &server, &recording)
        };
        let mut walks = cycles.iter().filter(|cycle| walked(cycle)).count();
        let mut seen = Seen::now(source, &server);
        let backstop = WALK_GAP / STEP;
        for step in 1..=backstop + 1 {
            if step == 2 {
                arm(&home, &server, Moment::Gap);
            }
            let cycle = pass(&mut home, &server, &recording, STEP);
            let walk = if owed && (step < 2 || !gated) {
                assert!(walked(&cycle), "{row}: an owed source walks");
                true
            } else if owed {
                walked(&cycle)
            } else {
                step == backstop || !gated
            };
            expect_pass(source, row, &cycle, walk, &server, &mut seen);
            walks += usize::from(walk);
            cycles.push(cycle);
        }
        Lifecycle::of(&server, &cycles, walks)
    })
}

/// One source, gated and gate off: the gap idles (an owed source never arms),
/// and the money is the same.
fn no_hint_arm_pair(
    prefix: &str,
    source: SnapshotSource,
    owed: bool,
    arm: &dyn Fn(&OracleHome, &OracleServer, Moment),
) -> (Lifecycle, Lifecycle) {
    let row = |suffix: &str| -> &'static str {
        Box::leak(format!("{prefix}_{}{suffix}", source.api_slug()).into_boxed_str())
    };
    let gated = no_hint_arm(source, row(""), true, owed, arm);
    let today = no_hint_arm(source, row("_today"), false, owed, arm);
    assert!(
        gated.walks < today.walks || (owed && gated.walks == today.walks),
        "{prefix} {source:?}: the gap idled"
    );
    gated.assert_matches(&today, prefix);
    (gated, today)
}

/// Every source's pair; none where the layout bound is unsupported.
fn no_hint_arm_matches(
    prefix: &str,
    owed: bool,
    arm: &dyn Fn(&OracleHome, &OracleServer, Moment),
) -> Vec<(Lifecycle, Lifecycle)> {
    if !crate::heap_layout_bound::layout_supported() {
        return Vec::new();
    }
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .map(|source| no_hint_arm_pair(prefix, source, owed, arm))
    .collect()
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn accepted_holder_deleted_without_a_hint_matches_back_to_back_walks() {
    no_hint_arm_matches("w07", false, &|home, _, moment| {
        if moment == Moment::Gap {
            std::fs::remove_file(transcript(home)).unwrap();
        }
    });
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn unaccepted_holder_deleted_without_a_hint_matches_back_to_back_walks() {
    let pairs = no_hint_arm_matches("w08", true, &|home, server, moment| match moment {
        // The server keeps no stored body for the holder, so it is never
        // accepted.
        Moment::Install => *server.fallback.lock().unwrap() = Answer::Unstored,
        Moment::Gap => std::fs::remove_file(transcript(home)).unwrap(),
    });
    // The deleted holder's parsed body was never ACKed: each run counts it lost.
    for (gated, today) in pairs {
        for run in [gated, today] {
            let files = run.unacked_lost.get("files").copied().unwrap_or(0);
            assert!(files > 0, "unacked lost: {:?}", run.unacked_lost);
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn unread_input_vanishing_in_the_gap_matches_back_to_back_walks() {
    // It appears and vanishes between two passes: no run reads it.
    no_hint_arm_matches("w09", false, &|home, _, moment| {
        if moment == Moment::Gap {
            let unread = transcript(home).with_file_name("unread.jsonl");
            std::fs::write(&unread, b"{}\n").unwrap();
            std::fs::remove_file(&unread).unwrap();
        }
    });
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn candidate_at_the_window_edge_across_the_gap_matches_back_to_back_walks() {
    // The oracle hint's window; the edge itself is inside it.
    const WINDOW: u64 = 183 * 24 * 60 * 60;
    no_hint_arm_matches("w10", false, &|home, _, moment| {
        if moment == Moment::Gap {
            let edge = std::time::UNIX_EPOCH + std::time::Duration::from_secs(home.now - WINDOW);
            let file = std::fs::File::options().write(true).open(transcript(home));
            file.unwrap().set_modified(edge).unwrap();
        }
    });
}

/// A walk whose census completes with settled named loss never arms, so the
/// next pass walks and discloses that loss again: no idle receipt replaces it.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn settled_loss_never_arms_and_the_next_pass_rediscloses_it() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::Pi;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w13";
    // A conflicted pair leaves one ownership-incomplete file no retry changes.
    home.write_rows(&pi_rows(true));
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        let mut cycle = home.cycle(&server, &recording);
        for _ in 0..3 {
            if walked(&cycle) {
                break;
            }
            cycle = home.cycle(&server, &recording);
        }
        assert!(walked(&cycle), "the census completes: {}", cycle.gate);
        assert!(cycle.gate["ownership_incomplete_file_count"].as_u64() > Some(0));
        assert_eq!(walk_idle::armed_for_test(source), None, "settled loss");
        for _ in 0..2 {
            let sent = status_count(&server);
            let next = pass(&mut home, &server, &recording, STEP);
            assert!(walked(&next), "the next pass walks: {}", next.gate);
            assert_eq!(walk_idle::armed_for_test(source), None, "never arms");
            assert!(status_count(&server) > sent, "each walk sends its receipt");
            let status = last_status(&server);
            assert_eq!(status["report_kind"], "scan_status", "{status}");
            let lost: u64 = [
                "last_ownership_incomplete_file_count",
                "last_zero_snapshot_usage_evidence_count",
                "last_dropped_usage_record_count",
            ]
            .iter()
            .map(|field| status[*field].as_u64().unwrap())
            .sum();
            assert!(lost > 0, "a loss vector: {status}");
            assert!(!status["last_error_code"].is_null(), "disclosed: {status}");
        }
    });
}

/// Arming needs a fully settled upload: a walk whose upload the backend sheds
/// completes its census, yet does not arm, and the next pass walks.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn unsettled_upload_never_arms() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::Pi;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w14";
    install(&home);
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        settle_idle(&mut home, &server, &recording);
        // The backend sheds the upload (503): the pass does not settle, and its
        // finish returns before arming. (An unchanged, unstored answer is a
        // scheduled quarantine retry, which owes nothing until it is due.)
        *server.fallback.lock().unwrap() = Answer::Shed;
        change(&home);
        hint(&home);
        let unsettled = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&unsettled), "{}", unsettled.gate);
        assert!(!unsettled.batches.is_empty(), "the change was offered");
        assert_eq!(walk_idle::armed_for_test(source), None, "unsettled upload");
        let next = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&next), "the next pass walks: {}", next.gate);
    });
}

/// The lane's clears drop armed records: a resumed (reconnected) source, and
/// a requested sync of every source, cleared under the cycle lock before
/// credentials load, so it holds even when that cycle then fails.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn lane_clears_drop_armed_records() {
    let base = crate::test_scratch::ScratchDir::new("walk-gate-lane");
    let support = base.join("support");
    let secrets = base.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    // No device anywhere: the requested cycle stops at its credentials.
    let _env = [
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
        EnvVarGuard::set_str("OTTTO_API_BASE_URL", "http://127.0.0.1:9"),
    ];
    walk_idle::restart_for_test();
    walk_idle::arm_for_test(SnapshotSource::Pi);
    crate::snapshot_sync::disable_snapshot_source(&support, SnapshotSource::Pi).unwrap();
    crate::snapshot_sync::reconnect_snapshot_source(&support, SnapshotSource::Pi).unwrap();
    crate::snapshot_sync::resume_reconnected_sources(&support);
    assert_eq!(
        walk_idle::armed_for_test(SnapshotSource::Pi),
        None,
        "resumed"
    );
    let sources = [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ];
    for source in sources {
        walk_idle::arm_for_test(source);
    }
    let daemon = test_daemon("otm_lane");
    let _ = crate::snapshot_sync::lane::sync_once(&base, &support, &daemon, true);
    for source in sources {
        assert_eq!(
            walk_idle::armed_for_test(source),
            None,
            "{source:?}: requested"
        );
    }
}

/// Idle passes after an armed walk: no receipt reaches the server, so the
/// walk's receipt is the last one it holds, and the walk's manifest stays
/// cached for check-in beats.
fn idle_passes_keep_the_walk(
    home: &mut OracleHome,
    server: &OracleServer,
    recording: &Recording,
    row: &str,
) {
    let receipt = last_status(server);
    assert_eq!(receipt["report_kind"], "scan_status", "{row}: {receipt}");
    assert_eq!(receipt["last_census_complete"], true, "{row}: {receipt}");
    let published = manifest(home.source);
    assert!(
        published.is_some(),
        "{row}: the walk published its manifest"
    );
    let sent = status_count(server);
    for _ in 0..2 {
        assert_idle(&pass(home, server, recording, STEP));
        assert_eq!(
            status_count(server),
            sent,
            "{row}: an idle pass sends no receipt"
        );
        assert_eq!(
            last_status(server),
            receipt,
            "{row}: the walk's receipt stands"
        );
        assert_eq!(
            manifest(home.source),
            published,
            "{row}: the walk's manifest"
        );
        assert!(walk_idle::armed_for_test(home.source).is_some(), "{row}");
    }
}

/// A clean source settles, then idles without a receipt: the server keeps the
/// walk's clean census and its manifest pairing.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn clean_source_idles_without_a_receipt() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for (source, row) in [
        (SnapshotSource::ClaudeCode, "w15_claude"),
        (SnapshotSource::Codex, "w15_codex"),
        (SnapshotSource::Pi, "w15_pi"),
    ] {
        let recording = Recording::start();
        let server = OracleServer::new(source, recording.handle());
        let mut home = OracleHome::new(source, &server);
        home.row = row;
        install(&home);
        let watched = roots(&home);
        with_simulated_watch(&watched, || {
            walk_idle::restart_for_test();
            settle(&mut home, &server, &recording);
            let receipt = last_status(&server);
            assert!(receipt["last_error_code"].is_null(), "{row}: {receipt}");
            idle_passes_keep_the_walk(&mut home, &server, &recording, row);
        });
    }
}

/// A standing terminal hold is disclosed by every receipt but is not this
/// walk's loss, so it does not keep the gate from arming; real loss still does.
#[test]
fn a_standing_terminal_hold_is_not_walk_loss() {
    let mut index = ScanIndex::default();
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::ClaudeCode);
    record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
    record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    index
        .quarantined_snapshot_fingerprints
        .insert("d".repeat(64), record);
    let counts = SyncCounts::for_policy(30).with_snapshot_terminal_counts(&index);
    assert_eq!(counts.snapshot_unproven_terminal_count, 1);
    assert!(
        counts.has_disclosed_loss(),
        "the receipt discloses the hold"
    );
    assert!(
        !counts.has_walk_loss(&index),
        "but it is not this walk's loss"
    );
    let mut lossy = SyncCounts::for_policy(30).with_snapshot_terminal_counts(&index);
    lossy.ownership_incomplete_file_count += 1;
    assert!(lossy.has_walk_loss(&index), "one more incomplete file is");
}

/// The cycle-start beat of an armed source carries no scan start, so the
/// server keeps the window the walk's manifest is paired with.
#[test]
fn an_armed_source_beats_without_a_scan_start() {
    let source = SnapshotSource::Pi;
    walk_idle::restart_for_test();
    let start = crate::snapshot_sync::lane::cycle_start_scan_started_at;
    assert_eq!(start(source, "now"), Some("now"));
    walk_idle::arm_for_test(source);
    assert_eq!(start(source, "now"), None);
    assert_eq!(start(SnapshotSource::Codex, "now"), Some("now"));
    walk_idle::restart_for_test();
    assert_eq!(start(source, "now"), Some("now"));
}

/// Settles a clean Claude home, then holds its root family in a standing
/// UnprovenTerminal authority record bound to the present, unchanged
/// transcript, and requests a listing so the next pass walks.
fn hold_claude_family(home: &mut OracleHome, server: &OracleServer, recording: &Recording) {
    walk_idle::restart_for_test();
    settle(home, server, recording);
    let path = home.index_path();
    let mut index = ScanIndex::load(&path).unwrap();
    let key = transcript(home).to_string_lossy().into_owned();
    let revision = index.files[&key].source_file_fingerprint.clone();
    assert!(!revision.is_empty(), "the transcript is indexed");
    index.insert_unproven_terminal_claude_authority_for_test(IDENTITY_PIPELINE_ROOT, &revision);
    index.save_fixture(&path).unwrap();
    request_listing_all(ListingTrigger::Rescan);
}

fn claude_authority_terminal_members(home: &OracleHome) -> usize {
    ScanIndex::load(&home.index_path())
        .unwrap()
        .claude_usage_authority_terminal_entity_count()
}

/// A standing Claude authority hold on a present member goes through the real
/// finish fold: the walk discloses it as settled ownership loss and still
/// arms, and the idle passes after it send no receipt.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn claude_standing_authority_hold_arms_and_idles() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w17";
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        hold_claude_family(&mut home, &server, &recording);
        let walk = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&walk), "the listing walks: {}", walk.gate);
        assert_eq!(
            claude_authority_terminal_members(&home),
            1,
            "the hold stands"
        );
        let receipt = last_status(&server);
        let incomplete = receipt["last_ownership_incomplete_file_count"].as_u64();
        assert!(incomplete >= Some(1), "disclosed: {receipt}");
        assert_eq!(
            receipt["last_terminal_ownership_incomplete_file_count"].as_u64(),
            incomplete,
            "settled: {receipt}"
        );
        assert!(
            walk_idle::armed_for_test(source).is_some(),
            "a standing hold is not walk loss: {receipt}"
        );
        idle_passes_keep_the_walk(&mut home, &server, &recording, "w17");
        assert_eq!(claude_authority_terminal_members(&home), 1);
    });
}

/// Control: the same standing hold plus a transcript whose positive usage
/// yields no entity (this walk's own loss) never arms; each pass reports.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn claude_standing_authority_hold_with_walk_loss_never_arms() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w18";
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        hold_claude_family(&mut home, &server, &recording);
        // Positive usage with no timestamp: no entity, so the file is loss.
        let lossy = transcript(&home).with_file_name(format!("{SECOND_CODEX_THREAD}.jsonl"));
        let row = json!({"type":"assistant","sessionId":SECOND_CODEX_THREAD,
            "requestId":"req_lossy","message":{"id":"m_lossy","model":"claude-haiku-4-5",
            "usage":{"input_tokens":5,"output_tokens":1}}});
        std::fs::write(&lossy, format!("{row}\n")).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&lossy)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 3600))
            .unwrap();
        for _ in 0..2 {
            let sent = status_count(&server);
            let next = pass(&mut home, &server, &recording, STEP);
            assert!(next.finish.is_ok(), "{:?}", next.finish);
            assert_eq!(
                walk_idle::armed_for_test(source),
                None,
                "walk loss: {}",
                next.gate
            );
            assert!(status_count(&server) > sent, "each pass reports");
            let receipt = last_status(&server);
            let walk_loss: u64 = [
                "last_zero_snapshot_usage_evidence_count",
                "last_dropped_usage_record_count",
            ]
            .iter()
            .map(|field| receipt[*field].as_u64().unwrap())
            .sum();
            assert!(walk_loss > 0, "this walk's loss: {receipt}");
            assert!(
                receipt["last_ownership_incomplete_file_count"].as_u64() >= Some(1),
                "the hold is still disclosed: {receipt}"
            );
        }
    });
}

/// What a process start loses that the scan index does not keep, except the
/// recensus arms: the walk gate's slots and the cached terminal manifests.
/// The home reloads as `restart` does: a new daemon over the same files. It is
/// not a cold open of the state store, which stays live in this process.
fn restart_keeping_recensus(home: &mut OracleHome) {
    walk_idle::restart_for_test();
    crate::snapshot_sync::finish::clear_source_manifests_for_test();
    home.restart();
}

/// A process start: the recensus arms over this home's roots and this
/// thread's walk folds are gone too. The scan index on disk, with any walk
/// checkpoint, stays.
fn process_start(home: &mut OracleHome) {
    let collection = home.collection();
    let roots = crate::snapshot_roots::scan_roots(
        home.source,
        &home.fixture.home,
        &collection.codex_scan_homes,
    )
    .unwrap();
    home.source.forget_in_process_walk_state_for_test(&roots);
    restart_keeping_recensus(home);
}

/// One more response in the second session `c12_install` writes.
fn grow_other(home: &OracleHome) {
    let other = home
        .transcript()
        .with_file_name(format!("{C12_OTHER}.jsonl"));
    let line = json!({"timestamp":"2026-11-01T07:05:00Z","type":"assistant",
        "sessionId":C12_OTHER,"requestId":"restart-other-request",
        "message":{"id":"restart-other-message","model":"claude-haiku-4-5",
        "usage":{"input_tokens":4,"output_tokens":1}}});
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(other)
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

/// The session of every body the server acknowledged in these passes.
fn acknowledged_sessions(cycles: &[Cycle]) -> Vec<String> {
    cycles
        .iter()
        .flat_map(|cycle| cycle.acknowledged.concat())
        .map(|row| row["source_session_id"].as_str().unwrap().to_owned())
        .collect()
}

/// settle -> both sessions grow -> a requested walk whose first page reads
/// one file -> (`restart`: a process start) -> the rest of the walk. One
/// grown body is acknowledged before the restart point and the other after
/// it. Returns the money through the walk's end, and whether that walk armed
/// the gate.
fn walk_across_a_restart(row: &'static str, restart: bool) -> (Lifecycle, bool) {
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    // Only the two session files stay, so a one-file page reads one of them.
    let sibling = c12_install(&home);
    std::fs::remove_file(&sibling).unwrap();
    std::fs::remove_dir(sibling.parent().unwrap()).unwrap();
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        let mut cycles = settle(&mut home, &server, &recording);
        let settled = cycles.len();
        change(&home);
        grow_other(&home);
        request_listing_all(ListingTrigger::Rescan);
        home.schedule = Some(Schedule {
            one_chunk: false,
            limit: 1,
            reverse: false,
        });
        let first = pass(&mut home, &server, &recording, STEP);
        home.schedule = None;
        assert!(!walked(&first), "{row}: one file per page: {}", first.gate);
        assert!(
            !walk_idle::idle_finish(&first.index),
            "{row}: the walk checkpoint is stored"
        );
        let before = acknowledged_sessions(std::slice::from_ref(&first));
        assert_eq!(before.len(), 1, "{row}: one grown body before: {before:?}");
        cycles.push(first);
        if restart {
            process_start(&mut home);
        }
        loop {
            assert!(cycles.len() < settled + 5, "{row}: the walk did not finish");
            let cycle = pass(&mut home, &server, &recording, STEP);
            let done = walked(&cycle);
            cycles.push(cycle);
            if done {
                break;
            }
        }
        let after = acknowledged_sessions(&cycles[settled + 1..]);
        assert_eq!(
            after.len(),
            1,
            "{row}: the other grown body after: {after:?}"
        );
        assert_ne!(after, before, "{row}: each session once");
        // 10 + 20 + 5 and 6 + 4: each grown session's whole body.
        let grown = cycles[settled..]
            .iter()
            .flat_map(|cycle| &cycle.finalized)
            .map(|item| item.input_tokens)
            .collect::<BTreeSet<_>>();
        assert_eq!(grown, BTreeSet::from([10, 35]), "{row}");
        let armed = walk_idle::armed_for_test(source).is_some();
        let walks = cycles.iter().filter(|cycle| walked(cycle)).count();
        let money = Lifecycle::of(&server, &cycles, walks);
        let next = pass(&mut home, &server, &recording, STEP);
        if restart {
            // No walk start survived, so this pass walks afresh and arms.
            assert!(walked(&next), "{row}: a fresh walk: {}", next.gate);
            assert!(walk_idle::armed_for_test(source).is_some(), "{row}");
            assert_idle(&pass(&mut home, &server, &recording, STEP));
        } else {
            assert_idle(&next);
        }
        (money, armed)
    })
}

/// A process start between the pages of one walk: the walk resumes from its
/// stored checkpoint and its money is the unbroken walk's. The resumed walk
/// has no walk start on the gate clock, so it does not arm; the next walk,
/// a fresh one, does.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn restart_in_the_middle_of_a_walk_matches_the_unbroken_walk() {
    assert!(crate::heap_layout_bound::layout_supported());
    let (restarted, restarted_armed) = walk_across_a_restart("w19_restarted", true);
    let (unbroken, unbroken_armed) = walk_across_a_restart("w19_unbroken", false);
    assert!(!restarted_armed, "the resumed walk arms nothing");
    assert!(unbroken_armed, "the unbroken walk arms");
    assert_eq!(restarted.passes, unbroken.passes, "passes");
    assert_eq!(restarted.walks, unbroken.walks, "completed walks");
    assert_eq!(
        restarted.amounts, unbroken.amounts,
        "the same bodies, in order"
    );
    assert_eq!(restarted.acknowledged, unbroken.acknowledged);
    assert_eq!(restarted.placement, unbroken.placement);
    assert_eq!(restarted.unacked_lost, unbroken.unacked_lost);
}

// The sleep below comes before the backstop: only the gap makes it walk.
const _: () = assert!(2 * STEP + walk_idle::PASS_GAP + 1 < WALK_GAP);

/// settle -> idle -> (`restart`: a process start, else a requested listing)
/// -> walk -> two idle passes -> a gap longer than PASS_GAP -> walk -> idle.
/// Returns the statuses the first walk sent and the server's placement.
fn walk_after_armed_idle(row: &'static str, restart: bool) -> (Vec<Value>, Value) {
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        settle_idle(&mut home, &server, &recording);
        assert!(manifest(source).is_some(), "{row}: the settled manifest");
        if restart {
            process_start(&mut home);
            assert!(manifest(source).is_none(), "{row}: none cached yet");
        } else {
            request_listing_all(ListingTrigger::Rescan);
        }
        let sent = status_count(&server);
        let walk = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&walk), "{row}: the first pass walks: {}", walk.gate);
        let statuses = server.statuses.lock().unwrap()[sent..].to_vec();
        assert_eq!(statuses.len(), 1, "{row}: the walk's one receipt");
        for status in &statuses {
            assert_eq!(status["report_kind"], "scan_status", "{row}: {status}");
        }
        assert!(manifest(source).is_some(), "{row}: published by the walk");
        assert!(walk_idle::armed_for_test(source).is_some(), "{row}: armed");
        idle_passes_keep_the_walk(&mut home, &server, &recording, row);
        let sent = status_count(&server);
        let slept = pass(&mut home, &server, &recording, walk_idle::PASS_GAP + 1);
        assert!(walked(&slept), "{row}: after a sleep: {}", slept.gate);
        assert_eq!(status_count(&server) - sent, statuses.len(), "{row}");
        assert!(
            walk_idle::armed_for_test(source).is_some(),
            "{row}: re-armed"
        );
        assert_idle(&pass(&mut home, &server, &recording, STEP));
        (statuses, placement(&server))
    })
}

/// A process start while armed: the first pass walks, sends the receipts and
/// publishes the manifest a requested walk does, and idles once re-armed. A
/// later gap longer than PASS_GAP walks again.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn restart_while_armed_walks_once_then_idles() {
    assert!(crate::heap_layout_bound::layout_supported());
    let (restarted, placed) = walk_after_armed_idle("w20_restarted", true);
    let (requested, requested_placed) = walk_after_armed_idle("w20_requested", false);
    assert_eq!(restarted.len(), requested.len(), "the same receipts");
    assert_eq!(placed, requested_placed);
}

/// A standing terminal hold is on disk, so a process start keeps it: the
/// first walk after it discloses the same settled loss as the walk before,
/// and still arms.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn standing_hold_arms_on_the_first_walk_after_a_restart() {
    assert!(crate::heap_layout_bound::layout_supported());
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "w21";
    let watched = roots(&home);
    let loss = |receipt: &Value| {
        [
            "last_ownership_incomplete_file_count",
            "last_terminal_ownership_incomplete_file_count",
        ]
        .map(|field| receipt[field].clone())
    };
    with_simulated_watch(&watched, || {
        hold_claude_family(&mut home, &server, &recording);
        let sent = status_count(&server);
        let held = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&held), "the listing walks: {}", held.gate);
        assert!(walk_idle::armed_for_test(source).is_some(), "armed before");
        let held_sent = status_count(&server) - sent;
        assert_eq!(held_sent, 1, "the held walk's one receipt");
        let before = loss(&last_status(&server));
        assert!(before[0].as_u64() >= Some(1), "disclosed: {before:?}");
        assert_eq!(before[1], before[0], "settled: {before:?}");
        process_start(&mut home);
        let sent = status_count(&server);
        let after = pass(&mut home, &server, &recording, STEP);
        assert!(walked(&after), "a process start walks: {}", after.gate);
        assert_eq!(
            status_count(&server) - sent,
            held_sent,
            "the walk's receipts"
        );
        let receipt = last_status(&server);
        assert_eq!(receipt["report_kind"], "scan_status", "{receipt}");
        assert_eq!(loss(&receipt), before, "the same settled loss: {receipt}");
        assert!(
            walk_idle::armed_for_test(source).is_some(),
            "a standing hold is not walk loss after a restart either"
        );
        idle_passes_keep_the_walk(&mut home, &server, &recording, "w21");
        assert_eq!(claude_authority_terminal_members(&home), 1);
    });
}

/// The `routine_recensus` of the first walk after a restart right after a
/// walk retired, with the recensus arms kept or forgotten.
fn recensus_after_restart(row: &'static str, forget: bool) -> bool {
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = row;
    let watched = roots(&home);
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        settle(&mut home, &server, &recording);
        if forget {
            process_start(&mut home);
        } else {
            restart_keeping_recensus(&mut home);
        }
        let frame = prepare_once(&mut home).unwrap().expect("due pass");
        let now = home.now;
        let (preparation, index, scan) =
            run_on_scan_worker_stack_with_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES, move || {
                with_scan_clock(now, || {
                    let mut frame = frame;
                    for _ in 0..1024 {
                        match frame.step() {
                            SourcePreparationStep::Pending(next) => frame = next,
                            SourcePreparationStep::Refused(_, reason) => {
                                panic!("{row}: unexpected refusal: {reason:?}")
                            }
                            SourcePreparationStep::Complete {
                                preparation,
                                index,
                                scan,
                            } => return (preparation, index, scan),
                        }
                    }
                    panic!("{row}: the pass exceeded 1024 steps");
                })
            });
        assert!(!scan.walk_idle, "{row}: a restart walks");
        let routine = scan.routine_recensus;
        let collection = home.collection();
        let finished = with_scan_clock(home.now, || {
            crate::agent_status_refresh::with_test_collection(collection, || {
                finish_sync_source(
                    preparation,
                    index,
                    scan,
                    &home.device,
                    "device-secret",
                    "otm_test",
                    &home.fixture.home,
                    &home.support,
                    &home.daemon,
                )
            })
        });
        assert!(finished.is_ok(), "{row}: {finished:?}");
        routine
    })
}

/// A walk that retires complete arms the next walk as a routine recensus.
/// That arm lives only in this process: a restart right after the walk
/// starts the next one without it.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn a_process_start_forgets_the_routine_recensus_arm() {
    assert!(crate::heap_layout_bound::layout_supported());
    assert!(recensus_after_restart("w22_kept", false), "kept: routine");
    assert!(!recensus_after_restart("w22_forgotten", true), "forgotten");
}
