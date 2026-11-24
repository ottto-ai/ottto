//! The walk gate's decisions on synthetic inputs: arming, the backstop, the
//! pass gap, input and generation binding, coverage, and the projection of
//! what a walk would select from an index whose stamps have not moved.
use super::*;
use crate::snapshot_client::decode_activity_hint;
use crate::test_scratch::ScratchDir;

const START: u64 = 1_900_000_000;
const DAYS: u64 = 183;
const KEY: &str = "/walk-gate/project/session.jsonl";

struct Fixture {
    scratch: ScratchDir,
    source: SnapshotSource,
    roots: Vec<PathBuf>,
}

impl Fixture {
    /// A fresh thread state: no record, and the roots covered.
    fn new(source: SnapshotSource) -> Self {
        restart_for_test();
        let scratch = ScratchDir::new("walk-gate");
        let roots = vec![scratch.join("roots").join(source.api_slug())];
        std::fs::create_dir_all(&roots[0]).unwrap();
        crate::snapshot_watcher::cover_paths_for_test(Some(roots.clone()));
        Self {
            scratch,
            source,
            roots,
        }
    }

    fn pass(&self, index: &ScanIndex, replay: &str) -> Pass {
        self.pass_days(index, replay, DAYS)
    }

    /// A pass whose server hint and window ask for `days`.
    fn pass_days(&self, index: &ScanIndex, replay: &str, days: u64) -> Pass {
        let hint = decode_activity_hint(serde_json::json!({
            "source": self.source.api_slug(), "server_time": "2026-11-18T00:00:00Z",
            "last_data_at": null, "record_count_15m": 0, "record_count_24h": 0,
            "local_usage_reconciliation_enabled": true, "backfill_window_days": days,
            "recommended_scan_after": "2099-01-01T00:00:00Z"
        }))
        .unwrap();
        Pass::new(
            self.source,
            &self.roots,
            &self.scratch,
            &Scope("walk-gate-scope".into()),
            &self.scratch.join("index"),
            days,
            replay,
            &hint,
            b"policy",
            index,
        )
    }

    fn gate(&self, index: &ScanIndex, now: u64) -> bool {
        gate(self.source, &self.pass(index, "a"), index, true, now)
    }

    /// One walking pass at `now` that retires a clean walk started then.
    fn walk(&self, index: &ScanIndex, now: u64) {
        assert!(!self.gate(index, now));
        self.arm(index, now);
    }

    /// The finish of a clean walk that began at `started`.
    fn arm(&self, index: &ScanIndex, started: u64) {
        let mut scan = SourceScanResult::empty(self.source);
        scan.census_complete = true;
        scan.settled_walk = true;
        let path = self.scratch.join("index");
        let pass = self.pass(index, "a");
        crate::scan_clock::with_clock(started, || {
            arm_after_finish(pass, index, &path, &scan, true);
        });
    }

    /// The finish of an idle pass whose maintenance left `index`.
    fn finish_idle(&self, index: &ScanIndex) {
        let mut scan = SourceScanResult::empty(self.source);
        scan.walk_idle = true;
        let path = self.scratch.join("index");
        arm_after_finish(self.pass(index, "a"), index, &path, &scan, false);
    }
}

/// An index entry every gate of the walk's decision skips while its stamp
/// holds: an outcome on record, current identity, valid activity.
fn settled_entry(index: &mut ScanIndex, modified: u64) {
    let entry = ScanIndexEntry {
        size_bytes: 10,
        modified_unix_seconds: modified,
        source_file_fingerprint: "source".into(),
        last_snapshot_fingerprint: Some("fp".into()),
        scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()),
        ..ScanIndexEntry::default()
    };
    index.files.insert(KEY.into(), entry);
    let fingerprints = BTreeSet::from(["fp".to_owned()]);
    index
        .file_snapshot_fingerprints
        .insert(KEY.into(), fingerprints);
    index.snapshot_activity_at.insert("fp".into(), None);
}

fn selects(index: &ScanIndex, now: u64) -> bool {
    stored_stamp_selects(index, KEY, index.files.get(KEY).unwrap(), now)
}

/// The ordinary walk's decision for the same unchanged file.
fn walk_decision(index: &ScanIndex, now: u64) -> (CandidateDecision, Option<CandidateParseReason>) {
    let candidate = stored_candidate(KEY, index.files.get(KEY).unwrap());
    index.candidate_decision_with_reason_at(&candidate, now)
}

#[test]
fn settled_walk_idles_until_the_start_to_start_backstop() {
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    assert!(!fixture.gate(&index, START), "nothing armed yet");
    fixture.walk(&index, START);
    assert_eq!(armed_for_test(SnapshotSource::Pi), Some((0, START)));
    for gap in (1800..WALK_GAP).step_by(1800) {
        assert!(fixture.gate(&index, START + gap), "idle at +{gap}s");
    }
    assert!(
        !fixture.gate(&index, START + WALK_GAP),
        "the backstop walks"
    );
    assert_eq!(armed_for_test(SnapshotSource::Pi), None);
}

/// `armed` is what the lane reads before a cycle's passes: true from a
/// settled walk until a walking gate, a clear or a restart drops the record.
#[test]
fn armed_follows_the_record() {
    let source = SnapshotSource::Codex;
    let fixture = Fixture::new(source);
    let index = ScanIndex::default();
    assert!(!armed(source), "nothing armed yet");
    fixture.walk(&index, START);
    assert!(armed(source));
    assert!(!armed(SnapshotSource::Pi), "per source");
    assert!(fixture.gate(&index, START + 1800), "an idle pass");
    assert!(armed(source), "an idle pass keeps it");
    clear(source);
    assert!(!armed(source), "cleared");
    fixture.walk(&index, START + 3600);
    assert!(armed(source), "re-armed");
    assert!(
        !fixture.gate(&index, START + 3600 + WALK_GAP),
        "the backstop"
    );
    assert!(!armed(source), "a walking gate drops it");
    fixture.walk(&index, START + 3600 + WALK_GAP + 60);
    assert!(armed(source));
    restart_for_test();
    assert!(!armed(source), "a restart drops it");
}

#[test]
fn pass_gap_equal_to_twice_the_longest_interval_idles_and_longer_walks() {
    assert_eq!(PASS_GAP, 2 * 30 * 60);
    const { assert!(2 * PASS_GAP + 1 < WALK_GAP) };
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    assert!(fixture.gate(&index, START + PASS_GAP), "the tie idles");
    assert!(
        !fixture.gate(&index, START + 2 * PASS_GAP + 1),
        "a longer gap walks"
    );
}

#[test]
fn clock_moved_back_or_past_the_backstop_walks() {
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    // The scan clock is the wall clock, not monotonic: a step back (or a
    // restored clock) before the walk's start is due, and drops the record.
    assert!(!fixture.gate(&index, START - 1), "a backward clock walks");
    assert_eq!(armed_for_test(SnapshotSource::Pi), None);
    assert!(!fixture.gate(&index, START + 60), "and stays due");
    fixture.walk(&index, START);
    assert!(
        !fixture.gate(&index, START + WALK_GAP + 1),
        "a forward jump walks"
    );
}

#[test]
fn changed_input_walks_and_changing_back_still_walks() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    let changed = fixture.pass(&index, "b");
    assert!(!gate(
        SnapshotSource::ClaudeCode,
        &changed,
        &index,
        true,
        START + 60
    ));
    assert!(
        !fixture.gate(&index, START + 120),
        "A -> B -> A walks again"
    );
}

#[test]
fn backfill_window_flip_walks_and_flipping_back_still_walks() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    let narrow = fixture.pass_days(&index, "a", 30);
    assert!(!gate(
        SnapshotSource::ClaudeCode,
        &narrow,
        &index,
        true,
        START + 60
    ));
    assert_eq!(armed_for_test(SnapshotSource::ClaudeCode), None);
    assert!(
        !fixture.gate(&index, START + 120),
        "the old window never revives the old record"
    );
    assert_eq!(armed_for_test(SnapshotSource::ClaudeCode), None);
}

#[test]
fn rebuilt_or_externally_saved_index_walks() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let mut index = ScanIndex::default();
    fixture.walk(&index, START);
    index.generation = 7;
    assert!(!fixture.gate(&index, START + 60));
}

#[test]
fn owed_upload_work_walks_and_clears_the_record() {
    let fixture = Fixture::new(SnapshotSource::Codex);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    let pass = fixture.pass(&index, "a");
    assert!(!gate(
        SnapshotSource::Codex,
        &pass,
        &index,
        false,
        START + 60
    ));
    assert!(!fixture.gate(&index, START + 120), "the record is gone");
}

#[test]
fn final_generation_arming_follows_the_last_commit() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let mut index = ScanIndex::default();
    assert!(!fixture.gate(&index, START));
    // The walk's save and its exit Tail commit moved the store: the record
    // binds the generation the next prepare loads.
    index.generation = 5;
    fixture.arm(&index, START);
    assert_eq!(armed_for_test(SnapshotSource::ClaudeCode), Some((5, START)));
    assert!(fixture.gate(&index, START + 60), "a quiet pass idles");
    // An idle pass's own bookkeeping commit refreshes the record.
    index.generation = 6;
    fixture.finish_idle(&index);
    assert!(
        fixture.gate(&index, START + 120),
        "still idle after bookkeeping"
    );
    // Another writer's save is not followed: the next pass walks.
    index.generation = 7;
    assert!(!fixture.gate(&index, START + 180));
}

#[test]
fn restart_always_walks() {
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    restart_for_test();
    assert!(!fixture.gate(&index, START + 60));
}

#[test]
fn deferred_account_hold_does_not_arm() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let mut index = ScanIndex::default();
    index
        .claude_account_deferred_holds
        .insert("held".into(), "reason".into());
    fixture.walk(&index, START);
    assert_eq!(armed_for_test(SnapshotSource::ClaudeCode), None);
}

#[test]
fn walk_without_a_settled_start_does_not_arm() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let index = ScanIndex::default();
    assert!(!fixture.gate(&index, START));
    let mut scan = SourceScanResult::empty(SnapshotSource::ClaudeCode);
    scan.census_complete = true;
    let path = fixture.scratch.join("index");
    // The step leaves no settled start after a budget hold or a page cut.
    arm_after_finish(fixture.pass(&index, "a"), &index, &path, &scan, true);
    assert_eq!(armed_for_test(SnapshotSource::ClaudeCode), None);
}

#[test]
fn input_moved_during_the_walk_does_not_arm() {
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    assert!(!fixture.gate(&index, START));
    let mut scan = SourceScanResult::empty(SnapshotSource::Pi);
    scan.census_complete = true;
    scan.settled_walk = true;
    let path = fixture.scratch.join("index");
    arm_after_finish(fixture.pass(&index, "b"), &index, &path, &scan, true);
    assert_eq!(armed_for_test(SnapshotSource::Pi), None);
}

#[test]
fn absent_root_does_not_block_coverage() {
    let fixture = Fixture::new(SnapshotSource::Codex);
    let absent = fixture.scratch.join("roots").join("archived");
    let roots = vec![fixture.roots[0].clone(), absent.clone()];
    assert!(crate::snapshot_watcher::covers(&roots));
    std::fs::create_dir_all(&absent).unwrap();
    assert!(
        !crate::snapshot_watcher::covers(&roots),
        "an unwatched root walks"
    );
    crate::snapshot_watcher::cover_paths_for_test(None);
    assert!(!crate::snapshot_watcher::covers(&fixture.roots[..1]));
}

#[test]
fn uncovered_roots_never_idle() {
    let fixture = Fixture::new(SnapshotSource::Pi);
    let index = ScanIndex::default();
    fixture.walk(&index, START);
    crate::snapshot_watcher::cover_paths_for_test(None);
    assert!(!fixture.gate(&index, START + 60));
}

/// Codex home side files are not gate inputs: an edit to any of them during
/// a walk still arms it, and while resting neither wakes the source nor moves
/// the start-to-start backstop. The launch inbox still wakes Codex.
#[test]
fn codex_home_side_files_neither_wake_nor_move_the_backstop() {
    let fixture = Fixture::new(SnapshotSource::Codex);
    let home = fixture.roots[0].parent().unwrap().to_path_buf();
    let side = [
        "state_5.sqlite",
        "thread_history_1.sqlite",
        "session_index.jsonl",
        "config.toml",
    ];
    let edit = |n: u64| {
        for name in side {
            std::fs::write(home.join(name), format!("edit {n}\n")).unwrap();
        }
    };
    let index = ScanIndex::default();
    assert!(!fixture.gate(&index, START), "nothing armed yet");
    edit(0);
    fixture.arm(&index, START);
    assert_eq!(
        armed_for_test(SnapshotSource::Codex),
        Some((0, START)),
        "a side edit during the walk still arms it"
    );
    for (n, gap) in (1_u64..).zip((600..WALK_GAP).step_by(600)) {
        edit(n);
        assert!(fixture.gate(&index, START + gap), "rests at +{gap}s");
        assert_eq!(armed_for_test(SnapshotSource::Codex), Some((0, START)));
    }
    assert!(
        !fixture.gate(&index, START + WALK_GAP),
        "the backstop walks on the first walk's clock"
    );
    fixture.walk(&index, START + WALK_GAP);
    assert!(fixture.gate(&index, START + WALK_GAP + 60));
    let [pending, _] = crate::launch_events::inbox_dirs(&fixture.scratch);
    std::fs::create_dir_all(&pending).unwrap();
    assert!(
        !fixture.gate(&index, START + WALK_GAP + 120),
        "the launch inbox still wakes Codex"
    );
}

#[test]
fn claude_sidecar_and_otlp_rows_are_inputs() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let index = ScanIndex::default();
    use crate::local_resource_diagnostics::cache_lifecycle;
    let ((before, after), counts) = cache_lifecycle::observe(|| {
        let before = fixture.pass(&index, "a");
        cache_lifecycle::add(cache_lifecycle::Event::OtlpRelayAppendedRows, 1);
        (before, fixture.pass(&index, "a"))
    });
    assert_eq!(counts.otlp_relay_appended_rows, 1);
    assert!(!before.same(&after), "telemetry rows wake the walk");
    // A row accepted after a scan-start drain is readable only after the next
    // drain, which must wake that pass even with no new arrival.
    let ((before, after), _) = cache_lifecycle::observe(|| {
        let before = fixture.pass(&index, "a");
        cache_lifecycle::add(cache_lifecycle::Event::OtlpRelayJournalDrainedRows, 1);
        (before, fixture.pass(&index, "a"))
    });
    assert!(!before.same(&after), "drained journal rows wake the walk");
}

#[test]
fn overdue_audit_is_served_by_the_backstop_walk() {
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let mut index = ScanIndex::default();
    settled_entry(&mut index, START);
    assert!(!selects(&index, START));
    let entry = index.files.get_mut(KEY).unwrap();
    entry.set_unverified_deadline(START - 60);
    let ordinary = walk_decision(&index, START + 60);
    assert_eq!(ordinary.1, Some(CandidateParseReason::Audit));
    assert!(!selects(&index, START + 60), "a due audit does not wake");
    fixture.walk(&index, START);
    for gap in (1800..WALK_GAP).step_by(1800) {
        assert!(
            fixture.gate(&index, START + gap),
            "the audit waits at +{gap}s"
        );
    }
    assert!(
        !fixture.gate(&index, START + WALK_GAP),
        "the backstop walks"
    );
    assert_eq!(
        walk_decision(&index, START + WALK_GAP).1,
        Some(CandidateParseReason::Audit),
        "and that walk reads the audit"
    );
}

/// For every combination of index states over an unchanged file, the
/// projection selects exactly what the walk's own decision selects, except
/// a due sampled audit, which only the backstop walk serves.
#[test]
fn projection_owes_iff_walk_selects() {
    let mutations: [fn(&mut ScanIndex); 6] = [
        |index| index.files.get_mut(KEY).unwrap().last_snapshot_fingerprint = None,
        |index| {
            let entry = index.files.get_mut(KEY).unwrap();
            entry.scan_identity_version = Some("semantic_sync:v1".into());
        },
        |index| index.files.get_mut(KEY).unwrap().codex_captured_uncommitted = true,
        |index| {
            index
                .claude_account_deferred_holds
                .insert(KEY.into(), "reason".into());
        },
        |index| {
            index
                .snapshot_activity_at
                .insert("fp".into(), Some("not-a-time".into()));
        },
        |index| {
            index
                .files
                .get_mut(KEY)
                .unwrap()
                .set_unverified_deadline(START - 1)
        },
    ];
    let mut selected = 0;
    for mask in 0..1u32 << mutations.len() {
        let mut index = ScanIndex::default();
        settled_entry(&mut index, START);
        for (bit, mutate) in mutations.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                mutate(&mut index);
            }
        }
        let (decision, reason) = walk_decision(&index, START);
        let walk_selects = decision != CandidateDecision::Skip;
        let projected = selects(&index, START);
        if reason == Some(CandidateParseReason::Audit) {
            // The audit gate runs first; the projection sees what is left.
            assert!(walk_selects, "mask {mask:#08b}");
        } else {
            assert_eq!(projected, walk_selects, "mask {mask:#08b}: {reason:?}");
        }
        assert!(!projected || walk_selects, "mask {mask:#08b}");
        selected += usize::from(projected);
        let owed = !owes_nothing(&index, DAYS, START);
        assert_eq!(owed, projected || mask & 0b1000 != 0, "mask {mask:#08b}");
    }
    assert!(selected > 0 && selected < 64);
    // Outside the window an unchanged file owes nothing.
    let mut index = ScanIndex::default();
    settled_entry(&mut index, START - (DAYS + 1) * 86_400);
    index.files.get_mut(KEY).unwrap().last_snapshot_fingerprint = None;
    assert!(owes_nothing(&index, DAYS, START));
}

/// Wakes no transcript hint names, each idle -> event -> walk: a watched
/// Claude sidecar edit (subagent `.meta.json`, workflow record) and a
/// launch-event inbox stamp (`pending/`, `processed/`).
#[test]
fn sidecar_and_launch_inbox_events_walk_an_idle_source() {
    let source = SnapshotSource::ClaudeCode;
    let fixture = Fixture::new(source);
    let index = ScanIndex::default();
    let root = &fixture.roots[0];
    let sidecar = |path: PathBuf| {
        crate::snapshot_watcher::simulate_transcript_events(source, &fixture.roots, &[path]);
    };
    let [pending, processed] = crate::launch_events::inbox_dirs(&fixture.scratch);
    let wakes: [(&str, &dyn Fn()); 4] = [
        ("meta", &|| {
            sidecar(root.join("p/s/subagents/agent-a.meta.json"))
        }),
        ("workflow", &|| sidecar(root.join("p/workflows/run.json"))),
        ("pending", &|| std::fs::create_dir_all(&pending).unwrap()),
        ("processed", &|| {
            std::fs::create_dir_all(&processed).unwrap()
        }),
    ];
    for (n, (name, wake)) in (0_u64..).zip(&wakes) {
        let at = START + n * 600;
        fixture.walk(&index, at);
        assert!(
            fixture.gate(&index, at + 60),
            "{name}: idle before the event"
        );
        wake();
        assert!(!fixture.gate(&index, at + 120), "{name}: the event walks");
    }
}
