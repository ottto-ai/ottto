use super::*;
use crate::snapshots::claude_family_census_shadow as shadow;
use crate::snapshots::*;

const DAY: u64 = 24 * 60 * 60;
const NOW: u64 = 1_793_318_400;

fn path(n: usize) -> ScanTraversalPath {
    ScanTraversalPath {
        scan_root: PathBuf::from("/synthetic"),
        path: PathBuf::from(format!("/synthetic/{n}.jsonl")),
        census_member: true,
        watcher_hint: false,
    }
}
fn fixture() -> ScanIndex {
    ScanIndex {
        traversal: Some(ScanTraversalCheckpoint {
            context_fingerprint: "synthetic".into(),
            census_window_end: "2026-10-30T00:00:00Z".into(),
            scan_roots: Vec::new(),
            pending_directories: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            observed_index_keys: Default::default(),
            codex_rollout_paths: BTreeSet::new(),
            codex_join_directory_census: None,
            reconciliation_upper_bound: None,
            reconciliation_after: None,
            reconciliation_started: false,
            watcher_hint_seen: false,
            codex_freshness_yield: false,
            codex_parent_resolution_retry_required: false,
            unhealthy_retry_attempt: 0,
            unhealthy_retry_not_before_unix_seconds: None,
            oversized_discovery: BTreeMap::new(),
            counts: ScanTraversalCounts::default(),
            residue: ScanTraversalResidue::default(),
            context_inputs: None,
            listing_started_unix_seconds: None,
            listing_owed_requeued_unix_seconds: Default::default(),
        }),
        ..ScanIndex::default()
    }
}
fn queue(index: &mut ScanIndex, n: usize, indexed: bool) {
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .push_back(path(n));
    if indexed {
        let mut entry = crate::snapshots::tests::manifest_index_entry(None);
        entry.size_bytes = 100;
        entry.modified_unix_seconds = 10;
        entry.modified_unix_nanos = Some(10_000_000_000);
        index.files.insert(local_index_key(&path(n).path), entry);
    }
}
fn hash(n: usize) -> u64 {
    shadow::hash64(path(n).path.as_os_str().as_encoded_bytes())
}
fn stamp(stamps: &mut shadow::FirstPending, index: &ScanIndex, now: u64) {
    stamps.observe(shadow::skipped_view(index), |_| false, now, Some(index));
}

fn measure(
    index: &ScanIndex,
    stamps: &mut shadow::FirstPending,
    now: u64,
) -> shadow::PendingCensusMembers {
    stamps
        .observe(shadow::skipped_view(index), |_| false, now, Some(index))
        .0
}

/// [behaviour] Pending ages are aggregate-only lower bounds.
#[test]
fn each_gauge_is_distinct_and_read_free() {
    let mut index = fixture();
    queue(&mut index, 0, false);
    queue(&mut index, 1, true);
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    // Duplicate queue+replay occurrence must not double-count a tracked file.
    index.claude_stale_family_carry.replay.push(path(1));
    let before = serde_json::to_vec(&index).unwrap();
    let row = with_transcript_io_denied(|| measure(&index, &mut stamps, NOW + DAY + 1));
    assert_eq!(serde_json::to_vec(&index).unwrap(), before);
    assert_eq!(row.tracked, 2);
    assert_eq!(row.oldest_age_s, DAY + 1);
    assert_eq!(row.over_24h, 2);
    assert_eq!(row.freshness.discovered_unread_tracked_files, 1);
    assert_eq!(row.freshness.discovered_unread_over_24h_tracked_files, 1);
    assert_eq!(row.freshness.oldest_discovered_unread_age_seconds, DAY + 1);
    assert_eq!(row.freshness.indexed_or_replay_tracked_files, 1);
    assert!(row.freshness.ages_are_process_local_lower_bounds);
    assert_eq!(measure(&index, &mut stamps, NOW + DAY).over_24h, 0);
}

/// [behaviour] Replay is distinct from unread work.
#[test]
fn replay_without_index_is_not_never_read() {
    let mut index = fixture();
    index.claude_stale_family_carry.replay.push(path(1));
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &mut stamps, NOW + DAY + 1);
    assert_eq!(row.freshness.discovered_unread_tracked_files, 0);
    assert_eq!(row.freshness.indexed_or_replay_tracked_files, 1);
}

/// [behaviour] Bounded coverage loss is explicit and restart ages are lower bounds.
#[test]
fn eviction_is_reported_as_missing_coverage_and_restart_ages_reset() {
    let mut index = fixture();
    for n in 0..=shadow::MAX_FIRST_PENDING {
        queue(&mut index, n, false);
    }
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &mut stamps, NOW + DAY + 1);
    assert_eq!(row.tracked, shadow::MAX_FIRST_PENDING as u64);
    assert_eq!(row.freshness.skipped_untracked_entries, 1);
    assert_eq!(row.freshness.discovered_unread_untracked_entries, 1);
    let mut restarted = shadow::FirstPending::default();
    stamp(&mut restarted, &index, NOW + DAY + 1);
    let restarted = measure(&index, &mut restarted, NOW + DAY + 1);
    assert_eq!(restarted.oldest_age_s, 0);
    assert_eq!(
        restarted.freshness.discovered_unread_over_24h_tracked_files,
        0
    );
    assert!(restarted.freshness.ages_are_process_local_lower_bounds);
}

/// [behaviour] A scope change or reload restarts the process-local stamp clock.
#[test]
fn stamp_clock_restarts_with_scope_and_reload() {
    let mut runtime = shadow::Runtime::default();
    let mut index = fixture();
    let touched = shadow::Touched::default();
    for (scope, now, age, reload) in [
        ("original", NOW, 0, false),
        ("original", NOW + 1, 1, false),
        ("moved", NOW + 2, 0, false),
        ("reloaded", NOW + 3, 0, true),
    ] {
        if reload {
            index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
            runtime = shadow::Runtime::default();
        }
        let row = shadow::evaluate_page(
            &mut runtime,
            &index,
            &touched,
            std::iter::empty(),
            false,
            scope,
            now,
        )
        .unwrap();
        assert_eq!(row.pending_census_members.stamped_for_s, age);
    }
}

/// [off=main] Disabling the shadow adds no tracker state, allocation or diagnostic emission.
#[test]
fn disabled_shadow_has_no_tracker_state_box_or_emission() {
    let _disabled = DisabledForTest::new();
    let index = fixture();
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic"),
        path: path(0).path,
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1_000_000_000,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let (_, records) = crate::local_resource_diagnostics::capture(|| {
        shadow::attest_equality_skip(&index, &candidate, &None, NOW);
        shadow::observe_page(&index, &None, &[], &ScanCensus::default(), &None, NOW);
    });
    assert!(records.is_empty());
    assert!(shadow::runtime_pristine_for_test());
    let scan = OwnedSourceScan::new_selecting(
        SnapshotSource::ClaudeCode,
        &[],
        index,
        "2026-10-30T00:00:00Z",
        7,
        1,
        false,
        None,
        &[],
        false,
        false,
        &[],
    );
    assert!(scan.claude_family_shadow.is_none());
}

/// [behaviour] Only a regular-file disable sentinel changes the default-ON policy.
#[test]
fn kill_switch_defaults_on_and_requires_a_regular_file() {
    let scratch = crate::test_scratch::ScratchDir::new("money-freshness-policy");
    assert!(enabled_at(&scratch));
    std::fs::write(scratch.join("money_freshness_disabled"), b"").unwrap();
    assert!(!enabled_at(&scratch));
    std::fs::remove_file(scratch.join("money_freshness_disabled")).unwrap();
    std::fs::create_dir(scratch.join("money_freshness_disabled")).unwrap();
    assert!(enabled_at(&scratch));
    std::fs::remove_dir(scratch.join("money_freshness_disabled")).unwrap();
    #[cfg(unix)]
    {
        std::fs::write(scratch.join("target"), b"").unwrap();
        std::os::unix::fs::symlink(
            scratch.join("target"),
            scratch.join("money_freshness_disabled"),
        )
        .unwrap();
        assert!(enabled_at(&scratch));
    }
}

/// [regress] Duplicate heap-eviction coverage bug: retained queue/replay keys keep complete coverage.
#[test]
fn replay_overlap_at_capacity_keeps_complete_coverage() {
    let mut index = fixture();
    let mut stamps = shadow::FirstPending::default();
    for n in 0..shadow::MAX_FIRST_PENDING {
        queue(&mut index, n, true);
    }
    stamp(&mut stamps, &index, NOW);
    let duplicate = (0..shadow::MAX_FIRST_PENDING)
        .min_by_key(|n| hash(*n))
        .unwrap();
    index.claude_stale_family_carry.replay.push(path(duplicate));
    let row = measure(&index, &mut stamps, NOW + 1);
    assert_eq!(row.tracked, shadow::MAX_FIRST_PENDING as u64);
    assert_eq!(row.freshness.skipped_untracked_entries, 0);
}

fn alarm_rows(rows: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    rows.iter()
        .filter(|row| row["stage"] == "freshness_alarm")
        .map(|row| &row["counts"])
        .collect()
}

fn age_a_week(path: &Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - std::time::Duration::from_secs(7 * DAY))
        .unwrap();
}

fn stored_entry(path: &Path) -> ScanIndexEntry {
    let live = std::fs::metadata(path).unwrap();
    let mut stored = crate::snapshots::tests::manifest_index_entry(None);
    stored.size_bytes = live.len();
    stored.modified_unix_nanos = live.modified().ok().and_then(unix_nanos);
    stored
}

fn start_walk(source: SnapshotSource, root: &Path, index: &mut ScanIndex) {
    index.traversal = None;
    ensure_bounded_traversal(
        source,
        &[root.to_path_buf()],
        index,
        "2026-10-30T00:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
}

fn walk_page(source: SnapshotSource, index: &mut ScanIndex) {
    advance_bounded_directory_traversal_with_budget(source, index, BACKFILL_WINDOW_DAYS, 2, None);
}

/// [regress] The old gauge restarted with the process: the first walk of a new process
/// reads the true age from the stored stamp and live mtime, across pages that reload the index.
#[test]
fn first_walk_after_restart_reports_the_durable_age_across_pages() {
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let scratch = crate::test_scratch::ScratchDir::new("freshness-alarm-walk");
        let root = scratch.join("root");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        let (grown, settled, unindexed) = (
            root.join("a/grown.jsonl"),
            root.join("b/settled.jsonl"),
            root.join("b/unindexed.jsonl"),
        );
        std::fs::write(&grown, b"{}\n{}\n").unwrap();
        std::fs::write(&settled, b"{}\n").unwrap();
        std::fs::write(&unindexed, b"{}\n").unwrap();
        age_a_week(&grown);
        age_a_week(&unindexed);
        let mut index = ScanIndex::default();
        start_walk(source, &root, &mut index);
        let stale = crate::snapshots::tests::manifest_index_entry(None);
        index.files.insert(local_index_key(&grown), stale);
        index
            .files
            .insert(local_index_key(&settled), stored_entry(&settled));
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            // Budget 2: the root, directory a, then directory b, each pass reloading the index.
            for _ in 0..3 {
                walk_page(source, &mut index);
                index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
            }
            // A directory refreshed after the walk is marked: it is not a walk.
            let traversal = index.traversal.as_mut().unwrap();
            traversal.pending_directories.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path: root.join("a"),
                census_member: true,
                watcher_hint: true,
            });
            walk_page(source, &mut index);
        });
        let rows = alarm_rows(&rows);
        assert_eq!(rows.len(), 1, "one row per walk");
        assert!(rows[0]["age_s"].as_u64().unwrap() > 6 * DAY);
        assert_eq!(rows[0]["changed_files"], 1);
        assert_eq!(rows[0]["over_6h_files"], 1);
        assert_eq!(rows[0]["authority_terminal_files"], 0);
        assert_eq!(rows[0]["basis"], "walk");
        assert_eq!(rows[0]["alarm"], true);
    }
}

/// [behaviour] Authority-terminal growth alarms under its own label until its stamp settles.
#[test]
fn authority_terminal_growth_has_its_own_label_until_settled() {
    let source = SnapshotSource::ClaudeCode;
    let scratch = crate::test_scratch::ScratchDir::new("freshness-alarm-terminal");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let held = root.join("family.jsonl");
    std::fs::write(&held, b"{}\n{}\n").unwrap();
    age_a_week(&held);
    let mut index = ScanIndex::default();
    let stale = crate::snapshots::tests::manifest_index_entry(None);
    index.files.insert(local_index_key(&held), stale);
    index.insert_unproven_terminal_claude_authority_for_test("family", &"1".repeat(64));
    let walk = |index: &mut ScanIndex| {
        start_walk(source, &root, index);
        crate::local_resource_diagnostics::capture(|| walk_page(source, index)).1
    };
    let rows = walk(&mut index);
    let row = alarm_rows(&rows)[0];
    assert_eq!(row["authority_terminal_files"], 1);
    assert!(row["authority_terminal_oldest_age_s"].as_u64().unwrap() > 6 * DAY);
    assert_eq!(row["age_s"], 0);
    assert_eq!(row["changed_files"], 0);
    assert_eq!(row["over_6h_files"], 0);
    assert_eq!(row["alarm"], true);
    index
        .files
        .insert(local_index_key(&held), stored_entry(&held));
    let rows = walk(&mut index);
    let row = alarm_rows(&rows)[0];
    assert_eq!(row["authority_terminal_files"], 0);
    assert_eq!(row["alarm"], false);
}

/// [behaviour] A failed pass ages from the newest acceptance for its source; none is unknown.
#[test]
fn failed_pass_reports_the_last_ack_and_unknown_alarms() {
    use crate::upload_receipts::newest_accepted_unix_seconds;
    use ottto_protocol::SourceKind;
    let scratch = crate::test_scratch::ScratchDir::new("freshness-alarm-failed-pass");
    let report = || {
        crate::local_resource_diagnostics::capture(|| {
            report_failed_pass(
                SnapshotSource::Pi,
                newest_accepted_unix_seconds(&scratch, SourceKind::Pi),
            )
        })
        .1
    };
    let ack = |source, accepted: u64| {
        let response = serde_json::from_value(serde_json::json!({
            "accepted": accepted,
            "sessions_reconciled": 0,
            "session_ids": [],
            "disabled": false,
        }))
        .unwrap();
        crate::upload_receipts::append_success(&scratch, source, 1, 200, None, &response).unwrap();
    };
    let assert_unknown = |rows: Vec<serde_json::Value>| {
        let row = alarm_rows(&rows)[0];
        assert!(row["age_s"].is_null());
        assert_eq!(row["basis"], "last_ack");
        assert_eq!(row["alarm"], true);
    };
    assert_unknown(report());
    ack(SourceKind::Codex, 1);
    ack(SourceKind::Pi, 0);
    assert_unknown(report());
    ack(SourceKind::Pi, 1);
    let rows = report();
    let row = alarm_rows(&rows)[0];
    assert!(row["age_s"].as_u64().unwrap() < ALARM_AFTER);
    assert_eq!(row["basis"], "last_ack");
    assert_eq!(row["alarm"], false);
}
