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
            ..crate::snapshots::claude_family_census_shadow_tests::traversal()
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
