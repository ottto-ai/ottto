use super::*;
use crate::snapshots::*;

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
            observed_index_keys: BTreeSet::new(),
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
fn observed(stamps: &mut shadow::FirstPending, n: usize, size: u64, nanos: u64, epoch: u64) {
    stamps.observe_metadata(
        hash(n),
        Metadata {
            epoch,
            size,
            seconds: 10,
            nanos,
        },
    );
}
fn stamp(stamps: &mut shadow::FirstPending, index: &ScanIndex, now: u64) {
    stamps.observe(shadow::skipped_view(index), |_| false, now);
}

#[test]
fn each_gauge_and_metadata_coverage_are_distinct_and_read_free() {
    let mut index = fixture();
    queue(&mut index, 0, false);
    for n in 1..=4 {
        queue(&mut index, n, true);
    }
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    observed(&mut stamps, 1, 101, 10_000_000_000, 1); // size changed
    observed(&mut stamps, 2, 100, 10_000_000_001, 1); // nanos-only change
    observed(&mut stamps, 3, 100, 10_000_000_000, 1); // unchanged
    observed(&mut stamps, 4, 101, 10_000_000_000, 0); // prior page is unknown
                                                      // Duplicate queue+replay occurrence must not double-count a tracked file.
    index.claude_stale_family_carry.replay.push(path(1));
    let before = serde_json::to_vec(&index).unwrap();
    let row = with_transcript_io_denied(|| measure(&index, &stamps, 1, NOW + DAY + 1));
    assert_eq!(serde_json::to_vec(&index).unwrap(), before);
    assert_eq!(row.skipped_tracked_files, 5);
    assert_eq!(row.oldest_skipped_age_seconds, DAY + 1);
    assert_eq!(row.pending_over_24h_tracked_files, 5);
    assert_eq!(row.discovered_unread_tracked_files, 1);
    assert_eq!(row.discovered_unread_over_24h_tracked_files, 1);
    assert_eq!(row.oldest_discovered_unread_age_seconds, DAY + 1);
    assert_eq!(row.indexed_or_replay_tracked_files, 4);
    assert_eq!(row.changed_since_scan_files, 2);
    assert_eq!(row.unchanged_since_scan_files, 1);
    assert_eq!(row.changed_since_scan_unknown_files, 2);
    assert_eq!(row.metadata_observed_files, 3);
    assert_eq!(row.changed_since_scan_complete_count, None);
    assert!(row.ages_are_process_local_lower_bounds);
    assert_eq!(
        measure(&index, &stamps, 1, NOW + DAY).pending_over_24h_tracked_files,
        0
    );
}

#[test]
fn replay_without_index_is_not_never_read_and_unknown_is_not_zero() {
    let mut index = fixture();
    index.claude_stale_family_carry.replay.push(path(1));
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &stamps, 1, NOW + DAY + 1);
    assert_eq!(row.discovered_unread_tracked_files, 0);
    assert_eq!(row.indexed_or_replay_tracked_files, 1);
    assert_eq!(row.changed_since_scan_complete_count, None);
    let empty = measure(&fixture(), &stamps, 1, NOW);
    assert_eq!(empty.changed_since_scan_complete_count, Some(0));
}

#[test]
fn eviction_is_reported_as_missing_coverage_and_restart_ages_reset() {
    let mut index = fixture();
    for n in 0..=shadow::MAX_FIRST_PENDING {
        queue(&mut index, n, false);
    }
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &stamps, 1, NOW + DAY + 1);
    assert_eq!(row.skipped_tracked_files, shadow::MAX_FIRST_PENDING as u64);
    assert_eq!(row.skipped_untracked_entries, 1);
    assert_eq!(row.discovered_unread_untracked_entries, 1);
    let mut restarted = shadow::FirstPending::default();
    stamp(&mut restarted, &index, NOW + DAY + 1);
    let restarted = measure(&index, &restarted, 1, NOW + DAY + 1);
    assert_eq!(restarted.oldest_skipped_age_seconds, 0);
    assert_eq!(restarted.discovered_unread_over_24h_tracked_files, 0);
    assert!(restarted.ages_are_process_local_lower_bounds);
    assert_eq!(restarted.restart_started_with_open_condition, None);
}

fn positive() -> Counts {
    Counts {
        changed_since_scan_files: 1,
        ..Counts::default()
    }
}

#[test]
fn alarm_strict_edge_zero_unknown_restart_clock_and_scope_isolation() {
    let mut a = Episode::new();
    let mut b = Episode::new();
    a.update(&mut positive(), NOW);
    b.update(&mut Counts::default(), NOW + ALARM_AFTER);
    let mut edge = positive();
    a.update(&mut edge, NOW + ALARM_AFTER);
    assert!(!edge.changed_over_6h_alarm);
    a.update(&mut edge, NOW + ALARM_AFTER + 1);
    assert!(edge.changed_over_6h_alarm);
    a.update(&mut Counts::default(), NOW + ALARM_AFTER + 2);
    let mut row = positive();
    a.update(&mut row, NOW + ALARM_AFTER + 3);
    assert_eq!(row.changed_episode_age_seconds, 0);
    a.update(
        &mut Counts {
            changed_since_scan_unknown_files: 1,
            ..Counts::default()
        },
        NOW + 2 * ALARM_AFTER,
    );
    let mut restarted = Episode::new();
    let mut restart_row = positive();
    restarted.update(&mut restart_row, NOW + 2 * ALARM_AFTER + 1);
    assert!(restart_row.tracker_initialized);
    assert!(!restart_row.changed_over_6h_alarm);
    assert_eq!(restart_row.restart_started_with_open_condition, None);
    let mut rollback = positive();
    a.update(&mut rollback, NOW - 1);
    assert_eq!(rollback.changed_episode_age_seconds, 0);
}

#[test]
fn alarm_payload_uses_existing_carrier_and_contains_only_aggregates() {
    let mut row = Counts {
        discovered_unread_tracked_files: 3,
        ages_are_process_local_lower_bounds: true,
        ..positive()
    };
    let mut episode = Episode::new();
    episode.update(&mut row, NOW);
    episode.update(&mut row, NOW + ALARM_AFTER + 1);
    let (_, records) = crate::local_resource_diagnostics::capture(|| emit(&row));
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["stage"], "money_freshness_alarm");
    assert_eq!(records[1]["counts"]["discovered_unread_tracked_files"], 3);
    assert!(records[1]["counts"]
        .get("restart_reset_open_episode_total")
        .is_none());
    let text = serde_json::to_string(&records).unwrap();
    for private in [
        "/synthetic",
        ".jsonl",
        "source_file_fingerprint",
        "index_key",
    ] {
        assert!(!text.contains(private));
    }
}

#[test]
fn startup_condition_proxy_counts_only_first_observation_per_process_scope() {
    let mut starts = ScopeStarts::new();
    let mut first = positive();
    starts.observe(1, &mut first);
    assert_eq!(first.restart_started_with_open_condition, Some(1));
    let mut next = positive();
    starts.observe(1, &mut next);
    assert_eq!(next.restart_started_with_open_condition, None);
    let mut clear = Counts::default();
    starts.observe(2, &mut clear);
    assert_eq!(clear.restart_started_with_open_condition, Some(0));
    starts.observe(2, &mut next);
    assert_eq!(next.restart_started_with_open_condition, None);
    // Returning to an earlier scope must not re-emit the process proxy.
    starts.observe(1, &mut next);
    assert_eq!(next.restart_started_with_open_condition, None);
    let mut restarted = ScopeStarts::new();
    restarted.observe(1, &mut next);
    assert_eq!(next.restart_started_with_open_condition, Some(1));
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        emit(&first);
        let mut later = positive();
        starts.observe(1, &mut later);
        emit(&later);
    });
    assert_eq!(rows[0]["counts"]["restart_started_with_open_condition"], 1);
    assert!(rows[0]["process_id"].is_number());
    assert!(rows[1]["counts"]
        .get("restart_started_with_open_condition")
        .is_none());
    // Bounded coverage overflow is explicit and never re-counts an old scope.
    for scope in 3..=64 {
        starts.observe(scope, &mut positive());
    }
    starts.observe(65, &mut next);
    assert!(next.restart_scope_tracking_full);
    assert_eq!(next.restart_started_with_open_condition, None);
    starts.observe(1, &mut next);
    assert!(!next.restart_scope_tracking_full);
    assert_eq!(next.restart_started_with_open_condition, None);
}
