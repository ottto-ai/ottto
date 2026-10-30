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
    stamps.observe(shadow::skipped_view(index), |_| false, now, Some(index), 1);
}

fn measure(
    index: &ScanIndex,
    stamps: &mut shadow::FirstPending,
    epoch: u64,
    now: u64,
) -> shadow::PendingCensusMembers {
    stamps
        .observe(
            shadow::skipped_view(index),
            |_| false,
            now,
            Some(index),
            epoch,
        )
        .0
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
    let row = with_transcript_io_denied(|| measure(&index, &mut stamps, 1, NOW + DAY + 1));
    assert_eq!(serde_json::to_vec(&index).unwrap(), before);
    assert_eq!(row.tracked, 5);
    assert_eq!(row.oldest_age_s, DAY + 1);
    assert_eq!(row.over_24h, 5);
    assert_eq!(row.freshness.discovered_unread_tracked_files, 1);
    assert_eq!(row.freshness.discovered_unread_over_24h_tracked_files, 1);
    assert_eq!(row.freshness.oldest_discovered_unread_age_seconds, DAY + 1);
    assert_eq!(row.freshness.indexed_or_replay_tracked_files, 4);
    assert_eq!(row.freshness.changed_since_scan_files, 2);
    assert_eq!(row.freshness.unchanged_since_scan_files, 1);
    assert_eq!(row.freshness.changed_since_scan_unknown_files, 2);
    assert_eq!(row.freshness.metadata_observed_files, 3);
    assert_eq!(row.freshness.changed_since_scan_complete_count, None);
    assert!(row.freshness.ages_are_process_local_lower_bounds);
    assert_eq!(measure(&index, &mut stamps, 1, NOW + DAY).over_24h, 0);
}

#[test]
fn replay_without_index_is_not_never_read_and_unknown_is_not_zero() {
    let mut index = fixture();
    index.claude_stale_family_carry.replay.push(path(1));
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &mut stamps, 1, NOW + DAY + 1);
    assert_eq!(row.freshness.discovered_unread_tracked_files, 0);
    assert_eq!(row.freshness.indexed_or_replay_tracked_files, 1);
    assert_eq!(row.freshness.changed_since_scan_complete_count, None);
    let empty = measure(&fixture(), &mut stamps, 1, NOW);
    assert_eq!(empty.freshness.changed_since_scan_complete_count, Some(0));
}

#[test]
fn eviction_is_reported_as_missing_coverage_and_restart_ages_reset() {
    let mut index = fixture();
    for n in 0..=shadow::MAX_FIRST_PENDING {
        queue(&mut index, n, false);
    }
    let mut stamps = shadow::FirstPending::default();
    stamp(&mut stamps, &index, NOW);
    let row = measure(&index, &mut stamps, 1, NOW + DAY + 1);
    assert_eq!(row.tracked, shadow::MAX_FIRST_PENDING as u64);
    assert_eq!(row.freshness.skipped_untracked_entries, 1);
    assert_eq!(row.freshness.discovered_unread_untracked_entries, 1);
    let mut restarted = shadow::FirstPending::default();
    stamp(&mut restarted, &index, NOW + DAY + 1);
    let restarted = measure(&index, &mut restarted, 1, NOW + DAY + 1);
    assert_eq!(restarted.oldest_age_s, 0);
    assert_eq!(
        restarted.freshness.discovered_unread_over_24h_tracked_files,
        0
    );
    assert!(restarted.freshness.ages_are_process_local_lower_bounds);
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
    assert!(!restart_row.tracker_initialized);
    assert!(!restart_row.changed_over_6h_alarm);
    let mut rollback = positive();
    a.update(&mut rollback, NOW - 1);
    assert_eq!(rollback.changed_episode_age_seconds, 0);
}

#[test]
fn first_observation_is_process_wide_and_never_rearmed() {
    assert!(first_observation() && !first_observation());
    let _reset_episode = Episode::new();
    {
        let _disabled = DisabledForTest::new();
        assert!(!first_observation());
    }
    assert!(!first_observation());
}

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
    };
    let (_, records) = crate::local_resource_diagnostics::capture(|| {
        shadow::attest_equality_skip(&index, &candidate, &None, NOW);
        shadow::observe_freshness_metadata(&candidate, &None);
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
        false,
        &[],
    );
    assert!(scan.claude_family_shadow.is_none());
    assert!(
        first_observation(),
        "OFF did not consume the process's first emission"
    );
}

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

#[test]
fn replay_overlap_at_capacity_keeps_complete_known_metadata_coverage() {
    let mut index = fixture();
    let mut stamps = shadow::FirstPending::default();
    for n in 0..shadow::MAX_FIRST_PENDING {
        queue(&mut index, n, true);
    }
    stamp(&mut stamps, &index, NOW);
    for n in 0..shadow::MAX_FIRST_PENDING {
        observed(&mut stamps, n, 100, 10_000_000_000, 1);
    }
    let duplicate = (0..shadow::MAX_FIRST_PENDING)
        .min_by_key(|n| hash(*n))
        .unwrap();
    index.claude_stale_family_carry.replay.push(path(duplicate));
    let row = measure(&index, &mut stamps, 1, NOW + 1);
    assert_eq!(row.tracked, shadow::MAX_FIRST_PENDING as u64);
    assert_eq!(row.freshness.skipped_untracked_entries, 0);
    assert_eq!(row.freshness.changed_since_scan_complete_count, Some(0));
}
