use super::*;

/// [behaviour] First-read pages use the existing source cadence even without
/// filling the file limit (including a listing-only Codex page).
#[test]
fn first_read_pacing_covers_empty_walk_power_gates_and_census_drain() {
    let now = Instant::now();
    let mut scan = empty_scan();
    assert!(!scan.page_file_limit_hit);
    assert_eq!(scan.scanned_file_count, 0);
    assert!(scan.snapshots.is_empty());
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        scan.source = source;
        scan.first_read_pending = true;
        scan.census_status.pending_work = true;
        for (power, gap) in [
            (PlatformState::Allowed, Some(30)),
            (PlatformState::Battery, Some(180)),
            (PlatformState::Unknown, None),
            (PlatformState::Refused, None),
        ] {
            let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
            cadence.record_scan_success(now, 0);
            assert!(resident_scan_requested(&scan));
            if resident_scan_requested(&scan)
                && let Some(pacing) = resident_pacing(power)
            {
                cadence.request_paced_scan(now, Duration::ZERO, pacing);
            }
            assert_eq!(
                cadence.paced_scan_due(),
                gap.map(|s| now + Duration::from_secs(s))
            );
        }
        // Held-only work has no schedulable queue, even while import is owed.
        scan.census_status.pending_work = false;
        scan.census_complete = false;
        assert!(
            !resident_scan_requested(&scan),
            "held-only work must not spin"
        );
        scan.census_complete = true;
        assert!(
            !resident_scan_requested(&scan),
            "a completed census adds no wake"
        );
        scan.census_status.pending_work = true;
        scan.routine_recensus = true;
        assert!(
            !resident_scan_requested(&scan),
            "routine walks keep ordinary cadence"
        );
        scan.routine_recensus = false;
        scan.first_read_pending = false;
        assert!(
            !resident_scan_requested(&scan),
            "after bootstrap, an underfull page is unchanged"
        );
    }
}

/// [behaviour] First-read means the existing destination/replay predicate:
/// a replay revision bump re-arms pacing, its completion clears it again.
#[test]
fn first_read_pacing_replay_bump_uses_existing_destination_predicate() {
    use crate::snapshot_sync::backfill_replay_pending;
    let destination = "first-read-pacing-destination";
    let mut state = crate::backfill::BackfillState::default();
    let mut scan = empty_scan();
    scan.census_status.pending_work = true;
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        scan.source = source;
        scan.first_read_pending = backfill_replay_pending(source, &state, destination);
        assert!(resident_scan_requested(&scan), "new destination");
        crate::backfill::mark_backfill_complete_for_destination(&mut state, source, destination);
        scan.first_read_pending = backfill_replay_pending(source, &state, destination);
        assert!(!resident_scan_requested(&scan), "current replay completed");
        // A saved older revision stands for an upgrade which bumped the replay.
        state
            .completed_replay_revisions
            .insert(source.api_slug().into(), "old-revision".into());
        scan.first_read_pending = backfill_replay_pending(source, &state, destination);
        assert!(resident_scan_requested(&scan), "replay bump is pending too");
        crate::backfill::mark_backfill_complete_for_destination(&mut state, source, destination);
        scan.first_read_pending = backfill_replay_pending(source, &state, destination);
        assert!(!resident_scan_requested(&scan));
    }
}
