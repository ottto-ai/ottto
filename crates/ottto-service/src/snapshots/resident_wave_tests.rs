//! Resident admission at the real shared scan seam, using synthetic files.
use super::e2_pipeline_scan_fixture::E2ScanFixture;
use super::*;

const B: f64 = 230.0;
const FILE_CHARGE: f64 = 0.0871;

/// [behaviour] A mass re-fold wave whose file charges alone exceed 3 B
/// must defer work. This test predates the resident meter: on the base all
/// selected files finish in one page, retaining more than B + one unit.
#[test]
fn resident_wave_shape_defers_before_three_b_of_refolds() {
    let home = crate::test_scratch::private_dir("resident-wave-shape")
        .canonicalize()
        .unwrap();
    let root = home.join("transcripts");
    fs::create_dir_all(&root).unwrap();
    let n = (3.0 * B / FILE_CHARGE).ceil() as usize;
    for i in 0..n {
        fs::write(root.join(format!("session-{i:05}.jsonl")), format!(
            "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", i + 1
        )).unwrap();
    }
    let fixture = E2ScanFixture::with_identity_capture(false);
    let roots = [root];
    let state = home.join("state");
    fs::create_dir_all(&state).unwrap();
    let (session, mut index) = StateV2ColdSession::publish(
        scan_index_persistence::Source::Pi,
        &ScanIndex::default(),
        &state,
    );
    let route = session.path().to_owned();
    fixture.on_committed_route(&route);
    index.activate_upload_context("resident-wave".into());
    for _ in 0..100 {
        let (next, mut page, _) =
            fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, 1000, &[]);
        index = next;
        finalize_scan_after_policy(SnapshotSource::Pi, &mut page, &mut index);
        let mut ledger = crate::snapshot_sync::tail_ack_ledger::AckLedger::new(SnapshotSource::Pi);
        ledger.deliver(&page.snapshots);
        assert!(page.snapshots.iter().all(|item| ledger.settled(item)));
        index.record_accepted_snapshot_fingerprints(
            &page
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
            &mut index,
            &page.snapshots,
            &e2_pipeline_scan_fixture::exact_acks_for_test(&page.snapshots),
        );
        index.save(&route).unwrap();
        index = ScanIndex::load(&route).unwrap();
        index.activate_upload_context("resident-wave".into());
        if page.census_complete {
            break;
        }
    }
    assert_eq!(index.files.len(), n, "seed every stored reduction");
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint = "source-changed".into();
    }
    index.traversal = None;
    state_v2::set_collection_page_limit_for_test(&index, n + 1);
    let (index, page, modes) =
        fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, n + 1, &[]);
    let q = page.scanned_file_count as f64 * FILE_CHARGE;
    let deferred = index
        .traversal
        .as_ref()
        .map_or(0, |walk| walk.pending_candidates.len());
    eprintln!(
        "resident_shape files={} charge={q} deferred={deferred} full={} tail={} unchanged={}",
        page.scanned_file_count, modes.0, modes.1, modes.2
    );
    assert!(q <= B + FILE_CHARGE, "resident charge {q} > B + U_max");
    assert!(deferred > 0, "a 3 B wave must leave pending work");
    assert!(
        !page.census_complete,
        "deferred first-read membership holds census"
    );
    assert_eq!(
        modes.0, 0,
        "unchanged transcripts re-fold from their stored Tail"
    );
    fs::remove_dir_all(home).unwrap();
}
