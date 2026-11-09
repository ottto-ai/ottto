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
    let home = tests::temp_dir("resident-wave-shape");
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
    let mut index = ScanIndex::default();
    for _ in 0..100 {
        let (next, page, _) =
            fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, 1000, &[]);
        index = next;
        if page.census_complete {
            break;
        }
    }
    assert_eq!(index.files.len(), n, "seed every stored reduction");
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint = "source-changed".into();
    }
    index.traversal = None;
    let (index, page, modes) =
        fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, n + 1, &[]);
    assert_eq!(
        modes.0, 0,
        "unchanged transcripts re-fold from their stored Tail"
    );
    let q = page.scanned_file_count as f64 * FILE_CHARGE;
    let deferred = index
        .traversal
        .as_ref()
        .map_or(0, |walk| walk.pending_candidates.len());
    assert!(q <= B + FILE_CHARGE, "resident charge {q} > B + U_max");
    assert!(deferred > 0, "a 3 B wave must leave pending work");
    assert!(
        !page.census_complete,
        "deferred first-read membership holds census"
    );
    fs::remove_dir_all(home).unwrap();
}
