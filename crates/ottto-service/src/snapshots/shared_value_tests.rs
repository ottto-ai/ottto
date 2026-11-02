//! Copy-on-write values through `ScanIndex::clone`.
use super::tests::manifest_index_entry;
use super::*;

/// [behaviour] A clone stays a value and a write copies only what it touches:
/// after one write to a file entry and to a side map, the clone keeps the old
/// values and every untouched value is still the same allocation.
#[test]
fn clone_then_one_write_copies_only_the_written_values() {
    let mut working = ScanIndex::default();
    for key in ["written", "untouched"] {
        working
            .files
            .insert(key.to_string(), manifest_index_entry(Some("old")));
        working
            .file_snapshot_fingerprints
            .insert(key.to_string(), BTreeSet::from(["old".to_string()]));
    }
    let committed = working.clone();

    working.files.get_mut("written").unwrap().size_bytes += 1;
    working
        .file_snapshot_fingerprints
        .get_mut("written")
        .unwrap()
        .insert("new".to_string());

    assert_eq!(
        committed.files["written"].size_bytes + 1,
        working.files["written"].size_bytes
    );
    assert_eq!(
        committed.file_snapshot_fingerprints["written"],
        BTreeSet::from(["old".to_string()])
    );
    assert!(Shared::ptr_eq(
        committed.files.get_shared("untouched").unwrap(),
        working.files.get_shared("untouched").unwrap()
    ));
    assert!(Shared::ptr_eq(
        committed
            .file_snapshot_fingerprints
            .get_shared("untouched")
            .unwrap(),
        working
            .file_snapshot_fingerprints
            .get_shared("untouched")
            .unwrap()
    ));
}
