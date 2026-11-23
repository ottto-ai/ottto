include!("tests/part_01.rs");
include!("tests/part_02.rs");
include!("tests/part_03.rs");
include!("tests/part_04.rs");
include!("tests/part_05.rs");
include!("../retry_integrated_driver.rs");
include!("../retry_bounded_native_tests.rs");
include!("../retry_allocation_native_tests.rs");
include!("continuation_prepare_tests.rs");
include!("tests/part_06.rs");
// Main's original shared pipeline assertions run at the production OFF
// default, independently of the explicit-ON containment fixtures above.

include!("claude_request_census_pipeline_tests.rs");
include!("tests/part_07.rs");
include!("request_identity_pipeline_tests.rs");
include!("tests/part_08.rs");

/// Attach a synthetic working ledger to the same native owner the service uses.
fn route_fixture_progress(
    index: &ScanIndex,
    index_path: &Path,
    path: &Path,
    mut progress: SnapshotUploadProgress,
) -> SnapshotUploadProgress {
    let native = SnapshotUploadProgress::load_for_index(
        index,
        index_path,
        path,
        &progress.destination_namespace_hash,
        progress.active_quarantine_witness.clone().unwrap(),
    )
    .expect("native fixture progress owner");
    progress.generation = native.generation;
    progress.rows = native.rows;
    progress
}

/// `progress` as the first ledger of the empty native route that `index`, a
/// committed fixture graph at `index_path`, owns: on the canonical sibling
/// path, with the destination and source the route's binding names.
pub(super) fn routed_progress(
    index: &ScanIndex,
    index_path: &Path,
    progress: SnapshotUploadProgress,
) -> (PathBuf, SnapshotUploadProgress) {
    let (source, namespace) =
        crate::snapshots::e2_pipeline_scan_fixture::binding_for_test(index_path);
    let active = progress.active_quarantine_witness.clone().unwrap();
    let bound = snapshot_quarantine_witness(source);
    assert_eq!(
        progress.destination_namespace_hash, namespace,
        "ledger destination"
    );
    assert_eq!(
        (&active.parser_version, &active.scan_identity_version),
        (&bound.parser_version, &bound.scan_identity_version),
        "ledger source"
    );
    let path = snapshot_upload_progress_path(index_path);
    let empty =
        SnapshotUploadProgress::load_for_index(index, index_path, &path, &namespace, active)
            .expect("native fixture progress owner");
    assert!(empty.rows.is_some(), "native fixture progress");
    assert!(
        empty.accepted_fingerprints.is_empty()
            && empty.quarantined_fingerprints.is_empty()
            && empty.permanent_rejections.is_empty()
            && empty.accepted_cache_heads.is_empty()
            && empty.pending_cache_heads.is_empty(),
        "a fixture ledger seeds only an empty route"
    );
    let progress = route_fixture_progress(index, index_path, &path, progress);
    (path, progress)
}

/// The route's committed upload progress, as the next pass loads it for its
/// loaded `index`.
pub(super) fn load_routed_progress(
    index: &ScanIndex,
    index_path: &Path,
    namespace: &str,
    witness: SnapshotQuarantineWitness,
) -> SnapshotUploadProgress {
    let progress = SnapshotUploadProgress::load_for_index(
        index,
        index_path,
        &snapshot_upload_progress_path(index_path),
        namespace,
        witness,
    )
    .unwrap();
    assert!(progress.rows.is_some(), "native fixture progress");
    progress
}

fn clear_fixture_progress(progress: &mut SnapshotUploadProgress, path: &Path) -> Result<()> {
    let mut empty = SnapshotUploadProgress::new(
        progress.destination_namespace_hash.clone(),
        progress.active_quarantine_witness.clone().unwrap(),
    );
    empty.generation = progress.generation;
    empty.rows = progress.rows.take();
    empty.save(path)?;
    *progress = empty;
    Ok(())
}

// Every server answer to a page or a pass and the ledger it leaves.
mod answer_table_tests {
    include!("answer_table_tests.rs");
}
