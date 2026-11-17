include!("tests/part_01.rs");
include!("tests/part_02.rs");
include!("tests/part_03.rs");
include!("tests/part_04.rs");
include!("tests/part_05.rs");
include!("../retry_integrated_driver.rs");
include!("../retry_owned_rotation.rs");
include!("../retry_bounded_native_tests.rs");
include!("../retry_live_native_tests.rs");
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
