use super::*;

/// [behaviour] A real listing-only Codex page still reports schedulable work;
/// a held-only/finished empty walk reports none. The scheduler consumes this
/// existing status, independently of file selection or a full page.
#[test]
fn first_read_pacing_listing_only_page_retains_queued_census_work() {
    let home = crate::test_scratch::private_dir("first-read-pacing-listing");
    let root = home.join("sessions");
    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("rollout.jsonl"), concat!(
        "{\"timestamp\":\"2026-10-27T07:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"first-read-pacing\"}}\n",
        "{\"timestamp\":\"2026-10-27T07:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":2,\"request_count\":1},\"last_token_usage\":{\"input_tokens\":10,\"output_tokens\":2},\"model\":\"gpt-5.4\"}}}\n",
    )).unwrap();
    let mut index = ScanIndex::default();
    let scan = with_test_directory_entries(1, || {
        scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-10-27T08:00:00Z",
            60,
            100,
        )
        .unwrap()
    });
    assert_eq!(scan.scanned_file_count, 0);
    assert!(scan.snapshots.is_empty());
    assert!(!scan.page_file_limit_hit);
    assert!(!scan.census_complete);
    assert!(scan.census_status.pending_work);
    let empty = home.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let quiet = scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        &[empty],
        &mut ScanIndex::default(),
        "2026-10-27T08:00:00Z",
        60,
        100,
    )
    .unwrap();
    assert!(!quiet.census_status.pending_work);
    std::fs::remove_dir_all(home).unwrap();
}
