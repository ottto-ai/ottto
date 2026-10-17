use super::*;
use crate::snapshots::*;
use std::io::Write;
#[test]
fn copy_containment_completion_accounting_actual_scan_refuses_without_allocation_or_mutation() {
    let base = std::env::temp_dir().join(format!(
        "ottto-copy-completion-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let path = base.join("5f9ab1cc-0000-4000-8000-0000000000dd.jsonl");
    std::fs::write(&path, "{\"type\":\"assistant\",\"sessionId\":\"5f9ab1cc-0000-4000-8000-0000000000dd\",\"timestamp\":\"2026-10-16T23:00:00Z\",\"requestId\":\"req_component\",\"message\":{\"id\":\"msg_component\",\"model\":\"claude-fixture-model\",\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}}\n").unwrap();
    let mut index = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&base),
        &mut index,
        "2026-10-17T00:00:00Z",
        730,
        32,
        false,
    )
    .unwrap();
    assert_eq!(scan.scanned_file_count, 1);
    reset_observation_counts();
    let _default = crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_permit(
        &base.join("synthetic-evidence"),
        &mut scan,
        &mut index,
        None,
    );
    assert_eq!(
        observation_counts(),
        (0, 0),
        "actual default hook does not invoke the observation"
    );
    index.attach_unknown_copy_owner("a".repeat(64)).unwrap();
    let before = serde_json::to_vec(&scan.snapshots).unwrap();
    let disposition = ClaudeUsageAuthorityDisposition::default();
    let api = ClaudeLocalOtelLoadReport::default();
    let trace = ClaudeTraceOwnershipLoadReport::default();
    let originals = BTreeMap::new();
    let frame = || BorrowedClaudeCompletion {
        index: &index,
        scan: &scan,
        disposition: &disposition,
        api: &api,
        trace: &trace,
        evidence: None,
        originals: &originals,
    };
    reset_observation_counts();
    let (refused, allocations) =
        crate::retry_allocation_probe::measure(|| observe_owned_completion(frame(), 0));
    assert_eq!(refused, None);
    assert_eq!(allocations.allocations, 0);
    assert_eq!(
        observation_counts(),
        (1, 0),
        "zero budget/layout returns before graph traversal"
    );
    reset_observation_counts();
    let observed = observe_owned_completion(frame(), crate::source_rotation::OVERLAP_BUDGET);
    assert_eq!(
        observation_counts(),
        (1, usize::from(heap_layout_bound::layout_supported())),
        "one actual frame observation, never one per held key"
    );
    if heap_layout_bound::layout_supported() {
        assert!(
            observed.is_some(),
            "small actual completed fixture must be observable"
        );
    } else {
        assert_eq!(observed, None);
    }
    assert_eq!(serde_json::to_vec(&scan.snapshots).unwrap(), before);
    let mut c = Counter::new(crate::source_rotation::OVERLAP_BUDGET);
    scan.completed_claude_heap_bound(&mut c).unwrap();
    let visits = c.visits_for_test();
    assert!(visits > 0 && visits <= 4096);
    writeln!(std::io::stderr().lock(), "copy_containment_completion_accounting: actual_native_files=1 actual_default_hook_invocations=0 unsupported_before_graph_walk=true budget0_observation_allocations=0 layout_supported={} positive_observation_executed={} source_frame_top_level_visits={visits} identity_body_bytes_unchanged=true future_peak_unqualified=true cache_admission=false", heap_layout_bound::layout_supported(), observed.is_some()).unwrap();
    let _ = std::fs::remove_dir_all(base);
}
