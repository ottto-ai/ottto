use super::*;

/// [regress] Sidecar hit/reload counters and reload causes reach the
/// existing emitted scan row.
#[test]
fn sidecar_reuse_counters_reach_emitted_row() {
    let mut scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Codex,
        &[],
        &mut ScanIndex::default(),
        "2026-11-09T12:00:00Z",
        30,
    )
    .unwrap();
    let row = SyncCounts::from_scan_result(&scan, 0, 30).terminal_census_line("codex");
    for field in [
        "state_5_reused=0",
        "state_5_reloaded=0",
        "thread_history_1_reused=0",
        "thread_history_1_reloaded=0",
        "session_index_reused=0",
        "session_index_reloaded=0",
        "absent_roots=0",
        "sidecar_facts_heap_bytes=0",
        "sidecar_reload_cause=none",
        "sidecar_keep_declined=none",
        "session_index_changed=0",
    ] {
        assert!(row.contains(field), "missing emitted field: {field}");
    }
    let d = scan.local_codex_diagnostics.as_mut().unwrap();
    d.state_titles.reused_roots = 7;
    d.state_titles.reloaded_roots = 9;
    d.state_titles.absent_roots = 3;
    d.rollout_extents.reused_roots = 2;
    d.session_index.reloaded_roots = 4;
    d.sidecar_facts_heap_bytes = 12_345;
    d.sidecar_reload_cause = "stamp_changed";
    d.sidecar_keep_declined = "changed_during_load";
    d.sidecar_changed_homes = [0, 0, 0b1001];
    let row = SyncCounts::from_scan_result(&scan, 0, 30).terminal_census_line("codex");
    for field in [
        "state_5_reused=7",
        "state_5_reloaded=9",
        "thread_history_1_reused=2",
        "session_index_reloaded=4",
        "absent_roots=3",
        "sidecar_facts_heap_bytes=12345",
        "sidecar_reload_cause=stamp_changed",
        "sidecar_keep_declined=changed_during_load",
        "state_5_changed=0",
        "session_index_changed=2 session_index_changed_homes=0,3",
    ] {
        assert!(row.contains(field), "missing emitted value: {field}");
    }
}
