use super::*;

/// [regress] Sidecar hit/reload counters reach the existing emitted scan row.
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
        "logs_2_delta_rows=0",
        "absent_roots=0",
    ] {
        assert!(row.contains(field), "missing emitted field: {field}");
    }
    let d = scan.local_codex_diagnostics.as_mut().unwrap();
    d.state_titles.reused_roots = 7;
    d.state_titles.reloaded_roots = 9;
    d.state_titles.absent_roots = 3;
    d.rollout_extents.reused_roots = 2;
    d.session_index.reloaded_roots = 4;
    d.logs_2.delta_rows = 11;
    let row = SyncCounts::from_scan_result(&scan, 0, 30).terminal_census_line("codex");
    for field in [
        "state_5_reused=7",
        "state_5_reloaded=9",
        "thread_history_1_reused=2",
        "session_index_reloaded=4",
        "logs_2_delta_rows=11",
        "absent_roots=3",
    ] {
        assert!(row.contains(field), "missing emitted value: {field}");
    }
}
