use super::*;

/// [regress] Absent-root counts reach the existing emitted scan row.
#[test]
fn sidecar_absent_roots_reach_emitted_row() {
    let mut scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Codex,
        &[],
        &mut ScanIndex::default(),
        "2026-11-09T12:00:00Z",
        30,
    )
    .unwrap();
    let row = SyncCounts::from_scan_result(&scan, 0, 30).terminal_census_line("codex");
    assert!(row.contains("absent_roots=0"));
    scan.local_codex_diagnostics
        .as_mut()
        .unwrap()
        .state_titles
        .absent_roots = 3;
    let row = SyncCounts::from_scan_result(&scan, 0, 30).terminal_census_line("codex");
    assert!(row.contains("absent_roots=3"));
}
