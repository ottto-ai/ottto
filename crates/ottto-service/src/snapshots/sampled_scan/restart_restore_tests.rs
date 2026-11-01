//! Dependency-gated restart policy fixtures.
use super::*;
use crate::snapshots::RestartRestoreForTest;

/// [behaviour] on without discovery is off and diagnostic counts one refused request.
#[test]
fn on_without_discovery_is_off_and_diagnostic_counts_one_refused_request() {
    let _refused = RestartRestoreForTest::requested_without_dependency();
    assert!(!restart_restore::enabled());
    // Exercise the same restart route under the refused request, rather than
    // merely checking the boolean. The nested OFF guard restores this request.
    assert_eq!(restart_restore::on_refused_discovery_dependency(), 1);
}

/// [regress] off discovery keeps main predicate and on adds only its recovery path.
#[test]
fn off_discovery_keeps_main_predicate_and_on_adds_only_its_recovery_path() {
    let source = SnapshotSource::ClaudeCode;
    let path = Path::new("/synthetic/source.jsonl");
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(path),
        serde_json::from_value(serde_json::json!({
            "size_bytes":100,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "effective_upload_body_witness_revision":999
        }))
        .unwrap(),
    );
    let main = sampled_audit::path_requires_verification(&index.files, path);
    assert!(!main);
    for length in [1, 100, 200] {
        let _off = RestartRestoreForTest::disabled();
        assert_eq!(
            sampled_audit::path_requires_recovery(source, &index.files, path, length),
            main
        );
        let _on = RestartRestoreForTest::enabled();
        assert!(sampled_audit::path_requires_recovery(
            source,
            &index.files,
            path,
            length
        ));
    }
}
