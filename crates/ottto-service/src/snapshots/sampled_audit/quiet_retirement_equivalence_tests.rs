//! OFF retirement keeps the original two-save index settlement.
use super::*;

/// [regress] Qualification preserves the first saved marker until the second CAS.
#[test]
fn off_quiet_retirement_keeps_two_save_marker_settlement() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _off = RestartRestoreForTest::disabled();
    struct ResetClock;
    impl Drop for ResetClock {
        fn drop(&mut self) {
            sampled_scan::set_test_now(None);
        }
    }
    let _clock = ResetClock;
    sampled_scan::set_test_now(Some(1_700_000_000));
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let state = fixture.dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let writer = crate::locked_state_dir::test_locks::hold(&state);
        let index_path = state.join("index.json");
        let namespace = Scope("quiet-retirement-extraction".into());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let (mut index, _, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            &namespace.0,
        );
        let key = local_index_key(&fixture.file.0);
        let fingerprint = index.files[&key].source_file_fingerprint.clone();
        assert!(index.stage_sampled_audit(
            &key,
            &fingerprint,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: 1_700_007_200,
            },
        ));
        assert!(cache.durable_stage_quiet_retirement(source, &key, &fingerprint));
        assert_eq!(
            cache.durable_reconcile_retirements(writer, source, &mut index, &index_path),
            0
        );
        index.save(&index_path).unwrap();
        let first = ScanIndex::load(&index_path).unwrap();
        assert!(first.files[&key].has_unverified_source());
        assert!(cache
            .durable_write_after_save(writer, source, &index)
            .is_none());
        let qualified = ScanIndex::load(&index_path).unwrap();
        assert_eq!(qualified.generation, first.generation);
        assert_eq!(
            qualified.files[&key].scan_identity_version,
            first.files[&key].scan_identity_version
        );
        assert_eq!(
            cache.durable_reconcile_retirements(writer, source, &mut index, &index_path),
            1
        );
        let second = ScanIndex::load(&index_path).unwrap();
        assert_eq!(second.generation, first.generation + 1);
        assert!(!second.files[&key].has_unverified_source());
        assert_eq!(second.files[&key].source_file_fingerprint, fingerprint);
        assert_eq!(
            cache.durable_reconcile_retirements(writer, source, &mut index, &index_path),
            0
        );
        assert_eq!(
            ScanIndex::load(&index_path).unwrap().generation,
            second.generation
        );
    }
}
