use super::*;

#[test]
fn capacity_debt_survives_save_restart_and_keeps_idle_growth_discoverable() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _on = RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("capacity-idle");
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.tail_capacity_debt.insert(key.clone(), 3);
    index.save(&index_path).unwrap();
    // A crash at refusal is safe: no record was unlinked and the committed
    // index remains the discovery carrier, even with no delivery entry.
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(loaded.tail_capacity_debt.get(&key), Some(&3));
    let recovery = DiscoveryRecovery {
        files: &loaded.files,
        capacity_debt: Some(&loaded.tail_capacity_debt),
        cache: None,
    };
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        assert!(recovery.requires(source, &path, 3));
        // No timestamp/age check can turn this outstanding obligation off.
        assert!(recovery.requires(source, &path, 9));
    }
    // Revalidate an idle file beyond the activity window at BOTH discovery
    // and no-follow open. The future census avoids changing host timestamps.
    let future = unix_seconds(SystemTime::now()).unwrap() + 400 * 24 * 60 * 60;
    let mut census = ScanCensus::default();
    let candidate = candidate_from_traversal_path(
        SnapshotSource::Codex,
        ScanTraversalPath {
            scan_root: root.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        Some(future),
        30,
        recovery,
    )
    .expect("capacity debt must survive the age filter");
    assert!(open_and_identify_capacity_candidate(
        SnapshotSource::Codex,
        candidate,
        &mut census,
        Some(future),
        30,
        &loaded.files,
        &loaded.tail_capacity_debt,
    )
    .is_some());
    let _off = RestartRestoreForTest::disabled();
    assert!(!recovery.requires(SnapshotSource::Codex, &path, 3));
}

#[test]
fn capacity_off_default_writes_no_new_index_field() {
    let _off = RestartRestoreForTest::disabled();
    let value = serde_json::to_value(ScanIndex::default()).unwrap();
    assert!(value.get("tail_capacity_debt").is_none());
}

#[test]
fn capacity_debt_carries_through_a_subset_that_withholds_delivery_entries() {
    let _on = RestartRestoreForTest::enabled();
    let previous = ScanIndex::default();
    let mut working = previous.clone();
    working.tail_capacity_debt.insert("synthetic".into(), 99);
    let subset = working.committable_subset_with_local_holds(
        &previous,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    assert_eq!(subset.tail_capacity_debt.get("synthetic"), Some(&99));
    assert!(subset.files.is_empty());
}

#[test]
fn capacity_full_defers_to_each_existing_admission_owner() {
    // A Claude resource read paid inside restore; a Codex selection-clear
    // read pays at its later start. Neither can be charged by capacity too.
    assert_eq!(capacity_full_phase(true, true, false, false, None), None);
    assert_eq!(capacity_full_phase(true, false, true, false, None), None);
    assert_eq!(capacity_full_phase(true, false, false, true, None), None);
    assert_eq!(
        capacity_full_phase(true, false, false, false, None),
        Some("capacity")
    );
    assert_eq!(
        capacity_full_phase(false, false, false, false, Some("cache_transit")),
        Some("cache_transit")
    );
}

#[test]
fn capacity_off_tolerates_existing_debt_but_never_serializes_or_saves_it() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _on = RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("capacity-off-loaded-debt");
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index
        .tail_capacity_debt
        .insert("synthetic-index-key".into(), u64::MAX);
    let bytes = serde_json::to_vec(&index).unwrap();
    let encoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        encoded["tail_capacity_debt"],
        serde_json::json!({"synthetic-index-key": u64::MAX})
    );
    for dependency_refused in [false, true] {
        let _off = if dependency_refused {
            RestartRestoreForTest::requested_without_dependency()
        } else {
            RestartRestoreForTest::disabled()
        };
        assert!(!restart_restore::enabled());
        let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let streaming =
            lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
        let bounded = lenient_decode::read_bounded(&bytes).unwrap();
        for decoded in [native, streaming, bounded] {
            assert_eq!(
                decoded.tail_capacity_debt.get("synthetic-index-key"),
                Some(&u64::MAX)
            );
            assert!(serde_json::to_value(decoded)
                .unwrap()
                .get("tail_capacity_debt")
                .is_none());
        }
        fs::write(&index_path, &bytes).unwrap();
        let mut loaded = ScanIndex::load(&index_path).unwrap();
        assert_eq!(
            loaded.tail_capacity_debt.get("synthetic-index-key"),
            Some(&u64::MAX)
        );
        loaded.save(&index_path).unwrap();
        let saved: Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
        assert!(saved.get("tail_capacity_debt").is_none());
        assert!(ScanIndex::load(&index_path)
            .unwrap()
            .tail_capacity_debt
            .is_empty());
    }
}
