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
