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
        // Discovery preserves debt until complete-census retirement decides it.
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

#[cfg(unix)]
fn capacity_scan(index: &mut ScanIndex, root: &Path, limit: usize) -> SourceScanResult {
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    scan_source_roots_with_limit(
        SnapshotSource::Pi,
        &[root.to_path_buf()],
        index,
        &now,
        BACKFILL_WINDOW_DAYS,
        limit,
        false,
    )
    .unwrap()
}

#[cfg(unix)]
fn capacity_cleared(alarms: &[Value], reason: &str) -> u64 {
    alarms
        .iter()
        .filter_map(|alarm| alarm["counts"]["tail_capacity_debt_cleared"][reason].as_u64())
        .sum()
}

#[test]
#[cfg(unix)]
fn capacity_deleted_file_clears_only_on_complete_census_without_reading() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _on = RestartRestoreForTest::enabled();
    for delivery_entry in [false, true] {
        let root = crate::test_scratch::ScratchDir::new("capacity-deleted");
        let path = root.join("deleted.jsonl");
        fs::write(&path, b"{}\n").unwrap();
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        if delivery_entry {
            index
                .files
                .insert(key.clone(), tests::manifest_index_entry(None));
        }
        index.tail_capacity_debt.insert(key.clone(), 3);
        fs::remove_file(&path).unwrap();
        let ((scan, alarms), bytes) = sampled_scan::transition_fixture::observe_consumed(|| {
            crate::local_resource_diagnostics::capture(|| {
                capacity_scan(&mut index, &root, MAX_BACKFILL_FILES_PER_SOURCE)
            })
        });
        assert!(scan.census_complete);
        assert_eq!(scan.scanned_file_count, 0);
        assert_eq!(bytes, 0, "absence must not read transcript bytes");
        assert!(!index.tail_capacity_debt.contains_key(&key));
        assert!(!index.files.contains_key(&key));
        assert_eq!(capacity_cleared(&alarms, "absent"), 1);
        assert_eq!(capacity_cleared(&alarms, "aged"), 0);
        let index_path = root.join("index.json");
        index.save(&index_path).unwrap();
        assert!(ScanIndex::load(&index_path)
            .unwrap()
            .tail_capacity_debt
            .is_empty());
    }
}

#[test]
#[cfg(unix)]
fn capacity_incomplete_census_retains_deleted_file_debt() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _on = RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("capacity-incomplete");
    let path = root.join("deleted.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    index.tail_capacity_debt.insert(key.clone(), 3);
    fs::remove_file(path).unwrap();
    for name in ["a.jsonl", "b.jsonl"] {
        fs::write(root.join(name), b"{}\n").unwrap();
    }
    let (scan, alarms) =
        crate::local_resource_diagnostics::capture(|| capacity_scan(&mut index, &root, 1));
    assert!(!scan.census_complete);
    assert_eq!(index.tail_capacity_debt.get(&key), Some(&3));
    assert_eq!(capacity_cleared(&alarms, "absent"), 0);
}

#[test]
#[cfg(unix)]
fn capacity_idle_aging_uses_current_mtime_and_the_existing_35_day_cutoff() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _on = RestartRestoreForTest::enabled();
    for days in [34, 36] {
        let root = crate::test_scratch::ScratchDir::new("capacity-aged");
        let path = root.join("source.jsonl");
        fs::write(&path, b"{}\n").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - std::time::Duration::from_secs(days * 86_400))
            .unwrap();
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        // The delivery entry alone would age both cases. Current source
        // metadata must preserve the 34-day file's obligation.
        index
            .files
            .insert(key.clone(), tests::manifest_index_entry(None));
        index.tail_capacity_debt.insert(key.clone(), 3);
        let (scan, alarms) = crate::local_resource_diagnostics::capture(|| {
            capacity_scan(&mut index, &root, MAX_BACKFILL_FILES_PER_SOURCE)
        });
        assert!(scan.census_complete);
        assert_eq!(index.tail_capacity_debt.contains_key(&key), days == 34);
        assert_eq!(capacity_cleared(&alarms, "aged"), u64::from(days == 36));
        assert_eq!(capacity_cleared(&alarms, "absent"), 0);
    }
}

#[test]
#[cfg(unix)]
fn capacity_replacement_counts_only_a_released_obligation_and_off_is_inert() {
    let _on = RestartRestoreForTest::enabled();
    let mut index = ScanIndex::default();
    index.tail_capacity_debt.insert("synthetic".into(), 3);
    let (_, alarms) = crate::local_resource_diagnostics::capture(|| {
        index.clear_tail_capacity_debt(SnapshotSource::Codex, "synthetic", "replaced");
        index.clear_tail_capacity_debt(SnapshotSource::Codex, "synthetic", "replaced");
    });
    assert!(index.tail_capacity_debt.is_empty());
    assert_eq!(capacity_cleared(&alarms, "replaced"), 1);
    index.tail_capacity_debt.insert("synthetic".into(), 3);
    for dependency_refused in [false, true] {
        let _off = if dependency_refused {
            RestartRestoreForTest::requested_without_dependency()
        } else {
            RestartRestoreForTest::disabled()
        };
        let (_, alarms) = crate::local_resource_diagnostics::capture(|| {
            index.clear_tail_capacity_debt(SnapshotSource::Codex, "synthetic", "replaced");
        });
        assert_eq!(index.tail_capacity_debt.get("synthetic"), Some(&3));
        assert_eq!(capacity_cleared(&alarms, "replaced"), 0);
        assert!(serde_json::to_value(&index)
            .unwrap()
            .get("tail_capacity_debt")
            .is_none());
    }
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
    for resource in [
        "cache_transit",
        "decode",
        "rederive_refused",
        "rederive_budget",
    ] {
        assert_eq!(
            capacity_full_phase(true, false, false, false, Some(resource)),
            Some(resource)
        );
    }
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
