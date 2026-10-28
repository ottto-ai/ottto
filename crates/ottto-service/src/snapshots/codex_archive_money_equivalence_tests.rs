// Synthetic candidates exercise backlog plumbing before production discovery.
fn seeded_scan(f: &ArchiveFixture, mut index: ScanIndex, limit: usize) -> OwnedSourceScan {
    let root = f.0.parent().unwrap().to_owned();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut index,
        &now,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        &index.files,
    );
    // Explicit test-only roster/queue seeding; no production discovery opt-in.
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if codex_archive_path(&path) {
            traversal.codex_rollout_paths.insert(local_index_key(&path));
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path,
                census_member: true,
                watcher_hint: true,
            });
        }
    }
    OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root],
        index,
        &now,
        BACKFILL_WINDOW_DAYS,
        limit,
        false,
        None,
        &[],
        false,
        false,
    )
}

#[test]
fn fake_thread_cpu_and_clock_enforce_archive_boundary_pacing() {
    use crate::snapshots::codex_archive_catchup::Pass;
    let mut pass = Pass::default();
    assert!(!pass.ready(1));
    pass.power = true;
    assert!(pass.ready(1));
    assert!(!pass.ready(0));
    pass.observe(Some(0), 19_999_999);
    pass.started = true;
    pass.observe(Some(29_999_999), 1);
    assert!(pass.ready(1));
    pass.observe(Some(2), 1);
    assert!(!pass.ready(1));
    pass.cpu = 0;
    pass.observe(Some(1), 20_000_001);
    assert!(!pass.ready(1));
    pass.work = 0;
    pass.observe(None, 1);
    assert!(!pass.ready(1));
}

#[test]
fn cpu_budget_survives_scan_completion_partial_commit_and_continuation_pages() {
    let f = ArchiveFixture::new(b"no decoder permission");
    let mut scan = seeded_scan(&f, ScanIndex::default(), 1);
    scan.index.archive_pass.power = true;
    scan.index.archive_pass.started = true;
    scan.index.archive_pass.observe(Some(30_000_001), 1);
    let mut completed = None;
    for _ in 0..100 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, .. } => {
                completed = Some(index);
                break;
            }
        }
    }
    let index = completed.expect("denied backlog yields without decoding");
    assert!(index.archive_pass.cpu >= 30_000_001);
    let partial =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(partial.archive_pass.cpu, index.archive_pass.cpu);
    let root = f.0.parent().unwrap().to_owned();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let next = OwnedSourceScan::new_continuation(
        &[root],
        partial,
        &now,
        BACKFILL_WINDOW_DAYS,
        1,
        false,
        false,
        &BTreeSet::new(),
        None,
    );
    assert!(next.index.archive_pass.cpu >= 30_000_001);
    assert!(!next.index.archive_pass.ready(u64::MAX));
    let restarted: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&next.index).unwrap()).unwrap();
    assert!(
        !restarted.archive_pass.power,
        "RAM scheduling is not durable permission"
    );
    let ordinary = seeded_scan(&f, next.index, 1);
    assert_eq!(ordinary.index.archive_pass.cpu, 0);
    assert!(
        !ordinary.index.archive_pass.power,
        "temporary adapter is unknown, not AC detection"
    );
}

#[test]
fn no_inventory_storm_and_live_work_precedes_paced_backlog() {
    let f = ArchiveFixture::new(b"never decode denied backlog");
    let root = f.0.parent().unwrap();
    for n in 0..16 {
        fs::write(
            root.join(format!("rollout-unseen-{n}.jsonl.zst")),
            b"no decoder permission",
        )
        .unwrap();
    }
    let plain = root.join("rollout-live.jsonl");
    fs::write(
        &plain,
        String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", "live"),
    )
    .unwrap();
    for (power, cpu) in [(false, 0), (true, 30_000_000)] {
        let mut scan = seeded_scan(&f, ScanIndex::default(), 100);
        assert_eq!(scan.identified_candidates.front().unwrap().path, plain);
        assert_eq!(
            scan.identified_candidates.len(),
            18,
            "all synthetic archives supplied"
        );
        scan.index.archive_pass.power = power;
        scan.index.archive_pass.cpu = cpu;
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..1000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete {
                        index,
                        scan: result,
                        ..
                    } => {
                        assert_eq!(result.snapshots.len(), 1);
                        assert_eq!(result.snapshots[0].source_session_id, "live");
                        assert_eq!(
                            index.traversal.as_ref().unwrap().pending_candidates.len(),
                            17
                        );
                        assert_eq!(result.unreadable_path_count, 0);
                        return;
                    }
                }
            }
            panic!("denied backlog did not yield");
        });
        assert_eq!(decodes(&rows), 0);
    }
}

#[test]
fn archive_hints_are_backlog_and_newest_archive_is_selected_first() {
    let f = ArchiveFixture::new(b"constructor does not decode");
    let older = f.0.parent().unwrap().join("rollout-older.jsonl.zst");
    fs::write(&older, b"constructor does not decode").unwrap();
    let now = std::time::SystemTime::now();
    File::options()
        .write(true)
        .open(&older)
        .unwrap()
        .set_modified(now - std::time::Duration::from_secs(60))
        .unwrap();
    File::options()
        .write(true)
        .open(&f.0)
        .unwrap()
        .set_modified(now)
        .unwrap();
    let pending = ScanTraversalPath {
        scan_root: f.0.parent().unwrap().into(),
        path: f.0.clone(),
        census_member: true,
        watcher_hint: true,
    };
    assert!(!codex_fresh_data_pending(&pending, &BTreeMap::new()));
    let scan = seeded_scan(&f, ScanIndex::default(), 1);
    assert_eq!(scan.identified_candidates.len(), 1);
    assert_eq!(scan.identified_candidates.front().unwrap().path, f.0);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn stamp_matching_header_inventory_never_decodes_archives() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    state
        .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
        .unwrap();
    let mut scan = seeded_scan(&f, state, 1);
    let mut inventory = scan.codex_join_inventory.take().unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        while !inventory.step_with_archive(
            &CodexTitleMetadata::default(),
            &mut scan.index,
            Some(&cache),
        ) {}
    });
    assert_eq!(decodes(&rows), 0);
    assert!(inventory.complete);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].owner, "compressed-fixture");
    File::options()
        .append(true)
        .open(&f.0)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    assert!(scan.index.archive_header(&f.0).is_none());
    let mut replaced = seeded_scan(&f, scan.index, 1);
    let inventory = replaced.codex_join_inventory.as_mut().unwrap();
    assert!(inventory.step_with_archive(
        &CodexTitleMetadata::default(),
        &mut replaced.index,
        Some(&cache)
    ));
    assert!(
        inventory.complete,
        "unacquired replacement cannot poison plain inventory"
    );
    assert!(inventory.headers.is_empty());
}

#[test]
fn unseen_archives_do_not_spend_the_plain_header_population_cap() {
    let f = ArchiveFixture::new(b"not read");
    let root = f.0.parent().unwrap().to_owned();
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&root, &fs::metadata(&root).unwrap());
    let paths = (0..32_769)
        .map(|n| local_index_key(&root.join(format!("rollout-{n}.jsonl.zst"))))
        .collect();
    let mut inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&dirs));
    assert!(!inventory.complete, "full roster exceeds original cap");
    let mut index = ScanIndex::default();
    inventory.retain_cached_archives(&index, &paths);
    assert!(inventory.complete);
    assert!(inventory.step_with_archive(&CodexTitleMetadata::default(), &mut index, None));
    assert!(inventory.headers.is_empty());
}

#[test]
fn watcher_retained_refresh_and_bounded_walk_remain_plain_only() {
    let f = ArchiveFixture::new(b"discovery must not decode");
    let root = f.0.parent().unwrap().to_owned();
    let plain = root.join("rollout-live.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let paths = vec![plain.clone(), f.0.clone()];
    assert_eq!(
        paths_from_events(paths.clone()),
        BTreeSet::from([plain.clone()])
    );
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            source,
            std::slice::from_ref(&root),
            &mut index,
            &now,
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().unwrap();
        enqueue_watcher_hints(source, traversal, &paths, false);
        assert!(traversal.pending_candidates.iter().all(|p| p.path == plain));
        refresh_retained_codex_roster(source, traversal, BACKFILL_WINDOW_DAYS, &index.files);
        assert!(!traversal
            .codex_rollout_paths
            .contains(&local_index_key(&f.0)));
        advance_bounded_directory_traversal(source, traversal, BACKFILL_WINDOW_DAYS, &index.files);
        assert!(traversal.pending_candidates.iter().all(|p| p.path == plain));
        assert!(!traversal
            .codex_rollout_paths
            .contains(&local_index_key(&f.0)));
        assert!(traversal.pending_directories.is_empty());
    }
}
