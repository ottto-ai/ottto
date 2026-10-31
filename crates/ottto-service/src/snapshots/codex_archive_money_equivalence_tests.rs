// Synthetic filesystem fixtures exercise the production discovery path.
fn discovered_scan(f: &ArchiveFixture, mut index: ScanIndex, limit: usize) -> OwnedSourceScan {
    let root = f.0.parent().unwrap().to_owned();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut index,
        &now,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(SnapshotSource::Codex, &mut index, BACKFILL_WINDOW_DAYS, None);
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

/// [money] Read bound: thread CPU and clock pacing stop archive decodes at the boundary.
#[test]
fn fake_thread_cpu_and_clock_enforce_archive_boundary_pacing() {
    use crate::snapshots::sampled_scan::ArchivePass as Pass;
    let mut pass = Pass::default();
    assert!(!pass.ready(1));
    archive_power(&mut pass, true);
    assert!(pass.ready(1));
    assert!(!pass.ready(0));
    pass.observe(Some(0), 19_999_999);
    pass.started = true;
    pass.observe(Some(29_999_999), 0);
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

/// [money] Read bound: the archive CPU budget is not reset by completion, partial commit or
/// continuation.
#[test]
fn cpu_budget_survives_scan_completion_partial_commit_and_continuation_pages() {
    let f = ArchiveFixture::new(b"no decoder permission");
    let mut scan = discovered_scan(&f, ScanIndex::default(), 1);
    archive_power(&mut scan.index.archive_pass, true);
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
        None,
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
    let ordinary = discovered_scan(&f, next.index, 1);
    assert_eq!(ordinary.index.archive_pass.cpu, 0);
    assert!(
        !ordinary.index.archive_pass.started,
        "ordinary pass renews CPU accounting"
    );
}

/// [money] Read bound: no per-pass inventory re-read storm; live work precedes the paced backlog.
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
        let mut scan = discovered_scan(&f, ScanIndex::default(), 100);
        assert_eq!(scan.identified_candidates.front().unwrap().path, plain);
        assert_eq!(
            scan.identified_candidates.len(),
            18,
            "all synthetic archives supplied"
        );
        archive_power(&mut scan.index.archive_pass, power);
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

/// [behaviour] Archive hints queue as backlog and the newest archive is selected first.
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
        order_modified: None,
        scan_root: f.0.parent().unwrap().into(),
        path: f.0.clone(),
        census_member: true,
        watcher_hint: true,
    };
    assert!(!codex_fresh_data_pending(&pending, &BTreeMap::new()));
    let scan = discovered_scan(&f, ScanIndex::default(), 1);
    assert_eq!(scan.identified_candidates.len(), 1);
    assert_eq!(scan.identified_candidates.front().unwrap().path, f.0);
}

/// [money] Read bound: an unchanged archive stamp never re-decodes during inventory.
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
    let (read, rows) = crate::local_resource_diagnostics::capture(|| {
        state.inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
    });
    assert_header_validated(&read, &rows);
    let mut scan = discovered_scan(&f, state, 1);
    let mut inventory = scan.codex_join_inventory.take().unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        while inventory.step_with_archive(
            &CodexTitleMetadata::default(),
            &mut scan.index,
            Some(&cache),
        ) != codex_file_join::HeaderStep::Complete
        {}
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
    let mut replaced = discovered_scan(&f, scan.index, 1);
    let inventory = replaced.codex_join_inventory.as_mut().unwrap();
    assert_eq!(
        inventory.step_with_archive(
            &CodexTitleMetadata::default(),
            &mut replaced.index,
            Some(&cache)
        ),
        codex_file_join::HeaderStep::Complete
    );
    assert!(
        inventory.complete,
        "unacquired replacement cannot poison plain inventory"
    );
    assert!(inventory.headers.is_empty());
}

/// [money] Plain reads unchanged: unseen archives do not spend the plain header cap.
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
    index.archive_pass.prep_after = inventory.retain_cached_archives(&index, &paths);
    assert!(
        !inventory.complete,
        "partial roster never certifies absence"
    );
    assert!(index.archive_pass.prep_after.is_some());
    assert_eq!(
        inventory.step_with_archive(&CodexTitleMetadata::default(), &mut index, None),
        codex_file_join::HeaderStep::Complete
    );
    assert!(inventory.headers.is_empty());
}

/// [behaviour] Watcher, retained refresh and bounded walk admit exact Codex archive names.
#[test]
fn watcher_retained_refresh_and_bounded_walk_admit_exact_codex_archives() {
    let f = ArchiveFixture::new(b"discovery must not decode");
    let root = f.0.parent().unwrap().to_owned();
    let plain = root.join("rollout-live.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let paths = vec![plain.clone(), f.0.clone()];
    assert_eq!(
        paths_from_events(SnapshotSource::Codex, paths.clone()),
        BTreeSet::from([plain.clone(), f.0.clone()])
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
        assert!(traversal
            .pending_candidates
            .iter()
            .all(|p| p.path == plain || (source == SnapshotSource::Codex && p.path == f.0)));
        advance_bounded_directory_traversal(source, &mut index, BACKFILL_WINDOW_DAYS, None);
        let traversal = index.traversal.as_mut().unwrap();
        assert!(traversal.pending_directories.is_empty());
        // The retained refresh runs only on a walked generation; it keeps the
        // walk's exact archive roster.
        refresh_retained_codex_roster(
            source,
            traversal,
            BACKFILL_WINDOW_DAYS,
            DiscoveryRetention::unverified(&index.files),
        );
        assert!(traversal
            .pending_candidates
            .iter()
            .all(|p| p.path == plain || (source == SnapshotSource::Codex && p.path == f.0)));
        assert_eq!(
            traversal
                .codex_rollout_paths
                .contains(&local_index_key(&f.0)),
            source == SnapshotSource::Codex
        );
    }
}

/// [money] Read bound: repeated short steps under contention decode no archive.
#[test]
fn many_short_steps_over_contention_work_decode_no_archive() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(b"contention denies before decode");
    let mut scan = selector_scan(
        &f,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
        VecDeque::from([f.candidate()]),
        true,
    );
    for _ in 0..21 {
        scan.index.archive_pass.observe(Some(0), 1_000_000);
    }
    assert!(!scan.index.archive_pass.ready(u64::MAX));
    let ((_, result), rows) = crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(decodes(&rows), 0);
    assert_eq!(result.unreadable_path_count, 0);
}

/// [behaviour] Bounded preparation skips rejected archives and still admits a late eligible entry.
#[test]
fn rejected_archives_then_late_eligible_entry_bounded_prep() {
    let f = ArchiveFixture::new(b"never read rejected archives");
    let root = f.0.parent().unwrap().to_owned();
    let plain = root.join("rollout-zzzz.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let paths = (0..codex_file_join::MAX_HEADER_FILES + 5)
        .map(|n| local_index_key(&root.join(format!("rollout-{n:06}.jsonl.zst"))))
        .chain([local_index_key(&f.0), local_index_key(&plain)])
        .collect();
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&root, &fs::metadata(&root).unwrap());
    let mut index = ScanIndex::default();
    // An actual archive evidence entry forces the metadata path, but supplies
    // no cached owning header: it must still be rejected without decoding.
    index
        .files
        .entry(local_index_key(&f.0))
        .or_default()
        .archive = Some(Box::new(
        ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap(),
    ));
    let mut inventory =
        codex_file_join::HeaderInventory::new(std::slice::from_ref(&root), &paths, Some(&dirs));
    let (_, first_rows) = crate::local_resource_diagnostics::capture(|| {
        index.archive_pass.prep_after = inventory.retain_cached_archives(&index, &paths);
    });
    assert_eq!(
        archive_event_count(&first_rows, "codex_zst_cached_inventory_metadata_checks"),
        0
    );
    assert!(!inventory.complete);
    assert!(index.archive_pass.prep_after.is_some());
    let (_, later_rows) = crate::local_resource_diagnostics::capture(|| {
        index.archive_pass.prep_after = inventory.retain_cached_archives(&index, &paths);
    });
    assert_eq!(
        archive_event_count(&later_rows, "codex_zst_cached_inventory_metadata_checks"),
        1,
        "positive control: the rejected cached archive performs exactly one real metadata check"
    );
    assert_eq!(decoded_archive_bytes(&later_rows), 0);

    assert!(
        !inventory.complete,
        "later quantum is not whole-roster authority"
    );
    assert!(index.archive_pass.prep_after.is_none());
    while inventory.step_with_archive(&CodexTitleMetadata::default(), &mut index, None)
        != codex_file_join::HeaderStep::Complete
    {}
    assert_eq!(inventory.headers.len(), 1, "late plain entry reached");
    assert_eq!(inventory.headers[0].candidate.path, plain);
}

/// [behaviour] Source-aware events reject non-exact archive suffixes.
#[test]
fn source_aware_events_reject_nonexact_archive_suffixes() {
    let paths = [
        "rollout-x.jsonl",
        "rollout-x.jsonl.zst",
        "rollout-x.zst",
        "rollout-x.jsonl.zst.tmp",
    ]
    .map(PathBuf::from);
    assert_eq!(
        paths_from_events(SnapshotSource::Codex, paths.clone()).len(),
        2
    );
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        assert_eq!(
            paths_from_events(source, paths.clone()),
            BTreeSet::from([paths[0].clone()])
        );
    }
}

/// [money] An archive-only root is read once, settles on exact ACK, and restarts quietly.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn compressed_only_root_read_once_and_acked_then_quiet_restart() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let mut scan = discovered_scan(&f, ScanIndex::default(), 10).with_sampled_acquisition(
        Arc::new(sampled_scan::SharedCache::default()),
        Scope("discovery-recovery".into()),
    );
    archive_power(&mut scan.index.archive_pass, true);
    let ((mut index, result), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(decodes(&rows), 2, "one inventory prefix and one A1 body");
    index.settle_archive_bodies(
        &result
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect(),
    );
    assert!(matches!(
        index.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Acquired
    ));
    for _ in 0..5 {
        let mut scan = discovered_scan(&f, checkpoint(&index), 10).with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            Scope("discovery-recovery".into()),
        );
        archive_power(&mut scan.index.archive_pass, true);
        let ((next, result), rows) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan));
        assert_eq!(decodes(&rows), 0, "restart is not a Full cause");
        assert!(result.snapshots.is_empty());
        index = next;
    }
}

/// [money] Read bound: a declared >1 GiB archive is held without a decoder and restart stays quiet.
#[test]
fn declared_over_1gib_held_without_decoder_and_restart_is_quiet() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xe0];
    frame.extend_from_slice(&(FIRST_READ_DECODED_LIMIT + 1).to_le_bytes());
    let f = ArchiveFixture::new(&frame);
    let mut scan = discovered_scan(&f, ScanIndex::default(), 10);
    archive_power(&mut scan.index.archive_pass, true);
    let ((index, result), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
    assert_eq!(
        index.files[&local_index_key(&f.0)].codex_compressed_hold,
        Some(CodexZstCause::CatchupTooLarge)
    );
    let mut scan = discovered_scan(&f, checkpoint(&index), 10);
    archive_power(&mut scan.index.archive_pass, true);
    let ((_, result), rows) = crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert!(result.snapshots.is_empty());
    assert_eq!(decodes(&rows), 0);
    assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_frame_header"));
}
