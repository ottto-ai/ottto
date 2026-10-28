// These native scan fixtures join the existing money_equivalence_tests:: filter.
// All paths, headers, usage and acknowledgements are synthetic.
fn persist(index: &ScanIndex) -> ScanIndex {
    serde_json::from_slice(&serde_json::to_vec(index).unwrap()).unwrap()
}
fn scan(
    f: &ArchiveFixture,
    index: ScanIndex,
    power: bool,
    cpu: u64,
) -> (ScanIndex, SourceScanResult, Vec<Value>) {
    let root = f.0.parent().unwrap().to_owned();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root],
            index,
            &now,
            BACKFILL_WINDOW_DAYS,
            100,
            false,
            None,
            &[],
            false,
            false,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            Scope("zst-money".into()),
        );
        // Fake the platform and thread CPU boundary; production has no flag.
        scan.archive_pass.power = power;
        scan.archive_pass.cpu = cpu;
        for _ in 0..5000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    mut index,
                    mut scan,
                    ..
                } => {
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                    return (index, scan);
                }
            }
        }
        panic!("bounded synthetic scan did not finish");
    });
    (index, result, rows)
}
fn accept(index: &mut ScanIndex, result: &SourceScanResult) {
    let accepted = result
        .snapshots
        .iter()
        .map(|s| {
            (
                s.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(s),
            )
        })
        .collect::<BTreeMap<_, _>>();
    index.record_accepted_snapshot_fingerprints(&accepted.keys().cloned().collect());
    index.settle_archive_bodies(&accepted);
}
fn class(rows: &[Value], name: &str) -> u64 {
    rows.iter()
        .filter_map(|r| r["counts"]["codex_zst_classification"][name].as_u64())
        .sum()
}
fn held(index: &ScanIndex, path: &Path, cause: CodexZstCause) {
    assert!(
        matches!(index.files[&local_index_key(path)].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Held { cause: actual } if actual == cause)
    );
}
fn money(item: &SnapshotItem) -> Value {
    let v = serde_json::to_value(item).unwrap();
    let fields = [
        "source_session_id",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
        "model_usage",
        "usage_buckets",
        "usage_accounting_contract",
    ];
    Value::Object(
        fields
            .into_iter()
            .map(|k| (k.to_owned(), v[k].clone()))
            .collect(),
    )
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn archive_only_first_read_has_plain_money_and_same_session_id_once() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let bytes = synthetic_rollout();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&bytes, 1).unwrap());
    let plain = f.0.with_extension("");
    // Plain oracle uses the identical logical owner and normal scan finish.
    fs::remove_file(&f.0).unwrap();
    fs::write(&plain, &bytes).unwrap();
    let (_, oracle, plain_rows) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(oracle.snapshots.len(), 1);
    assert_eq!(decodes(&plain_rows), 0);
    let expected = money(&oracle.snapshots[0]);
    assert!(oracle.snapshots[0].input_tokens > 0);
    fs::remove_file(&plain).unwrap();
    fs::write(&f.0, zstd::bulk::compress(&bytes, 1).unwrap()).unwrap();
    let (mut state, result, rows) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(money(&result.snapshots[0]), expected);
    assert_eq!(class(&rows, "codex_zst_first_read"), 1);
    assert_eq!(
        decodes(&rows),
        2,
        "one bounded header plus one A1 body, per 11a.3"
    );
    accept(&mut state, &result);
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Acquired
    ));
    for _ in 0..3 {
        let (next, quiet, rows) = scan(&f, persist(&state), true, 0);
        assert!(quiet.snapshots.is_empty());
        assert_eq!(class(&rows, "codex_zst_first_read"), 0);
        assert_eq!(
            decodes(&rows),
            0,
            "quiet walk and restart never renew a decode"
        );
        state = next;
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn coexisting_plain_wins_and_is_one_parent_census_member() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let bytes = synthetic_rollout();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&bytes, 1).unwrap());
    let plain = f.0.with_extension("");
    fs::write(&plain, &bytes).unwrap();
    let root = plain.parent().unwrap().to_owned();
    let paths = BTreeSet::from([local_index_key(&plain), local_index_key(&f.0)]);
    let roots = [root];
    let found = codex_parent_census_matches(
        CodexParentCensus::new(&roots, &paths),
        &["compressed-fixture"],
    );
    assert!(
        matches!(found.as_slice(), [CodexCensusMatch::One(key)] if *key == local_index_key(&plain))
    );
    let (mut state, result, rows) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(result.snapshots.len(), 1);
    assert!(result.snapshots[0].input_tokens > 0);
    assert_eq!(result.snapshots[0].source_session_id, "compressed-fixture");
    assert_eq!(class(&rows, "codex_zst_plain_twin_skip"), 1);
    assert_eq!(decodes(&rows), 0);
    assert!(!state.files.contains_key(&local_index_key(&f.0)));
    accept(&mut state, &result);
    let (_, quiet, rows) = scan(&f, persist(&state), true, 0);
    assert!(quiet.snapshots.is_empty());
    assert_eq!(decodes(&rows), 0);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn plain_compress_restart_holds_without_second_count_or_absence_retirement() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let bytes = synthetic_rollout();
    let f = ArchiveFixture::new(b"not present during the plain read");
    fs::remove_file(&f.0).unwrap();
    let plain = f.0.with_extension("");
    fs::write(&plain, &bytes).unwrap();
    let (mut state, result, _) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(result.snapshots.len(), 1);
    accept(&mut state, &result);
    let body = serde_json::to_value(&result.snapshots).unwrap();
    let old_key = local_index_key(&plain);
    let entry = serde_json::to_value(&state.files[&old_key]).unwrap();
    let incidence = state.file_snapshot_fingerprints[&old_key].clone();
    let acks = state.accepted_snapshot_fingerprints.clone();
    fs::write(&f.0, zstd::bulk::compress(&bytes, 1).unwrap()).unwrap();
    fs::remove_file(&plain).unwrap();
    // Exercise retained watcher/remove and stale candidate paths too.
    if let Some(t) = state.traversal.as_mut() {
        enqueue_watcher_hints(
            SnapshotSource::Codex,
            t,
            &[plain.clone(), f.0.clone()],
            false,
        );
    }
    for _ in 0..3 {
        let (next, held_scan, rows) = scan(&f, persist(&state), true, 0);
        assert!(
            held_scan.snapshots.is_empty(),
            "never second, zero or removal body"
        );
        assert_eq!(
            decodes(&rows),
            0,
            "a move is held before any archive header decode"
        );
        assert_eq!(held_scan.disappeared_file_count, 0);
        assert_eq!(
            held_scan.unreadable_path_count, 0,
            "move debt is not a read/absence failure"
        );
        assert_eq!(serde_json::to_value(&next.files[&old_key]).unwrap(), entry);
        assert_eq!(next.file_snapshot_fingerprints[&old_key], incidence);
        assert_eq!(next.accepted_snapshot_fingerprints, acks);
        assert!(next.codex_counting_tombstones.is_empty());
        held(&next, &f.0, CodexZstCause::ArchiveEquivalenceUnproven);
        let partial = next.committable_subset_with_local_holds(
            &state,
            &acks,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(
            serde_json::to_value(&partial.files[&old_key]).unwrap(),
            entry
        );
        assert!(body[0]["input_tokens"].as_u64().unwrap() > 0);
        if let Some(t) = &next.traversal {
            assert!(t.unhealthy_retry_not_before_unix_seconds.is_none());
        }
        state = next;
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn held_archive_keeps_prior_output_and_fingerprint_at_scan_level() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&synthetic_rollout(), 1).unwrap());
    let (mut state, first, _) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(first.snapshots.len(), 1);
    accept(&mut state, &first);
    let key = local_index_key(&f.0);
    let fingerprint = state.files[&key].last_snapshot_fingerprint.clone();
    let body_witness = state.files[&key].last_upload_body_witness.clone();
    let incidence = state.file_snapshot_fingerprints[&key].clone();
    assert!(fingerprint.is_some() && body_witness.is_some());
    fs::write(&f.0, b"changed corrupt archive with accepted history").unwrap();
    for _ in 0..2 {
        let (next, result, rows) = scan(&f, persist(&state), true, 0);
        assert!(
            result.snapshots.is_empty(),
            "accepted money remains, never an empty replacement"
        );
        assert_eq!(decodes(&rows), 0);
        held(&next, &f.0, CodexZstCause::ArchiveEquivalenceUnproven);
        assert_eq!(next.files[&key].last_snapshot_fingerprint, fingerprint);
        assert_eq!(next.files[&key].last_upload_body_witness, body_witness);
        assert_eq!(next.file_snapshot_fingerprints[&key], incidence);
        state = next;
    }
}

#[test]
fn fake_thread_cpu_and_clock_enforce_archive_boundary_pacing() {
    use crate::snapshots::codex_archive_catchup::Pass;
    let mut pass = Pass {
        started: false,
        cpu: 0,
        work: 0,
        power: false,
        seen: BTreeSet::new(),
        aliases: BTreeSet::new(),
    };
    assert!(!pass.ready(1), "unknown/battery power defers");
    pass.power = true;
    assert!(pass.ready(1));
    assert!(!pass.ready(0), "same E2-4 decoded-byte budget");
    // Fake wall clock includes long idle gaps; CPU is only measured scan work.
    pass.observe(Some(0), 19_999_999);
    pass.started = true;
    pass.observe(Some(29_999_999), 1);
    assert!(pass.ready(1));
    pass.observe(Some(2), 1); // one archive can cross the limit, then stop
    assert!(!pass.ready(1));
    pass.cpu = 0;
    pass.observe(Some(1), 20_000_001);
    assert!(!pass.ready(1), "contention skips backlog");
    pass.work = 0;
    pass.observe(None, 1);
    assert!(!pass.ready(1), "unknown CPU is never unlimited credit");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn large_declared_archive_is_a_persistent_zero_decode_hold() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xe0];
    frame.extend_from_slice(&((1_u64 << 30) + 1).to_le_bytes());
    frame.extend_from_slice(&[1, 0, 0]);
    assert_eq!(
        zstd::zstd_safe::get_frame_content_size(&frame).unwrap(),
        Some((1 << 30) + 1)
    );
    let f = ArchiveFixture::new(&frame);
    let mut state = ScanIndex::default();
    for _ in 0..3 {
        let (next, result, rows) = scan(&f, persist(&state), true, 0);
        assert!(result.snapshots.is_empty());
        assert_eq!(decodes(&rows), 0);
        held(&next, &f.0, CodexZstCause::CatchupTooLarge);
        state = next;
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn no_inventory_storm_and_live_work_precedes_paced_backlog() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&synthetic_rollout(), 1).unwrap());
    let root = f.0.parent().unwrap();
    for n in 0..16 {
        fs::write(
            root.join(format!("rollout-unseen-{n}.jsonl.zst")),
            b"must never decode on a denied pass",
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
        let (_, result, rows) = scan(&f, ScanIndex::default(), power, cpu);
        assert_eq!(
            decodes(&rows),
            0,
            "inventory cannot acquire any of the unseen headers"
        );
        assert_eq!(result.snapshots.len(), 1, "live plain work is still read");
        assert_eq!(result.snapshots[0].source_session_id, "live");
        assert_eq!(class(&rows, "codex_zst_first_read"), 0);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn stamp_matching_header_inventory_never_decodes_archives() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&synthetic_rollout(), 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    state
        .inventory_archive_header(&f.candidate(), Some(&cache))
        .unwrap();
    let plain = f.0.parent().unwrap().join("rollout-live.jsonl");
    fs::write(
        &plain,
        String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", "live"),
    )
    .unwrap();
    let (_, result, rows) = scan(&f, state, false, 0);
    assert_eq!(
        decodes(&rows),
        0,
        "matching header evidence is served without a new decoder"
    );
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(result.snapshots[0].source_session_id, "live");
}

#[test]
fn compressed_parent_is_no_ledger_and_real_second_owner_stays_duplicate() {
    let f = ArchiveFixture::new(b"no body reader may run");
    let root = f.0.parent().unwrap().to_owned();
    let roots = [root.clone()];
    let paths = BTreeSet::from([local_index_key(&f.0)]);
    let census = CodexParentCensus::new(&roots, &paths);
    assert!(matches!(
        codex_parent_open_match_witnessed(census, CodexCensusMatch::One(paths.first().unwrap())),
        Err(CodexParentUnresolvable::NoLedger)
    ));
    let plain = f.0.with_extension("");
    let second = root.join("different/rollout-compressed-fixture.jsonl");
    let paths = BTreeSet::from([
        local_index_key(&plain),
        local_index_key(&f.0),
        local_index_key(&second),
    ]);
    let found = codex_parent_census_matches(
        CodexParentCensus::new(&roots, &paths),
        &["compressed-fixture"],
    );
    assert!(matches!(found.as_slice(), [CodexCensusMatch::Duplicated]));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn pending_deadline_never_rearms_an_unchanged_discovered_archive() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::bulk::compress(&synthetic_rollout(), 1).unwrap());
    let (mut state, first, rows) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(first.snapshots.len(), 1);
    assert_eq!(class(&rows, "codex_zst_first_read"), 1);
    let key = local_index_key(&f.0);
    retry_due(&mut state, &key);
    let (next, result, rows) = scan(&f, persist(&state), true, 0);
    assert!(result.snapshots.is_empty());
    assert_eq!(decodes(&rows), 0);
    assert_eq!(
        next.files[&key].last_snapshot_fingerprint,
        state.files[&key].last_snapshot_fingerprint
    );
}

#[test]
fn archive_hints_are_backlog_and_newest_archive_is_selected_first() {
    let f = ArchiveFixture::new(b"not decoded by constructor");
    let root = f.0.parent().unwrap().to_owned();
    let older = root.join("rollout-older.jsonl.zst");
    fs::write(&older, b"not decoded either").unwrap();
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
        scan_root: root.clone(),
        path: f.0.clone(),
        census_member: true,
        watcher_hint: true,
    };
    assert!(
        !codex_fresh_data_pending(&pending, &BTreeMap::new()),
        "archive hints do not preempt live work"
    );
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root],
        ScanIndex::default(),
        &now,
        BACKFILL_WINDOW_DAYS,
        1,
        false,
        None,
        &[],
        false,
        false,
    );
    assert_eq!(scan.identified_candidates.len(), 1);
    assert_eq!(scan.identified_candidates.front().unwrap().path, f.0);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn cross_directory_compression_keeps_the_plain_carrier_without_absence_or_decode() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(b"temporary placeholder");
    fs::remove_file(&f.0).unwrap();
    let root = f.0.parent().unwrap();
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let plain = sessions.join("rollout-compressed-fixture.jsonl");
    let bytes = synthetic_rollout();
    fs::write(&plain, &bytes).unwrap();
    let (mut state, original, _) = scan(&f, ScanIndex::default(), true, 0);
    assert_eq!(original.snapshots.len(), 1);
    accept(&mut state, &original);
    let key = local_index_key(&plain);
    let prior = serde_json::to_value(&state.files[&key]).unwrap();
    fs::write(&f.0, zstd::bulk::compress(&bytes, 1).unwrap()).unwrap();
    fs::remove_file(&plain).unwrap();
    let (next, result, rows) = scan(&f, persist(&state), true, 0);
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
    assert_eq!(result.disappeared_file_count, 0);
    assert_eq!(result.unreadable_path_count, 0);
    held(&next, &f.0, CodexZstCause::ArchiveEquivalenceUnproven);
    assert_eq!(serde_json::to_value(&next.files[&key]).unwrap(), prior);
    assert!(next.codex_counting_tombstones.is_empty());
}

#[test]
fn compression_between_selection_and_open_is_not_a_disappearance_or_removal() {
    let f = ArchiveFixture::new(b"metadata-only archive witness");
    let plain = f.0.with_extension("");
    fs::write(&plain, b"selected while still plain").unwrap();
    let candidate = super::super::super::codex_zst_refusal_tests::candidate(&plain);
    fs::remove_file(&plain).unwrap();
    let mut census = ScanCensus::default();
    assert!(open_and_identify_scan_candidate(
        SnapshotSource::Codex,
        candidate,
        &mut census,
        None,
        BACKFILL_WINDOW_DAYS,
        &BTreeMap::new()
    )
    .is_none());
    assert_eq!(census.disappeared_file_count, 0);
    assert_eq!(census.unreadable_path_count, 0);
    assert!(census.removed_index_keys.is_empty());
    assert!(census.claude_vanished_index_keys.is_empty());
}
