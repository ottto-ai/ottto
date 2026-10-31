fn funded_header_work() -> HeaderWork {
    HeaderWork {
        allowed: true,
        ..HeaderWork::default()
    }
}

/// [format] An index saved with the retired optional header `cli_version`
/// still loads with its validated header; new saves omit the field.
#[test]
fn saved_header_with_retired_cli_version_still_loads() {
    let f = ArchiveFixture::new(b"synthetic stamp only");
    let key = local_index_key(&f.0);
    let mut bytes = serde_json::to_vec(&json!({"type":"session_meta", "payload": {
        "id":"compressed-fixture", "cli_version": "v1.2", "timestamp": NOW,
    }}))
    .unwrap();
    bytes.push(b'\n');
    let header = ValidatedHeader::from_bytes(&bytes).unwrap();
    assert!(header.created_unix_ms.is_some());
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.header_validated = Some(header);
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    let current = serde_json::to_value(&index).unwrap();
    assert!(current["files"][&key]["archive"]["header_validated"]
        .get("cli_version")
        .is_none());
    let saved = f.0.parent().unwrap().join("index.json");
    for version in [json!("v1.2"), json!(" ".repeat(64)), json!(null)] {
        let mut old = current.clone();
        old["files"][&key]["archive"]["header_validated"]["cli_version"] = version;
        fs::write(&saved, serde_json::to_vec(&old).unwrap()).unwrap();
        let restored = ScanIndex::load(&saved).unwrap();
        assert!(restored.archive_header(&f.0).is_some());
        assert_eq!(
            serde_json::to_value(&restored).unwrap()["files"][&key]["archive"]["header_validated"],
            current["files"][&key]["archive"]["header_validated"]
        );
    }
    assert!(ValidatedHeader::from_bytes(b"{}\n").is_none());
    assert!(
        ValidatedHeader::from_bytes(b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"x\"}}")
            .is_none()
    );
}

/// Diagnostic: a test that assumes a header shows why none was stored
/// (read outcome plus `codex_zst_refused` counts).
fn assert_header_validated(read: &anyhow::Result<HeaderRead>, rows: &[Value]) {
    assert!(
        matches!(read, Ok(HeaderRead::Validated(_))),
        "header read {read:?}; codex_zst_refused={:?}",
        rows.iter()
            .filter_map(|r| r["counts"].get("codex_zst_refused"))
            .collect::<Vec<_>>()
    );
}

fn header_inventory(
    f: &ArchiveFixture,
    state: &mut ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> Vec<Value> {
    let root = f.0.parent().unwrap().to_owned();
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(&root, &fs::metadata(&root).unwrap());
    let mut inventory = codex_file_join::HeaderInventory::new(
        &[root],
        &BTreeSet::from([local_index_key(&f.0)]),
        Some(&directories),
    );
    let mut work = funded_header_work();
    let (read, rows) = crate::local_resource_diagnostics::capture(|| {
        // Selected admission acquires the header; inventory reads only its
        // same-stamp facts and never decodes.
        let read = state.inventory_archive_header(&f.candidate(), Some(cache), &mut work);
        while inventory.step_with_archive(&CodexTitleMetadata::default(), state, Some(cache))
            != codex_file_join::HeaderStep::Complete
        {}
        read
    });
    assert_header_validated(&read, &rows);
    assert!(inventory.complete);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].owner, "compressed-fixture");
    assert_eq!(cache.cursor_reserved(), 0, "no parked decoder");
    assert_eq!(inventory.read_bytes, 0, "inventory never reads archives");
    let before = rows
        .iter()
        .filter(|r| r["stage"] == "codex_zst_input")
        .count();
    assert_eq!(before, 0, "inventory has no Full/encoding row");
    assert_eq!(decodes(&rows), usize::from(work.physical_bytes > 0));
    let (_, witness_rows) = crate::local_resource_diagnostics::capture(|| {
        assert_eq!(
            codex_file_join::header_reduction_witness(&f.candidate(), state.archive_header(&f.0))
                .unwrap(),
            state.archive_header(&f.0).unwrap().digest
        );
    });
    assert!(witness_rows.is_empty(), "dependency witness never decodes");
    rows
}

/// [money] Read bound: one header read then one Full read, with physical-byte accounting.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn inventory_header_once_then_full_once_with_physical_accounting() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut value: Value =
        serde_json::from_slice(synthetic_rollout().split(|b| *b == b'\n').next().unwrap()).unwrap();
    value["payload"]["cli_version"] = json!("0.77.0");
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    let header_length = bytes.len();
    bytes.extend(
        synthetic_rollout()
            .splitn(2, |b| *b == b'\n')
            .nth(1)
            .unwrap(),
    );
    let encoded = zstd::stream::encode_all(&bytes[..], 1).unwrap();
    let f = ArchiveFixture::new(&encoded);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    let rows = header_inventory(&f, &mut state, &cache);
    assert_eq!(decodes(&rows), 1);
    let row = rows
        .iter()
        .find(|r| r["stage"] == "codex_zst_inventory")
        .unwrap();
    let physical = row["counts"]["codex_zst_inventory_physical_bytes"]
        .as_u64()
        .unwrap();
    let decoded = row["counts"]["codex_zst_inventory_decoded_bytes"]
        .as_u64()
        .unwrap();
    assert!(decoded >= header_length as u64 && decoded <= 64 * 1024);
    assert!(physical > 0 && physical <= 128 * 1024);
    assert_eq!(
        physical,
        encoded.len() as u64,
        "small input read-ahead counted physically"
    );
    assert_eq!(
        row["counts"]["codex_aux_reads"]["header_read_bytes"]["inventory"],
        physical
    );
    assert!(state.files[&local_index_key(&f.0)]
        .archive
        .as_ref()
        .unwrap()
        .owner
        .is_none());
    assert_eq!(
        state.candidate_decision_with_reason(&f.candidate()).1,
        Some(CandidateParseReason::NewFile)
    );
    assert!(state.file_snapshot_fingerprints.is_empty());
    assert!(state.codex_parent_ownership_ledgers.is_empty());
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::HeaderValidated
    ));
    assert!(!state.files[&local_index_key(&f.0)]
        .archive
        .as_ref()
        .unwrap()
        .quiet(&File::open(&f.0).unwrap()));
    assert!(state.archive_header(&f.0).is_some());
    assert_eq!(
        decodes(&header_inventory(&f, &mut state, &cache)),
        0,
        "second inventory reuses header"
    );
    let mut restored = checkpoint(&state);
    assert_eq!(
        decodes(&header_inventory(&f, &mut restored, &cache)),
        0,
        "persisted header reused"
    );
    let (mut state, result, rows, _) = archive_pass(&f, restored, true, None);
    assert_eq!(
        decodes(&rows),
        1,
        "single full A1 acquisition remains authorized"
    );
    assert!(!result.snapshots.is_empty());
    assert_eq!(
        rows.iter()
            .filter(|r| r["stage"] == "codex_zst_input")
            .map(|r| r["counts"]["codex_zst_compressed_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        encoded.len() as u64
    );
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 0);
    let (mut quiet, _, rows, _) = archive_pass(&f, checkpoint(&state), true, None);
    assert_eq!(
        decodes(&rows),
        0,
        "pending full read quiet before retry deadline"
    );
    assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 0);
    let key = local_index_key(&f.0);
    for disposition in [
        ArchiveDisposition::Held {
            cause: CodexZstCause::OutputHeld,
        },
        ArchiveDisposition::Refused {
            cause: CodexZstCause::DecodeFailed,
        },
        ArchiveDisposition::Acquired,
    ] {
        quiet
            .files
            .get_mut(&key)
            .unwrap()
            .archive
            .as_mut()
            .unwrap()
            .disposition = disposition;
        assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 0);
        let (_, result, rows, _) = archive_pass(&f, checkpoint(&quiet), true, None);
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
    }
    // Content stamp change invalidates the accessor and permits one new header attempt.
    fs::write(&f.0, [encoded.as_slice(), b"changed"].concat()).unwrap();
    assert!(quiet.archive_header(&f.0).is_none());
    assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 1);
    assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 0);
}

/// [behaviour] A header read never checks archive completion; a failed Full keeps the projection.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_read_never_checks_archive_completion_and_failed_full_keeps_projection() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let first = b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"compressed-fixture\"}}\n";
    let mut encoded = zstd::stream::encode_all(&first[..], 1).unwrap();
    // A separately truncated later frame does not invalidate first-record evidence.
    let later = zstd::stream::encode_all(&b"{\"type\":\"event_msg\"}\n"[..], 1).unwrap();
    encoded.extend_from_slice(&later[..later.len() - 1]);
    let f = ArchiveFixture::new(&encoded);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 1);
    let (mut state, result, rows, _) = archive_pass(&f, state, true, None);
    assert_eq!(decodes(&rows), 1);
    assert!(result.snapshots.is_empty());
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Refused { .. }
    ));
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 0);
    assert!(state.codex_parent_ownership_ledgers.is_empty());
}

/// [money] Read bound: header limits and failures do not re-decode the same stamp.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_limits_and_failures_do_not_redecode_same_stamp() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut skippable = vec![0x50, 0x2a, 0x4d, 0x18];
    skippable.extend_from_slice(&(256_u32 * 1024).to_le_bytes());
    skippable.extend(vec![0; 256 * 1024]);
    for encoded in [skippable, b"garbage".to_vec()] {
        let f = ArchiveFixture::new(&encoded);
        let mut state = ScanIndex::default();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            assert!(state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .is_err());
        });
        assert_eq!(decodes(&rows), 1);
        let counts = &rows
            .iter()
            .find(|r| r["stage"] == "codex_zst_inventory")
            .unwrap()["counts"];
        assert!(
            counts["codex_zst_inventory_physical_bytes"]
                .as_u64()
                .unwrap()
                <= 128 * 1024
        );
        assert!(
            counts["codex_zst_inventory_decoded_bytes"]
                .as_u64()
                .unwrap()
                <= 64 * 1024
        );
        assert_eq!(cache.cursor_reserved(), 0);
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            assert!(state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .is_err());
        });
        assert_eq!(decodes(&rows), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_inventory"));
        assert!(state.accepted_snapshot_fingerprints.is_empty());
    }
}

/// [behaviour] Refused header admission does not spend a decode attempt.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn refused_header_admission_does_not_spend_a_decode_attempt() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .unwrap()
        .unwrap();
    let mut state = ScanIndex::default();
    let key = local_index_key(&f.0);
    for attempt in 1..=14 {
        let mut work = funded_header_work();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            assert!(matches!(
                state
                    .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                    .unwrap(),
                HeaderRead::Deferred
            ));
        });
        assert_eq!(decodes(&rows), 0);
        assert_eq!(
            rows.iter()
                .filter_map(
                    |r| r["counts"]["codex_zst_refused"]["CompressedAdmissionRefused"].as_u64()
                )
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r["stage"] == "codex_zst_admission_alarm")
                .count(),
            usize::from(attempt == 12)
        );
        assert_eq!(
            cache.archive_starved_count(Some(&key)),
            usize::from(attempt >= 12)
        );
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_inventory"));
        assert!(!state.files.contains_key(&key));
        assert_eq!((work.physical_bytes, work.decoded_bytes), (0, 0));
    }
    occupied.close();
    let rows = header_inventory(&f, &mut state, &cache);
    assert_eq!(decodes(&rows), 1);
    let counts = &rows
        .iter()
        .find(|r| r["stage"] == "codex_zst_inventory")
        .unwrap()["counts"];
    assert!(
        counts["codex_zst_decoder_native_peak_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(counts["codex_zst_decoder_allocation_refusals"], 0);
    assert_eq!(cache.archive_starved_count(Some(&key)), 0);
    assert_eq!(
        cache.archive_streak(&key, true),
        1,
        "funded header reset the streak to zero"
    );
    assert_eq!(
        state.files[&key].archive.as_ref().unwrap().decode_attempts,
        0
    );
}

/// [money] Plain sibling output: an invalid archive does not hold live plain work on the next pass.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn invalid_archive_does_not_hold_live_plain_on_next_pass() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut f = ArchiveFixture::new(b"corrupt");
    let bad = f.0.with_file_name("rollout-bad.jsonl.zst");
    fs::rename(&f.0, &bad).unwrap();
    f.0 = bad;
    let root = f.0.parent().unwrap().to_owned();
    let plain = root.join("rollout-compressed-fixture.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    let mut work = funded_header_work();
    assert!(state
        .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
        .is_err());
    assert!(work.physical_bytes > 0);
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&root, &fs::metadata(&root).unwrap());
    let paths = BTreeSet::from([local_index_key(&f.0), local_index_key(&plain)]);
    let inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&dirs));
    let mut live = super::super::codex_zst_refusal_tests::candidate(&plain);
    live.size_bytes = fs::metadata(&plain).unwrap().len();
    let ((_, result), rows) = crate::local_resource_diagnostics::capture(|| {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[],
            checkpoint(&state),
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache.clone(), Scope("mixed-header-test".into()));
        scan.identified_candidates = VecDeque::from([f.candidate(), live]);
        scan.census.observed_index_keys.extend(paths);
        scan.codex_join_inventory = Some(inventory);
        scan.codex_join_prepared = false;
        scan.census_unix_seconds = None;
        for _ in 0..1000 {
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
        panic!("mixed inventory did not complete");
    });
    assert_eq!(decodes(&rows), 0, "bad archive never decoded again");
    assert_eq!(
        result.scanned_file_count, 1,
        "live plain selected and parsed"
    );
    assert!(result
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "compressed-fixture"));
}

/// [behaviour] A Full read accepts a 70 KiB header and settles once.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn full_read_accepts_seventy_kib_header_and_settles_once() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut bytes = serde_json::to_vec(&json!({"type":"session_meta", "payload": {
        "id":"compressed-fixture", "instructions":"x".repeat(70 * 1024), "cli_version":"v-large"
    }}))
    .unwrap();
    bytes.push(b'\n');
    assert!(bytes.len() > codex_file_join::MAX_HEADER_BYTES);
    bytes.extend(
        synthetic_rollout()
            .splitn(2, |b| *b == b'\n')
            .nth(1)
            .unwrap(),
    );
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let (mut state, result, rows, observer) = selector_archive_pass(&f, ScanIndex::default());
    assert_eq!(decodes(&rows), 2, "one inventory prefix then one A1 Full");
    assert_eq!(
        rows.iter()
            .filter(|r| r["stage"] == "codex_zst_inventory")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|r| r["stage"] == "codex_zst_input")
            .count(),
        1
    );
    assert_eq!(
        *observer.1.lock().unwrap(),
        0,
        "no physical-offset callbacks"
    );
    assert!(observer.0.lock().unwrap().is_empty());
    assert_eq!(result.ownership_incomplete_file_count, 0);
    assert!(!result.snapshots.is_empty());
    assert!(state.archive_header(&f.0).is_some());
    state.settle_archive_bodies(
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
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Acquired
    ));
    for _ in 0..5 {
        let (next, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
        state = next;
    }
}

/// [money] Read bound: a Full admission refusal keeps the header without re-decoding it.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn real_full_admission_refusal_preserves_header_without_redecode() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 1);
    let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .unwrap()
        .unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(sampled_scan::new_source_parser(
            File::open(&f.0).unwrap(),
            &f.candidate(),
            &mut state,
            sampled_scan::ParserOptions {
                source: SnapshotSource::Codex,
                metadata: &CodexTitleMetadata::default(),
                traces: None,
                parents: None,
                artifacts: false,
                curve: false,
                identity_capture: false,
                cache: Some(&cache),
                archive_scope: None
            }
        )
        .is_err());
    });
    assert_eq!(decodes(&rows), 0);
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::HeaderValidated
    ));
    occupied.close();
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 0);
}

/// [behaviour] Header permission and CPU gates spend no transcript bytes or attempt.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_permission_and_cpu_gate_spend_no_transcript_bytes_or_attempt() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    for mut work in [
        HeaderWork::default(),
        HeaderWork {
            allowed: true,
            cpu_micros: 30_000_000,
            ..Default::default()
        },
    ] {
        let before = (work.physical_bytes, work.decoded_bytes, work.cpu_micros);
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            assert!(matches!(
                state
                    .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                    .unwrap(),
                HeaderRead::Deferred
            ));
        });
        assert_eq!(decodes(&rows), 0);
        assert_eq!(
            (work.physical_bytes, work.decoded_bytes, work.cpu_micros),
            before
        );
        assert!(state.files.is_empty());
    }
    let mut work = funded_header_work();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        let HeaderRead::Validated(_) = state
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
            .unwrap()
        else {
            panic!("header not validated")
        };
        assert!(work.physical_bytes > 0);
    });
    let row = rows
        .iter()
        .find(|r| r["stage"] == "codex_zst_inventory")
        .unwrap();
    assert_eq!(
        row["counts"]["codex_zst_inventory_decoded_bytes"],
        work.decoded_bytes
    );
    assert_eq!(
        row["counts"]["codex_zst_inventory_cpu_micros"],
        work.cpu_micros
    );
    assert_eq!(decodes(&rows), 1);
    assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_input"));
}

/// [behaviour] A double-UUID archive gets a named-owner hold with no replacement or re-decode.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn double_uuid_archive_has_named_owner_hold_no_replacement_or_redecode() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let owner = "019fa111-2222-7333-8444-555555555555";
    let other = "019fa111-aaaa-7333-8444-555555555555";
    let mut lines: Vec<Value> = synthetic_rollout()
        .split(|b| *b == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| serde_json::from_slice(row).unwrap())
        .collect();
    lines[0]["payload"]["id"] = json!(owner);
    lines[0]["payload"]["cli_version"] = json!("unbound-version");
    let mut bytes = Vec::new();
    for line in lines {
        serde_json::to_writer(&mut bytes, &line).unwrap();
        bytes.push(b'\n');
    }
    let mut f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let double =
        f.0.with_file_name(format!("rollout-{other}-{owner}.jsonl.zst"));
    fs::rename(&f.0, &double).unwrap();
    f.0 = double;
    let (mut state, result, rows, _) = archive_pass(&f, ScanIndex::default(), true, None);
    assert_eq!(decodes(&rows), 1);
    assert!(result.snapshots.is_empty());
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::OwnerUnproven
        }
    ));
    assert!(rows.iter().any(
        |r| r["counts"]["codex_zst_refused"]["CompressedOwnerUnproven"]
            .as_u64()
            .unwrap_or(0)
            > 0
    ));
    assert!(
        state.archive_header(&f.0).is_none(),
        "unbound full header is not shared metadata"
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (_, reuse) = crate::local_resource_diagnostics::capture(|| {
        assert!(state
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
            .is_err());
    });
    assert_eq!(decodes(&reuse), 0);
    assert!(reuse.iter().any(
        |r| r["counts"]["codex_zst_refused"]["CompressedHeaderInvalid"]
            .as_u64()
            .unwrap_or(0)
            > 0
    ));
    let (_, result, rows, _) = archive_pass(&f, checkpoint(&state), true, None);
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
}

/// [money] Plain sibling output: an unreadable segment holds its filename owner, not unrelated
/// plain.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn unreadable_segment_holds_its_filename_owner_but_not_unrelated_plain() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(b"corrupt archive segment");
    let root = f.0.parent().unwrap().to_owned();
    let related = root.join("rollout-compressed-fixture.jsonl");
    let unrelated = root.join("rollout-unrelated.jsonl");
    fs::write(&related, synthetic_rollout()).unwrap();
    let mut bytes = Vec::new();
    for row in synthetic_rollout()
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
    {
        let mut value: Value = serde_json::from_slice(row).unwrap();
        if value["type"] == "session_meta" {
            value["payload"]["id"] = json!("unrelated");
        }
        serde_json::to_writer(&mut bytes, &value).unwrap();
        bytes.push(b'\n');
    }
    fs::write(&unrelated, bytes).unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    assert!(state
        .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
        .is_err());
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&root, &fs::metadata(&root).unwrap());
    let paths = BTreeSet::from([
        local_index_key(&f.0),
        local_index_key(&related),
        local_index_key(&unrelated),
    ]);
    let inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&dirs));
    let candidates = [f.0.clone(), related, unrelated].map(|path| {
        let mut candidate = super::super::codex_zst_refusal_tests::candidate(&path);
        candidate.size_bytes = fs::metadata(&path).unwrap().len();
        candidate
    });
    let ((_, result), rows) = crate::local_resource_diagnostics::capture(|| {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[],
            checkpoint(&state),
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache, Scope("unresolved-family-test".into()));
        scan.identified_candidates = VecDeque::from(candidates);
        scan.census.observed_index_keys.extend(paths);
        scan.codex_join_inventory = Some(inventory);
        scan.codex_join_prepared = false;
        scan.census_unix_seconds = None;
        for _ in 0..1000 {
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
        panic!("unresolved family did not complete");
    });
    assert_eq!(decodes(&rows), 0);
    assert_eq!(result.scanned_file_count, 1);
    assert!(result
        .snapshots
        .iter()
        .any(|s| s.source_session_id == "unrelated"));
    assert!(
        !result
            .snapshots
            .iter()
            .any(|s| s.source_session_id == "compressed-fixture"),
        "unresolved segment cannot certify a partial singleton body"
    );
}

/// [behaviour] A cached archive header does not bypass the permission gate.
#[test]
fn cached_archive_header_does_not_bypass_permission_gate() {
    let bytes = synthetic_rollout();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let mut archive = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    archive.header_validated =
        ValidatedHeader::from_bytes(bytes.split_inclusive(|b| *b == b'\n').next().unwrap());
    archive.disposition = ArchiveDisposition::HeaderValidated;
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(archive));
    let before = serde_json::to_value(&index.files[&key]).unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut work = HeaderWork::default();
    assert!(matches!(
        index
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
            .unwrap(),
        HeaderRead::Deferred
    ));
    assert_eq!(serde_json::to_value(&index.files[&key]).unwrap(), before);
    assert_eq!((work.physical_bytes, work.decoded_bytes), (0, 0));
    assert_eq!(cache.cursor_reserved(), 0);
    assert!(
        index.archive_header(&f.0).is_some(),
        "cached metadata remains available"
    );
}

/// [format] Every persisted pre-composition archive disposition label still decodes.
#[test]
fn merged_causes_decode_every_precomposition_archive_disposition_label() {
    use CodexZstCause::*;
    // Literal labels and indices written by #887 at 11ae5e0a2. Do not derive
    // them from the current enum, or a rename/reorder would update the oracle.
    let previous = [
        ("CompressedReplayNotAuthorized", ReplayNotAuthorized),
        ("CompressedProofParentUnsupported", ProofParentUnsupported),
        ("CompressedProofChildUnsupported", ProofChildUnsupported),
        ("CompressedParentSideUnsupported", ParentSideUnsupported),
        ("CompressedDurableTailUnsupported", DurableTailUnsupported),
        ("CompressedGroupProbeUnsupported", GroupProbeUnsupported),
        ("CompressedGroupReadUnsupported", GroupReadUnsupported),
        ("CompressedParentLedgerUnbound", ParentLedgerUnbound),
        (
            "CompressedPhysicalOffsetUnsupported",
            PhysicalOffsetUnsupported,
        ),
        (
            "CompressedCompatibilityUnsupported",
            CompatibilityUnsupported,
        ),
        ("CompressedAdmissionRefused", AdmissionRefused),
        ("CompressedDecodeFailed", DecodeFailed),
        ("CompressedOwnerUnproven", OwnerUnproven),
        ("CompressedOutputHeld", OutputHeld),
        ("CompressedSettlementStuck", SettlementStuck),
        ("CompressedConstructorUnfunded", ConstructorUnfunded),
        ("CompressedDecodedOverLimit", DecodedOverLimit),
        ("CompressedParserStateRequired", ParserStateRequired),
        ("CompressedHeaderInvalid", HeaderInvalid),
        ("decode_budget", DecodeBudget),
        ("admission_starved", AdmissionStarved),
        ("CompressedCorrectionUnapplied", CorrectionUnapplied),
    ];
    for (index, (label, expected)) in previous.into_iter().enumerate() {
        assert_eq!(expected as usize, index);
        for disposition in ["Held", "Refused"] {
            let written = json!({(disposition): {"cause": label}});
            let restored: ArchiveDisposition = serde_json::from_value(written.clone()).unwrap();
            assert!(matches!(restored,
                ArchiveDisposition::Held { cause } | ArchiveDisposition::Refused { cause }
                if cause == expected));
            assert_eq!(serde_json::to_value(&restored).unwrap(), written);
        }
    }
    assert_eq!(HeaderUnfunded as usize, 22);
    assert_eq!(CompatibilityUnfunded as usize, 23);
    assert_eq!(DecoderRefusedHeaderOccupancy as usize, 24);
}

/// [behaviour] A changed stamp keeps the historical logical identity and resets acquisition state.
#[test]
fn changed_stamp_preserves_historical_logical_identity_but_resets_acquisition_state() {
    let id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let mut f = ArchiveFixture::new(b"old-stamp");
    let path =
        f.0.with_file_name(format!("rollout-2026-10-07T12-00-00-{id}.jsonl.zst"));
    fs::rename(&f.0, &path).unwrap();
    f.0 = path;
    let key = local_index_key(&f.0);
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    assert_ne!(
        evidence.logical_id, id,
        "filename alone has an ambiguous timestamp prefix"
    );
    let filename_id = evidence.logical_id.clone();
    let header = format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{id}\"}}}}\n");
    evidence.header_validated = ValidatedHeader::from_bytes(header.as_bytes());
    assert!(evidence.header_validated.is_some());
    evidence.header_attempted = true;
    evidence.logical_id = id.into();
    evidence.owner = Some(id.into());
    evidence.disposition = ArchiveDisposition::Acquired;
    evidence.body_witness = Some("b".repeat(64));
    evidence.decode_attempts = 6;
    evidence.terminal_failures = 3;
    evidence.terminal_attempt = 6;
    evidence.user_change = true;
    evidence.user_context = Some("c".repeat(64));
    evidence.user_generation = 7;
    evidence.user_change_spent = 7;
    let fingerprint = "a".repeat(64);
    let body = "b".repeat(64);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        ScanIndexEntry {
            last_snapshot_fingerprint: Some(fingerprint.clone()),
            last_upload_body_witness: Some(body.clone()),
            archive: Some(Box::new(evidence)),
            ..Default::default()
        },
    );
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from([fingerprint.clone()]));
    index
        .accepted_snapshot_fingerprints
        .insert(fingerprint.clone());
    let saved = f.0.parent().unwrap().join("identity-index.json");
    let mut metadata = CodexTitleMetadata::default();
    metadata.state_threads.insert(
        id.into(),
        CodexStateThread {
            tokens_used: 440,
            ..Default::default()
        },
    );
    let mut control = index.clone();
    control
        .files
        .get_mut(&key)
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .logical_id = filename_id;
    let mut replacement = Vec::new();
    append_codex_state_only_snapshots(
        &mut replacement,
        &metadata,
        NOW,
        &mut control,
        &BTreeSet::new(),
    );
    assert_eq!(
        replacement.len(),
        1,
        "losing the validated id admits a state-only replacement"
    );
    assert_eq!(replacement[0].source_session_id, id);
    let constructions = codex_zst_refusal_tests::decoder_construction_count();
    for _ in 0..3 {
        index.save(&saved).unwrap();
        let (restored, origin) =
            ScanIndex::load_inner(&saved, Some(SnapshotSource::Codex)).unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded(_)));
        index = restored;
        fs::OpenOptions::new()
            .append(true)
            .open(&f.0)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        let previous = index.files[&key].archive.as_deref().unwrap();
        let file = File::open(&f.0).unwrap();
        assert!(!previous.matches(&file));
        let next = ArchiveEvidence::begin(&file, &f.0, Some(previous)).unwrap();
        assert_eq!(next.logical_id, id);
        assert!(next.matches(&file));
        assert!(next.owner.is_none());
        assert!(next.header_validated.is_none());
        assert!(!next.header_attempted);
        assert!(next.body_witness.is_none());
        assert!(!next.reservation_saved);
        assert_eq!(next.decode_attempts, 1);
        assert_eq!(next.terminal_failures, 0);
        assert_eq!(next.terminal_attempt, 0);
        assert!(!next.user_change);
        assert!(next.user_context.is_none());
        assert_eq!(next.user_generation, 0);
        assert_eq!(next.user_change_spent, 0);
        index.files.get_mut(&key).unwrap().archive = Some(Box::new(next));
        let mut fallback = Vec::new();
        append_codex_state_only_snapshots(
            &mut fallback,
            &metadata,
            NOW,
            &mut index,
            &BTreeSet::new(),
        );
        assert!(
            fallback.is_empty(),
            "historical exclusive body still covers the real id"
        );
        assert_eq!(
            index.files[&key].last_snapshot_fingerprint.as_ref(),
            Some(&fingerprint)
        );
        assert_eq!(
            index.files[&key].last_upload_body_witness.as_ref(),
            Some(&body)
        );
        assert_eq!(
            index.file_snapshot_fingerprints[&key],
            BTreeSet::from([fingerprint.clone()])
        );
        assert!(index.accepted_snapshot_fingerprints.contains(&fingerprint));
    }
    assert_eq!(
        codex_zst_refusal_tests::decoder_construction_count(),
        constructions
    );
}

// Inject the roster/candidates while retaining the native

// inventory, selector, parser, owner finish, upload policy and checkpoint intact.
fn selector_scan(
    f: &ArchiveFixture,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    candidates: VecDeque<CandidateFile>,
    power: bool,
) -> OwnedSourceScan {
    let root = f.0.parent().unwrap().to_owned();
    let paths: BTreeSet<String> = candidates
        .iter()
        .map(|c| local_index_key(&c.path))
        .collect();
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(&root, &fs::metadata(&root).unwrap());
    let mut inventory = codex_file_join::HeaderInventory::new(
        std::slice::from_ref(&root),
        &paths,
        Some(&directories),
    );
    // Production feed: metadata-only F3 inventory; selected admission reads headers.
    inventory.feed_prepared = false;
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(cache, Scope("selector-archive-test".into()));
    scan.identified_candidates = candidates;
    scan.census
        .observed_index_keys
        .extend(paths.iter().cloned());
    scan.codex_join_inventory = Some(inventory);
    scan.codex_join_prepared = false;
    scan.census_unix_seconds = None;
    archive_power(&mut scan.index.archive_pass, power);
    let traversal = scan.index.traversal.as_mut().unwrap();
    traversal.codex_rollout_paths = paths;
    traversal.scan_roots = vec![root];
    scan
}

fn finish_selector(scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
    finish_selector_with(scan, |_| {})
}

fn finish_selector_with(
    mut scan: OwnedSourceScan,
    mut observe: impl FnMut(&OwnedSourceScan),
) -> (ScanIndex, SourceScanResult) {
    let mut committed = scan.index.clone();
    // A valid committed index: the strict decoder refuses a bare `{}`.
    let reservation = fixture(&serde_json::to_vec(&committed).unwrap(), ".json");
    for _ in 0..1000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(mut next) => {
                next.persist_archive_reservation(&mut committed, &reservation.0)
                    .unwrap();
                observe(&next);
                scan = next;
            }
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut scan.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                return (index, scan);
            }
        }
    }
    panic!("normal selector did not finish");
}

fn selector_archive_pass(
    f: &ArchiveFixture,
    index: ScanIndex,
) -> (ScanIndex, SourceScanResult, Vec<Value>, Ends) {
    let observer = Ends::default();
    let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
        let scan = selector_scan(
            f,
            index,
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([f.candidate()]),
            true,
        )
        .with_line_observer("codex_prelude", Box::new(observer.clone()));
        assert!(
            !scan.codex_join_prepared,
            "exercise production inventory/selection"
        );
        finish_selector(scan)
    });
    (index, result, rows, observer)
}

/// [behaviour] Production inventory denial holds only its scope; the sibling progresses.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn production_inventory_denial_holds_scoped_and_sibling_progresses() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for gate in ["battery", "admission", "cpu", "page"] {
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let plain = f.0.with_file_name("rollout-unrelated.jsonl");
        let mut bytes = Vec::new();
        for row in synthetic_rollout()
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
        {
            let mut value: Value = serde_json::from_slice(row).unwrap();
            if value["type"] == "session_meta" {
                value["payload"]["id"] = json!("unrelated");
            }
            serde_json::to_writer(&mut bytes, &value).unwrap();
            bytes.push(b'\n');
        }
        fs::write(&plain, bytes).unwrap();
        let mut live = super::super::codex_zst_refusal_tests::candidate(&plain);
        live.size_bytes = fs::metadata(&plain).unwrap().len();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let occupied = (gate == "admission").then(|| {
            OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
                .unwrap()
                .unwrap()
        });
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([f.candidate(), live.clone()]),
            gate != "battery",
        );
        if gate == "cpu" {
            scan.index.archive_pass.cpu = 30_000_000;
        }
        if gate == "page" {
            let remaining = scan
                .codex_page
                .singleton_remaining(sampled_scan::codex_cursor::Limits::current());
            scan.codex_page.charge(
                false,
                remaining - 2 * codex_file_join::MAX_HEADER_BYTES as u64 + 1,
            );
        }
        let ((mut state, result), rows) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan));
        assert_eq!(decodes(&rows), 0, "{gate}");
        assert_eq!(
            rows.iter()
                .filter(|r| r["stage"] == "codex_zst_refused")
                .count(),
            usize::from(gate == "admission"),
            "only an actual A header claim emits its funding refusal"
        );
        if gate == "admission" {
            assert!(rows.iter().any(|r| r["counts"]["codex_zst_refused"]
                ["CompressedAdmissionRefused"]
                .as_u64()
                .is_some_and(|count| count > 0)));
        }
        assert_eq!(result.unreadable_path_count, 0, "{gate}");
        assert_eq!(result.ownership_incomplete_file_count, 0, "{gate}");
        assert_eq!(result.scanned_file_count, 1, "{gate}");
        assert_eq!(
            result.snapshots.len(),
            1,
            "plain upload body survives {gate}"
        );
        assert_eq!(result.snapshots[0].source_session_id, "unrelated");
        assert!(result.snapshots[0].input_tokens > 0);
        state.record_accepted_snapshot_fingerprints(&BTreeSet::from([result.snapshots[0]
            .snapshot_fingerprint
            .clone()]));
        assert!(state
            .accepted_snapshot_fingerprints
            .contains(&result.snapshots[0].snapshot_fingerprint));
        let pending = &state.traversal.as_ref().unwrap().pending_candidates;
        assert_eq!(
            pending.iter().filter(|p| p.path == f.0).count(),
            1,
            "same archive remains queued"
        );
        assert!(
            !state.files.contains_key(&local_index_key(&f.0)),
            "no attempt spent"
        );
        if let Some(occupied) = occupied {
            occupied.close();
        }
        // Next page may admit the same work; previous deferral granted no Full.
        let (state, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
        assert_eq!(decodes(&rows), 2, "header + first Full after {gate}");
        assert_eq!(result.snapshots.len(), 1);
        assert!(state.archive_header(&f.0).is_some());
        assert_eq!(cache.cursor_reserved(), 0);
    }
}

/// [format] The persisted header-bound marker survives restart without an inventory re-decode.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn bound_header_marker_survives_restart_without_inventory_redecode() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bytes = vec![b'x'; codex_file_join::MAX_HEADER_BYTES + 1];
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    for expected in [1, 0, 0] {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            assert!(matches!(
                state
                    .inventory_archive_header(
                        &f.candidate(),
                        Some(&cache),
                        &mut funded_header_work()
                    )
                    .unwrap(),
                HeaderRead::BoundReached
            ));
        });
        assert_eq!(decodes(&rows), expected);
        state = checkpoint(&state);
    }
    // A bound is not a validity claim: the one full decode refuses this junk,
    // and all later selector passes stay quiet rather than yielding forever.
    let (mut state, result, rows, _) = selector_archive_pass(&f, state);
    assert_eq!(decodes(&rows), 1);
    assert!(result.snapshots.is_empty());
    assert!(matches!(
        state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Held { .. } | ArchiveDisposition::Refused { .. }
    ));
    for _ in 0..5 {
        let (next, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
        state = next;
    }
}

fn large_header_rollout() -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"type":"session_meta", "payload": {
        "id":"compressed-fixture", "instructions":"x".repeat(70 * 1024)
    }}))
    .unwrap();
    bytes.push(b'\n');
    bytes.extend(
        synthetic_rollout()
            .splitn(2, |b| *b == b'\n')
            .nth(1)
            .unwrap(),
    );
    bytes
}

/// [money] Plain sibling output: mixed-owner plain publishes identical bytes while the hold stays
/// quiet.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn bound_archive_mixed_owner_plain_publishes_identical_and_hold_stays_quiet() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
    let plain = f.0.with_file_name("rollout-compressed-fixture.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
    member.size_bytes = fs::metadata(&plain).unwrap().len();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (_, first_control) = finish_selector(selector_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
        VecDeque::from([member.clone()]),
        true,
    ));
    assert_eq!(first_control.snapshots.len(), 1);
    let mut state = ScanIndex::default();
    let (_, first_rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(matches!(
            state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .unwrap(),
            HeaderRead::BoundReached
        ));
    });
    assert_eq!(decodes(&first_rows), 1);
    for pass in 0..5 {
        let mut control_index = checkpoint(&state);
        control_index.files.remove(&local_index_key(&f.0));
        let (_, control) = finish_selector(selector_scan(
            &f,
            control_index,
            cache.clone(),
            VecDeque::from([member.clone()]),
            true,
        ));
        let ((next, result), rows) = crate::local_resource_diagnostics::capture(|| {
            finish_selector(selector_scan(
                &f,
                checkpoint(&state),
                cache.clone(),
                VecDeque::from([f.candidate(), member.clone()]),
                true,
            ))
        });
        assert_eq!(decodes(&rows), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_inventory"));
        assert_eq!(result.unreadable_path_count, 0);
        if pass == 0 {
            assert_eq!(result.snapshots.len(), 1);
        }
        assert_eq!(
            result
                .snapshots
                .iter()
                .map(snapshot_upload_body_witness)
                .collect::<Vec<_>>(),
            control
                .snapshots
                .iter()
                .map(snapshot_upload_body_witness)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            next.files[&local_index_key(&f.0)].codex_compressed_hold,
            Some(CodexZstCause::FamilyUnproven)
        );
        state = next;
    }
}

/// [format] Crash safety: the header bound survives a saved reservation and a crash before the
/// first line.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn bound_header_survives_saved_reservation_before_first_line_crash() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut committed = ScanIndex::default();
    let path = f.0.parent().unwrap().join("before-line-index.json");
    committed.save(&path).unwrap();
    let mut scan = selector_scan(
        &f,
        committed.clone(),
        cache.clone(),
        VecDeque::from([f.candidate()]),
        true,
    );
    let key = local_index_key(&f.0);
    for _ in 0..1000 {
        scan = match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            OwnedSourceScanStep::Complete { .. } => panic!("read must await reservation"),
        };
        if scan.active_file.is_some() {
            break;
        }
    }
    assert!(scan.active_file.is_some());
    assert_eq!(decoded_in(&scan), 0);
    scan.persist_archive_reservation(&mut committed, &path)
        .unwrap();
    let mut restored = ScanIndex::load(&path).unwrap();
    assert_pending(&restored, &f.0, 1);
    assert!(
        restored.files[&key]
            .archive
            .as_ref()
            .unwrap()
            .header_bound_reached
    );
    assert!(
        restored.archive_header(&f.0).is_none(),
        "no captured full header before crash"
    );
    scan.active_file
        .take()
        .unwrap()
        .parser
        .reader
        .reader
        .close();
    assert_eq!(cache.cursor_reserved(), 0);
    let (quiet, result, rows, _) = selector_archive_pass(&f, restored);
    assert_eq!(
        decodes(&rows),
        0,
        "deadline still binds the reserved attempt"
    );
    assert!(result.snapshots.is_empty());
    restored = checkpoint(&quiet);
    retry_due(&mut restored, &key);
    let (mut state, result, rows, _) = selector_archive_pass(&f, restored);
    assert_eq!(decodes(&rows), 1, "no repeated inventory prefix on retry");
    assert_eq!(result.snapshots.len(), 1);
    assert_pending(&state, &f.0, 2);
    state.settle_archive_bodies(
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
        state.files[&key].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Acquired
    ));
    let (_, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
}

/// [format] The inventory bound marker survives a normal save before the Full reservation.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn inventory_bound_marker_survives_normal_save_before_full_reservation() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut scan = selector_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
        VecDeque::from([f.candidate()]),
        true,
    );
    let key = local_index_key(&f.0);
    let path = f.0.parent().unwrap().join("inventory-checkpoint.json");
    for expected in [1, 0, 0, 0, 0] {
        let (pending, rows) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..1000 {
                scan = match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => next,
                    OwnedSourceScanStep::Complete { .. } => panic!("stop before installing Full"),
                };
                if scan
                    .index
                    .files
                    .get(&key)
                    .and_then(|e| e.archive.as_ref())
                    .is_some_and(|e| e.header_bound_pending())
                {
                    return scan;
                }
            }
            panic!("inventory marker not reached");
        });
        assert_eq!(
            decodes(&rows),
            expected,
            "clean restart reuses inventory marker"
        );
        assert!(
            pending.active_file.is_none(),
            "crash edge precedes Full reservation"
        );
        let marker = pending.index.files[&key].archive.as_ref().unwrap();
        assert!(marker.header_bound_reached);
        assert!(matches!(
            marker.disposition,
            ArchiveDisposition::HeaderValidated
        ));
        assert!(marker.body_witness.is_none());
        let mut saved = checkpoint(&pending.index); // production committable subset
        assert!(saved.save(&f.0.join("not-a-directory.json")).is_err());
        assert!(
            saved.files[&key]
                .archive
                .as_ref()
                .unwrap()
                .header_bound_reached
        );
        saved.save(&path).unwrap();
        let restored = ScanIndex::load(&path).unwrap();
        assert!(restored.files[&key]
            .archive
            .as_ref()
            .unwrap()
            .header_bound_pending());
        scan = selector_scan(
            &f,
            restored,
            cache.clone(),
            VecDeque::from([f.candidate()]),
            true,
        );
    }
    assert_eq!(cache.cursor_reserved(), 0);
}

/// [behaviour] Sibling inventory at the population cap counts shared physical keys once.
#[test]
fn sibling_inventory_at_population_cap_counts_shared_physical_keys_once() {
    let paths = (0..codex_file_join::MAX_HEADER_FILES - 2)
        .map(|n| format!("/synthetic/rollout-owner-{n:05}.jsonl.zst"))
        .collect::<BTreeSet<_>>();
    let mut inventory = codex_file_join::HeaderInventory::new(&[], &paths, None);
    inventory.first_read_archives = paths.clone();
    let shared = paths.last().unwrap().clone();
    inventory.deferred_archives.insert(shared.clone());
    let (_, phases) =
        crate::local_resource_diagnostics::capture(|| inventory.classify_bound_archives());
    assert!(
        inventory.classification_ready(),
        "live classification phase refused: {phases:?}"
    );
    assert_eq!(
        inventory.deferred_archives,
        BTreeSet::from([shared.clone()]),
        "distinct-owner bound archives never become siblings of themselves"
    );
    let held_peer = "/synthetic/elsewhere/rollout-owner-00001.jsonl.zst".to_owned();
    let deferred_peer = "/synthetic/elsewhere/rollout-owner-00002.jsonl.zst".to_owned();
    inventory.held_archives.insert(held_peer);
    inventory.deferred_archives.insert(deferred_peer.clone());
    assert_eq!(paths.len() + 2, codex_file_join::MAX_HEADER_FILES);
    let (_, phases) =
        crate::local_resource_diagnostics::capture(|| inventory.classify_bound_archives());
    assert!(
        inventory.classification_ready(),
        "live classification phase refused: {phases:?}"
    );
    assert_eq!(
        inventory
            .family_held
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["/synthetic/rollout-owner-00001.jsonl.zst".to_owned()]),
        "a resolved held peer gives a named family hold, not a transient deferral"
    );
    assert_eq!(
        inventory.deferred_archives,
        BTreeSet::from([
            shared,
            deferred_peer,
            "/synthetic/rollout-owner-00002.jsonl.zst".to_owned(),
        ])
    );
}

/// [behaviour] A changed archive stamp resets the header bound and decodes one bounded prefix.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn changed_archive_stamp_resets_header_bound_and_decodes_one_bounded_prefix() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for replace in [false, true] {
        let bytes = zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap();
        let f = ArchiveFixture::new(&bytes);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let key = local_index_key(&f.0);
        let mut index = ScanIndex::default();
        assert!(matches!(
            index
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .unwrap(),
            HeaderRead::BoundReached
        ));
        let old = index.files[&key].archive.as_ref().unwrap().clone();
        assert!(old.header_bound_reached);
        if replace {
            // New object, byte-identical contents.
            let replacement = f.0.with_extension("replacement");
            fs::write(&replacement, bytes).unwrap();
            fs::rename(replacement, &f.0).unwrap();
        } else {
            // Real bytes change on the same object.
            let mut changed = large_header_rollout();
            changed.extend_from_slice(b"{\"type\":\"synthetic_change\"}\n");
            fs::write(&f.0, zstd::stream::encode_all(&changed[..], 1).unwrap()).unwrap();
        }
        let reset = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, Some(&old)).unwrap();
        assert!(!reset.header_bound_reached);
        let mut work = funded_header_work();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..3 {
                assert!(matches!(
                    index
                        .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                        .unwrap(),
                    HeaderRead::BoundReached
                ));
            }
        });
        assert_eq!(decodes(&rows), 1);
        assert_eq!(work.decoded_bytes, codex_file_join::MAX_HEADER_BYTES as u64);
    }
}

/// [format] A missing or malformed persisted header bound loads false and reads at most one prefix.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn missing_or_malformed_header_bound_loads_false_and_reads_at_most_one_prefix() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for value in [
        None,
        Some(json!("true")),
        Some(json!({"invalid": [true]})),
        Some(json!(null)),
        Some(json!(1)),
    ] {
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let key = local_index_key(&f.0);
        let mut archive = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        archive.disposition = ArchiveDisposition::HeaderValidated;
        archive.decode_attempts = 0;
        let mut index = ScanIndex::default();
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(archive));
        let path = f.0.parent().unwrap().join("header-flag-index.json");
        index.save(&path).unwrap();
        let mut raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let flags = raw["files"][&key]["archive"].as_object_mut().unwrap();
        if let Some(value) = value {
            flags.insert("header_bound_reached".into(), value);
        } else {
            flags.remove("header_bound_reached");
        }
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(
            !loaded.files[&key]
                .archive
                .as_ref()
                .unwrap()
                .header_bound_reached
        );
        let mut work = funded_header_work();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..3 {
                assert!(matches!(
                    loaded
                        .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                        .unwrap(),
                    HeaderRead::BoundReached
                ));
            }
        });
        assert_eq!(decodes(&rows), 1);
        assert_eq!(work.decoded_bytes, codex_file_join::MAX_HEADER_BYTES as u64);
    }
}

/// [behaviour] Warm evidence with a changed stamp defers without reading an unselected header.
#[test]
fn warm_archive_evidence_changed_stamp_defers_without_unselected_header_read() {
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.header_validated = Some(
        ValidatedHeader::from_line(
            synthetic_rollout()
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
        )
        .unwrap(),
    );
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    let paths = BTreeSet::from([key.clone()]);
    let root = f.0.parent().unwrap().to_owned();
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(&root, &fs::metadata(&root).unwrap());
    let mut inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&directories));
    assert!(inventory.retain_cached_archives(&index, &paths).is_none());
    let before = serde_json::to_value(&index.files[&key]).unwrap();
    // Warm fact selected by F3, then object changes before inventory consumes it.
    File::options()
        .append(true)
        .open(&f.0)
        .unwrap()
        .write_all(b"changed stamp")
        .unwrap();
    let (step, rows) = crate::local_resource_diagnostics::capture(|| {
        inventory.step_with_archive(&CodexTitleMetadata::default(), &mut index, None)
    });
    assert_eq!(step, codex_file_join::HeaderStep::Deferred);
    assert!(inventory.deferred_archives.contains(&key));
    assert_eq!(decodes(&rows), 0);
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert_eq!(serde_json::to_value(&index.files[&key]).unwrap(), before);
}

/// [money] Read bound: denied inventory debt releases once and paces without a plain body re-read.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn denied_archive_inventory_debt_releases_once_and_paces_without_plain_body_reread() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut f =
        ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let state = f.0.parent().unwrap().to_owned();
    let root = state.join("sessions");
    fs::create_dir(&root).unwrap();
    let other = state.join("other/sessions");
    fs::create_dir_all(&other).unwrap();
    let roots = [root.clone(), other.clone()];
    let plain = root.join("rollout-stable-plain.jsonl");
    fs::write(
        &plain,
        String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", "stable-plain"),
    )
    .unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    // The predecessor release never discovered archives: its accepted plain
    // state is built before any archive exists under the configured roots.
    let ((mut index, baseline), baseline_reads) =
        terminal_contract_retry::source_acquisitions(|| {
            finish_selector(
                OwnedSourceScan::new(
                    SnapshotSource::Codex,
                    &roots,
                    ScanIndex::default(),
                    NOW,
                    BACKFILL_WINDOW_DAYS,
                    10,
                    false,
                    None,
                    &[],
                    false,
                    false,
                )
                .with_sampled_acquisition(cache.clone(), Scope("activation-held-debt".into())),
            )
        });
    let archive = root.join(f.0.file_name().unwrap());
    fs::rename(&f.0, &archive).unwrap();
    f.0 = archive;
    let mut archives = BTreeSet::from([local_index_key(&f.0)]);
    for owner in ["second-archive", "third-archive"] {
        let path = root.join(format!("rollout-{owner}.jsonl.zst"));
        let body = String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", owner);
        fs::write(&path, zstd::stream::encode_all(body.as_bytes(), 1).unwrap()).unwrap();
        archives.insert(local_index_key(&path));
    }
    let owed = archives.clone();
    let hidden = other.join("rollout-unlisted-archive.jsonl.zst");
    let body = String::from_utf8(synthetic_rollout())
        .unwrap()
        .replace("compressed-fixture", "unlisted-archive");
    fs::write(
        &hidden,
        zstd::stream::encode_all(body.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    archives.insert(local_index_key(&hidden));
    assert_eq!(
        baseline_reads.get(&plain).copied().unwrap_or(0),
        1,
        "positive control for native body I/O probe"
    );
    assert_eq!(baseline.snapshots.len(), 1);
    assert_eq!(baseline.snapshots[0].source_session_id, "stable-plain");
    index.record_accepted_snapshot_fingerprints(&BTreeSet::from([baseline.snapshots[0]
        .snapshot_fingerprint
        .clone()]));
    let plain_key = local_index_key(&plain);
    let before = serde_json::to_value(&index.files[&plain_key]).unwrap();
    let saved = state.join("held.json");
    // The predecessor's saved inventory hold: archives owed, one refused.
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &roots,
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    traversal.pending_directories.clear();
    traversal.pending_candidates.clear();
    traversal.codex_rollout_paths = BTreeSet::from([plain_key.clone()]);
    traversal
        .observed_index_keys
        .extend(archives.iter().cloned());
    traversal.observed_index_keys.insert(plain_key.clone());
    let mut dirs = codex_file_join::DirectoryCensus::new();
    for directory in &roots {
        dirs.observe(directory, &fs::metadata(directory).unwrap());
    }
    traversal.codex_join_directory_census = Some(dirs);
    traversal.residue.codex_inventory_hold = Some(CodexInventoryHold {
        owed: owed.clone(),
        refused_headers: BTreeMap::from([(
            local_index_key(&f.0),
            codex_file_join::path_witness(&f.0),
        )]),
        ..Default::default()
    });
    traversal
        .counts
        .record_unreadable(UnreadableCause::AliasParser, 1);
    traversal.unhealthy_retry_not_before_unix_seconds =
        Some(rfc3339_unix_seconds(NOW).unwrap() + 1800);
    index.save(&saved).unwrap();
    let (((mut index, _), rows), acquisitions) =
        terminal_contract_retry::source_acquisitions(|| {
            crate::local_resource_diagnostics::capture(|| {
                let mut scan = OwnedSourceScan::new(
                    SnapshotSource::Codex,
                    &roots,
                    ScanIndex::load(&saved).unwrap(),
                    NOW,
                    BACKFILL_WINDOW_DAYS,
                    1,
                    false,
                    None,
                    &[],
                    false,
                    false,
                )
                .with_sampled_acquisition(cache.clone(), Scope("activation-held-debt".into()));
                assert!(scan
                    .index
                    .traversal
                    .as_ref()
                    .unwrap()
                    .residue
                    .codex_inventory_hold
                    .is_none());
                assert!(
                    owed.iter().all(|key| scan
                        .index
                        .traversal
                        .as_ref()
                        .unwrap()
                        .codex_rollout_paths
                        .contains(key)),
                    "scoped activation relist includes every sibling"
                );
                assert!(
                    !scan
                        .index
                        .traversal
                        .as_ref()
                        .unwrap()
                        .pending_directories
                        .is_empty(),
                    "full metadata census is still owed before any archive decode"
                );
                scan.index.archive_pass.power = false;
                scan.index.archive_pass.cpu = 30_000_000;
                finish_selector(scan)
            })
        });
    assert_eq!(
        archive_event_count(&rows, "codex_archive_inventory_debt_released"),
        1
    );
    assert_eq!(
        decoded_archive_bytes(&rows),
        0,
        "metadata release never grants a paid decoder"
    );
    assert_eq!(acquisitions.get(&plain).copied().unwrap_or(0), 0);
    let mut bodies = 0;
    for _ in 0..8 {
        index.save(&saved).unwrap();
        let (((mut next, result), rows), acquisitions) =
            terminal_contract_retry::source_acquisitions(|| {
                crate::local_resource_diagnostics::capture(|| {
                    let mut scan = OwnedSourceScan::new(
                        SnapshotSource::Codex,
                        &roots,
                        ScanIndex::load(&saved).unwrap(),
                        NOW,
                        BACKFILL_WINDOW_DAYS,
                        1,
                        false,
                        None,
                        &[],
                        false,
                        false,
                    )
                    .with_sampled_acquisition(cache.clone(), Scope("activation-held-debt".into()));
                    archive_power(&mut scan.index.archive_pass, true);
                    finish_selector(scan)
                })
            });
        assert_eq!(
            archive_event_count(&rows, "codex_archive_inventory_debt_released"),
            0,
            "save/restart cannot release consumed debt again"
        );
        assert_eq!(
            acquisitions.get(&plain).copied().unwrap_or(0),
            0,
            "unchanged plain native body is never re-read"
        );
        assert_eq!(
            serde_json::to_value(&next.files[&plain_key]).unwrap(),
            before
        );
        assert!(
            result.snapshots.len() <= 1,
            "ordinary one-file page bounds the archive burst"
        );
        bodies += result.snapshots.len();
        next.settle_archive_bodies(&ack_bodies(&result));
        next.record_accepted_snapshot_fingerprints(
            &result
                .snapshots
                .iter()
                .map(|body| body.snapshot_fingerprint.clone())
                .collect(),
        );
        index = next;
        if bodies == archives.len() {
            break;
        }
    }
    assert_eq!(bodies, archives.len());
    for key in archives {
        assert!(matches!(
            index.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Acquired
        ));
    }
}

/// [behaviour] Activation does not release an unchanged non-regular archive inventory witness.
#[test]
fn activation_does_not_release_unchanged_nonregular_archive_inventory_witness() {
    let f = ArchiveFixture::new(b"metadata-only fixture");
    let root = f.0.parent().unwrap().to_owned();
    let directory = root.join("rollout-nonregular.jsonl.zst");
    fs::create_dir(&directory).unwrap();
    let key = local_index_key(&directory);
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    for listed in [false, true] {
        let traversal = index.traversal.as_mut().unwrap();
        traversal.pending_directories.clear();
        traversal.pending_candidates.clear();
        traversal.codex_rollout_paths.clear();
        if listed {
            traversal.codex_rollout_paths.insert(key.clone());
        }
        let witness = codex_file_join::path_witness(&directory);
        let hold = CodexInventoryHold {
            owed: BTreeSet::from([key.clone()]),
            refused_headers: BTreeMap::from([(key.clone(), witness.clone())]),
            outside_roster: BTreeMap::from([(key.clone(), witness)]),
            awaiting_directories: false,
        };
        traversal.residue.codex_inventory_hold = Some(hold.clone());
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            release_codex_inventory_hold(SnapshotSource::Codex, traversal, &index.decode_holds)
        });
        assert_eq!(
            archive_event_count(&rows, "codex_archive_inventory_debt_released"),
            0
        );
        assert_eq!(traversal.residue.codex_inventory_hold.as_ref(), Some(&hold));
        assert!(traversal.pending_candidates.is_empty());
    }
}

/// [behaviour] An incomplete archive inventory defers before frame or header I/O.
#[test]
fn incomplete_archive_inventory_defers_before_frame_or_header_io() {
    let f = ArchiveFixture::new(b"no read permission from incomplete membership");
    let mut index = ScanIndex::default();
    archive_power(&mut index.archive_pass, true);
    let inventory = codex_file_join::HeaderInventory::new(&[], &BTreeSet::new(), None);
    let (admission, rows) = crate::local_resource_diagnostics::capture(|| {
        index
            .classify_archive(
                &f.candidate(),
                &File::open(&f.0).unwrap(),
                Some(&inventory),
                None,
                &mut sampled_scan::codex_cursor::PageBudget::default(),
            )
            .unwrap()
    });
    assert!(matches!(
        admission,
        codex_archive_catchup::Admission::Deferred(_)
    ));
    assert!(index.files.is_empty());
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert!(!rows
        .iter()
        .any(|row| row["stage"] == "codex_zst_frame_header"));
}

/// [behaviour] Deferred header gates and an absent cache do not increment the admission streak.
#[test]
fn header_deferred_gates_and_absent_cache_do_not_increment_admission_streak() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut state = ScanIndex::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        for _ in 0..12 {
            for mut work in [
                HeaderWork::default(),
                HeaderWork {
                    allowed: true,
                    cpu_micros: 30_000_000,
                    ..HeaderWork::default()
                },
            ] {
                assert!(matches!(
                    state
                        .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                        .unwrap(),
                    HeaderRead::Deferred
                ));
                assert_eq!((work.physical_bytes, work.decoded_bytes), (0, 0));
            }
            assert!(matches!(
                state
                    .inventory_archive_header(&f.candidate(), None, &mut funded_header_work())
                    .unwrap(),
                HeaderRead::Deferred
            ));
            let mut outside_scope = f.candidate();
            outside_scope.scan_root = f.0.parent().unwrap().join("different-root");
            assert!(state
                .inventory_archive_header(&outside_scope, Some(&cache), &mut funded_header_work())
                .is_err());
        }
    });
    assert_eq!(decodes(&rows), 0);
    assert!(state.files.is_empty());
    assert!(!rows
        .iter()
        .any(|r| r["stage"] == "codex_zst_admission_alarm"));
    assert_eq!(
        cache.archive_streak(&key, true),
        1,
        "no actual claim was refused"
    );
}

fn power_plain_sibling(f: &ArchiveFixture) -> CandidateFile {
    let path = f.0.with_file_name("rollout-unrelated.jsonl");
    let mut bytes = Vec::new();
    for row in synthetic_rollout()
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
    {
        let mut value: Value = serde_json::from_slice(row).unwrap();
        if value["type"] == "session_meta" {
            value["payload"]["id"] = json!("unrelated");
        }
        serde_json::to_writer(&mut bytes, &value).unwrap();
        bytes.push(b'\n');
    }
    fs::write(&path, bytes).unwrap();
    let mut candidate = codex_zst_refusal_tests::candidate(&path);
    candidate.size_bytes = fs::metadata(path).unwrap().len();
    candidate
}

/// [behaviour] Power loss after construction defers without a read or attempt; plain progresses.
#[test]
fn archive_power_loss_after_construction_defers_without_read_or_attempt_and_plain_progresses() {
    use crate::snapshot_sync::continuation::PlatformState;
    for denied in [PlatformState::Refused, PlatformState::Unknown] {
        // Refused and Unknown both deny.
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let plain = power_plain_sibling(&f);
        let key = local_index_key(&f.0);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let decoders = codex_zst_refusal_tests::decoder_construction_count();
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([plain, f.candidate()]),
            true,
        );
        assert!(scan.index.archive_pass.power, "constructed while Allowed");
        // Power is lost after construction: every live re-query is denied.
        scan.index.archive_pass.gates = scripted_power(&[denied]);
        scan.index.archive_pass.cpu = 123;
        scan.index.archive_pass.work = 456;
        let before = (scan.index.archive_pass.cpu, scan.index.archive_pass.work);
        let ((state, result), rows) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan));
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].source_session_id, "unrelated");
        assert!(result.snapshots[0].input_tokens > 0);
        assert!(!state.files.contains_key(&key));
        assert_eq!(
            codex_zst_refusal_tests::decoder_construction_count(),
            decoders
        );
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_frame_header"));
        assert!(state.archive_pass.cpu >= before.0 && state.archive_pass.work >= before.1);
        assert_eq!(
            state
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .filter(|p| p.path == f.0)
                .count(),
            1
        );
        assert_eq!(
            cache.archive_starved_count(Some(&key)),
            0,
            "power refusal is not a claim"
        );
    }
}

/// [behaviour] Power loss between header and body keeps the paid header; plain progresses.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn archive_power_loss_between_header_and_body_preserves_paid_header_and_plain_progress() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    use crate::snapshot_sync::continuation::PlatformState::{self, Allowed};
    for denied in [PlatformState::Refused, PlatformState::Unknown] {
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let plain = power_plain_sibling(&f);
        let key = local_index_key(&f.0);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let decoders = codex_zst_refusal_tests::decoder_construction_count();
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([plain, f.candidate()]),
            true,
        );
        // Allowed through the header's live re-queries, lost before the body.
        scan.index.archive_pass.gates = scripted_power(&[Allowed, Allowed, denied]);
        let ((state, result), rows) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan));
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].source_session_id, "unrelated");
        let evidence = state.files[&key].archive.as_ref().unwrap();
        assert!(evidence.header_validated.is_some());
        assert_eq!(
            evidence.decode_attempts, 0,
            "body reservation was never installed"
        );
        assert!(evidence.body_witness.is_none());
        assert_eq!(
            codex_zst_refusal_tests::decoder_construction_count() - decoders,
            1,
            "only the allowed header decoder"
        );
        assert_eq!(decodes(&rows), 1);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_input"));
        assert_eq!(
            state
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .filter(|p| p.path == f.0)
                .count(),
            1
        );
        assert_eq!(cache.archive_starved_count(Some(&key)), 0);
        let (state, result, retry_rows, _) = selector_archive_pass(&f, checkpoint(&state));
        assert_eq!(
            decodes(&retry_rows),
            1,
            "cached paid header; one body after AC returns"
        );
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(
            state.files[&key].archive.as_ref().unwrap().decode_attempts,
            1
        );
    }
}

/// [behaviour] The activated selector reaches header-claim starvation and resets on progress.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn activated_selector_reaches_inherited_header_claim_starvation_and_resets_on_progress() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .unwrap()
        .unwrap();
    for attempt in 1..=14 {
        let scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([f.candidate()]),
            true,
        );
        let ((index, result), rows) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan));
        assert!(!index.files.contains_key(&key));
        assert!(result.snapshots.is_empty());
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert_eq!(
            rows.iter()
                .filter(|r| r["stage"] == "codex_zst_admission_alarm")
                .count(),
            usize::from(attempt == 12)
        );
        assert_eq!(
            cache.archive_starved_count(Some(&key)),
            usize::from(attempt >= 12)
        );
        assert_eq!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .filter(|p| p.path == f.0)
                .count(),
            1
        );
    }
    occupied.close();
    let scan = selector_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
        VecDeque::from([f.candidate()]),
        true,
    );
    let ((index, result), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(decodes(&rows), 2);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        1
    );
    assert_eq!(
        cache.archive_streak(&key, true),
        1,
        "successful funding reset the inherited streak"
    );
}
