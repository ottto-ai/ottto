fn funded_header_work() -> HeaderWork {
    HeaderWork {
        allowed: true,
        ..HeaderWork::default()
    }
}

#[test]
fn header_cli_version_is_bounded_at_capture_restore_and_accessor() {
    for (version, keep) in [
        ("v1.2".to_owned(), true),
        (" ".repeat(64), true),
        ("x".repeat(65), false),
        ("bad\nversion".to_owned(), false),
        ("bad\u{7f}".to_owned(), false),
        ("λ".to_owned(), false),
    ] {
        let mut bytes = serde_json::to_vec(&json!({"type":"session_meta", "payload": {
            "id":"compressed-fixture", "cli_version": version, "timestamp": NOW,
        }}))
        .unwrap();
        bytes.push(b'\n');
        let header = ValidatedHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.cli_version(), keep.then_some(version.as_str()));
        assert!(header.created_unix_ms.is_some());
        let mut persisted = serde_json::to_value(&header).unwrap();
        persisted["cli_version"] = json!(version);
        let restored: ValidatedHeader = serde_json::from_value(persisted).unwrap();
        assert_eq!(restored.cli_version(), keep.then_some(version.as_str()));
        assert_eq!(
            restored.cli_version.is_some(),
            keep,
            "invalid stored value dropped"
        );
    }
    assert!(ValidatedHeader::from_bytes(b"{}\n").is_none());
    assert!(
        ValidatedHeader::from_bytes(b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"x\"}}")
            .is_none()
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
    inventory.archive_work.allowed = true;
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        while !inventory.step_with_archive(&CodexTitleMetadata::default(), state, Some(cache)) {}
    });
    assert!(inventory.complete);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].owner, "compressed-fixture");
    assert_eq!(cache.cursor_reserved(), 0, "no parked decoder");
    assert_eq!(
        inventory.read_bytes as u64,
        inventory.archive_work.physical_bytes
    );
    let before = rows
        .iter()
        .filter(|r| r["stage"] == "codex_zst_input")
        .count();
    assert_eq!(before, 0, "inventory has no Full/encoding row");
    assert_eq!(decodes(&rows), usize::from(inventory.read_bytes > 0));
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn inventory_header_once_then_full_once_with_physical_accounting() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
    assert_eq!(state.codex_archive_cli_version(&f.0), Some("0.77.0"));
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
    assert!(quiet.codex_archive_cli_version(&f.0).is_none());
    assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 1);
    assert_eq!(decodes(&header_inventory(&f, &mut quiet, &cache)), 0);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_read_never_checks_archive_completion_and_failed_full_keeps_projection() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_limits_and_failures_do_not_redecode_same_stamp() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let large = vec![b'x'; codex_file_join::MAX_HEADER_BYTES + 1];
    let mut skippable = vec![0x50, 0x2a, 0x4d, 0x18];
    skippable.extend_from_slice(&(256_u32 * 1024).to_le_bytes());
    skippable.extend(vec![0; 256 * 1024]);
    for encoded in [
        zstd::stream::encode_all(&large[..], 1).unwrap(),
        skippable,
        b"garbage".to_vec(),
    ] {
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn refused_header_admission_does_not_spend_a_decode_attempt() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .unwrap()
        .unwrap();
    let mut state = ScanIndex::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(state
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
            .is_err());
    });
    assert_eq!(decodes(&rows), 0);
    assert_eq!(
        rows.iter()
            .filter_map(|r| r["counts"]["codex_zst_refused"]["CompressedAdmissionRefused"].as_u64())
            .count(),
        1
    );
    assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_inventory"));
    assert!(!state.files.contains_key(&local_index_key(&f.0)));
    occupied.close();
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 1);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn invalid_archive_does_not_hold_live_plain_on_next_pass() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
    let mut inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&dirs));
    inventory.archive_work.allowed = true;
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
    assert!(rows.iter().any(
        |r| r["counts"]["codex_zst_refused"]["CompressedHeaderInvalid"]
            .as_u64()
            .unwrap_or(0)
            > 0
    ));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn full_read_accepts_seventy_kib_header_and_settles_once() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
    let mut unseen = ScanIndex::default();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    assert!(unseen
        .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
        .is_err());
    let (mut state, result, rows, _) = archive_pass(&f, unseen, true, None);
    assert_eq!(decodes(&rows), 1);
    assert!(!result.snapshots.is_empty());
    assert_eq!(state.codex_archive_cli_version(&f.0), Some("v-large"));
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
    let (_, result, rows, _) = archive_pass(&f, checkpoint(&state), true, None);
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn real_full_admission_refusal_preserves_header_without_redecode() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
            SnapshotSource::Codex,
            &CodexTitleMetadata::default(),
            None,
            None,
            false,
            false,
            false,
            &mut state,
            Some(&cache)
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn header_permission_and_cpu_gate_spend_no_transcript_bytes_or_attempt() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
            assert!(state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
                .is_err());
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
        let (_, physical) = state
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut work)
            .unwrap();
        assert_eq!(physical as u64, work.physical_bytes);
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn double_uuid_archive_has_named_owner_hold_no_replacement_or_redecode() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
        state.codex_archive_cli_version(&f.0).is_none(),
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn inventory_step_charges_actual_physical_bytes_to_page_budget() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let root = f.0.parent().unwrap().to_owned();
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&root, &fs::metadata(&root).unwrap());
    let paths = BTreeSet::from([local_index_key(&f.0)]);
    let mut inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&dirs));
    inventory.archive_work.allowed = true; // synthetic AC + utility permission
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(cache, Scope("inventory-budget-test".into()));
    scan.identified_candidates = VecDeque::from([f.candidate()]);
    scan.codex_join_inventory = Some(inventory);
    scan.codex_join_prepared = false;
    let limits = sampled_scan::codex_cursor::Limits::current();
    let before = scan.codex_page.singleton_remaining(limits);
    for _ in 0..1000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => {
                let inventory = next.codex_join_inventory.as_ref().unwrap();
                if inventory.archive_work.decoded_bytes > 0 {
                    assert_eq!(
                        next.codex_page.singleton_remaining(limits),
                        before - inventory.archive_work.physical_bytes
                    );
                    assert_eq!(
                        inventory.read_bytes as u64,
                        inventory.archive_work.physical_bytes
                    );
                    assert!(inventory.archive_work.physical_bytes > 0);
                    return;
                }
                scan = next;
            }
            OwnedSourceScanStep::Complete { .. } => panic!("inventory read was not charged"),
        }
    }
    panic!("inventory budget test did not reach its step");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn unreadable_segment_holds_its_filename_owner_but_not_unrelated_plain() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
