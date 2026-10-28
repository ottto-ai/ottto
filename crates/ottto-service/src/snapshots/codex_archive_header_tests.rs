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
        while inventory.step_with_archive(&CodexTitleMetadata::default(), state, Some(cache))
            != codex_file_join::HeaderStep::Complete
        {}
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
        assert!(matches!(
            state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .unwrap(),
            HeaderRead::Deferred
        ));
    });
    assert_eq!(decodes(&rows), 0);
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
    for _ in 0..5 {
        let (next, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
        state = next;
    }
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

// Discovery remains off: inject only the roster/candidates, leaving the native
// inventory, selector, parser, owner finish, upload policy and checkpoint intact.
fn selector_scan(
    f: &ArchiveFixture,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    candidates: VecDeque<CandidateFile>,
    allowed: bool,
) -> OwnedSourceScan {
    let root = f.0.parent().unwrap().to_owned();
    let paths = candidates
        .iter()
        .map(|c| local_index_key(&c.path))
        .collect();
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(&root, &fs::metadata(&root).unwrap());
    let mut inventory = codex_file_join::HeaderInventory::new(&[root], &paths, Some(&directories));
    inventory.archive_work.allowed = allowed;
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
    scan.census.observed_index_keys.extend(paths);
    scan.codex_join_inventory = Some(inventory);
    scan.codex_join_prepared = false;
    scan.census_unix_seconds = None;
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
    let reservation = fixture(b"{}", ".json");
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn deferred_archive_keeps_plain_uploads_and_requeues_without_refusal_debt() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
            scan.codex_join_inventory
                .as_mut()
                .unwrap()
                .archive_work
                .cpu_micros = 30_000_000;
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
        assert!(
            !rows.iter().any(|r| r["stage"] == "codex_zst_refused"),
            "{gate}"
        );
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn bound_header_marker_survives_restart_without_inventory_redecode() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
        assert!(!state.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .invalid_header(&f.0, &fs::metadata(&f.0).unwrap()));
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn oversized_archive_defers_before_full_without_blocking_unrelated_census_work() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
    let plain = f.0.with_file_name("rollout-compressed-fixture.jsonl");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
    member.size_bytes = fs::metadata(&plain).unwrap().len();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut state, result) = finish_selector(selector_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
        VecDeque::from([member.clone()]),
        true,
    ));
    assert_eq!(result.snapshots.len(), 1);
    let accepted = BTreeSet::from([result.snapshots[0].snapshot_fingerprint.clone()]);
    state.record_accepted_snapshot_fingerprints(&accepted);
    let plain_body = state.files[&local_index_key(&plain)]
        .last_upload_body_witness
        .clone();
    assert!(plain_body.is_some());
    // Establish the once-only inventory partial before testing zero-byte deferral.
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(matches!(
            state
                .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
                .unwrap(),
            HeaderRead::BoundReached
        ));
    });
    assert_eq!(decodes(&rows), 1);
    assert_eq!(
        rows.iter()
            .map(
                |row| row["counts"]["codex_aux_reads"]["header_read_attempts"]["inventory"]
                    .as_u64()
                    .unwrap_or(0)
            )
            .sum::<u64>(),
        1
    );
    assert!(!rows
        .iter()
        .any(|row| row["counts"]["whole_reads"].as_u64().unwrap_or(0) > 0));
    for pass in 0..5 {
        let unrelated = format!("unrelated-{pass}");
        let live_path = f.0.with_file_name(format!("rollout-{unrelated}.jsonl"));
        let mut bytes = Vec::new();
        for row in synthetic_rollout()
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
        {
            let mut row: Value = serde_json::from_slice(row).unwrap();
            if row["type"] == "session_meta" {
                row["payload"]["id"] = json!(unrelated);
            }
            serde_json::to_writer(&mut bytes, &row).unwrap();
            bytes.push(b'\n');
        }
        fs::write(&live_path, bytes).unwrap();
        let mut live = super::super::codex_zst_refusal_tests::candidate(&live_path);
        live.size_bytes = fs::metadata(&live_path).unwrap().len();
        let mut gated_steps = 0;
        let ((next, result), rows) = crate::local_resource_diagnostics::capture(|| {
            let mut scan = selector_scan(
                &f,
                checkpoint(&state),
                cache.clone(),
                VecDeque::from([f.candidate(), member.clone(), live]),
                true,
            );
            scan.state_census_complete = true;
            scan.sidecar_census_complete = true;
            finish_selector_with(scan, |next| {
                if next.codex_join_prepared
                    && next
                        .identified_candidates
                        .iter()
                        .any(|c| c.path == live_path)
                {
                    gated_steps += 1;
                    let inventory = next.codex_join_inventory.as_ref().unwrap();
                    assert!(inventory.deferred_archives.contains(&local_index_key(&f.0)));
                    assert!(inventory.complete_for(Some(&unrelated)));
                    assert!(!inventory.complete_for(Some(&"compressed-fixture".to_owned())));
                    // Exercise the production census health predicate that RU used to veto.
                    assert!(next.native_comparison_is_healthy());
                    for held in [&f.0, &plain] {
                        assert!(next.residue_index_keys.contains(&local_index_key(held)));
                    }
                }
            })
        });
        assert!(
            gated_steps > 0,
            "unrelated work actually reached its census gate"
        );
        assert_eq!(
            decodes(&rows),
            0,
            "no inventory or Full decode during sibling deferral"
        );
        assert!(!rows.iter().any(|row| row["stage"] == "codex_zst_refused"));
        assert_eq!(result.unreadable_path_count, 0);
        assert_eq!(result.ownership_incomplete_file_count, 0);
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].source_session_id, unrelated);
        assert!(result.snapshots[0].input_tokens > 0);
        assert_eq!(
            next.files[&local_index_key(&plain)].last_upload_body_witness,
            plain_body
        );
        assert_eq!(next.accepted_snapshot_fingerprints, accepted);
        let evidence = next.files[&local_index_key(&f.0)].archive.as_ref().unwrap();
        assert!(matches!(
            evidence.disposition,
            ArchiveDisposition::HeaderValidated
        ));
        assert!(evidence.body_witness.is_none());
        let pending = &next.traversal.as_ref().unwrap().pending_candidates;
        for held in [&f.0, &plain] {
            assert_eq!(pending.iter().filter(|p| p.path == *held).count(), 1);
        }
        state = next;
    }
    fs::remove_file(&plain).unwrap();
    let (mut state, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
    assert_eq!(
        decodes(&rows),
        1,
        "exactly one A1 Full after sibling resolution"
    );
    assert!(!rows.iter().any(|row| row["stage"] == "codex_zst_inventory"));
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(result.snapshots[0].source_session_id, "compressed-fixture");
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
    let (_, result, rows, _) = selector_archive_pass(&f, checkpoint(&state));
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn bound_header_survives_saved_reservation_before_first_line_crash() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn inventory_bound_marker_survives_normal_save_before_full_reservation() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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

#[test]
fn sibling_inventory_at_population_cap_counts_shared_physical_keys_once() {
    let paths = (0..codex_file_join::MAX_HEADER_FILES - 2)
        .map(|n| format!("/synthetic/rollout-owner-{n:05}.jsonl.zst"))
        .collect::<BTreeSet<_>>();
    let mut inventory = codex_file_join::HeaderInventory::new(&[], &paths, None);
    inventory.first_read_archives = paths.clone();
    let shared = paths.last().unwrap().clone();
    inventory.deferred_archives.insert(shared.clone());
    inventory.defer_bound_siblings();
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
    inventory.defer_bound_siblings();
    assert_eq!(
        inventory.deferred_archives,
        BTreeSet::from([
            shared,
            deferred_peer,
            "/synthetic/rollout-owner-00001.jsonl.zst".to_owned(),
            "/synthetic/rollout-owner-00002.jsonl.zst".to_owned(),
        ])
    );
}
