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
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        while !inventory.step_with_archive(&CodexTitleMetadata::default(), state, Some(cache)) {}
    });
    assert!(inventory.complete);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].owner, "compressed-fixture");
    assert_eq!(cache.cursor_reserved(), 0, "no parked decoder");
    let before = rows
        .iter()
        .filter(|r| r["stage"] == "codex_zst_input")
        .count();
    assert_eq!(before, usize::from(inventory.read_bytes > 0));
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
    assert_eq!(
        row["counts"]["codex_zst_inventory_decoded_bytes"],
        header_length
    );
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
        "deferred acquisition reuses header"
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
                .inventory_archive_header(&f.candidate(), Some(&cache))
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
                .inventory_archive_header(&f.candidate(), Some(&cache))
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
    let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache).unwrap();
    let mut state = ScanIndex::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(state
            .inventory_archive_header(&f.candidate(), Some(&cache))
            .is_err());
    });
    assert_eq!(decodes(&rows), 0);
    assert!(!state.files.contains_key(&local_index_key(&f.0)));
    occupied.close();
    assert_eq!(decodes(&header_inventory(&f, &mut state, &cache)), 1);
}
