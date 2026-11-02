//! Existing record-erasure fixtures, with unchanged assertions.
use super::*;

/// [format] A fresh index has no original-binding proof for either source's v3 record.
#[test]
fn fresh_index_cleanup_preserves_unproved_v3_records() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let root = crate::test_scratch::private_dir("ottto-v3-fresh-index");
        let lock = test_locks::hold(&root);
        let path = root.join("certificate.jsonl");
        std::fs::write(&path, b"{}\n").unwrap();
        let index_path = root.join("index.json");
        let namespace = Scope("fresh-index-v3".into());
        let ds = durable_source(source).unwrap();
        let key = store::key_digest(ds, "/synthetic/absent.jsonl");
        let mut disk = fixture::store(&index_path, ds);
        assert_eq!(
            disk.write_after_save(
                lock,
                1,
                0,
                vec![PendingRecord {
                    acquisition: fixture_acquisition(source),
                    binding: Binding {
                        source: ds,
                        key,
                        context: [0; 32],
                        scope: [0; 32],
                        entry: [0; 32]
                    },
                    certificate: certificate(&path, &namespace),
                    body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                }]
            )
            .unwrap()
            .written,
            1
        );
        let record_path = disk.dir().join(format!(
            "{}.rec",
            key.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let before = std::fs::read(&record_path).unwrap();
        assert_eq!(
            u16::from_le_bytes(before[8..10].try_into().unwrap()),
            store::FORMAT_V3
        );
        drop(disk);
        let cache = SharedCache::default();
        crate::snapshots::begin_durable_pass(
            &cache,
            &root,
            source,
            &index_path,
            true,
            &namespace,
            false,
            true,
        );
        assert_eq!(std::fs::read(&record_path).unwrap(), before);
        let (_, counters) = cache.durable_counters(source).unwrap();
        assert_eq!(counters.gc_records_deleted, 0);
        assert_eq!(counters.mutation_unproved, 1);
        let _ = std::fs::remove_dir_all(root);
    }
}

/// [format] OFF consent and committed-key absence erase by digest, with distinct counts and unlink retries.
#[test]
fn consent_off_post_save_purges_pl_records_and_on_does_not_force_a_read_or_write() {
    let _reset = ClearWriteFaults;
    for (source, fork) in [
        (SnapshotSource::ClaudeCode, false),
        (SnapshotSource::Pi, false),
        (SnapshotSource::Pi, true),
    ] {
        for case in [
            "consent",
            "unreadable",
            "failure",
            "no-marker",
            "key-absence",
            "key-absence-failure",
        ] {
            let orphan = case.starts_with("key-absence");
            // Committed-key absence is source-generic GC: one source covers it.
            if orphan && source != SnapshotSource::ClaudeCode {
                continue;
            }
            let failure = case.ends_with("failure");
            let root = crate::test_scratch::ScratchDir::new("skill-consent-save");
            let lock = test_locks::hold(&root);
            let ds = durable_source(source).unwrap();
            let path = root.join("synthetic.jsonl");
            if source == SnapshotSource::Pi {
                std::fs::write(&path, b"{\"type\":\"session\",\"id\":\"synthetic\"}\n").unwrap();
            } else {
                native_fixture(&path);
            }
            let scope = Scope("skill-consent".into());
            let index_path = root.join("index.json");
            let mut index = ScanIndex::default();
            if orphan {
                index.files.insert(
                    "live".into(),
                    serde_json::from_value(serde_json::json!({
                        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
                    }))
                    .unwrap(),
                );
            }
            index.save(&index_path).unwrap();
            let before_index = std::fs::read(&index_path).unwrap();
            let key = if case == "unreadable" {
                [255; 32]
            } else {
                store::key_digest(ds, "synthetic")
            };
            let dir = store::store_dir_for_index(&index_path);
            let marker = dir.with_extension("private-labels");
            if case != "no-marker" {
                let _on = crate::snapshots::RestartRestoreForTest::enabled();
                let (mut reduction, _) = native_record_of(&path, &scope, source);
                let acc = reduction.accumulator_for_test();
                acc.note_provider_skill(Some("SyntheticPurgeLabel".into()));
                if fork {
                    acc.seen_pi_usage_keys = PiLedger::from_parts(
                        BTreeMap::from([("11".repeat(32), PiUsageDedupState::default())]),
                        true,
                        Some(1),
                    );
                }
                let body = codec::encode_permitted(
                    &reduction,
                    store::RECORD_BYTES,
                    jsonl_line_cap() as u64,
                    true,
                )
                .unwrap();
                assert_eq!(codec::body_has_skill_labels(source, &body), Ok(true));
                let mut disk = DurableTailStore::new(dir.clone(), ds);
                disk.mark_private_labels(lock, key).unwrap();
                let record = PendingRecord {
                    acquisition: fixture_acquisition(source),
                    binding: Binding {
                        source: ds,
                        key,
                        context: [1; 32],
                        scope: [2; 32],
                        entry: [0; 32],
                    },
                    certificate: certificate(&path, &scope),
                    body,
                    allowlist: codec::allowlist_digest(source),
                };
                let mut records = vec![record.clone()];
                if orphan {
                    let mut live = record;
                    live.binding.key = store::key_digest(ds, "live");
                    disk.mark_private_labels(lock, live.binding.key).unwrap();
                    records.push(live);
                }
                disk.write_after_save(lock, index.generation, 0, records)
                    .unwrap();
            }
            let _off = crate::snapshots::RestartRestoreForTest::disabled();
            let cache = fixture::cache(source, &index_path, &scope, false);
            cache.durable_skill_label_permission(source, true);
            cache.durable_write_after_save(lock, source, &index);
            if case == "unreadable" {
                std::fs::remove_file(&marker).unwrap();
                std::fs::create_dir(&marker).unwrap();
                // The unknown-inventory fallback must advance past a full page
                // of retained, content-free records to reach the labelled tail.
                let empty = PendingRecord {
                    acquisition: fixture_acquisition(source),
                    binding: Binding {
                        source: ds,
                        key: [0; 32],
                        context: [1; 32],
                        scope: [2; 32],
                        entry: [3; 32],
                    },
                    certificate: certificate(&path, &scope),
                    body: codec::store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                };
                for n in 0..store::INVENTORY_BOUND {
                    let mut record = empty.clone();
                    record.binding.key[24..].copy_from_slice(&(n as u64).to_be_bytes());
                    let name: String = record
                        .binding
                        .key
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    let path = dir.join(format!("{name}.rec"));
                    std::fs::write(&path, store::tests::pinned_v1_bytes(&record, 1)).unwrap();
                    std::fs::set_permissions(
                        path,
                        std::os::unix::fs::PermissionsExt::from_mode(0o600),
                    )
                    .unwrap();
                }
            }
            if failure {
                store::test_hooks::set_before_unlink(Some(Box::new(|_| {
                    Err(std::io::Error::other("erase failed"))
                })));
            }
            let erase = || {
                if orphan {
                    cache.durable_gc(lock, source, &index).unwrap();
                } else {
                    cache.durable_skill_label_permission(source, false);
                    cache.durable_write_after_save(lock, source, &index);
                }
            };
            erase();
            store::test_hooks::set_before_unlink(None);
            if case == "unreadable" {
                erase();
            }
            if case == "no-marker" {
                // Ordinary OFF registration allocates no store or counters.
                assert!(cache.durable_counters(source).is_none());
                assert!(cache.durable.lock().unwrap().state.is_none());
                assert!(!dir.exists());
            } else {
                let (counts, stats) = cache.durable_counters(source).unwrap();
                assert_eq!(stats.rec_orphans_erased, u64::from(orphan && !failure));
                assert_eq!(
                    counts.not_persisted.get("skill_label_scanned"),
                    Some(&if case == "unreadable" {
                        store::INVENTORY_BOUND as u64 + 1
                    } else {
                        1
                    })
                );
                if failure {
                    assert_eq!(counts.not_persisted.get("skill_label_purged"), Some(&0));
                    assert_eq!(
                        counts.not_persisted.get("skill_label_purge_failed"),
                        Some(&1)
                    );
                    assert!(marker.exists());
                    erase();
                    assert_eq!(
                        cache
                            .durable_counters(source)
                            .unwrap()
                            .0
                            .not_persisted
                            .get("skill_label_purged"),
                        Some(&1)
                    );
                }
                let record_path = |key: store::Digest32| {
                    dir.join(format!(
                        "{}.rec",
                        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ))
                };
                assert!(
                    !record_path(key).exists(),
                    "the exact erased digest is absent"
                );
                let (counts, stats) = cache.durable_counters(source).unwrap();
                assert_eq!(stats.rec_orphans_erased, u64::from(orphan));
                assert!(counts
                    .summary(source, &stats)
                    .contains(&format!("rec_orphans_erased={}", u64::from(orphan))));
                if orphan {
                    assert!(
                        record_path(store::key_digest(ds, "live")).exists(),
                        "live owner survives"
                    );
                    erase();
                    assert_eq!(
                        cache.durable_counters(source).unwrap().1.rec_orphans_erased,
                        1,
                        "no repeat credit"
                    );
                    assert_eq!(std::fs::read(&index_path).unwrap(), before_index);
                    continue;
                }
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.extension().is_some_and(|ext| ext == "rec") {
                        let bytes = std::fs::read(path).unwrap();
                        assert!(!bytes
                            .windows(b"syntheticpurgelabel".len())
                            .any(|s| s == b"syntheticpurgelabel"));
                    }
                }
                assert_eq!(std::fs::read(&index_path).unwrap(), before_index);
            }
        }
    }
}

/// [regress] unknown PL inventory converges above the memo bound on every durable source.
#[test]
fn live_private_label_inventory_above_256_converges_without_purge_failure() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    for row in crate::snapshots::durable_sources::SOURCES {
        let source = row.snapshot;
        for labelled in [false, true] {
            for unknown_marker in [false, true] {
                let owner = fixture::NativeColdStore::with_scope(
                    source,
                    "pl-inventory-above-memo",
                    Scope("pl-inventory".into()),
                );
                let index_path = owner.root.join("index.json");
                let path = owner.path("synthetic");
                native_fixture(&path);
                let mut index = ScanIndex::default();
                let body = if labelled {
                    codec::store_skill_fixture_body_for_source(source)
                } else {
                    codec::store_fixture_body(source, 0, 0)
                };
                assert_eq!(
                    codec::body_has_skill_labels(source, &body).unwrap(),
                    labelled
                );
                let mut pending = Vec::new();
                let mut live = BTreeSet::new();
                for n in 0..257 {
                    let key = format!("live-{n}");
                    let digest = store::key_digest(row.source, &key);
                    live.insert(digest);
                    index.files.insert(
                        key,
                        serde_json::from_value(serde_json::json!({
                            "size_bytes":1,"modified_unix_seconds":1,
                            "source_file_fingerprint":"fp"
                        }))
                        .unwrap(),
                    );
                    pending.push(fixture::pending(
                        source,
                        Binding {
                            source: row.source,
                            key: digest,
                            context: store::context_digest(&owner.namespace.0, None),
                            scope: [2; 32],
                            entry: [0; 32],
                        },
                        certificate(&path, &owner.namespace),
                        body.clone(),
                    ));
                }
                index.save(&index_path).unwrap();
                let mut disk = fixture::store(&index_path, row.source);
                for batch in pending.chunks(store::MAX_BATCH) {
                    assert_eq!(
                        disk.write_after_save(owner.writer, index.generation, 0, batch.to_vec())
                            .unwrap()
                            .written,
                        batch.len()
                    );
                }
                // Reproduce a pre-inventory store, rather than marking literals
                // through the current writer before arranging the missing file.
                let marker =
                    store::store_dir_for_index(&index_path).with_extension("private-labels");
                assert!(!marker.exists());
                if unknown_marker {
                    std::fs::write(&marker, b"PL??").unwrap();
                    std::fs::set_permissions(
                        &marker,
                        std::os::unix::fs::PermissionsExt::from_mode(0o600),
                    )
                    .unwrap();
                }
                let cache = fixture::cache(source, &index_path, &owner.namespace, false);
                cache.durable_skill_label_permission(source, true);
                cache.durable_gc(owner.writer, source, &index).unwrap();
                let (first, _) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    first.not_persisted.get("skill_label_purge_failed"),
                    Some(&0)
                );
                assert_eq!(
                    first.not_persisted.get("skill_label_entries_visited"),
                    Some(&257)
                );
                assert!(std::fs::read(&marker).unwrap().starts_with(b"PL01"));
                assert_eq!(
                    disk.private_label_keys().unwrap(),
                    Some(if labelled {
                        live.clone()
                    } else {
                        BTreeSet::new()
                    })
                );
                cache.durable_gc(owner.writer, source, &index).unwrap();
                let (second, _) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    second.not_persisted, first.not_persisted,
                    "no second PL walk or failure"
                );
                assert!(live
                    .iter()
                    .all(|key| fixture::record_path(disk.dir(), key).exists()));
                {
                    let mut stores = cache.durable().unwrap();
                    assert_eq!(
                        stores
                            .slot(row.source)
                            .as_ref()
                            .unwrap()
                            .skill_label_purge_failures,
                        0
                    );
                }
                if labelled && !unknown_marker {
                    // A known inventory also stays bounded after expanding
                    // beyond one erase page. Missing keys are conservative
                    // positives; they consume scan work but no erase credit.
                    for n in 0..256 {
                        disk.mark_private_labels(
                            owner.writer,
                            store::key_digest(row.source, &format!("missing-{n}")),
                        )
                        .unwrap();
                    }
                    let first = disk
                        .purge_private_labels(owner.writer, |body| {
                            codec::body_has_skill_labels(source, body).unwrap_or(true)
                        })
                        .unwrap();
                    assert_eq!(first.scanned, store::INVENTORY_BOUND as u64);
                    assert_eq!(first.refused, 0);
                    assert_eq!(disk.private_label_keys().unwrap().unwrap().len(), 1);
                    let second = disk
                        .purge_private_labels(owner.writer, |body| {
                            codec::body_has_skill_labels(source, body).unwrap_or(true)
                        })
                        .unwrap();
                    assert_eq!(second.scanned, 1);
                    assert_eq!(second.refused, 0);
                    assert_eq!(first.erased + second.erased, 257);
                    assert_eq!(disk.private_label_keys().unwrap(), Some(BTreeSet::new()));
                }
            }
        }
    }
}

/// [off=main] Empty or ON-written v3 records take ordinary Full then Tail OFF;
/// only the approved off_v1 header dispatch can inspect the surviving record.
#[test]
fn off_no_record_growth_uses_ordinary_full_without_store_io() {
    // The fold is initialized before the scan driver's per-file birth setter.
    // Give that existing constructor seam the same synthetic physical birth.
    claude_request_money::e2::with_fixture_birth(1_785_542_400_000_000_000, || {
        for stored in [false, true] {
            let _off = crate::snapshots::RestartRestoreForTest::disabled();
            let root = crate::test_scratch::ScratchDir::new("off-no-record");
            let lock = test_locks::hold(&root);
            let projects = root.join("projects");
            std::fs::create_dir(&projects).unwrap();
            let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
            std::fs::write(&path, a1a_row("accepted", 100)).unwrap();
            let births = BTreeMap::from([(path.clone(), 1_785_542_400_000_000_000)]);
            let startup_on = stored.then(RestartRestoreForTest::enabled);
            let owner = crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture::default();
            let index_path = root.join("index.json");
            owner.begin_durable(SnapshotSource::ClaudeCode, &root, &index_path);
            let scan = |owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
                        index| {
                owner.scan(
                    std::slice::from_ref(&projects),
                    &root,
                    index,
                    100,
                    true,
                    &births,
                    &[],
                )
            };
            let mut initial = ScanIndex::default();
            // The real sync caller activates the current row before scanning.
            // Revision zero would correctly veto the request-owned literal.
            initial.activate_effective_upload_body_witness_revision(
                crate::snapshot_sync::effective_upload_body_witness_revision(
                    SnapshotSource::ClaudeCode,
                ),
            );
            let (mut prior, mut first, modes) = scan(&owner, initial);
            assert_eq!(modes.0, 1);
            a1a_wire(&root, &mut prior, &mut first);
            assert_eq!(first.snapshots[0].input_tokens, 100);
            prior.record_accepted_snapshot_fingerprints(
                &first
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            // ON's native settlement already wrote the record before effects;
            // the daemon still makes its post-save offer.
            prior.save(&index_path).unwrap();
            let receipt =
                owner
                    .cache
                    .durable_write_after_save(lock, SnapshotSource::ClaudeCode, &prior);
            if stored {
                receipt.unwrap();
                assert_eq!(
                    owner
                        .cache
                        .durable_counters(SnapshotSource::ClaudeCode)
                        .unwrap()
                        .1
                        .records_written,
                    1,
                    "native settlement wrote the record once before effects"
                );
            } else {
                assert!(receipt.is_none());
            }
            let dir = store::store_dir_for_index(&index_path);
            let digest = store::key_digest(DurableSource::ClaudeCode, &local_index_key(&path));
            let record_path = dir.join(format!(
                "{}.rec",
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            let written = fs::read(&record_path).ok();
            if stored {
                let bytes = written.as_ref().expect("ON wrote the native record");
                assert_eq!(&bytes[8..10], &3u16.to_le_bytes());
            } else {
                assert!(written.is_none());
            }
            drop(startup_on);
            let owner = crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture::default();
            owner.begin_durable(SnapshotSource::ClaudeCode, &root, &index_path);
            store::test_hooks::set_before_access(Some(Box::new(move |_, phase| {
                if !stored {
                    panic!("OFF store I/O");
                }
                // The separately approved off_v1 exception may inspect headers,
                // but it cannot restore or decode this ON-written v3 body.
                assert_ne!(phase, "body", "OFF never reads a restart body");
                Ok(())
            })));
            let (prior, quiet, modes) = scan(&owner, prior);
            assert!(quiet.snapshots.is_empty());
            assert_eq!(modes.0 + modes.1, 0);
            // A present ON record supplies no acquisition/hold authority OFF.
            // Cold growth is ordinary paced Full, then the RAM copy takes Tail.
            owner.evict();
            std::io::Write::write_all(
                &mut std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
                a1a_row("growth", 200).as_bytes(),
            )
            .unwrap();
            let (mut prior, mut grown, modes) = scan(&owner, prior);
            assert_eq!(modes.0, 1);
            assert_eq!(modes.1, 0);
            a1a_wire(&root, &mut prior, &mut grown);
            assert_eq!(grown.snapshots[0].input_tokens, 300);
            if let Some((counts, disk)) = owner.cache.durable_counters(SnapshotSource::ClaudeCode) {
                assert_eq!(counts.restore_attempts, 0);
                assert_eq!(disk.records_read, 0);
                assert_eq!(disk.bytes_read, 0);
                assert_eq!(disk.off_v1_invalidated, 0);
                assert_eq!(disk.mode_repaired, 0);
            }
            std::io::Write::write_all(
                &mut fs::OpenOptions::new().append(true).open(&path).unwrap(),
                a1a_row("tail", 300).as_bytes(),
            )
            .unwrap();
            let (_, tail, modes) = scan(&owner, prior);
            assert_eq!((modes.0, modes.1), (0, 1));
            assert_eq!(tail.snapshots[0].input_tokens, 600);
            store::test_hooks::set_before_access(None);
            assert_eq!(fs::read(&record_path).ok(), written);
            if !stored {
                assert!(!dir.exists());
            }
        }
    });
}

/// [format] OFF publication discards outgrown v1 bytes without reading bodies.
#[test]
fn off_publication_invalidates_outgrown_v1() {
    use std::os::unix::fs::PermissionsExt;
    claude_request_money::e2::with_fixture_birth(1_785_542_400_000_000_000, || {
        let _off = RestartRestoreForTest::disabled();
        let root = crate::test_scratch::ScratchDir::new("off-outgrown-v1");
        let _lock = test_locks::hold(&root);
        let projects = root.join("projects");
        fs::create_dir(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        fs::write(&path, a1a_row("accepted", 100)).unwrap();
        let births = BTreeMap::from([(path.clone(), 1_785_542_400_000_000_000)]);
        let owner = crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture::default();
        let index_path = root.join("index.json");
        owner.begin_durable(SnapshotSource::ClaudeCode, &root, &index_path);
        let key = store::key_digest(DurableSource::ClaudeCode, &local_index_key(&path));
        let mut binding = store::tests::binding("account", "old", ("accepted", None));
        binding.key = key;
        let mut record =
            store::tests::pending(binding, certificate(&path, &Scope("old".into())), 1);
        record.allowlist = store::parse_hex_digest(
            "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
        )
        .unwrap();
        let dir = store::store_dir_for_index(&index_path);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let record_path = dir.join(format!(
            "{}.rec",
            key.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        fs::write(&record_path, store::tests::pinned_v1_bytes(&record, 1)).unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        store::test_hooks::set_before_access(Some(Box::new(|_, phase| {
            assert_ne!(phase, "body", "OFF never acquires a restart body");
            Ok(())
        })));
        let scan = |index| {
            owner.scan(
                std::slice::from_ref(&projects),
                &root,
                index,
                100,
                true,
                &births,
                &[],
            )
        };
        let mut index = ScanIndex::default();
        index.activate_effective_upload_body_witness_revision(
            crate::snapshot_sync::effective_upload_body_witness_revision(
                SnapshotSource::ClaudeCode,
            ),
        );
        let (mut index, mut first, _) = scan(index);
        a1a_wire(&root, &mut index, &mut first);
        assert_eq!(first.snapshots[0].input_tokens, 100);
        owner.evict();
        std::io::Write::write_all(
            &mut fs::OpenOptions::new().append(true).open(&path).unwrap(),
            a1a_row("growth", 200).as_bytes(),
        )
        .unwrap();
        let (mut next, mut result, _) = scan(index);
        a1a_wire(&root, &mut next, &mut result);
        assert_eq!(result.snapshots[0].input_tokens, 300);
        let disk = owner
            .cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .1;
        assert_eq!(disk.off_v1_invalidated, 1);
        // No file remains for the historical v1 reader to open. Check
        // physical absence, rather than the current retired-pin refusal.
        assert_eq!(
            File::open(&record_path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let mut reader = DurableTailStore::new(dir, DurableSource::ClaudeCode);
        assert!(matches!(reader.read(&key), ReadOutcome::Missing));
        store::test_hooks::set_before_access(None);
    });
}
