// Synthetic, normal inventory/selector fixtures. No upload, durable archive
// restoration, physical sample or archive Tail is used by these controls.
fn retained_archive_scan(
    f: &ArchiveFixture,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
) -> OwnedSourceScan {
    let mut scan = selector_scan(f, index, cache, VecDeque::from([f.candidate()]), true);
    scan.state_census_complete = true;
    scan.sidecar_census_complete = true;
    scan
}
fn decoded_archive_bytes(rows: &[Value]) -> u64 {
    rows.iter()
        .map(|r| {
            r["counts"]["codex_zst_decoded_bytes"].as_u64().unwrap_or(0)
                + r["counts"]["codex_zst_inventory_decoded_bytes"]
                    .as_u64()
                    .unwrap_or(0)
        })
        .sum()
}
fn archive_event_count(rows: &[Value], event: &str) -> u64 {
    rows.iter()
        .map(|r| r["counts"][event].as_u64().unwrap_or(0))
        .sum()
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn unsettled_retained_archive_resends_zero_decoded_bytes_and_exact_ack_settles() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(
        cache.retained_checkpoint(&key).is_some(),
        "completed decode actually admitted"
    );
    let attempt = index.files[&key].archive.as_ref().unwrap().decode_attempts;
    // Exact accepted history is not enough to call a zero-I/O resend a Full.
    index
        .accepted_snapshot_fingerprints
        .insert(first.snapshots[0].snapshot_fingerprint.clone());
    index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
    retry_due(&mut index, &key);
    let ((mut index, resent), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(&f, index, cache.clone()))
    });
    assert_eq!(
        decoded_archive_bytes(&rows),
        0,
        "actual decoder/input counters"
    );
    assert_eq!(decodes(&rows), 0, "no inventory decoder either");
    assert_eq!(archive_event_count(&rows, "codex_zst_retained_resend"), 1);
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read_retry"), 0);
    assert_eq!(archive_event_count(&rows, "archive_reupgrade_full"), 0);
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        attempt
    );
    assert_eq!(resent.snapshots.len(), 1);
    assert_eq!(
        snapshot_upload_body_witness(&first.snapshots[0]),
        snapshot_upload_body_witness(&resent.snapshots[0])
    );
    let wrong = BTreeMap::from([(
        resent.snapshots[0].snapshot_fingerprint.clone(),
        "wrong".to_owned(),
    )]);
    index.settle_archive_bodies(&wrong);
    assert!(matches!(
        index.files[&key].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Pending { .. }
    ));
    index.settle_archive_bodies(&ack_bodies(&resent));
    assert!(matches!(
        index.files[&key].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Acquired
    ));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn evicted_archive_retries_once_with_counted_bounded_decode() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(cache.retained_checkpoint(&key).is_some());
    // Exercise the cache's actual budget-eviction path, not an explicit take.
    let (_, eviction) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        cache
            .retained()
            .unwrap()
            .release_until_for(0, crate::transcript_cache::Release::CopyAdmission)
    });
    assert_eq!(eviction.copy_refusal_admission_evicted, 1);
    assert!(eviction.copy_refusal_bytes_released > 0);
    assert!(cache.retained_checkpoint(&key).is_none());
    retry_due(&mut index, &key);
    let ((index, resent), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(&f, index, cache.clone()))
    });
    assert_eq!(decodes(&rows), 1);
    assert!(decoded_archive_bytes(&rows) > 0);
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read_retry"), 1);
    assert_eq!(archive_event_count(&rows, "codex_zst_retained_resend"), 0);
    assert_eq!(resent.snapshots.len(), 1);
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        2
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn changed_archive_object_never_takes_prior_retained_copy() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(cache.retained_checkpoint(&key).is_some());
    let replacement = f.0.with_extension("replacement");
    fs::write(
        &replacement,
        zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap(),
    )
    .unwrap();
    fs::rename(replacement, &f.0).unwrap();
    let (((index, result), rows), cache_events) =
        crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            crate::local_resource_diagnostics::capture(|| {
                finish_selector(retained_archive_scan(&f, index, cache.clone()))
            })
        });
    assert_eq!(
        cache_events.take_hit, 0,
        "replacement never takes the old resident"
    );
    assert_eq!(archive_event_count(&rows, "codex_zst_retained_resend"), 0);
    assert!(decoded_archive_bytes(&rows) > 0);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        1
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn twin_without_content_equivalence_holds_archive_and_preserves_plain_body() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    for equivalent in [false, true] {
        let plain_bytes = synthetic_rollout();
        let mut archive_bytes = plain_bytes.clone();
        if !equivalent {
            archive_bytes.extend_from_slice(b"{\"type\":\"different_content\"}\n");
        }
        assert_eq!(plain_bytes == archive_bytes, equivalent);
        let f = ArchiveFixture::new(&zstd::stream::encode_all(&archive_bytes[..], 1).unwrap());
        let plain = f.0.with_extension("");
        fs::write(&plain, &plain_bytes).unwrap();
        let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
        member.size_bytes = plain_bytes.len() as u64;
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (_, control) = finish_selector(selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([member.clone()]),
            true,
        ));
        let mut index = ScanIndex::default();
        index
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
            .unwrap();
        let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
            finish_selector(selector_scan(
                &f,
                index,
                cache,
                VecDeque::from([member, f.candidate()]),
                true,
            ))
        });
        assert_eq!(decodes(&rows), 0);
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(
            snapshot_upload_body_witness(&result.snapshots[0]),
            snapshot_upload_body_witness(&control.snapshots[0])
        );
        assert!(matches!(
            index.files[&local_index_key(&f.0)]
                .archive
                .as_ref()
                .unwrap()
                .disposition,
            ArchiveDisposition::Held {
                cause: CodexZstCause::FamilyUnproven
            }
        ));
    }
}

#[test]
fn prior_plain_carrier_or_tombstone_holds_move_before_any_content_read() {
    let f = ArchiveFixture::new(b"not even a valid zstd frame: no header read allowed");
    let id = codex_protected_owner("compressed-fixture");
    for tombstone_only in [false, true] {
        let mut index = ScanIndex::default();
        let plain = local_index_key(&f.0.with_extension(""));
        if tombstone_only {
            index.codex_counting_tombstones.insert(
                id.clone(),
                codex_counting_version::CountingTombstone {
                    evidence: codex_counting_version::AckEvidence::LegacyAcked,
                    retired_in: NOW.into(),
                    created_unix_ms: None,
                },
            );
        } else {
            index.files.insert(
                plain.clone(),
                ScanIndexEntry {
                    codex_protected_owner: Some(id.clone()),
                    last_upload_body_witness: Some("accepted-body".into()),
                    ..ScanIndexEntry::default()
                },
            );
        }
        index.archive_pass.power = true;
        let before = serde_json::to_value(&index).unwrap();
        let (decision, rows) = crate::local_resource_diagnostics::capture(|| {
            index
                .classify_archive(
                    &f.candidate(),
                    &File::open(&f.0).unwrap(),
                    None,
                    None,
                    &mut sampled_scan::codex_cursor::PageBudget::default(),
                )
                .unwrap()
        });
        assert!(matches!(decision, codex_archive_catchup::Admission::Held));
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_frame_header"));
        let after = serde_json::to_value(&index).unwrap();
        assert_eq!(
            after["codex_counting_tombstones"],
            before["codex_counting_tombstones"]
        );
        assert_eq!(after["files"][&plain], before["files"][&plain]);
        assert!(matches!(
            index.files[&local_index_key(&f.0)]
                .archive
                .as_ref()
                .unwrap()
                .disposition,
            ArchiveDisposition::Held {
                cause: CodexZstCause::ArchiveEquivalenceUnproven
            }
        ));
    }
}

#[test]
fn only_pending_sibling_resolution_restores_one_a1_eligibility() {
    let f = ArchiveFixture::new(b"metadata only");
    let own = local_index_key(&f.0);
    let peer = local_index_key(
        &f.0.with_file_name("rollout-2026-10-07T00-00-00-compressed-fixture.jsonl.zst"),
    );
    let paths = BTreeSet::from([own.clone(), peer.clone()]);
    let mut inventory = codex_file_join::HeaderInventory::new(&[], &paths, None);
    inventory.first_read_archives.insert(own.clone());
    inventory.deferred_archives.insert(peer);
    inventory.classify_bound_archives();
    assert!(inventory.deferred_archives.contains(&own));
    assert!(inventory.family_held.is_empty());
    inventory.deferred_archives.clear(); // resolved to a different owner; no related peer remains
    inventory.classify_bound_archives();
    assert!(!inventory.deferred_archives.contains(&own));
    assert!(inventory.first_read_archives.contains(&own));
    assert!(
        inventory.family_held.is_empty(),
        "eligibility is not a sticky family hold"
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn plain_retained_output_and_charge_are_unchanged_beside_archive_pressure() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let plain = f.0.with_file_name("rollout-plain-peer.jsonl");
    fs::write(
        &plain,
        String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", "plain-peer"),
    )
    .unwrap();
    let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
    member.size_bytes = fs::metadata(&plain).unwrap().len();
    let mut observations = Vec::new();
    for with_archive in [false, true] {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        if with_archive {
            let (_, archive) = finish_selector(retained_archive_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
            ));
            assert_eq!(archive.snapshots.len(), 1);
            assert!(cache.retained_checkpoint(&local_index_key(&f.0)).is_some());
        }
        let pressure = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
            .unwrap()
            .unwrap();
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([member.clone()]),
            true,
        );
        scan.state_census_complete = true;
        scan.sidecar_census_complete = true;
        let (index, result) = finish_selector(scan);
        pressure.close();
        assert_eq!(result.snapshots.len(), 1);
        let checkpoint = cache
            .retained_checkpoint(&local_index_key(&plain))
            .expect("plain retained under the same pressure");
        assert_eq!(cache.cursor_reserved(), 0);
        observations.push((
            snapshot_upload_body_witness(&result.snapshots[0]),
            checkpoint.sealed_offset(),
            index.files[&local_index_key(&plain)]
                .last_upload_body_witness
                .clone(),
            cache
                .retained()
                .unwrap()
                .victims()
                .into_iter()
                .find(|(resident, _, _)| resident == &local_index_key(&plain))
                .unwrap()
                .2,
        ));
    }
    assert_eq!(observations[0], observations[1]);
}

#[test]
fn global_newest_archive_order_survives_small_pages_and_plain_fifo_is_first() {
    let f = ArchiveFixture::new(b"no content read");
    let root = f.0.parent().unwrap();
    let mut pending = VecDeque::new();
    let now = std::time::SystemTime::now();
    let mut expected = Vec::new();
    for (name, age) in [("older", 120), ("newest", 0), ("middle", 60)] {
        let path = root.join(format!("rollout-{name}.jsonl.zst"));
        fs::write(&path, b"not decoded").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now - std::time::Duration::from_secs(age))
            .unwrap();
        expected.push(path.clone());
        pending.push_back(ScanTraversalPath {
            order_modified: None,
            scan_root: root.to_owned(),
            path,
            census_member: true,
            watcher_hint: false,
        });
    }
    let plain = [
        root.join("rollout-z-plain.jsonl"),
        root.join("rollout-a-plain.jsonl"),
    ];
    for path in &plain {
        pending.push_back(ScanTraversalPath {
            order_modified: None,
            scan_root: root.to_owned(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        });
    }
    let (_, first) = crate::local_resource_diagnostics::capture(|| {
        codex_archive_catchup::order_pending(&mut pending)
    });
    assert_eq!(
        archive_event_count(&first, "codex_zst_order_metadata_checks"),
        3
    );
    assert_eq!(pending.pop_front().unwrap().path, plain[0]);
    assert_eq!(
        pending.pop_front().unwrap().path,
        plain[1],
        "plain native FIFO preserved"
    );
    for path in [&expected[1], &expected[2], &expected[0]] {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            codex_archive_catchup::order_pending(&mut pending)
        });
        assert_eq!(
            archive_event_count(&rows, "codex_zst_order_metadata_checks"),
            0,
            "metadata fact reused on later pages"
        );
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert_eq!(&pending.pop_front().unwrap().path, path);
    }
    assert!(pending.is_empty());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn only_pending_sibling_resolves_to_another_owner_then_exactly_one_a1() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&large_header_rollout()[..], 1).unwrap());
    let peer_owner = "2026-10-07T00-00-00-compressed-fixture";
    let peer =
        f.0.with_file_name(format!("rollout-{peer_owner}.jsonl.zst"));
    let peer_bytes = String::from_utf8(synthetic_rollout())
        .unwrap()
        .replace("compressed-fixture", peer_owner);
    fs::write(
        &peer,
        zstd::stream::encode_all(peer_bytes.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    let mut peer_candidate = super::super::codex_zst_refusal_tests::candidate(&peer);
    peer_candidate.size_bytes = fs::metadata(&peer).unwrap().len();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut index = ScanIndex::default();
    assert!(matches!(
        index
            .inventory_archive_header(&f.candidate(), Some(&cache), &mut funded_header_work())
            .unwrap(),
        HeaderRead::BoundReached
    ));
    let mut scan = selector_scan(
        &f,
        index,
        cache.clone(),
        VecDeque::from([f.candidate(), peer_candidate.clone()]),
        false,
    );
    let (index, deferred) = finish_selector_with(scan, |scan| {
        if scan.codex_join_prepared {
            let inventory = scan.codex_join_inventory.as_ref().unwrap();
            assert!(inventory.deferred_archives.contains(&local_index_key(&f.0)));
        }
    });
    assert!(deferred.snapshots.is_empty());
    let mut index = index;
    index
        .inventory_archive_header(&peer_candidate, Some(&cache), &mut funded_header_work())
        .unwrap();
    scan = selector_scan(
        &f,
        index,
        cache,
        VecDeque::from([f.candidate(), peer_candidate]),
        true,
    );
    // The peer remains a validated inventory member but only X is selected.
    scan.identified_candidates
        .retain(|candidate| candidate.path == f.0);
    let ((mut index, acquired), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(
        decodes(&rows),
        1,
        "the resolved peer grants exactly one A1 body decode"
    );
    assert_eq!(acquired.snapshots.len(), 1);
    assert_eq!(
        acquired.snapshots[0].source_session_id,
        "compressed-fixture"
    );
    index.settle_archive_bodies(&ack_bodies(&acquired));
    assert!(matches!(
        index.files[&local_index_key(&f.0)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::Acquired
    ));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn retained_archive_scope_mismatch_is_quiet_correction_residue_not_eviction_credit() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(cache.retained_checkpoint(&key).is_some());
    let attempt = index.files[&key].archive.as_ref().unwrap().decode_attempts;
    retry_due(&mut index, &key);
    let mut scan = retained_archive_scan(&f, index, cache.clone());
    scan.sampling.as_mut().unwrap().namespace = Scope("changed-interpretation".into());
    let ((index, held), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert!(held.snapshots.is_empty());
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        attempt
    );
    assert!(matches!(
        index.files[&key].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::CorrectionUnapplied
        }
    ));
    let ((_, held), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(&f, index, cache))
    });
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert_eq!(
        held.unreadable_path_count, 0,
        "terminal custody uses PR A scoped residue"
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn unavailable_retained_archive_scope_keeps_copy_and_defers_without_decode_credit() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(cache.retained_checkpoint(&key).is_some());
    let attempt = index.files[&key].archive.as_ref().unwrap().decode_attempts;
    retry_due(&mut index, &key);
    let mut scan = retained_archive_scan(&f, index, cache.clone());
    scan.state_census_complete = false;
    let ((index, held), rows) =
        crate::local_resource_diagnostics::capture(|| finish_selector(scan));
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read_retry"), 0);
    assert_eq!(held.unreadable_path_count, 0);
    assert!(
        cache.retained_checkpoint(&key).is_some(),
        "no take without current scope authority"
    );
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        attempt
    );
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn compressed_retained_save_never_writes_a_durable_record() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let index_path = f.0.parent().unwrap().join("retained-save-index.json");
    let writer = crate::locked_state_dir::test_locks::hold(f.0.parent().unwrap());
    let namespace = Scope("archive-ram-only".into());
    cache.durable_begin_pass(SnapshotSource::Codex, &index_path, &namespace, false);
    let (mut index, result) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(result.snapshots.len(), 1);
    let key = local_index_key(&f.0);
    assert!(cache.retained_checkpoint(&key).unwrap().is_compressed());
    // Archives must not spend the bounded selection quota for plain entries.
    assert_eq!(cache.durable_selected_count_for_test(), 0);
    cache.durable_note_selection(&key, &index.files[&key].source_file_fingerprint);
    assert_eq!(cache.durable_selected_count_for_test(), 0);
    // Force a hostile touch: the actual writer must independently fence this.
    cache.durable_touch_for_test(&key);
    index.save(&index_path).unwrap();
    cache.durable_write_after_save(writer, SnapshotSource::Codex, &index);
    cache
        .durable_gc(writer, SnapshotSource::Codex, &index)
        .unwrap();
    let (counts, disk) = cache.durable_counters(SnapshotSource::Codex).unwrap();
    assert_eq!(counts.not_persisted.get("compressed"), Some(&1));
    assert_eq!(disk.disk_records, 0);
    assert_eq!(disk.records_written, 0);
    assert_eq!(counts.gc_keep_peak, 0);
    let checkpoint = cache.retained_checkpoint(&key).unwrap();
    assert!(checkpoint.durable_certificate(0).is_none());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn plain_prepare_cannot_take_or_reuse_a_compressed_retained_entry() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = local_index_key(&f.0);
    let (_, result) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(result.snapshots.len(), 1);
    let old = {
        let resident = cache.retained().unwrap();
        let old = resident.peek(&key).unwrap();
        crate::transcript_cache::Retained {
            checkpoint: old.checkpoint.clone(),
            state: old.state.clone(),
        }
    };
    let scope = old.checkpoint.scope().clone();
    let plain = f.0.with_extension("");
    fs::write(&plain, synthetic_rollout()).unwrap();
    // Even a mismapped plain key cannot move this domain through normal take.
    cache.insert(
        local_index_key(&plain),
        super::super::sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: old.checkpoint.clone(),
            reduction: Some(old.state.clone()),
            released: None,
            unsealed: false,
        },
        0,
    );
    let (taken, events) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        cache.take(&local_index_key(&plain))
    });
    assert!(taken.is_none());
    assert_eq!(events.take_hit, 0);
    assert!(cache
        .retained_checkpoint(&local_index_key(&plain))
        .is_some());
    let mut parser = codex_parser(
        OpenedInput::Plain(BufReader::new(File::open(&plain).unwrap())),
        &plain,
    );
    let mode = parser
        .prepare_acquisition(Some(old), &scope, None, sampled_scan::now_seconds())
        .unwrap();
    assert!(matches!(
        mode,
        crate::transcript_acquisition::ReadMode::Full(_)
    ));
    assert!(cache.retained_checkpoint(&key).is_some());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn claude_retained_reuse_is_unchanged_beside_archive_pressure() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let plain =
        f.0.with_file_name("11111111-2222-4333-8444-555555555555.jsonl");
    fs::write(
        &plain,
        serde_json::to_string(&json!({
            "type":"assistant", "sessionId":"11111111-2222-4333-8444-555555555555",
            "timestamp":NOW,"requestId":"synthetic-mixed-request",
            "message":{"id":"synthetic-mixed-message","model":"fixture-model",
            "usage":{"input_tokens":100,"output_tokens":10}}
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
    let key = local_index_key(&plain);
    let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
    member.size_bytes = fs::metadata(&plain).unwrap().len();
    let mut observations = Vec::new();
    for with_archive in [false, true] {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        if with_archive {
            let (_, archive) = finish_selector(retained_archive_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
            ));
            assert_eq!(archive.snapshots.len(), 1);
            assert!(cache.retained_checkpoint(&local_index_key(&f.0)).is_some());
        }
        let pressure = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
            .unwrap()
            .unwrap();
        let mut index = ScanIndex::default();
        let mut bodies = Vec::new();
        for pass in 0..2 {
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
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
            .with_sampled_acquisition(cache.clone(), Scope("mixed-claude".into()));
            scan.identified_candidates = VecDeque::from([member.clone()]);
            scan.census.observed_index_keys.insert(key.clone());
            scan.census_unix_seconds = None;
            let ((next_index, result), events) =
                crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                    for _ in 0..1000 {
                        match scan.step(None) {
                            OwnedSourceScanStep::Pending(next) => scan = next,
                            OwnedSourceScanStep::Complete {
                                mut index,
                                mut scan,
                                ..
                            } => {
                                apply_upload_policy(
                                    SnapshotSource::ClaudeCode,
                                    &mut scan.snapshots,
                                    SnapshotUploadPolicy::default(),
                                );
                                finalize_scan_after_policy(
                                    SnapshotSource::ClaudeCode,
                                    &mut scan,
                                    &mut index,
                                );
                                return (index, scan);
                            }
                        }
                    }
                    panic!("plain Claude scan did not complete");
                });
            index = next_index;
            assert_eq!(result.snapshots.len(), 1);
            bodies.push(snapshot_upload_body_witness(&result.snapshots[0]));
            if pass == 1 {
                assert_eq!(events.take_hit, 1);
            }
        }
        assert_eq!(bodies[0], bodies[1]);
        let checkpoint = cache
            .retained_checkpoint(&key)
            .expect("Claude remains retained");
        assert!(!checkpoint.is_compressed());
        // Compare the plain entry's own frozen charge, excluding the distinct
        // archive resident and live decoder claim.
        let own_charge = cache
            .retained()
            .unwrap()
            .victims()
            .into_iter()
            .find(|(resident, _, _)| resident == &key)
            .unwrap()
            .2;
        observations.push((bodies, checkpoint.sealed_offset(), own_charge));
        assert!(own_charge > 0);
        pressure.close();
        assert_eq!(cache.cursor_reserved(), 0);
    }
    assert_eq!(observations[0], observations[1]);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn custody_precedes_retained_take_and_growing_archive_keeps_its_copy() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        cache.clone(),
    ));
    assert_eq!(first.snapshots.len(), 1);
    assert!(cache.retained_checkpoint(&key).is_some());
    retry_due(&mut index, &key);
    index.hold_compressed(
        &f.0,
        codex_session_id_candidates_from_path(&f.0)
            .into_iter()
            .collect(),
        CodexZstCause::ParentLedgerUnbound,
    );
    for grow in [false, true] {
        if grow {
            File::options()
                .append(true)
                .open(&f.0)
                .unwrap()
                .write_all(&zstd::stream::encode_all(&b"\n"[..], 1).unwrap())
                .unwrap();
        }
        let ((next, result), rows) = crate::local_resource_diagnostics::capture(|| {
            finish_selector(retained_archive_scan(&f, index, cache.clone()))
        });
        assert!(result.snapshots.is_empty());
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert_eq!(archive_event_count(&rows, "codex_zst_retained_resend"), 0);
        assert!(
            cache.retained_checkpoint(&key).is_some(),
            "custody precedes take even after growth"
        );
        assert!(next.files[&key].codex_compressed_hold.is_some());
        index = next;
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn new_archive_a1_with_exact_accepted_history_counts_reupgrade_full() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let (mut index, first) = finish_selector(retained_archive_scan(
        &f,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
    ));
    assert_eq!(first.snapshots.len(), 1);
    index
        .accepted_snapshot_fingerprints
        .insert(first.snapshots[0].snapshot_fingerprint.clone());
    index.files.remove(&key);
    index.file_snapshot_fingerprints.remove(&key);
    // The historical-runtime fixture proves the actual old census/save loss;
    // here the production funded A1 and exact-history counter are exercised.
    let ((mut index, upgraded), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(
            &f,
            index,
            Arc::new(sampled_scan::SharedCache::default()),
        ))
    });
    assert_eq!(archive_event_count(&rows, "archive_reupgrade_full"), 1);
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read_retry"), 0);
    assert!(decoded_archive_bytes(&rows) > 0);
    assert_eq!(
        index.files[&key].archive.as_ref().unwrap().decode_attempts,
        1
    );
    assert!(index.files[&key].codex_protected_owner.is_none());
    index.settle_archive_bodies(&ack_bodies(&upgraded));
    let ((_, quiet), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(
            &f,
            checkpoint(&index),
            Arc::new(sampled_scan::SharedCache::default()),
        ))
    });
    assert!(quiet.snapshots.is_empty());
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert_eq!(archive_event_count(&rows, "archive_reupgrade_full"), 0);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn activated_funded_decoder_uses_one_gib_and_unknown_size_probe_refuses() {
    let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    assert_eq!(FIRST_READ_DECODED_LIMIT, 1 << 30);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut input = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .unwrap()
        .unwrap();
    let OpenedInput::Compressed(reader, _) = &mut input else {
        panic!("funded archive")
    };
    assert_eq!(reader.get_ref().remaining, FIRST_READ_DECODED_LIMIT);
    // Same production over-limit branch with a tiny synthetic limit; no GiB allocation.
    reader.get_mut().remaining = 8;
    assert!(input.read_to_end(&mut Vec::new()).is_err());
    input.close();
}
