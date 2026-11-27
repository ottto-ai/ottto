#[test]
fn item_specific_422_isolates_poison_and_checkpoints_valid_siblings() {
    let poison_scope = &unique_poison_scope();
    let items = test_fingerprints(25);
    let poison = items[19].clone();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let uploaded = Arc::new(Mutex::new(Vec::new()));
    let uploaded_capture = uploaded.clone();

    let result = upload_resumable_batches(
        &items, poison_scope, &mut progress, &mut accepted, String::as_str,
        move |batch| {
            if let Some(index) = batch.iter().position(|item| *item == &poison) {
                return Err(anyhow::Error::new(BatchRejected::from_response(422,
                    serde_json::json!({"errors":[{"loc":["body","snapshots",index,"compaction_timestamps"]}]}).to_string().as_bytes(), batch.len())));
            }
            uploaded_capture.lock().expect("capture lock").extend(batch.iter().copied().cloned());
            Ok(accept_fingerprints(batch))
        }, |_| Ok(()),
    ).expect("indexed rejection holds only the refused entity");
    assert_eq!(
        result,
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 0,
            identity_503: 0
        }
    );
    assert_eq!(accepted, 24);
    assert_eq!(progress.accepted_fingerprints.len(), 24);
    // A retryable rejection now has durable custody rather than retrying every cycle.
    assert_eq!(progress.quarantined_fingerprints.len(), 1);
    assert!(!progress.accepted_fingerprints.contains(&items[19]));
    let uploaded = uploaded.lock().expect("capture lock");
    assert_eq!(uploaded.len(), 24);
    assert!(uploaded.iter().all(|item| item != &items[19]));
    assert_eq!(uploaded.iter().collect::<BTreeSet<_>>().len(), 24);
    drop(uploaded);
    let mut retry_accepted = 0;
    upload_resumable_batches(
        &items,
        poison_scope,
        &mut progress,
        &mut retry_accepted,
        String::as_str,
        |_| panic!("held body must wait for its deadline"),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(retry_accepted, 0);
}

#[test]
fn unlocated_validation_failure_keeps_whole_batch_pending() {
    let items = test_fingerprints(75);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut attempts = 0;
    let error = upload_resumable_batches(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            Err(anyhow::Error::new(BatchRejected::from_response(
                422,
                br#"{"errors":[{"loc":["body","snapshots",0,"field"]},{"loc":["body","other"]}]}"#
                    .as_slice(),
                batch.len(),
            )))
        },
        |_| Ok(()),
    )
    .expect_err("mixed locations cannot isolate entities");
    assert!(error
        .downcast_ref::<BatchRejected>()
        .unwrap()
        .snapshot_indexes
        .is_none());
    assert_eq!(attempts, 1);
    assert_eq!(accepted, 0);
    assert!(progress.quarantined_fingerprints.is_empty());
}

#[test]
fn held_validation_rejection_prunes_old_accepted_revisions_from_progress() {
    let poison_scope = &unique_poison_scope();
    let poison = format!("{:064x}", 9000);
    let mut progress = test_upload_progress();
    let scratch = crate::test_scratch::ScratchDir::new("poison-revision-retirement");
    let index_path = scratch.join("index.json");
    let progress_path = scratch.join("progress.json");
    let mut index = ScanIndex::default();
    index.save_fixture(&index_path).unwrap();
    progress.save_fixture(&progress_path).unwrap();

    for revision in 0..20 {
        let valid = format!("{:064x}", 10_000 + revision);
        // A committed replacement of this file's exact entity incidence
        // retires the prior revision. Page omission itself proves nothing.
        let previous = ScanIndex::load(&index_path).unwrap();
        index
            .file_snapshot_fingerprints
            .insert("changing.jsonl".into(), BTreeSet::from([valid.clone()]));
        let retired = progress.retired_ack_candidates(&previous, &index);
        index.save_fixture(&index_path).unwrap();
        index = ScanIndex::load(&index_path).unwrap();
        progress.retire_acks_after_index_save(&index, &retired, &BTreeSet::new());
        progress.save_fixture(&progress_path).unwrap();
        let items = vec![valid.clone(), poison.clone()];
        let mut accepted = 0;
        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                if batch.contains(&&poison) {
                    let index = batch.iter().position(|item| *item == &poison).unwrap();
                    Err(anyhow::Error::new(BatchRejected::from_response(
                        422,
                        serde_json::json!({"errors":[{"loc":["body","snapshots",index,"field"]}]})
                            .to_string()
                            .as_bytes(),
                        batch.len(),
                    )))
                } else {
                    Ok(accept_fingerprints(batch))
                }
            },
            |state| state.save_fixture(&progress_path),
        )
        .expect("held validation rejection preserves accepted siblings");

        progress = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        assert!(matches!(
            result,
            ResumableUploadResult::Deferred {
                count: 1,
                isolated: 0,
                identity_503: 0
            } | ResumableUploadResult::Completed
        ));
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        assert_eq!(accepted, 1);
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        assert!(progress.contains(&valid));
    }
}

#[test]
fn snapshot_upload_progress_path_stays_policy_scoped() {
    let index =
        Path::new("/support/snapshots/codex-scan-index-attribution-key-attribution-labels.json");

    assert_eq!(
        snapshot_upload_progress_path(index),
        PathBuf::from(
            "/support/snapshots/codex-scan-index-attribution-key-attribution-labels-upload-progress.json"
        )
    );
}

#[test]
fn snapshot_scan_index_is_relay_destination_scoped() {
    let policy_index = Path::new("/support/snapshots/codex-scan-index-attribution-labels.json");
    let destination = format!("{:064x}", 42);

    assert_eq!(
        snapshot_destination_scoped_index_path(policy_index, &destination),
        PathBuf::from(format!(
            "/support/snapshots/destinations/{destination}/codex-scan-index-attribution-labels.json"
        ))
    );
}

#[test]
fn snapshot_upload_progress_resets_when_relay_device_changes() {
    let root = test_dir("snapshot-upload-progress-destination-switch");
    let path = root.join("codex-scan-index-upload-progress.json");
    let device_a = LocalDeviceBinding {
        device_id: "relay-device-a".to_string(),
        machine_id: Some("machine-shared".to_string()),
        sources: vec!["codex".to_string()],
    };
    let device_b = LocalDeviceBinding {
        // Backend may preserve the device row while rotating its account
        // credential, so the secret participates in destination identity.
        device_id: "relay-device-a".to_string(),
        machine_id: Some("machine-shared".to_string()),
        sources: vec!["codex".to_string()],
    };
    let namespace_a = snapshot_upload_destination_namespace(&device_a, "secret-a");
    let namespace_b = snapshot_upload_destination_namespace(&device_b, "secret-b");
    assert_ne!(namespace_a, namespace_b);

    let accepted = format!("{:064x}", 7);
    let mut progress = SnapshotUploadProgress::new(namespace_a, test_quarantine_witness());
    progress.record([accepted.as_str()]);
    progress
        .save_fixture(&path)
        .expect("save account A progress");

    let rebuilt = SnapshotUploadProgress::load(&path, &namespace_b, test_quarantine_witness())
        .expect("mismatched ledger is quarantined and rebuilt");
    assert_eq!(rebuilt.destination_namespace_hash, namespace_b);
    assert!(
        !path.exists(),
        "invalid live ledger moved out of the active path"
    );
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn snapshot_upload_progress_compare_and_swap_rejects_stale_writer() {
    let root = test_dir("snapshot-upload-progress-cas");
    let path = root.join("progress-v2.json");
    let namespace = format!("{:064x}", 42);
    let mut initial = SnapshotUploadProgress::new(namespace, test_quarantine_witness());
    initial.save_fixture(&path).expect("initial progress");

    let mut stale = SnapshotUploadProgress::load(
        &path,
        &initial.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("stale view");
    let mut winner = SnapshotUploadProgress::load(
        &path,
        &initial.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("winner view");
    winner.record(["a".repeat(64).as_str()]);
    winner.save_fixture(&path).expect("winner save");
    stale.record(["b".repeat(64).as_str()]);
    stale
        .save_fixture(&path)
        .expect_err("stale upload progress must not clobber winner");
    let observed = SnapshotUploadProgress::load(
        &path,
        &initial.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("load winner");
    assert!(observed.accepted_fingerprints.contains(&"a".repeat(64)));
    assert!(!observed.accepted_fingerprints.contains(&"b".repeat(64)));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn snapshot_upload_progress_stale_clear_cannot_delete_winner() {
    let root = test_dir("snapshot-upload-progress-clear-cas");
    let path = root.join("progress-v2.json");
    let namespace = format!("{:064x}", 43);
    let mut initial = SnapshotUploadProgress::new(namespace, test_quarantine_witness());
    initial.save_fixture(&path).expect("initial progress");
    let stale = SnapshotUploadProgress::load(
        &path,
        &initial.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("stale view");
    let mut winner = stale.clone();
    winner.record(["c".repeat(64).as_str()]);
    winner
        .save_fixture(&path)
        .expect("winner advances generation");

    stale
        .clear(&path)
        .expect_err("stale clear cannot delete a newer checkpoint");
    assert!(path.exists());
    winner.clear(&path).expect("winning generation clears");
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

/// [money] The narrow CAS decode refuses a changed schema or namespace,
/// leaving the file and generation unchanged, and merges quarantine claims
/// only into records it holds, as from a full decode (disk-only stays out).
#[test]
fn snapshot_upload_progress_cas_stamps_and_quarantine_overlap() {
    let root = test_dir("snapshot-upload-progress-cas-stamps");
    let path = root.join("progress-v2.json");
    let namespace = format!("{:064x}", 44);
    let mut progress = SnapshotUploadProgress::new(namespace, test_quarantine_witness());
    progress.quarantine_body(&"a".repeat(64), &"b".repeat(64));
    progress.save_fixture(&path).expect("initial progress");
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let generation = progress.generation;
    for (field, value) in [
        (
            "schema_version",
            serde_json::json!(SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION - 1),
        ),
        (
            "destination_namespace_hash",
            serde_json::json!("d".repeat(64)),
        ),
    ] {
        let mut disk = saved.clone();
        disk[field] = value;
        let bytes = serde_json::to_vec_pretty(&disk).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        progress.save_fixture(&path).expect_err(field);
        assert_eq!(progress.generation, generation, "{field}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{field}");
    }
    let mut disk = saved;
    let records = &mut disk["quarantined_fingerprints"];
    let contract = records["a".repeat(64)]["reconstruction_contract"]
        .as_u64()
        .unwrap();
    records["a".repeat(64)]["reconstruction_contract"] = serde_json::json!(contract + 1);
    records["a".repeat(64)]["contract_retry_claims"] = serde_json::json!(1);
    let disk_only = records["a".repeat(64)].clone();
    records["c".repeat(64)] = disk_only;
    let bytes = serde_json::to_vec_pretty(&disk).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let full: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    let mut expected = progress.quarantined_fingerprints.clone();
    assert!(crate::snapshots::terminal_contract_retry::merge_maps(
        &mut expected,
        &full.quarantined_fingerprints
    ));
    progress.save_fixture(&path).expect("same stamps save");
    let written: SnapshotUploadProgress =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(written.quarantined_fingerprints, expected);
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn snapshot_upload_progress_quarantines_truncated_state_and_rebuilds() {
    let root = test_dir("snapshot-upload-progress-corrupt");
    let path = root.join("progress-v2.json");
    std::fs::create_dir_all(&root).expect("create progress root");
    std::fs::write(&path, b"{\"schema_version\":2").expect("write truncated progress");
    let namespace = format!("{:064x}", 44);
    let rebuilt = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness())
        .expect("truncated progress is quarantined");
    assert_eq!(
        rebuilt,
        SnapshotUploadProgress::new(namespace, test_quarantine_witness())
    );
    assert!(!path.exists());
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn snapshot_upload_progress_quarantines_unbounded_retry_deadline() {
    let root = test_dir("snapshot-upload-progress-unbounded-retry");
    let path = root.join("progress-v2.json");
    let namespace = format!("{:064x}", 46);
    let fingerprint = "f".repeat(64);
    let mut corrupt = SnapshotUploadProgress::new(namespace.clone(), test_quarantine_witness());
    corrupt.quarantined_fingerprints.insert(
        fingerprint,
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: test_quarantine_witness(),
            retry_after_unix_seconds: u64::MAX,
            upload_body_witness: None,
            failed_reconstruction_count: 1,
            disposition: SnapshotQuarantineDisposition::RetryPending,
        },
    );
    corrupt
        .save_fixture(&path)
        .expect("persist far-future deadline");

    let rebuilt = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness())
        .expect("far-future deadline is quarantined rather than fencing forever");
    assert!(rebuilt.quarantined_fingerprints.is_empty());
    assert!(!path.exists());
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

/// [regress] Version 0.1.206 moved 9/9 unchanged-body deadlines by 21,444s.
#[test]
fn version_only_quarantine_witness_change_keeps_retry_after() {
    let root = test_dir("snapshot-upload-progress-quarantine-upgrade");
    let path = root.join("progress-v2.json");
    let namespace = format!("{:064x}", 45);
    let fingerprint = "d".repeat(64);
    let old_witness = test_quarantine_witness();
    let mut progress = SnapshotUploadProgress::new(namespace.clone(), old_witness);
    progress.quarantine([fingerprint.as_str()]);
    let original = progress.quarantined_fingerprints[&fingerprint].clone();
    progress.save_fixture(&path).expect("persist quarantine");

    let mut upgraded = test_quarantine_witness();
    upgraded.collector_version.push_str("-upgrade");
    upgraded.parser_version.push_str("-upgrade");
    let mut repaired = SnapshotUploadProgress::load(&path, &namespace, upgraded.clone())
        .expect("load after version-only upgrade");
    repaired.prepare_quarantine_retries(&BTreeMap::new());
    assert!(repaired.contains(&fingerprint));
    assert!(repaired.active_quarantine_retries.is_empty());
    let retained = &repaired.quarantined_fingerprints[&fingerprint];
    assert_eq!(
        retained.retry_after_unix_seconds,
        original.retry_after_unix_seconds
    );
    assert_eq!(retained.upload_body_witness, original.upload_body_witness);
    assert_eq!(
        retained.failed_reconstruction_count,
        original.failed_reconstruction_count
    );
    repaired.save_fixture(&path).unwrap();
    repaired = SnapshotUploadProgress::load(&path, &namespace, upgraded.clone()).unwrap();
    assert!(!repaired.prepare_quarantine_retries(&BTreeMap::new()));
    assert_eq!(
        repaired.quarantined_fingerprints[&fingerprint].retry_after_unix_seconds,
        original.retry_after_unix_seconds
    );

    // A real contract correction retains the existing immediate retry.
    upgraded.contract.push_str("-repair");
    repaired = SnapshotUploadProgress::load(&path, &namespace, upgraded).unwrap();
    repaired.prepare_quarantine_retries(&BTreeMap::new());
    assert!(!repaired.contains(&fingerprint));
    assert!(repaired.active_quarantine_retries.contains(&fingerprint));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn unchanged_quarantine_waits_without_hot_loop_then_retries_backend_recovery() {
    let fingerprint = "e".repeat(64);
    let mut progress = test_upload_progress();
    progress.quarantine([fingerprint.as_str()]);
    let mut accepted = 0;
    let mut attempts = 0;
    upload_resumable_batches(
        std::slice::from_ref(&fingerprint),
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            Ok(accept_fingerprints(batch))
        },
        |_| Ok(()),
    )
    .expect("non-due quarantine is skipped");
    assert_eq!(attempts, 0);
    assert_eq!(accepted, 0);

    let mut failed = progress.clone();
    assert!(failed.retain_current_quarantines(&BTreeSet::new(), &ScanIndex::default()));
    let mut index = ScanIndex::default();
    index.file_snapshot_fingerprints.insert(
        "session.jsonl".into(),
        BTreeSet::from([fingerprint.clone()]),
    );
    assert!(failed.retain_current_quarantines(&index.current_snapshot_fingerprints(), &index));
    failed.prepare_quarantine_retries(&BTreeMap::new());
    failed.quarantine_body(&fingerprint, &fingerprint);
    let record = failed.quarantined_fingerprints[&fingerprint].clone();
    assert_eq!(record.failed_reconstruction_count, 2);
    assert!(record.retry_after_unix_seconds > current_unix_seconds());
    assert!(!failed.retain_current_quarantines(&index.current_snapshot_fingerprints(), &index));
    assert!(!failed.prepare_quarantine_retries(&BTreeMap::new()));
    upload_resumable_batches(
        std::slice::from_ref(&fingerprint),
        &unique_poison_scope(),
        &mut failed,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            Ok(accept_fingerprints(batch))
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!((attempts, accepted), (0, 0));

    progress
        .quarantined_fingerprints
        .get_mut(&fingerprint)
        .unwrap()
        .retry_after_unix_seconds = 0;
    progress.prepare_quarantine_retries(&BTreeMap::new());
    upload_resumable_batches(
        std::slice::from_ref(&fingerprint),
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            Ok(accept_fingerprints(batch))
        },
        |_| Ok(()),
    )
    .expect("backend-only recovery is retried after the bounded delay");
    assert_eq!(attempts, 1);
    assert_eq!(accepted, 1);
}

/// [regress] Observed live: four due quarantines had already left census pending.
/// Also retains the live 0.1.121 strand: the quarantine deadline became
/// due after a settled sibling had already advanced the shared backend
/// head, but an independently backed-off terminal-unhealthy traversal
/// yielded no upload item. A vacuous completed upload must not let the
/// disposable ledger erase the index-owned retry obligation.
#[test]
fn due_not_pending_quarantine_resends_once_and_paces_local_holds() {
    let root = test_dir("due-quarantine-terminal-unhealthy-empty-scan");
    let session_path = root.join("session.jsonl");
    std::fs::create_dir_all(&root).expect("create retry fixture root");
    std::fs::write(
        &session_path,
        concat!(
            "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-08-31T08:00:00Z\"}\n",
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1788163201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
        ),
    )
    .expect("write manifest-present source revision");
    let duplicate_path = root.join("z-copy.jsonl");
    std::fs::copy(&session_path, &duplicate_path).unwrap();
    let mut index = ScanIndex::default();
    let mut first_scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        &mut index,
        "2026-09-01T02:00:00Z",
        crate::snapshots::BACKFILL_WINDOW_DAYS,
    )
    .expect("seed manifest-present revision");
    crate::snapshots::finalize_scan_after_policy(SnapshotSource::Pi, &mut first_scan, &mut index);
    let fingerprint = first_scan.snapshots[0].snapshot_fingerprint.clone();
    assert_eq!(index.file_snapshot_fingerprints.len(), 2);
    assert!(index
        .file_snapshot_fingerprints
        .values()
        .all(|fingerprints| { fingerprints == &BTreeSet::from([fingerprint.clone()]) }));
    let mut quarantine = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Pi);
    quarantine.retry_after_unix_seconds = 0;
    quarantine.upload_body_witness = Some(fingerprint.clone());
    index
        .quarantined_snapshot_fingerprints
        .insert(fingerprint.clone(), quarantine);
    let collected_at = "2026-09-01T03:27:03Z";
    index.install_terminal_unhealthy_traversal_for_retry_test(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        crate::snapshots::BACKFILL_WINDOW_DAYS,
        u64::try_from(
            OffsetDateTime::parse(collected_at, &time::format_description::well_known::Rfc3339)
                .expect("fixture time")
                .unix_timestamp(),
        )
        .expect("positive fixture time")
        .saturating_add(60 * 60),
    );

    let mut progress = SnapshotUploadProgress::new(
        format!("{:064x}", 42),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    );
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    let failures = progress.quarantined_fingerprints[&fingerprint].failed_reconstruction_count;
    let (scan, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
        )
        .expect("independently backed-off terminal traversal returns a scan receipt")
    });
    assert!(
        reads.is_empty(),
        "source hold must not acquire the transcript"
    );
    assert!(scan.snapshots.is_empty());
    assert!(progress.defer_held_quarantine_retries(&scan.snapshots, &index, SnapshotSource::Pi));
    assert!(!scan.census_complete);
    let mut accepted = 0;
    let mut upload_calls = 0;
    let result = upload_resumable_batches(
        &scan.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |_| {
            upload_calls += 1;
            panic!("held body must not be uploaded")
        },
        |_| Ok(()),
    )
    .expect("an empty bounded scan leaves its prior quarantine owed");
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!((upload_calls, accepted), (0, 0));

    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    let retained = index
        .quarantined_snapshot_fingerprints
        .get(&fingerprint)
        .expect("an empty scan must leave the retry armed");
    assert!(retained.retry_after_unix_seconds > current_unix_seconds());
    assert!(snapshot_quarantine_deadline_is_bounded(retained));
    assert_eq!(retained.failed_reconstruction_count, failures);
    // Resume the retained traversal with this file already observed and
    // absent from its candidate queue, just like the four quarantines observed live.
    let mut state = serde_json::to_value(&index).unwrap();
    state["traversal"]["scan_roots"] = serde_json::json!([root]);
    state["traversal"]["observed_index_keys"] = serde_json::json!([session_path, duplicate_path]);
    assert_eq!(
        state["traversal"]["pending_candidates"],
        serde_json::json!([])
    );
    index = serde_json::from_value(state).unwrap();
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    index.save_fixture(&index_path).unwrap();
    progress.save_fixture(&progress_path).unwrap();
    progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .unwrap();
    assert!(!progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    // Save progress first, then crash before the terminal index is updated.
    let terminal = index
        .quarantined_snapshot_fingerprints
        .get_mut(&fingerprint)
        .unwrap();
    terminal.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
    terminal.retry_after_unix_seconds = 0;
    progress
        .quarantined_fingerprints
        .insert(fingerprint.clone(), terminal.clone());
    index.save_fixture(&index_path).unwrap();
    assert!(progress.retain_current_quarantines(&index.current_snapshot_fingerprints(), &index));
    progress.save_fixture(&progress_path).unwrap();
    index = ScanIndex::load(&index_path).unwrap();
    progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .unwrap();
    assert_eq!(
        index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::SupersededTerminal
    );
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    let hints = save_terminal_contract_claims_for_scan(&mut index, &progress, &index_path).unwrap();
    assert_eq!(hints, vec![session_path.clone()]);
    assert_eq!(
        ScanIndex::load(&index_path)
            .unwrap()
            .quarantined_snapshot_fingerprints[&fingerprint],
        progress.quarantined_fingerprints[&fingerprint]
    );
    let (pending, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            0,
            &hints,
        )
        .unwrap()
    });
    assert!(reads.is_empty());
    assert!(pending.snapshots.is_empty());
    assert!(index.quarantine_retry_is_queued(&fingerprint));
    assert!(!progress.defer_held_quarantine_retries(
        &pending.snapshots,
        &index,
        SnapshotSource::Pi
    ));
    assert_eq!(
        progress.quarantined_fingerprints[&fingerprint].retry_after_unix_seconds,
        0
    );
    let (mut retry, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            1,
            &hints,
        )
        .unwrap()
    });
    crate::snapshots::finalize_scan_after_policy(SnapshotSource::Pi, &mut retry, &mut index);
    assert_eq!(reads.values().sum::<usize>(), 1);
    assert_eq!(reads.get(&session_path), Some(&1));
    assert_eq!(retry.snapshots.len(), 1);
    assert_eq!(retry.snapshots[0].snapshot_fingerprint, fingerprint);
    assert!(!progress.defer_held_quarantine_retries(&retry.snapshots, &index, SnapshotSource::Pi));
    // The existing DNS incident class fails before a batch can be sent.
    let unsent = upload_resumable_batches(
        &retry.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |_| {
            Err(anyhow::Error::new(UploadFailureDiagnostics::for_test(
                "local snapshot upload",
                "snapshot_batch",
                "transport_dns",
                true,
                false,
            )))
        },
        |state| state.save_fixture(&progress_path),
    );
    assert!(unsent.is_err());
    assert_eq!(
        progress.quarantined_fingerprints[&fingerprint].retry_after_unix_seconds,
        0
    );
    // An invalid ACK still proves the retry reached the backend.
    let replied = upload_resumable_batches(
        &retry.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |_| {
            let mut response = entity_ack_response(1);
            response.entity_ack_contract = None;
            response.require_entity_ack_contract()?;
            Ok(response)
        },
        |state| state.save_fixture(&progress_path),
    );
    assert!(replied
        .unwrap_err()
        .downcast_ref::<SnapshotAckRejected>()
        .is_some());
    let paced = &progress.quarantined_fingerprints[&fingerprint];
    assert!(paced.retry_after_unix_seconds > current_unix_seconds());
    assert!(snapshot_quarantine_deadline_is_bounded(paced));
    assert_eq!(paced.failed_reconstruction_count, failures);
    assert_eq!(accepted, 0);
    assert!(!progress.accepted_fingerprints.contains(&fingerprint));
    progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .unwrap();
    assert!(!progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    // The next ordinary deadline becomes due; the retained body sends once.
    progress
        .quarantined_fingerprints
        .get_mut(&fingerprint)
        .unwrap()
        .retry_after_unix_seconds = 0;
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    upload_resumable_batches(
        &retry.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |batch| {
            upload_calls += 1;
            assert_eq!(batch.len(), 1);
            claude_money_e2_pipeline_tests::ack(batch)
        },
        |state| state.save_fixture(&progress_path),
    )
    .unwrap();
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    assert!(!progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    let hints = save_terminal_contract_claims_for_scan(&mut index, &progress, &index_path).unwrap();
    assert!(hints.is_empty());
    let (quiet, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            1,
            &hints,
        )
        .unwrap()
    });
    assert!(reads.is_empty());
    assert!(quiet.snapshots.is_empty());
    assert_eq!((upload_calls, accepted), (1, 1));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn due_retry_uploads_only_the_quarantined_revision_after_its_sibling_settled() {
    let settled_sibling = "d".repeat(64);
    let retry = "e".repeat(64);
    let mut progress = test_upload_progress();
    progress.record([settled_sibling.as_str()]);
    progress.quarantine([retry.as_str()]);
    progress
        .quarantined_fingerprints
        .get_mut(&retry)
        .expect("retry quarantine")
        .retry_after_unix_seconds = 0;
    assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));

    let mut accepted = 0;
    let mut uploaded = Vec::new();
    let result = upload_resumable_batches(
        &[settled_sibling.clone(), retry.clone()],
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            uploaded.push(batch.iter().copied().cloned().collect::<Vec<_>>());
            Ok(entity_ack_batch(batch, &[], &[]))
        },
        |_| Ok(()),
    )
    .expect("the later revision retries after its sibling settled");

    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(uploaded, vec![vec![retry.clone()]]);
    assert_eq!(accepted, 1);
    assert!(progress.accepted_fingerprints.contains(&settled_sibling));
    assert!(progress.accepted_fingerprints.contains(&retry));
    assert!(progress.quarantined_fingerprints.is_empty());
}

#[test]
// A local preflight quarantine records Poisoned in the shared client_report counters.
#[serial(client_report)]
fn admission_native_hourly_bodies_recover_without_losing_usage_or_siblings() {
    // Parse-stage native hours: gate on, e2::finish_page emits the hours.

    let root = test_dir("admission-native-hourly");
    std::fs::create_dir_all(&root).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let start = OffsetDateTime::parse("2026-07-01T00:00:00Z", &Rfc3339).unwrap();
    let mut items = Vec::new();
    for hours in [1, 1000, 1500] {
        let path = root.join(format!("synthetic-{hours}.jsonl"));
        let mut lines = String::new();
        for n in 0..hours {
            let timestamp = (start + TimeDuration::hours(n)).format(&Rfc3339).unwrap();
            let row = serde_json::json!({
                "timestamp": timestamp, "type": "assistant",
                "sessionId": format!("synthetic-{hours}"),
                "requestId": format!("request-{hours}-{n}"),
                "message": {"id": format!("message-{hours}-{n}"), "role": "assistant",
                    "model": "claude-opus-4-8", "content": [],
                    "usage": {"input_tokens": 100, "output_tokens": 10,
                        "cache_read_input_tokens": 50, "cache_creation_input_tokens": 20}}
            });
            lines.push_str(&row.to_string());
            lines.push('\n');
        }
        std::fs::write(&path, lines).unwrap();
        let mut parsed = crate::snapshots::e2_pipeline_scan_fixture::parse_ordinary(
            &path,
            "2026-10-05T00:00:00Z",
            format!("{hours:064x}"),
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        let item = parsed.pop().unwrap();
        assert_eq!(item.request_count, hours as u64);
        assert_eq!(item.usage_buckets.len(), hours as usize);
        assert_eq!(item.input_tokens, hours as u64 * 100);
        assert_eq!(item.output_tokens, hours as u64 * 10);
        assert_eq!(item.cache_read_tokens, hours as u64 * 50);
        assert_eq!(item.cache_creation_5m_tokens, hours as u64 * 20);
        items.push(item);
    }
    fn request<T>(source: SnapshotSource, snapshots: Vec<T>) -> SnapshotBatchRequest<T> {
        snapshot_batch_request(
            source,
            "otm_synthetic",
            snapshots,
            SnapshotUploadPolicy::default(),
            crate::client_report::ClientReport::empty(),
        )
    }
    let large = &items[1];
    let oversized = &items[2];
    let wire = serde_json::to_value(request(source, items.iter().collect::<Vec<_>>())).unwrap();
    let large_bytes = serde_json::to_vec(&wire["snapshots"][1]).unwrap().len();
    assert!(large_bytes > 128 * 1024 && large_bytes <= 640 * 1024);
    assert!(serde_json::to_vec(&wire["snapshots"][2]).unwrap().len() > 640 * 1024);
    validate_snapshot_batch_request(&request(source, vec![large])).unwrap();
    let mut progress = test_upload_progress();
    progress
        .active_quarantine_witness
        .as_mut()
        .unwrap()
        .item_wire_byte_limit = 128 * 1024;
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(
            &large.snapshot_fingerprint,
            &snapshot_upload_body_witness(large),
        );
    }
    let mut index =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
    index.file_snapshot_fingerprints.insert(
        "synthetic-large.jsonl".into(),
        BTreeSet::from([large.snapshot_fingerprint.clone()]),
    );
    index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
    assert!(index.prepare_snapshot_admission_reoffer(50));
    index.save_fixture(&root.join("index.json")).unwrap();
    progress.active_quarantine_witness = Some(test_quarantine_witness());
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    let before = snapshot_upload_body_witness(large);
    let mut accepted = 0;
    let mut sent = Vec::new();
    upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let req = request(source, batch.to_vec());
            validate_snapshot_batch_request(&req)
                .map_err(|reason| anyhow::Error::new(SnapshotBatchPreflightRejected { reason }))?;
            sent.extend(req.snapshots.iter().map(|item| {
                (
                    item.source_session_id.clone(),
                    item.request_count,
                    item.usage_buckets.len(),
                )
            }));
            claude_money_e2_pipeline_tests::ack(&req.items().collect::<Vec<_>>())
        },
        |p| p.save_fixture(&root.join("progress.json")),
    )
    .unwrap();
    assert_eq!(accepted, 2);
    assert!(sent.contains(&("synthetic-1000".into(), 1000, 1000)));
    assert!(sent.contains(&("synthetic-1".into(), 1, 1)));
    assert!(!sent.iter().any(|(id, _, _)| id == "synthetic-1500"));
    assert!(progress
        .accepted_fingerprints
        .contains(&large.snapshot_fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&oversized.snapshot_fingerprint));
    assert_eq!(
        before,
        snapshot_upload_body_witness(large),
        "admission recovery never edits accounting/body identity"
    );
    println!("native admission: item_bytes={large_bytes} hours=1000 accepted=2 quarantined=1 private_reads=0");
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn admission_reoffer_replaces_stale_terminal_progress_and_survives_restart() {
    let root = test_dir("admission-reoffer-progress");
    let path = root.join("progress.json");
    let namespace = "c".repeat(64);
    let fingerprint = "a".repeat(64);
    let sibling = "b".repeat(64);
    let mut progress = SnapshotUploadProgress::new(namespace.clone(), test_quarantine_witness());
    progress
        .active_quarantine_witness
        .as_mut()
        .unwrap()
        .item_wire_byte_limit = 128 * 1024;
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine([fingerprint.as_str()]);
    }
    progress.record([sibling.as_str()]);
    progress.save_fixture(&path).unwrap();
    let mut index = ScanIndex::default();
    index.file_snapshot_fingerprints.insert(
        "synthetic.jsonl".into(),
        BTreeSet::from([fingerprint.clone(), sibling.clone()]),
    );
    index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
    let index_path = root.join("index.json");
    assert!(index.prepare_snapshot_admission_reoffer(50));
    index.save_fixture(&index_path).unwrap();
    progress = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    assert!(progress.active_quarantine_retries.contains(&fingerprint));
    assert!(progress.contains(&sibling));
    progress.save_fixture(&path).unwrap();
    progress = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
    assert!(
        progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints),
        "restart keeps the unsent admission re-offer due"
    );
    let mut accepted = 0;
    let mut sent = Vec::new();
    upload_resumable_batches(
        &[fingerprint.clone(), sibling.clone()],
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            sent.extend(batch.iter().copied().cloned());
            let response = entity_ack_batch(&[], batch, &[]);
            let identities = batch
                .iter()
                .map(|fp| (format!("session-{fp}"), (*fp).clone()))
                .collect::<Vec<_>>();
            response.validate_entity_ack_identities(
                identities.iter().map(|(id, fp)| (id.as_str(), fp.as_str())),
            )?;
            Ok(response)
        },
        |p| p.save_fixture(&path),
    )
    .unwrap();
    assert_eq!(sent, vec![fingerprint.clone()]);
    assert_eq!(accepted, 1);
    assert!(progress.accepted_fingerprints.contains(&fingerprint));
    assert!(
        !progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints),
        "durable ACK dominates stale index"
    );
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    assert!(!index.prepare_snapshot_admission_reoffer(50));
    let mut unrelated =
        SnapshotUploadProgress::load(&path, &"d".repeat(64), test_quarantine_witness()).unwrap();
    assert!(unrelated.accepted_fingerprints.is_empty());
    assert!(unrelated.quarantined_fingerprints.is_empty());
    assert!(!unrelated.prepare_quarantine_retries(&BTreeMap::new()));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn durable_ack_dominates_stale_index_quarantine_after_restart() {
    let fingerprint = "c".repeat(64);
    let mut index_quarantine = BTreeMap::new();
    let mut stale = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    stale.retry_after_unix_seconds = 0;
    stale.upload_body_witness = Some(fingerprint.clone());
    index_quarantine.insert(fingerprint.clone(), stale);

    let mut progress = test_upload_progress();
    progress.record([fingerprint.as_str()]);
    assert!(!progress.prepare_quarantine_retries(&index_quarantine));
    assert!(progress.accepted_fingerprints.contains(&fingerprint));
    assert!(!progress.quarantined_fingerprints.contains_key(&fingerprint));
    assert!(!progress.active_quarantine_retries.contains(&fingerprint));
}

/// [regress] A returned entity owes one retry, keeping its original budget.
#[test]
fn a_superseded_quarantine_rearms_when_current_again() {
    let fingerprint = "b".repeat(64);
    let current = BTreeSet::from([fingerprint.clone()]);
    let mut index = ScanIndex::default();
    index
        .file_snapshot_fingerprints
        .insert("session.jsonl".into(), current.clone());
    let mut progress = test_upload_progress();
    progress.quarantine([fingerprint.as_str()]);
    assert!(progress.retain_current_quarantines(&BTreeSet::new(), &index));
    let terminal = progress.quarantined_fingerprints[&fingerprint].clone();
    assert!(progress.retain_current_quarantines(&current, &index));
    let mut expected = terminal;
    expected.disposition = SnapshotQuarantineDisposition::RetryPending;
    expected.retry_after_unix_seconds = 0;
    assert_eq!(progress.quarantined_fingerprints[&fingerprint], expected);
    assert!(!progress.retain_current_quarantines(&current, &index));
}

#[test]
fn supersede_while_quarantined_preserves_absence_holds_and_retry_budgets() {
    let current = "a".repeat(64);
    let stale = "b".repeat(64);
    let mut progress = test_upload_progress();
    progress.quarantine([current.as_str(), stale.as_str()]);
    let deadline = progress.quarantined_fingerprints[&current].retry_after_unix_seconds;
    let mut index = ScanIndex::default();
    index
        .file_snapshot_fingerprints
        .insert("current.jsonl".into(), BTreeSet::from([current.clone()]));
    let current_set = index.current_snapshot_fingerprints();
    assert!(progress.retain_current_quarantines(&current_set, &index));
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    assert_eq!(index.snapshot_superseded_terminal_count(), 1);
    assert!(!progress.retain_current_quarantines(&current_set, &index));
    assert_eq!(
        progress.quarantined_fingerprints[&current].retry_after_unix_seconds,
        deadline
    );
    assert_eq!(
        progress.quarantined_fingerprints[&stale].disposition,
        SnapshotQuarantineDisposition::SupersededTerminal
    );

    for guard in [
        "decode",
        "entity_decode",
        "refused",
        "stale_debt",
        "failures",
        "claims",
    ] {
        let mut index = ScanIndex::default();
        index
            .file_snapshot_fingerprints
            .insert("returned.jsonl".into(), BTreeSet::from([stale.clone()]));
        let mut blocked = progress.clone();
        match guard {
            "decode" => crate::snapshots::e2_pipeline_scan_fixture::hold_file_decode_for_test(
                &mut index,
                "returned.jsonl",
            ),
            "entity_decode" => {
                crate::snapshots::e2_pipeline_scan_fixture::hold_entity_decode_for_test(
                    &mut index, &stale,
                )
            }
            "refused" | "stale_debt" => {
                let reason = if guard == "stale_debt" {
                    "accepted_log_stale_older_upload"
                } else {
                    "usage_accounting_authority_downgrade"
                };
                blocked.quarantine_permanent_body(&stale, &stale, reason);
                let record = blocked.quarantined_fingerprints.get_mut(&stale).unwrap();
                record.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
                record.failed_reconstruction_count = 1;
            }
            "failures" => {
                blocked
                    .quarantined_fingerprints
                    .get_mut(&stale)
                    .unwrap()
                    .failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
            }
            "claims" => {
                blocked
                    .quarantined_fingerprints
                    .get_mut(&stale)
                    .unwrap()
                    .contract_retry_claims =
                    Some(crate::snapshots::terminal_contract_retry::MAX_CLAIMS)
            }
            _ => unreachable!(),
        }
        let before = blocked.quarantined_fingerprints[&stale].clone();
        blocked
            .retain_current_quarantines(&BTreeSet::from([current.clone(), stale.clone()]), &index);
        assert_eq!(blocked.quarantined_fingerprints[&stale], before, "{guard}");
        assert!(blocked.active_reason_reoffers.is_empty());
    }
}

#[test]
fn concurrent_relay_switch_rejects_final_cursor_commit() {
    let device_a = LocalDeviceBinding {
        device_id: "relay-device-a".to_string(),
        machine_id: Some("machine-shared".to_string()),
        sources: vec!["codex".to_string()],
    };
    let device_b = LocalDeviceBinding {
        device_id: "relay-device-a".to_string(),
        machine_id: Some("machine-shared".to_string()),
        sources: vec!["codex".to_string()],
    };
    let expected = snapshot_upload_destination_namespace(&device_a, "secret-a");

    let error = validate_snapshot_destination(&expected, &device_b, "secret-b")
        .expect_err("destination B must not commit destination A's cursor");
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::LocalState)
    );
    assert_eq!(safe_error(&error), "local snapshot state failed");
}

#[test]
fn enabled_snapshot_sources_follow_device_grants() {
    let device = LocalDeviceBinding {
        device_id: "device".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string(), "pi".to_string()],
    };

    assert_eq!(
        enabled_snapshot_sources(&device),
        vec![SnapshotSource::Codex, SnapshotSource::Pi]
    );
}

#[test]
fn snapshot_index_path_is_source_scoped() {
    let root = Path::new("/support");

    assert_eq!(
        snapshot_index_path(root, SnapshotSource::Codex),
        PathBuf::from("/support/snapshots/codex-scan-index.json")
    );
    assert_eq!(
        snapshot_index_path(root, SnapshotSource::ClaudeCode),
        PathBuf::from("/support/snapshots/claude_code-scan-index.json")
    );
    assert_eq!(
        snapshot_index_path(root, SnapshotSource::Pi),
        PathBuf::from("/support/snapshots/pi-scan-index.json")
    );
}

#[test]
fn copy_capability_context_preserves_partial_ack_progress_after_restart() {
    let base = cycle_upload_context(SnapshotUploadPolicy::default(), None, false);
    assert_eq!(copy_unproven_upload_context(base.clone(), false), base);
    assert_eq!(resumed_prefix_upload_context(base.clone(), false), base);
    let local_context = resumed_prefix_upload_context(base.clone(), true);
    assert_ne!(local_context, base);
    assert!(is_snapshot_fingerprint(&local_context));
    let context = copy_unproven_upload_context(local_context, true);
    assert_ne!(context, base);
    assert!(is_snapshot_fingerprint(&context));
    let root = test_dir("copy-capability-ack-context");
    let path = root.join("progress.json");
    let destination = "d".repeat(64);
    let entity = "e".repeat(64);
    let mut progress = SnapshotUploadProgress::new(destination.clone(), test_quarantine_witness());
    progress.accepted_fingerprints.insert(entity.clone());
    progress
        .accepted_body_witnesses
        .insert(entity.clone(), "b".repeat(64));
    progress
        .accepted_body_contexts
        .insert(entity.clone(), context.clone());
    progress.save_fixture(&path).unwrap();
    let loaded =
        SnapshotUploadProgress::load(&path, &destination, test_quarantine_witness()).unwrap();
    assert_eq!(loaded.accepted_body_contexts.get(&entity), Some(&context));
    assert!(loaded.accepted_fingerprints.contains(&entity));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn upload_context_is_inventory_independent_but_key_epoch_and_policy_sensitive() {
    let policy = SnapshotUploadPolicy {
        session_attribution_enabled: true,
        session_attribution_labels_enabled: true,
        ..SnapshotUploadPolicy::default()
    };
    let stable = snapshot_upload_context_fingerprint(policy, Some("stable-key-epoch"));
    assert_eq!(
        stable,
        snapshot_upload_context_fingerprint(policy, Some("stable-key-epoch"))
    );
    assert_ne!(
        stable,
        snapshot_upload_context_fingerprint(policy, Some("rotated-key-epoch"))
    );
    assert_ne!(
        stable,
        snapshot_upload_context_fingerprint(SnapshotUploadPolicy::default(), None)
    );
}

/// [money] The delivery context stays byte-identical while receipts,
/// stamps and ACK contexts still bind it: a changed formula would owe every
/// proven file again. Values computed independently of this code.
#[test]
fn upload_context_formula_is_pinned() {
    let off = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    let on = SnapshotUploadPolicy {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
        session_artifacts_enabled: true,
        session_attribution_enabled: true,
        session_attribution_labels_enabled: true,
    };
    assert_eq!(
        cycle_upload_context(off, None, false),
        "e69b3670ac30103faba7f9dadcff9acc5138dad509fb7ed49b52dff1668cbd4e"
    );
    let cached = cycle_upload_context(on, Some("stable-key-epoch"), true);
    assert_eq!(
        cached,
        "ee323545020e97a574089c2e4e03176ad17917d6d78658abb9f39494487581df"
    );
    assert_eq!(
        copy_unproven_upload_context(resumed_prefix_upload_context(cached, true), true),
        "ca93839676f7beb9078f01550cb3f0b77fca81c318f222f39ffabda0095302d7"
    );
}

#[test]
#[serial]
fn endpoint_load_failure_during_scan_is_local_state() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let root = test_dir("scan-endpoint-load-failure");
    std::fs::create_dir_all(&root).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
    let device = LocalDeviceBinding {
        sources: vec!["pi".into()],
        ..synthetic_device_binding()
    };
    FileDeviceStore::default().save(&device).unwrap();
    let daemon = test_daemon(&"a".repeat(64));
    let account = daemon.snapshot_scan_account_witness().unwrap();
    let client = SnapshotApiClient::new("https://synthetic.invalid");
    for bytes in [b"invalid-json".to_vec(), vec![b' '; 64 * 1024 + 1]] {
        std::fs::write(root.join("connection.json"), bytes).unwrap();
        let load_error = snapshot_api_base_url().unwrap_err();
        assert_eq!(
            safe_error(&load_error),
            "connection binding is unavailable or invalid; reconnect this device"
        );
        let error =
            ensure_snapshot_scan_authority(&device, SnapshotSource::Pi, &client, &account, &daemon)
                .unwrap_err();
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(safe_error(&error), "local snapshot state failed");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn connection_cap_refusal_never_selects_environment_or_default_endpoint() {
    use std::fs;
    let root = test_dir("connection-cap-endpoint");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("connection.json");
    let store = FileConnectionStore::new(&path);
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "setup_run_id": "synthetic", "setup_run_token_expires_at": "synthetic",
        "machine_id": null, "api_base_url": "https://api.ottto.net"
    }))
    .unwrap();
    bytes.resize(64 * 1024, b' ');
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        snapshot_api_base_url_from(store.load(), None).unwrap(),
        "https://api.ottto.net"
    );
    bytes.push(b' ');
    fs::write(&path, &bytes).unwrap();
    for env in [None, Some("https://ottto.net/backend".to_owned())] {
        let mut client_created = false;
        let result = snapshot_api_base_url_from(store.load(), env).map(|base| {
            client_created = true;
            SnapshotApiClient::new(base)
        });
        assert!(result.is_err());
        assert!(!client_created);
    }
    assert_eq!(
        snapshot_api_base_url_from(Ok(None), Some("https://api.ottto.net/".into())).unwrap(),
        "https://api.ottto.net"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn upload_destination_must_be_a_trusted_backend() {
    use std::fs;
    let root = test_dir("upload-destination-trust");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("connection.json");
    let store = FileConnectionStore::new(&path);
    for base in [
        "https://custom.invalid",
        "http://upload.invalid",
        "https://api.ottto.net.invalid",
    ] {
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "setup_run_id": "synthetic", "setup_run_token_expires_at": "synthetic",
                "machine_id": null, "api_base_url": base
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            snapshot_api_base_url_from(store.load(), None).is_err(),
            "{base}"
        );
    }
    assert!(snapshot_api_base_url_from(Ok(None), Some("https://fallback.invalid".into())).is_err());
    assert_eq!(
        snapshot_api_base_url_from(Ok(None), None).unwrap(),
        "https://api.ottto.net"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn safe_error_reports_sync_phase_without_raw_details() {
    let snapshot_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
        "local snapshot upload",
        "snapshot_batch",
        "http_5xx",
        true,
        true,
    ))
    .context("upload local snapshots");
    assert_eq!(
        safe_error(&snapshot_error),
        "local snapshot upload failed (endpoint=snapshot_batch, status_family=http_5xx, retryable=true, request_id=present)"
    );

    let agent_status_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
        "agent status upload",
        "agent_status",
        "transport_timeout",
        true,
        false,
    ));
    assert_eq!(
        safe_error(&agent_status_error),
        "agent status upload failed (endpoint=agent_status, status_family=transport_timeout, retryable=true, request_id=absent)"
    );

    assert_eq!(
        safe_error(&anyhow!("upload agent status failed: HTTP 500")),
        "agent status upload failed"
    );
    assert_eq!(
        safe_error(&anyhow!("upload local snapshots: request timed out")),
        "local snapshot upload failed"
    );
    assert_eq!(
        safe_error(&anyhow!("issue relay token failed: rejected")),
        "relay token request failed"
    );
    assert_eq!(
        safe_error(&anyhow!(
            "local snapshot batch failed daemon/backend contract preflight: snapshot[0]"
        )),
        "local snapshot payload validation failed"
    );
    assert_eq!(
        safe_error(&anyhow!(
            "backend rejected snapshot batch payload validation: HTTP 422"
        )),
        "local snapshot payload validation failed"
    );
    assert_eq!(
        safe_error(&anyhow::Error::new(LocalHealthProjectionRejected {
            status: 422
        })),
        "local health projection rejected"
    );
    assert_eq!(
        safe_error(&anyhow::Error::new(LocalHealthAuthorizationRejected {
            status: 401
        })),
        "local health authorization rejected"
    );
    assert_eq!(
        safe_error(
            &anyhow::Error::new(crate::snapshots::state_v2::Hold::SaveFull)
                .context("scan local snapshots /synthetic/private/path")
        ),
        "local state store held: state_v2_sqlite_full"
    );
    assert_eq!(
        safe_error(&SourcesFailed(vec!["claude_code", "codex"]).into()),
        "local snapshot sync failed for claude_code, codex"
    );
}

#[test]
#[serial]
fn manual_agent_status_upload_posts_granted_refreshed_snapshots() {
    let root = test_dir("manual-agent-status-upload");
    let support_dir = root.join("support");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let api_base_url = agent_status_upload_server(captured.clone());
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        })
        .expect("save device");
    std::fs::write(
        secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .expect("save device secret");

    let uploaded = upload_agent_status_snapshots(&[
        test_agent_status(SourceKind::Codex),
        test_agent_status(SourceKind::ClaudeCode),
    ])
    .expect("upload agent status");

    assert_eq!(uploaded, 1);
    let requests = captured.lock().expect("captured requests").clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
    assert!(requests[0].contains("\"source\":\"codex\""));
    assert!(requests[0].contains("\"client_name\":\"ottto-service\""));
    assert!(requests[0].contains("\"client_version\":"));
    assert!(requests[0].contains("\"machine_id\":\"otm_test\""));
    assert!(requests[0].contains("\"platform\":"));
    assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
    assert!(requests[1].contains("POST /api/v1/agent-status/snapshots"));
    assert!(requests[1].contains("Authorization:"));
    assert!(requests[1].contains("relay-token-codex"));
    assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
    assert!(requests[1].contains("\"source\":\"codex\""));
    assert!(!requests[1].contains("claude_code"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn per_source_agent_status_upload_batches_two_claude_accounts() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_server = captured.clone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status batch backend");
    let address = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept agent status batch");
        let request = read_complete_http_request(&mut stream);
        captured_server
            .lock()
            .expect("capture agent status batch")
            .push(request);
        let body = r#"{"accepted":2,"machine_id":"otm_test","sources":["claude_code"]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write agent status batch response");
    });
    let client = SnapshotApiClient::new(format!("http://{address}"));
    let mut first = test_agent_status(SourceKind::ClaudeCode);
    first.account = Some(test_agent_account("account-hash-a", "organization-hash-a"));
    let mut second = test_agent_status(SourceKind::ClaudeCode);
    second.account = Some(test_agent_account("account-hash-b", "organization-hash-b"));

    upload_agent_status(&client, "relay-token-claude", "otm_test", &[first, second])
        .expect("upload two-account batch");

    let requests = captured.lock().expect("captured batch requests");
    assert_eq!(requests.len(), 1);
    let body = requests[0].split("\r\n\r\n").nth(1).expect("request body");
    let request: serde_json::Value = serde_json::from_str(body).expect("parse request body");
    let snapshots = request["snapshots"].as_array().expect("snapshot batch");
    assert_eq!(snapshots.len(), 2);
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot["source"] == "claude_code"));
    assert_eq!(snapshots[0]["captured_at"], snapshots[1]["captured_at"]);
    assert_ne!(
        snapshots[0]["account"]["account_identifier_hash"],
        snapshots[1]["account"]["account_identifier_hash"]
    );
}

#[test]
fn empty_agent_status_upload_is_a_noop_and_reconciliation_keeps_default_owner() {
    let client = SnapshotApiClient::new("http://127.0.0.1:1".to_string());
    upload_agent_status(&client, "unused", "otm_test", &[])
        .expect("empty upload must not touch the network or abort scanning");

    let mut default_health = test_agent_status(SourceKind::ClaudeCode);
    default_health.account = Some(test_agent_account(
        "default-account-hash",
        "default-organization-hash",
    ));
    let mut custom_upload = test_agent_status(SourceKind::ClaudeCode);
    custom_upload.account = Some(test_agent_account(
        "custom-account-hash",
        "custom-organization-hash",
    ));
    let collection = AgentStatusCollection {
        snapshots: vec![custom_upload],
        source_health_snapshot: default_health,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
        setup_snapshot_index: None,
    };

    let reconciliation = reconciliation_agent_status(&collection);
    assert_eq!(
        reconciliation
            .account
            .as_ref()
            .and_then(|account| account.account_identifier_hash.as_deref()),
        Some("default-account-hash"),
        "a custom upload row must never become default-session ownership evidence"
    );
}

#[test]
#[serial]
fn manual_agent_status_upload_attempts_remaining_sources_after_failure() {
    let root = test_dir("manual-agent-status-partial-failure");
    let support_dir = root.join("support");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let api_base_url = agent_status_partial_failure_server(captured.clone());
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string(), "claude_code".to_string()],
        })
        .expect("save device");
    std::fs::write(
        secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .expect("save device secret");

    let error = upload_agent_status_snapshots(&[
        test_agent_status(SourceKind::Codex),
        test_agent_status(SourceKind::ClaudeCode),
    ])
    .expect_err("partial upload should report aggregate failure");

    assert_eq!(safe_error(&error), "agent status upload failed");
    let requests = captured.lock().expect("captured requests").clone();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("\"source\":\"codex\""));
    assert!(requests[1].contains("\"source\":\"claude_code\""));
    assert!(requests[2].contains("POST /api/v1/agent-status/snapshots"));
    assert!(requests[2].contains("\"source\":\"claude_code\""));
    assert!(!requests[2].contains("\"source\":\"codex\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[serial]
fn local_health_upload_refreshes_inactive_device_before_retry() {
    for (reject_in_other_caller, reject_retry) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let root = test_dir("local-health-upload-reactivates-device");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = local_health_reactivation_server(captured.clone(), reject_retry);

        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        FileDeviceStore::default()
            .save(&device)
            .expect("save device");
        FileConnectionStore::default()
            .save(&LocalConnectionBinding {
                setup_run_id: "setup_stale".to_string(),
                setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
                machine_id: Some("otm_test".to_string()),
                claim_code: None,
                api_base_url: api_base_url.clone(),
            })
            .expect("save connection");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");
        std::fs::write(
            secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
            "otsr_stale",
        )
        .expect("save setup token");

        if reject_in_other_caller {
            SnapshotApiClient::new(&api_base_url)
                .issue_relay_token_with_timeout(
                    &device,
                    "device-secret",
                    SnapshotSource::Codex,
                    Duration::from_secs(5),
                )
                .expect_err("another snapshot caller observes the initial authorization rejection");
        }
        let client = SnapshotApiClient::new(api_base_url);
        let result = upload_local_health_projection_reporting(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            &test_daemon("otm_test"),
        );
        if reject_retry {
            assert!(result.is_err());
            assert_eq!(
                captured.lock().unwrap().len(),
                3,
                "token, refresh, rejected retry"
            );
            assert!(!crate::relay_auth::take_setup_refresh(
                client.relay_auth_binding(&device, "device-secret", SnapshotSource::Codex)
            ));
            let held = upload_local_health_projection_reporting(
                &client,
                &device,
                "device-secret",
                SnapshotSource::Codex,
                "otm_test",
                &test_daemon("otm_test"),
            )
            .expect_err("new setup id inherits the consumed recovery attempt");
            assert!(
                held.downcast_ref::<RelayTokenAuthorizationRejected>()
                    .unwrap()
                    .suppressed
            );
            assert_eq!(
                captured.lock().unwrap().len(),
                3,
                "no second refresh or token request"
            );
            let _ = std::fs::remove_dir_all(root);
            continue;
        }
        result.expect("upload retries after refresh");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[1].contains("POST /api/v1/setup-runs/setup_stale/local-client/refresh"));
        assert!(requests[1].contains("\"device_secret\":\"device-secret\""));
        assert!(requests[2].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[3].contains("POST /api/v1/apps/health/heartbeat"));
        assert!(requests[4].contains("POST /api/v1/apps/health/projection"));
        assert_eq!(
            FileConnectionStore::default()
                .load()
                .expect("load refreshed connection")
                .expect("connection exists")
                .setup_run_id,
            "setup_fresh"
        );
        assert_eq!(
            std::fs::read_to_string(secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT))
                .expect("read refreshed setup token"),
            "otsr_fresh"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

/// A registered device granted `sources` against a backend whose
/// heartbeat replies are `replies`, in order. Holds the env guards.
struct SourceControlBackend {
    root: PathBuf,
    support_dir: PathBuf,
    device: LocalDeviceBinding,
    api_base_url: String,
    captured: Arc<Mutex<Vec<String>>>,
    _guards: [EnvVarGuard; 2],
}

fn source_control_backend(sources: &[&str], replies: &[(&str, u64, &str)]) -> SourceControlBackend {
    clear_setup_run_refresh_hold();
    let root = test_dir("source-control-heartbeat");
    let support_dir = root.join("support");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    let guards = [
        EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir),
        EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir),
    ];
    let replies = replies
        .iter()
        .map(|(source, revision, state)| {
            serde_json::json!({"accepted": true, "source_control": {"contract": "source_control:v1",
                "device_id": "device_test", "sources": [{"source": source,
                "revision": revision, "desired_state": state}]}})
        })
        .collect();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let api_base_url = source_control_heartbeat_server(captured.clone(), replies);
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: sources.iter().map(|source| source.to_string()).collect(),
    };
    FileDeviceStore::default()
        .save(&device)
        .expect("save device");
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: "setup_source_control".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("otm_test".to_string()),
            claim_code: None,
            api_base_url: api_base_url.clone(),
        })
        .expect("save connection");
    std::fs::write(
        secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .expect("save device secret");
    SourceControlBackend {
        root,
        support_dir,
        device,
        api_base_url,
        captured,
        _guards: guards,
    }
}

/// [regress] Paired health identity stays separate while the heartbeat runs
/// on a granted source's token while every source is paused, so a web ON
/// still arrives: OFF then ON pauses and resumes the source.
#[test]
#[serial]
fn all_sources_paused_heartbeat_still_runs() {
    let backend = source_control_backend(
        &["codex"],
        &[("codex", 1, "disabled"), ("codex", 2, "enabled")],
    );
    let codex = SnapshotSource::Codex;
    let daemon = test_daemon("otm_local");
    FileMachineStore::default()
        .save(&ottto_core::LocalMachineBinding {
            machine_id: "otm_local".into(),
            installation_id: "install_test".into(),
            hardware_uuid: None,
        })
        .unwrap();
    upload_local_health_projection_now(&daemon).expect("heartbeat");
    assert_eq!(
        source_marker(&backend.support_dir, codex).as_deref(),
        Some("pending")
    );
    assert!(enabled_snapshot_sources(&backend.device).is_empty());
    assert_eq!(heartbeat_source(&backend.device), Some(codex));
    let mut unpaired = backend.device.clone();
    unpaired.machine_id = None;
    FileDeviceStore::default().save(&unpaired).unwrap();
    upload_local_health_projection_now(&daemon).expect("heartbeat while all paused");
    assert!(snapshot_machine_id(&unpaired).unwrap().as_deref() == Some("otm_local"));
    assert!(daemon.machine_for_trusted_client().unwrap().machine_id == "otm_local");
    assert_eq!(
        source_marker(&backend.support_dir, codex).as_deref(),
        Some("reconnect")
    );
    resume_reconnected_sources(&backend.support_dir);
    assert_eq!(enabled_snapshot_sources(&backend.device), vec![codex]);
    let requests = backend.captured.lock().expect("captured").clone();
    let heartbeats = requests
        .iter()
        .filter(|request| request.contains("POST /api/v1/apps/health/heartbeat"))
        .collect::<Vec<_>>();
    assert_eq!(heartbeats.len(), 2);
    assert!(heartbeats
        .iter()
        .all(|request| request.contains("\"source_control:v1\"")));
    assert_eq!(requests.len(), 6);
    for (request, id) in requests
        .iter()
        .filter(|r| r.contains("/apps/health/"))
        .zip(["otm_test", "otm_test", "otm_local", "otm_local"])
    {
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["machine_id"], id);
    }
    let _ = std::fs::remove_dir_all(&backend.root);
}

/// [behaviour] An OFF carried by the cycle's own heartbeat stops that
/// source in the same cycle; the other one still runs.
#[test]
#[serial]
fn cycle_heartbeat_off_skips_source_same_cycle() {
    let backend = source_control_backend(&["codex", "claude_code"], &[("codex", 1, "disabled")]);
    assert_eq!(enabled_snapshot_sources(&backend.device).len(), 2);
    let sources = cycle_heartbeat(
        &SnapshotApiClient::new(backend.api_base_url.as_str()),
        &backend.device,
        "device-secret",
        "otm_test",
        &test_daemon("otm_test"),
    );
    assert_eq!(sources, vec![SnapshotSource::ClaudeCode]);
    let _ = std::fs::remove_dir_all(&backend.root);
}

#[test]
#[serial]
fn local_health_upload_holds_after_rejected_refresh_until_the_binding_changes() {
    clear_setup_run_refresh_hold();
    let root = test_dir("local-health-upload-refresh-hold");
    let support_dir = root.join("support");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rejecting backend");
    let api_base_url = format!("http://{}", listener.local_addr().expect("local address"));
    let server_captured = captured.clone();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_complete_http_request(&mut stream);
            server_captured
                .lock()
                .expect("capture request")
                .push(request);
            let body =
                r#"{"error":"AuthenticationError","detail":"Telemetry device is not active"}"#;
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    FileDeviceStore::default()
        .save(&device)
        .expect("save device");
    let connection = |setup_run_id: &str| LocalConnectionBinding {
        setup_run_id: setup_run_id.to_string(),
        setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
        machine_id: Some("otm_test".to_string()),
        claim_code: None,
        api_base_url: api_base_url.clone(),
    };
    FileConnectionStore::default()
        .save(&connection("setup_rejected"))
        .expect("save connection");
    std::fs::write(
        secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .expect("save device secret");
    let daemon = test_daemon("otm_test");
    let client = SnapshotApiClient::new(api_base_url.clone());
    let pass = || {
        upload_local_health_projection_reporting(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            &daemon,
        )
        .expect_err("a rejected device cannot upload")
    };
    let requests = || captured.lock().expect("captured requests").len();

    let rejected = pass();
    assert!(!local_health_upload_can_wait_quietly(&rejected));
    assert_eq!(requests(), 2, "relay token, then one refresh");
    assert!(matches!(
        crate::latest_local_health_upload(&daemon.status_for_trusted_client().expect("status")),
        Some(crate::LatestLocalHealthUpload::AuthRejected { .. })
    ));

    // "Telemetry device is not active" from the refresh endpoint is an
    // authoritative terminal answer: parked, not merely backed off.
    let held = pass();
    assert_eq!(
        held.downcast_ref::<LocalHealthRefreshHeld>(),
        Some(&LocalHealthRefreshHeld { remaining: None })
    );
    assert!(local_health_upload_can_wait_quietly(&held));
    assert_eq!(requests(), 2, "a held pass sends nothing");
    // The rejection stays the latest recorded outcome while held.
    assert!(matches!(
        crate::latest_local_health_upload(&daemon.status_for_trusted_client().expect("status")),
        Some(crate::LatestLocalHealthUpload::AuthRejected { .. })
    ));

    // Reattaching to another setup run is a real binding change.
    FileConnectionStore::default()
        .save(&connection("setup_reattached"))
        .expect("save reattached connection");
    pass();
    let captured = captured.lock().expect("captured requests").clone();
    assert_eq!(captured.len(), 4, "the reattached binding is tried again");
    assert!(captured[3].contains("POST /api/v1/setup-runs/setup_reattached/local-client/refresh"));

    clear_setup_run_refresh_hold();
    let _ = std::fs::remove_dir_all(root);
}
