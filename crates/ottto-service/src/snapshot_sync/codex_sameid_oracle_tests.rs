fn revert_archives(c: &Corpus, second_account: &str) -> Vec<PathBuf> {
    rollout(c, A, "a", 8);
    let original = c
        .root
        .join(format!("rollout-2026-10-27T07-00-00-{A}.jsonl"));
    let first = std::fs::read_to_string(&original).unwrap();
    rollout(c, A, second_account, 88);
    let mut second = std::fs::read_to_string(&original)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    second[0]["payload"]["history_base"] =
        json!({"thread_id": A, "end_ordinal_exclusive": 1, "end_byte_offset": 1});
    second[0]["payload"]["timestamp"] = json!("2026-10-27T07:01:00Z");
    second[0]["timestamp"] = json!("2026-10-27T07:01:00Z");
    for row in &mut second[1..] {
        row["timestamp"] = json!("2026-10-27T07:31:00Z");
    }
    let second = second
        .iter()
        .map(|row| row.to_string() + "\n")
        .collect::<String>();
    std::fs::remove_file(&original).unwrap();
    let paths = vec![
        original.with_extension("jsonl.zst"),
        c.root
            .join(format!("rollout-2026-10-27T07-01-00-{A}_{B}.jsonl.zst")),
    ];
    for (path, body) in paths.iter().zip([first, second]) {
        std::fs::write(path, zstd::stream::encode_all(body.as_bytes(), 1).unwrap()).unwrap();
    }
    paths
}

/// [money] Capture every physical revision, exact-ACK the combined body, recover
/// the receipt before saving source progress, then restart and upgrade quietly.
#[test]
fn combined_codex_ack_recovers_every_member_and_quiet_restarts_read_zero_bytes() {
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    let mut c = Corpus::new("codex-combined-ack-restart");
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    let paths = revert_archives(&c, "a");
    let (session, previous) =
        StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &c.base.join("state"));
    // Model the prior binary's accepted unchanged singleton state: no joined
    // marker exists yet, but all physical revisions and acceptance remain.
    let (mut legacy, old_scan, _) = page(&c, &E2ScanFixture::default(), previous.clone());
    legacy.record_accepted_snapshot_fingerprints(
        &old_scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    for entry in legacy.files.values_mut() {
        entry.codex_joined_member_set = None;
        entry.codex_captured_joined_member_set = None;
        entry.codex_captured_uncommitted = false;
        entry.codex_captured_tier_receipt_required = false;
    }
    let mut legacy = session.save_reload(&mut legacy);
    assert!(legacy
        .files
        .values()
        .all(|entry| !entry.source_file_fingerprint.is_empty()));
    // Same existing first-load re-arm used by the source-aware install/restart
    // loader. It changes only owed source state and the observed-file queue.
    crate::snapshots::codex_file_join::rearm_unsettled(&mut legacy);
    assert!(legacy
        .files
        .values()
        .all(|entry| entry.source_file_fingerprint.is_empty()));
    let previous = legacy;
    let (mut index, scan, _) = page(&c, &E2ScanFixture::default(), previous.clone());
    assert_eq!(scan.snapshots.len(), 1, "one upload body for both files");
    assert_eq!(scan.snapshots[0].request_count, 96);
    let (mut captured, changed) = index.stage_codex_recovery_capture(&previous, &scan.snapshots);
    assert!(changed.contains(A));
    assert_eq!(
        captured
            .files
            .values()
            .filter(|entry| entry.codex_captured_joined_member_set.is_some())
            .count(),
        2
    );
    let captured = session.save_reload(&mut captured);
    index.generation = captured.generation;
    index.retain_persistence_baseline_from(&captured);

    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(SOURCE));
    let before = serde_json::to_vec(&progress).unwrap();
    let progress_path = c.base.join("codex-progress.json");
    ottto_core::write_owner_only_file_atomic(&progress_path, &before).unwrap();
    let recovery = crate::snapshots::ProgressRecovery::synthetic(
        &c.base.join("receipt-index"),
        &"a".repeat(64),
        captured.generation,
    );
    recovery.adopt_synthetic(Some(&before));
    // The same acquired body/proof remains in the attempt for an exact retry.
    let ((failed, failed_batches, _), retry_bytes) = fixture::observe_consumed(|| {
        upload_source_under(
            SOURCE,
            SnapshotUploadPolicy::default(),
            &scan.snapshots,
            &mut progress,
            |_| Err(anyhow::anyhow!("synthetic transient upload failure")),
        )
    });
    assert!(failed.is_err());
    assert_eq!(retry_bytes, 0);
    let (outcome, batches, _) = upload_source_under(
        SOURCE,
        SnapshotUploadPolicy::default(),
        &scan.snapshots,
        &mut progress,
        ack,
    );
    assert_eq!(outcome.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1);
    assert_eq!(
        failed_batches, batches,
        "retry sends the retained exact body"
    );
    progress.generation += 1;
    let after = serde_json::to_vec(&progress).unwrap();
    recovery
        .before_progress_save(Some(&before), &after)
        .unwrap();
    // Process loss after the exact receipt, before either progress/source save.
    recovery.recover(&progress_path).unwrap();
    assert_eq!(std::fs::read(&progress_path).unwrap(), after);
    let recovered: SnapshotUploadProgress = serde_json::from_slice(&after).unwrap();
    settle_index_after_upload(&mut index, &captured, &recovered);
    let mut prior = session.save_reload(&mut index);
    crate::snapshots::codex_file_join::rearm_unsettled(&mut prior);
    assert!(
        prior
            .files
            .values()
            .all(|entry| !entry.source_file_fingerprint.is_empty()),
        "a settled group never re-arms on install/restart"
    );
    assert!(prior
        .files
        .values()
        .all(|entry| entry.codex_captured_joined_member_set.is_none()));
    assert_eq!(
        prior
            .files
            .values()
            .filter(|entry| entry.codex_joined_member_set.is_some())
            .count(),
        2
    );
    for mode in [fixture::Mode::Restart, fixture::Mode::DiskRestore] {
        let ((_, quiet, modes), io) =
            fixture::observe_codex_quiet(|| page(&c, &E2ScanFixture::default(), prior.clone()));
        let mut route = fixture::scan_money(SOURCE, &prior, &quiet);
        route.mode = mode;
        route.modes = modes;
        route.io = io;
        // All files reached the metadata-only Skip branch: no acquisition,
        // sample or re-derivation reader was entered on this quiet pass.
        assert_eq!(quiet.semantic_noop_count, paths.len());
        fixture::money_oracle::assert_quiet_restart_zero_bytes(&route);
    }

    let mut accepted_route = fixture::scan_money(SOURCE, &prior, &scan);
    accepted_route.accepted.insert(
        A.into(),
        fixture::Accepted {
            body: accepted_route.snapshots[A].clone(),
            witness: snapshot_upload_body_witness(&scan.snapshots[0]),
        },
    );
    // New material stays owed: no accepted sealed member is read again merely
    // to recreate the vanished in-memory admitted-key proof.
    let bytes = zstd::stream::decode_all(std::fs::File::open(&paths[1]).unwrap()).unwrap();
    let mut grown = String::from_utf8(bytes).unwrap();
    grown += &(json!({"timestamp":"2026-10-27T07:32:00Z","type":"event_msg","payload":{"type":"token_count",
        "info":{"last_token_usage":{"input_tokens":100},"total_token_usage":{"input_tokens":8900}}}}).to_string()+"\n");
    std::fs::write(
        &paths[1],
        zstd::stream::encode_all(grown.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    let ((_, growth, _), bytes) =
        fixture::observe_consumed(|| page(&c, &E2ScanFixture::default(), prior.clone()));
    assert_eq!(bytes, 0, "growth cannot reread accepted sealed history");
    let mut held_route = fixture::scan_money(SOURCE, &prior, &growth);
    held_route.accepted = accepted_route.accepted.clone();
    fixture::money_oracle::assert_no_smaller_reemit(
        A,
        &accepted_route,
        &held_route,
        &accepted_route,
        true,
    );

    // A lost carrier retains the logical accepted body, never the survivor sum.
    std::fs::remove_file(&paths[1]).unwrap();
    let (_, held, _) = page(&c, &E2ScanFixture::default(), prior.clone());
    let mut deleted = fixture::scan_money(SOURCE, &prior, &held);
    deleted.accepted = accepted_route.accepted.clone();
    fixture::money_oracle::assert_held(A, &accepted_route, &deleted, &accepted_route);
    assert!(held
        .snapshots
        .iter()
        .all(|item| item.source_session_id != A));
    assert!(recovered
        .accepted_fingerprints
        .contains(&scan.snapshots[0].snapshot_fingerprint));
}

/// [money] File-level creator evidence cannot authorize a mixed-account union.
#[test]
fn combined_codex_account_switch_holds_without_request_evidence() {
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    let c = Corpus::new("codex-combined-account-switch");
    revert_archives(&c, "b");
    let original_account =
        ottto_core::billing_identity_hash("openai", "account", "synthetic-user-a").unwrap();
    let original_workspace =
        ottto_core::billing_identity_hash("openai", "workspace", "synthetic-workspace-a").unwrap();
    let mut prior = ScanIndex::default();
    let binding_key = fixture::codex_start_binding(
        &mut prior,
        "e2-synthetic-machine",
        A,
        original_account.clone(),
        Some(original_workspace),
    );
    let saved_binding =
        serde_json::to_value(&prior).unwrap()["session_account_bindings"][&binding_key].clone();
    let (after, scan, _) = page(&c, &E2ScanFixture::default(), prior);
    assert_eq!(
        serde_json::to_value(&after).unwrap()["session_account_bindings"][&binding_key],
        saved_binding,
        "the original saved starting binding survives the held revert"
    );
    assert_eq!(saved_binding["account_identifier_hash"], original_account);
    assert!(
        scan.snapshots
            .iter()
            .all(|item| item.source_session_id != A),
        "no carrier-account fallback or singleton"
    );
    assert!(scan.ownership_incomplete_file_count >= 2);
}
