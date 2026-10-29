// Synthetic archive correction, settlement and scoped census contracts. No discovery activation.
fn correction_archive() -> ArchiveFixture {
    ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap())
}
fn archive_evidence<'a>(index: &'a ScanIndex, f: &ArchiveFixture) -> &'a ArchiveEvidence {
    index.files[&local_index_key(&f.0)]
        .archive
        .as_deref()
        .unwrap()
}
fn archive_open(f: &ArchiveFixture, index: &ScanIndex, census: &mut ScanCensus) -> bool {
    open_and_identify_scan_candidate(
        SnapshotSource::Codex,
        f.candidate(),
        census,
        None,
        365,
        discovery_retention!(index),
    )
    .is_some()
}
fn user_context(label: &str) -> String {
    use sha2::Digest;
    format!(
        "{:x}",
        Sha256::new()
            .chain_update(b"ottto:codex-archive-user-context:v1\0")
            .chain_update(label)
            .finalize()
    )
}
fn synthetic_permission(scan: &mut OwnedSourceScan) {
    scan.index.archive_pass.power = true;
    let mut inventory = codex_file_join::HeaderInventory::new(&[], &BTreeSet::new(), None);
    inventory.archive_work.allowed = true; // synthetic AC + utility QoS, never production activation
    scan.codex_join_inventory = Some(inventory);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn user_setting_generation_redecodes_once_and_internal_churn_does_not() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for _ in 0..2 {
        // Every affected archive owns its own durable generation.
        let f = correction_archive();
        let mut index = ScanIndex::default();
        index.activate_archive_user_context(user_context("titles-on"));
        let (mut index, first, _, _) = archive_pass(&f, index, true, None);
        index.settle_archive_outcome(&ack_bodies(&first), true, None);
        assert!(matches!(
            archive_evidence(&index, &f).disposition,
            ArchiveDisposition::Acquired
        ));
        index.activate_upload_context("internal-cache-capability-churn".into());
        index.activate_archive_user_context(user_context("titles-on"));
        let (_, quiet, rows, _) = archive_pass(&f, index.clone(), true, None);
        assert_eq!(decodes(&rows), 0);
        assert!(quiet.snapshots.is_empty());
        index.activate_archive_user_context(user_context("titles-off"));
        index.activate_upload_context("titles-off".into());
        assert!(archive_evidence(&index, &f).user_change);
        assert!(
            archive_evidence(&index, &f).body_witness.is_none(),
            "old ACK cannot settle a queued correction"
        );
        let (mut index, correction, rows, _) =
            archive_pass_with(&f, index, true, None, &[], synthetic_permission);
        assert_eq!(decodes(&rows), 1);
        assert_eq!(
            rows.iter()
                .filter(|r| r["counts"]["compressed_user_change"] == 1)
                .count(),
            1
        );
        assert!(!rows
            .iter()
            .any(|r| r["stage"] == "codex_zst_first_read_retry"));
        assert!(!correction.snapshots.is_empty());
        index.settle_archive_outcome(&ack_bodies(&correction), true, None);
        assert!(matches!(
            archive_evidence(&index, &f).disposition,
            ArchiveDisposition::Acquired
        ));
        let mut restarted: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        restarted.activate_archive_user_context(user_context("titles-off"));
        let (_, _, rows, _) = archive_pass(&f, restarted, true, None);
        assert_eq!(decodes(&rows), 0);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn correction_waits_for_power_and_a4_keeps_historical_witness_without_decode() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let (mut index, first, _, _) = archive_pass(&f, ScanIndex::default(), true, None);
    index.settle_archive_outcome(&ack_bodies(&first), true, None);
    index.activate_archive_user_context(user_context("A"));
    let old = archive_evidence(&index, &f).body_witness.clone();
    let prior_incidence = index.file_snapshot_fingerprints.clone();
    index.accepted_snapshot_fingerprints = ack_bodies(&first).into_keys().collect();
    let prior_acceptance = index.accepted_snapshot_fingerprints.clone();
    let historical_entry = index.files[&local_index_key(&f.0)]
        .last_upload_body_witness
        .clone();
    index.prepare_historical_replay("unapproved-code-replay".into());
    assert_eq!(index.file_snapshot_fingerprints, prior_incidence);
    assert_eq!(index.accepted_snapshot_fingerprints, prior_acceptance);
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::CorrectionUnapplied
        }
    ));
    assert_eq!(archive_evidence(&index, &f).body_witness, old);
    assert_eq!(
        index.files[&local_index_key(&f.0)].last_upload_body_witness,
        historical_entry
    );
    index.settle_archive_outcome(&ack_bodies(&first), true, None);
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::CorrectionUnapplied
        }
    ));
    let (_, _, rows, _) = archive_pass(&f, index.clone(), true, None);
    assert_eq!(decodes(&rows), 0);
    index.activate_archive_user_context(user_context("B"));
    let (index, result, rows, _) = archive_pass(&f, index, true, None); // no synthetic AC permission
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
    assert!(archive_evidence(&index, &f).user_change);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn transient_attempt_three_continues_and_six_decodes_exhaust_budget() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    for attempt in 1..=6 {
        let (next, body, rows, _) = archive_pass(&f, index, true, None);
        index = next;
        assert_eq!(decodes(&rows), 1);
        assert_eq!(archive_evidence(&index, &f).decode_attempts, attempt);
        if attempt == 1 {
            // A transient EIO is not a sticky content refusal.
            index
                .archive_decode_error(&f.0, &anyhow::Error::new(io::Error::other("synthetic EIO")));
        }
        // Same production settlement callback used by transport Err, Shed and Deferred.
        index.settle_archive_outcome(&BTreeMap::new(), false, None);
        assert_eq!(archive_evidence(&index, &f).terminal_failures, 0);
        if attempt < 6 {
            assert!(matches!(
                archive_evidence(&index, &f).disposition,
                ArchiveDisposition::Pending { .. }
            ));
            if attempt == 3 {
                let mut success = index.clone();
                success.settle_archive_outcome(&ack_bodies(&body), false, None);
                assert!(matches!(
                    archive_evidence(&success, &f).disposition,
                    ArchiveDisposition::Acquired
                ));
            }
            index = checkpoint(&index);
            retry_due(&mut index, &key);
        }
    }
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::DecodeBudget
        }
    ));
    let (_, _, rows, _) = archive_pass(&f, checkpoint(&index), true, None);
    assert_eq!(decodes(&rows), 0);
}

#[test]
fn terminal_failures_count_once_per_attempt_and_late_exact_ack_revives_stuck() {
    let f = ArchiveFixture::new(b"stamp-only");
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    let digest = "b".repeat(64);
    evidence.body_witness = Some(snapshot_file_upload_body_set_hex(BTreeSet::from([&digest])));
    for attempt in 1..=3 {
        evidence.decode_attempts = attempt;
        evidence.disposition = ArchiveDisposition::Pending {
            attempts: attempt,
            retry_after: 0,
        };
        evidence.settle(false, true);
        evidence.settle(false, true);
        assert_eq!(evidence.terminal_failures, attempt);
    }
    assert!(matches!(
        evidence.disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::SettlementStuck
        }
    ));
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["fp".into()]));
    let mut census = ScanCensus::default();
    assert!(!archive_open(&f, &index, &mut census));
    assert!(!census.archive_terminal_sessions.is_empty());
    index.settle_archive_outcome(
        &BTreeMap::from([("fp".into(), "a".repeat(64))]),
        false,
        None,
    );
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Held { .. }
    ));
    index.settle_archive_outcome(&BTreeMap::from([("fp".into(), digest)]), false, None);
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Acquired
    ));
    let mut next_census = ScanCensus::default();
    assert!(!archive_open(&f, &index, &mut next_census));
    assert!(next_census.archive_terminal_sessions.is_empty());
    assert_eq!(next_census.unreadable_path_count, 0);
}

#[test]
fn terminal_archive_residue_skips_only_affected_session_and_pending_still_reduces() {
    let f = ArchiveFixture::new(b"stamp-only");
    let key = local_index_key(&f.0);
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.disposition = ArchiveDisposition::Refused {
        cause: CodexZstCause::DecodeFailed,
    };
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    let mut census = ScanCensus::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(!archive_open(&f, &index, &mut census));
    });
    assert_eq!(census.unreadable_path_count, 0);
    assert_eq!(
        census.archive_terminal_sessions,
        BTreeSet::from(["compressed-fixture".into()])
    );
    assert!(rows.iter().any(
        |r| r["counts"]["archive_terminal_residue"]["CompressedDecodeFailed"] == 1
            && r["counts"]["archive_terminal_residue_session_count"] == 1
    ));
    let root = f.0.parent().unwrap();
    for owner in ["healthy-one", "healthy-two"] {
        let path = root.join(format!("rollout-{owner}.jsonl"));
        fs::write(&path, b"{}\n").unwrap();
        let c = super::super::codex_zst_refusal_tests::candidate(&path);
        assert!(open_and_identify_scan_candidate(
            SnapshotSource::Codex,
            c,
            &mut census,
            None,
            365,
            discovery_retention!(index)
        )
        .is_some());
    }
    assert_eq!(
        census.unreadable_path_count, 0,
        "terminal archive does not poison healthy census"
    );
    let mut metadata = CodexTitleMetadata::default();
    for owner in ["compressed-fixture", "healthy-one", "healthy-two"] {
        metadata.state_threads.insert(
            owner.into(),
            CodexStateThread {
                tokens_used: 10,
                ..Default::default()
            },
        );
    }
    let mut items = Vec::new();
    append_codex_state_only_snapshots(
        &mut items,
        &metadata,
        NOW,
        &mut index,
        &census.archive_terminal_sessions,
    )
    .expect("funded state-only exclusion");
    assert_eq!(
        items
            .iter()
            .map(|i| i.source_session_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["healthy-one", "healthy-two"])
    );
    // Production missing-key reconciliation reuses the same scoped residue set.
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        index,
        NOW,
        365,
        10,
        false,
        None,
        &[],
        false,
        false,
    );
    let t = scan.index.traversal.as_mut().unwrap();
    t.residue.blocked_session_ids = census.archive_terminal_sessions;
    t.reconciliation_upper_bound = Some("z-absent".into());
    scan.index.files.insert(
        "rollout-compressed-fixture.jsonl".into(),
        ScanIndexEntry::default(),
    );
    scan.index
        .files
        .insert("z-absent".into(), ScanIndexEntry::default());
    assert!(reconcile_missing_index_entries_with_limit(
        &mut scan.index,
        100
    ));
    assert!(scan
        .index
        .files
        .contains_key("rollout-compressed-fixture.jsonl"));
    assert!(!scan.index.files.contains_key("z-absent"));
    scan.index
        .files
        .get_mut(&key)
        .unwrap()
        .last_snapshot_fingerprint = None;
    scan.index
        .files
        .get_mut(&key)
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .disposition = ArchiveDisposition::Pending {
        attempts: 2,
        retry_after: u64::MAX,
    };
    let mut pending = ScanCensus::default();
    assert!(!archive_open(&f, &scan.index, &mut pending));
    assert_eq!(pending.unreadable_path_count, 1);
    assert!(pending.archive_terminal_sessions.is_empty());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn rotating_admission_starvation_is_per_archive_and_alarm_reports_source_count() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    STREAKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let a = correction_archive();
    let b = correction_archive();
    let c = correction_archive();
    let keys = [&a, &b, &c].map(|f| local_index_key(&f.0));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let admit = |f: &ArchiveFixture, cache: Option<&Arc<sampled_scan::SharedCache>>| {
        sampled_scan::new_source_parser(
            File::open(&f.0).unwrap(),
            &f.candidate(),
            SnapshotSource::Codex,
            &CodexTitleMetadata::default(),
            None,
            None,
            false,
            false,
            false,
            &mut ScanIndex::default(),
            cache,
        )
    };
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        for pass in 1..=12 {
            assert!(admit(&a, None).is_err());
            assert!(admit(&b, None).is_err());
            admit(&c, Some(&cache)).unwrap().reader.reader.close();
            assert_eq!(admission_starved_count(None), if pass < 12 { 0 } else { 2 });
        }
    });
    assert!(
        (admission_starved_count(Some(&keys[0])) > 0)
            && (admission_starved_count(Some(&keys[1])) > 0)
    );
    assert!(rows
        .iter()
        .any(|r| r["stage"] == "codex_zst_admission_alarm"
            && r["counts"]["admission_starved_count"] == 2));
    let mut census = ScanCensus::default();
    census.archive_failure(&ScanIndex::default(), &a.0, UnreadableCause::Reduction);
    census.archive_failure(&ScanIndex::default(), &b.0, UnreadableCause::Reduction);
    assert_eq!(census.unreadable_path_count, 0);
    admit(&a, Some(&cache)).unwrap().reader.reader.close();
    assert_eq!(admission_starved_count(Some(&keys[0])), 0);
    assert_eq!(admission_starved_count(Some(&keys[1])), 1);
    assert_eq!(admission_starved_count(None), 1);
    let mut after = ScanCensus::default();
    after.archive_failure(&ScanIndex::default(), &a.0, UnreadableCause::Reduction);
    assert_eq!(
        after.unreadable_path_count, 1,
        "A left the admission residue"
    );
    admission_streak(&keys[1], false);
}

#[test]
fn activation_discovers_exact_archive_beside_plain_without_decoding() {
    let before = super::super::codex_zst_refusal_tests::activity().0;
    let f = correction_archive();
    let plain = f.0.with_extension("");
    fs::write(&plain, synthetic_rollout()).unwrap();
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[f.0.parent().unwrap().to_owned()],
        ScanIndex::default(),
        NOW,
        365,
        100,
        false,
        None,
        &[],
        false,
        false,
    );
    let paths = scan
        .identified_candidates
        .iter()
        .map(|c| &c.path)
        .collect::<BTreeSet<_>>();
    assert!(paths.contains(&plain));
    assert!(paths.contains(&f.0));
    assert!(scan
        .index
        .traversal
        .as_mut()
        .unwrap()
        .codex_rollout_paths
        .contains(&local_index_key(&f.0)));
    assert_eq!(super::super::codex_zst_refusal_tests::activity().0, before);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn reservation_crashes_spend_six_attempts_and_retry_counter_requires_saved_reservation() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let path = f.0.parent().unwrap().join("crash-index.json");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut committed = ScanIndex::default();
    committed.save(&path).unwrap();
    for attempt in 1..=6 {
        let mut scan = staged_archive(&f, committed.clone(), Arc::clone(&cache));
        assert_eq!(decoded_in(&scan), 0);
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            scan.persist_archive_reservation(&mut committed, &path)
                .unwrap();
            scan.persist_archive_reservation(&mut committed, &path)
                .unwrap();
        });
        assert_eq!(
            rows.iter()
                .filter(|r| r["stage"] == "codex_zst_first_read_retry")
                .count(),
            usize::from(attempt > 1)
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r["stage"] == "codex_zst_retry_alarm")
                .count(),
            usize::from(attempt > 1)
        );
        scan.active_file
            .take()
            .unwrap()
            .parser
            .reader
            .reader
            .close(); // crash after reservation, before first read
        committed = ScanIndex::load(&path).unwrap();
        assert_eq!(archive_evidence(&committed, &f).decode_attempts, attempt);
        retry_due(&mut committed, &key);
    }
    let (held, _, rows, _) = archive_pass(&f, committed, true, None);
    assert_eq!(decodes(&rows), 0, "attempt seven is refused before funding");
    assert!(matches!(
        archive_evidence(&held, &f).disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::DecodeBudget
        }
    ));
    let other = correction_archive();
    let (mut prior, _, _, _) = archive_pass(&other, ScanIndex::default(), true, None);
    retry_due(&mut prior, &local_index_key(&other.0));
    let mut scan = staged_archive(&other, prior.clone(), cache);
    let blocked = other.0.parent().unwrap().join("not-a-directory");
    fs::write(&blocked, b"fixture").unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        assert!(scan
            .persist_archive_reservation(&mut prior, &blocked.join("index.json"))
            .is_err());
    });
    assert!(!rows
        .iter()
        .any(|r| r["stage"] == "codex_zst_first_read_retry"));
    assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_retry_alarm"));
    assert_eq!(archive_evidence(&prior, &other).decode_attempts, 1);
}

#[test]
fn terminal_session_block_survives_empty_final_census_page() {
    let f = ArchiveFixture::new(b"stamp-only");
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.disposition = ArchiveDisposition::Refused {
        cause: CodexZstCause::DecodeFailed,
    };
    let mut index = ScanIndex::default();
    index
        .files
        .entry(local_index_key(&f.0))
        .or_default()
        .archive = Some(Box::new(evidence));
    assert!(index.codex_state_only_blocked_session_ids.is_empty()); // inventory-refused path never reached parser
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        index,
        NOW,
        365,
        10,
        false,
        None,
        &[],
        false,
        false,
    );
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .residue
        .blocked_session_ids
        .insert("compressed-fixture".into());
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .residue
        .index_keys
        .insert(local_index_key(&f.0));
    scan.codex_join_prepared = true;
    scan.codex_join_inventory = None;
    scan.identified_candidates.clear(); // later page finishes only bounded reconciliation
    for owner in ["compressed-fixture", "healthy-final-page"] {
        scan.codex_title_metadata.state_threads.insert(
            owner.into(),
            CodexStateThread {
                tokens_used: 10,
                ..Default::default()
            },
        );
    }
    assert!(scan.state_census_complete && scan.sidecar_census_complete);
    for _ in 0..1000 {
        scan = match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            OwnedSourceScanStep::Complete { scan: result, .. } => {
                assert!(result.census_complete, "{result:#?}");
                assert_eq!(result.census_residue_blocked_session_count, 1);
                assert_eq!(result.census_residue_index_key_count, 1);
                let owners = result
                    .snapshots
                    .iter()
                    .map(|s| s.source_session_id.as_str())
                    .collect::<BTreeSet<_>>();
                assert_eq!(owners, BTreeSet::from(["healthy-final-page"]));
                return;
            }
        };
    }
    panic!("final census page did not complete");
}

#[test]
fn compressed_removal_hint_keeps_scoped_unknown_without_counting_owner() {
    let f = ArchiveFixture::new(b"stamp-only");
    let key = local_index_key(&f.0);
    assert!(key.ends_with(".jsonl.zst"));
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.disposition = ArchiveDisposition::Held {
        cause: CodexZstCause::OwnerUnproven,
    };
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    assert!(index.files[&key].codex_counting_owner.is_none());
    let healthy = local_index_key(&f.0.parent().unwrap().join("rollout-healthy-retired.jsonl"));
    index
        .files
        .insert(healthy.clone(), ScanIndexEntry::default());
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        index,
        NOW,
        365,
        10,
        false,
        None,
        &[],
        false,
        false,
    );
    let traversal = scan.index.traversal.as_mut().unwrap();
    traversal
        .residue
        .blocked_session_ids
        .insert("compressed-fixture".into());
    assert!(scan.index.archive_scoped_unknown(&key));
    // The logical-id match must work even if no filename candidate names it.
    scan.index
        .files
        .get_mut(&key)
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .logical_id = "validated-logical-id".into();
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .residue
        .blocked_session_ids = BTreeSet::from(["validated-logical-id".into()]);
    assert!(scan.index.archive_scoped_unknown(&key));
    // Then exercise compressed filename fallback independently of logical-id matching.
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .residue
        .blocked_session_ids = BTreeSet::from(["compressed-fixture".into()]);
    assert!(scan.index.archive_scoped_unknown(&key));
    scan.codex_join_prepared = true;
    scan.identified_candidates.clear();
    scan.census
        .removed_index_keys
        .extend([key.clone(), healthy.clone()]);
    for _ in 0..1000 {
        scan = match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            OwnedSourceScanStep::Complete { index, .. } => {
                assert!(index.files[&key].archive.is_some());
                assert!(index.files[&key].codex_counting_owner.is_none());
                assert!(!index.files.contains_key(&healthy));
                return;
            }
        };
    }
    panic!("removal-hint page did not finish");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn crash_lost_terminal_outcomes_stop_at_exactly_six_decodes() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let path = f.0.parent().unwrap().join("outcome-crash-index.json");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut committed = ScanIndex::default();
    committed.save(&path).unwrap();
    let mut total_decodes = 0;
    for attempt in 1..=6 {
        let mut scan = staged_archive(&f, committed.clone(), Arc::clone(&cache));
        assert_eq!(decoded_in(&scan), 0);
        scan.persist_archive_reservation(&mut committed, &path)
            .unwrap();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..1000 {
                scan = match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => next,
                    OwnedSourceScanStep::Complete {
                        mut index,
                        mut scan,
                        ..
                    } => {
                        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                        let submitted = ack_bodies(&scan);
                        assert!(!submitted.is_empty());
                        index.settle_archive_outcome(&BTreeMap::new(), true, Some(&submitted));
                        assert_eq!(archive_evidence(&index, &f).terminal_failures, 1);
                        return; // crash after terminal outcome, before updated index save
                    }
                };
            }
            panic!("archive did not finish");
        });
        assert_eq!(decodes(&rows), 1);
        total_decodes += decodes(&rows);
        committed = ScanIndex::load(&path).unwrap();
        assert_eq!(archive_evidence(&committed, &f).decode_attempts, attempt);
        assert_eq!(archive_evidence(&committed, &f).terminal_failures, 0);
        retry_due(&mut committed, &key);
    }
    let (held, _, rows, _) = archive_pass(&f, committed, true, None);
    assert_eq!(total_decodes, 6);
    assert_eq!(decodes(&rows), 0);
    assert!(matches!(
        archive_evidence(&held, &f).disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::DecodeBudget
        }
    ));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn replaced_archive_uses_new_stamp_first_read_without_old_correction_permission() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let mut state = ScanIndex::default();
    state.activate_archive_user_context(user_context("A"));
    let (mut state, body, _, _) = archive_pass(&f, state, true, None);
    state.settle_archive_outcome(&ack_bodies(&body), true, None);
    state.activate_archive_user_context(user_context("B"));
    assert!(archive_evidence(&state, &f).user_change);
    let original_len = fs::metadata(&f.0).unwrap().len();
    let mut changed = fs::read(&f.0).unwrap();
    changed.extend(zstd::stream::encode_all(&b"\n"[..], 1).unwrap());
    fs::write(&f.0, changed).unwrap();
    assert!(fs::metadata(&f.0).unwrap().len() > original_len);
    assert!(!archive_evidence(&state, &f).matches(&File::open(&f.0).unwrap()));
    let (fresh, body, rows, _) = archive_pass(&f, state, true, None); // no correction power permission
    assert_eq!(decodes(&rows), 1);
    assert!(!body.snapshots.is_empty());
    assert_eq!(archive_evidence(&fresh, &f).decode_attempts, 1);
    assert!(!archive_evidence(&fresh, &f).user_change);
    assert!(!rows
        .iter()
        .any(|r| r["counts"]["compressed_user_change"] == 1));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn correction_ack_debt_survives_restart_without_regranting_full() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.activate_archive_user_context(user_context("A"));
    let (mut index, first, _, _) = archive_pass(&f, index, true, None);
    index.settle_archive_outcome(&ack_bodies(&first), true, None);
    index.activate_archive_user_context(user_context("B"));
    let (mut index, correction, rows, _) =
        archive_pass_with(&f, index, true, None, &[], synthetic_permission);
    assert_eq!(decodes(&rows), 1);
    assert!(!correction.snapshots.is_empty());
    assert_eq!(archive_evidence(&index, &f).user_generation, 1);
    assert_eq!(archive_evidence(&index, &f).user_change_spent, 1);
    // Transport loss / Deferred / Shed hold the same debt without a terminal count.
    let mut deferred = index.clone();
    deferred.settle_archive_outcome(&BTreeMap::new(), false, None);
    assert!(deferred.files[&key].archive.as_ref().unwrap().user_change);
    assert_eq!(archive_evidence(&deferred, &f).terminal_failures, 0);
    // No response/ACK callback at all: persist Pending and expire its deadline on restart.
    let path = f.0.parent().unwrap().join("correction-debt.json");
    index.save(&path).unwrap();
    let mut restored = ScanIndex::load(&path).unwrap();
    retry_due(&mut restored, &key);
    restored.activate_archive_user_context(user_context("B"));
    for _ in 0..5 {
        let (next, result, rows, _) =
            archive_pass_with(&f, restored, true, None, &[], synthetic_permission);
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
        assert_eq!(result.unreadable_path_count, 0);
        assert!(
            archive_evidence(&next, &f).user_change,
            "ACK debt must remain"
        );
        assert!(matches!(
            archive_evidence(&next, &f).disposition,
            ArchiveDisposition::Held {
                cause: CodexZstCause::CorrectionUnapplied
            }
        ));
        restored = ScanIndex::load(&path).unwrap();
        retry_due(&mut restored, &key);
        restored.activate_archive_user_context(user_context("B"));
    }
    let witness = archive_evidence(&restored, &f).body_witness.clone();
    assert!(witness.is_some());
    restored.settle_archive_outcome(
        &BTreeMap::from([("unrelated".into(), "a".repeat(64))]),
        false,
        None,
    );
    assert!(archive_evidence(&restored, &f).user_change);
    restored.settle_archive_outcome(&ack_bodies(&correction), false, None);
    assert!(!archive_evidence(&restored, &f).user_change);
    assert!(matches!(
        archive_evidence(&restored, &f).disposition,
        ArchiveDisposition::Acquired
    ));
    assert_eq!(archive_evidence(&restored, &f).body_witness, witness);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn correction_crash_after_reservation_spends_grant_before_any_byte() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.activate_archive_user_context(user_context("A"));
    let (mut index, first, _, _) = archive_pass(&f, index, true, None);
    index.settle_archive_outcome(&ack_bodies(&first), true, None);
    index.activate_archive_user_context(user_context("B"));
    let path = f.0.parent().unwrap().join("a3-reservation.json");
    index.save(&path).unwrap();
    let mut scan = staged_archive_with(
        &f,
        index.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
        synthetic_permission,
    );
    assert_eq!(decoded_in(&scan), 0);
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        scan.persist_archive_reservation(&mut index, &path).unwrap();
        scan.persist_archive_reservation(&mut index, &path).unwrap();
    });
    assert_eq!(
        rows.iter()
            .filter(|r| r["counts"]["compressed_user_change"] == 1)
            .count(),
        1
    );
    assert_eq!(decoded_in(&scan), 0);
    scan.active_file
        .take()
        .unwrap()
        .parser
        .reader
        .reader
        .close(); // simulated crash before decode
    let mut restored = ScanIndex::load(&path).unwrap();
    assert_eq!(archive_evidence(&restored, &f).user_change_spent, 1);
    assert_eq!(
        archive_evidence(&restored, &f).decode_attempts,
        1,
        "A1 counter unchanged"
    );
    retry_due(&mut restored, &key);
    restored.activate_archive_user_context(user_context("B"));
    let (mut held, result, rows, _) =
        archive_pass_with(&f, restored, true, None, &[], synthetic_permission);
    assert_eq!(decodes(&rows), 0);
    assert!(result.snapshots.is_empty());
    assert!(archive_evidence(&held, &f).user_change);
    assert!(archive_evidence(&held, &f).body_witness.is_none());
    held.settle_archive_outcome(&ack_bodies(&first), false, None);
    assert!(
        archive_evidence(&held, &f).user_change,
        "old ACK never fakes settlement"
    );
    // A later independent setting change remains available despite the spent prior generation.
    held.activate_archive_user_context(user_context("C"));
    let (next, body, rows, _) = archive_pass_with(&f, held, true, None, &[], synthetic_permission);
    assert_eq!(decodes(&rows), 1);
    assert!(!body.snapshots.is_empty());
    assert_eq!(archive_evidence(&next, &f).user_change_spent, 2);
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn sixth_first_read_success_and_repeated_acked_a3_generations_are_independent() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.activate_archive_user_context(user_context("A"));
    for attempt in 1..=6 {
        let (next, body, rows, _) = archive_pass(&f, index, true, None);
        assert_eq!(decodes(&rows), 1);
        index = next;
        if attempt == 6 {
            index.settle_archive_outcome(&ack_bodies(&body), true, None);
        } else {
            index.settle_archive_outcome(&BTreeMap::new(), attempt <= 2, Some(&ack_bodies(&body)));
            index = checkpoint(&index);
            retry_due(&mut index, &key);
        }
    }
    assert!(matches!(
        archive_evidence(&index, &f).disposition,
        ArchiveDisposition::Acquired
    ));
    assert_eq!(archive_evidence(&index, &f).decode_attempts, 6);
    assert_eq!(archive_evidence(&index, &f).terminal_failures, 2);
    for generation in 1..=8 {
        let context = user_context(if generation % 2 == 1 { "B" } else { "A" });
        index.activate_archive_user_context(context.clone());
        let (next, body, rows, _) =
            archive_pass_with(&f, index, true, None, &[], synthetic_permission);
        index = next;
        assert_eq!(decodes(&rows), 1, "grant {generation}");
        assert_eq!(
            rows.iter()
                .filter(|r| r["counts"]["compressed_user_change"] == 1)
                .count(),
            1
        );
        assert!(!rows
            .iter()
            .any(|r| r["stage"] == "codex_zst_first_read_retry"
                || r["stage"] == "codex_zst_retry_alarm"));
        assert_eq!(archive_evidence(&index, &f).decode_attempts, 6);
        assert_eq!(archive_evidence(&index, &f).terminal_failures, 2);
        assert_eq!(archive_evidence(&index, &f).user_change_spent, generation);
        index.settle_archive_outcome(&ack_bodies(&body), true, None);
        assert!(matches!(
            archive_evidence(&index, &f).disposition,
            ArchiveDisposition::Acquired
        ));
        index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        index.activate_archive_user_context(context);
        let (next, _, rows, _) = archive_pass(&f, index, true, None);
        assert_eq!(decodes(&rows), 0);
        index = next;
    }
}

// Partial fields model unreleased intermediate builds, not a released writer.
#[test]
fn missing_spent_fields_and_malformed_context_never_mint_a3_permission() {
    let f = ArchiveFixture::new(b"stamp-only");
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.user_change = true;
    evidence.user_context = Some(user_context("A"));
    let mut old = serde_json::to_value(&evidence).unwrap();
    old.as_object_mut().unwrap().remove("user_generation");
    old.as_object_mut().unwrap().remove("user_change_spent");
    let mut restored: ArchiveEvidence = serde_json::from_value(old.clone()).unwrap();
    assert!(restored.stop_exhausted());
    old["user_generation"] = serde_json::json!(1);
    old["user_context"] = serde_json::json!("synthetic raw text must not survive");
    let restored: ArchiveEvidence = serde_json::from_value(old).unwrap();
    assert!(restored.user_context.is_none());
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(restored));
    index.activate_archive_user_context(user_context("B"));
    let restored = index.files.get_mut(&key).unwrap().archive.as_mut().unwrap();
    assert!(restored.stop_exhausted());
    assert!(!serde_json::to_string(restored)
        .unwrap()
        .contains("synthetic raw text"));
}

#[test]
fn missing_only_spent_generation_is_exhausted_until_an_independent_user_change() {
    let f = ArchiveFixture::new(b"stamp-only");
    let key = local_index_key(&f.0);
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.user_change = true;
    evidence.user_context = Some(user_context("A"));
    evidence.user_generation = 1;
    let mut value = serde_json::to_value(&evidence).unwrap();
    value.as_object_mut().unwrap().remove("user_change_spent");
    let restored: ArchiveEvidence = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(restored.user_change_spent, u64::MAX);
    assert_eq!(restored.user_generation, 1);
    let mut index = ScanIndex::default();
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(restored));
    index.activate_archive_user_context(user_context("A"));
    assert!(index
        .files
        .get_mut(&key)
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .stop_exhausted());
    assert!(archive_evidence(&index, &f).user_change);
    index.activate_archive_user_context(user_context("B"));
    let archive = index.files.get_mut(&key).unwrap().archive.as_mut().unwrap();
    assert_eq!(archive.user_generation, 2);
    assert_eq!(archive.user_change_spent, 1);
    assert!(
        !archive.stop_exhausted(),
        "new independent grant remains available"
    );
    // The other asymmetric missing-field case must also stay closed.
    value["user_change_spent"] = serde_json::json!(1);
    value.as_object_mut().unwrap().remove("user_generation");
    let mut restored: ArchiveEvidence = serde_json::from_value(value).unwrap();
    assert!(restored.stop_exhausted());
}
