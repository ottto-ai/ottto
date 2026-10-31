// The decoder/selector fixtures are shared with the existing archive suites.

/// [money] The native identity superset replaces the same accepted session;
/// removing an accepted response/checkpoint keeps the old head instead.
#[test]
fn archive_replacement_requires_equal_session_and_accepted_identity_superset() {
    let bytes = synthetic_rollout();
    let metadata = CodexTitleMetadata {
        titles: BTreeMap::from([(
            "compressed-fixture".into(),
            CodexTitleCandidate {
                title: "Synthetic accepted title".into(),
                source: "session_index".into(),
            },
        )]),
        ..Default::default()
    };
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let plain = f.0.with_extension("");
    fs::write(&plain, &bytes).unwrap();
    let mut parser = codex_parser(OpenedInput::plain(File::open(&plain).unwrap()), &plain);
    let expected =
        opened_object_identity(SnapshotSource::Codex, parser.reader.reader.get_mut()).unwrap();
    while !parser.step().unwrap() {}
    let retained = parser.durable_test_reduction_copy();
    let parsed = parser
        .finish(
            &expected,
            &plain,
            NOW,
            "plain-baseline".into(),
            Some(&metadata),
            None,
            None,
        )
        .unwrap();
    assert_eq!(parsed.snapshots.len(), 1);
    let ack = parsed.snapshots[0].clone();
    let baseline = retained.clone().into_archive_baseline(
        &local_index_key(&plain),
        &ScanIndexEntry {
            source_file_fingerprint: "plain-baseline".into(),
            last_snapshot_fingerprint: Some(ack.snapshot_fingerprint.clone()),
            ..Default::default()
        },
        "compressed-fixture",
        &metadata,
    );
    assert_eq!(
        ack.session_display_name.as_deref(),
        Some("Synthetic accepted title")
    );
    assert_eq!(
        baseline.snapshots[0].session_display_name,
        ack.session_display_name
    );
    assert_eq!(
        baseline.snapshots[0].snapshot_fingerprint,
        ack.snapshot_fingerprint
    );

    for superset in [true, false] {
        let mut lines: Vec<Value> = String::from_utf8(bytes.clone())
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        if !superset {
            lines.remove(1);
        }
        lines.push(json!({"type":"event_msg","timestamp":"2026-10-07T10:01:00Z","payload":{"type":"token_count","info":{"model":"gpt-synthetic","total_token_usage":{"input_tokens":900,"output_tokens":90},"last_token_usage":{"input_tokens":900,"output_tokens":90}}}}));
        let extended = lines
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>();
        fs::write(
            &f.0,
            zstd::stream::encode_all(extended.as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let input = OpenedInput::compressed(
            File::open(&f.0).unwrap(),
            u64::MAX,
            compressed_input_credit().unwrap(),
        )
        .unwrap();
        let mut parser = codex_parser(input, &f.0);
        let expected =
            opened_object_identity(SnapshotSource::Codex, parser.reader.reader.get_mut()).unwrap();
        while !parser.step().unwrap() {}
        let usage = parser.accumulator.accepted_usage_totals.clone();
        let parsed = parser
            .finish(
                &expected,
                &f.0,
                NOW,
                "archive-replacement".into(),
                Some(&metadata),
                None,
                None,
            )
            .unwrap();
        // Same bytes through the ordinary native reader are the cold money
        // oracle. Placement absence is compared too; this is reader parity,
        // not a tagged-account or selector-level Replace positive control.
        fs::write(&plain, &extended).unwrap();
        let mut cold_parser = codex_parser(OpenedInput::plain(File::open(&plain).unwrap()), &plain);
        let cold_identity =
            opened_object_identity(SnapshotSource::Codex, cold_parser.reader.reader.get_mut())
                .unwrap();
        while !cold_parser.step().unwrap() {}
        let cold = cold_parser
            .finish(
                &cold_identity,
                &plain,
                NOW,
                "plain-oracle".into(),
                Some(&metadata),
                None,
                None,
            )
            .unwrap();
        let mut cold_scan = SourceScanResult::empty(SnapshotSource::Codex);
        cold_scan.snapshots = cold.snapshots;
        let mut archive_scan = SourceScanResult::empty(SnapshotSource::Codex);
        archive_scan.snapshots = parsed.snapshots.clone();
        let oracle_index = ScanIndex::default();
        use super::super::sampled_scan::transition_fixture::{money_oracle, scan_money};
        money_oracle::assert_equivalent(
            &scan_money(SnapshotSource::Codex, &oracle_index, &cold_scan),
            &scan_money(SnapshotSource::Codex, &oracle_index, &archive_scan),
        );
        let (owner, ledger) = parsed.codex_parent_ownership_ledger.as_ref().unwrap();
        let covers = matches!(
            retained.compare_archive(owner, &ledger.signatures, &usage, usize::MAX),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
        );
        assert_eq!(covers, superset);
        assert!(retained
            .compare_archive("another-session", &ledger.signatures, &usage, usize::MAX)
            .is_none());
        let mut heads = BTreeMap::from([(ack.source_session_id.clone(), ack.clone())]);
        if covers {
            assert_eq!(parsed.snapshots.len(), 1);
            let replacement = parsed.snapshots.into_iter().next().unwrap();
            assert!(replacement.input_tokens >= ack.input_tokens);
            heads.insert(replacement.source_session_id.clone(), replacement);
        }
        assert_eq!(
            heads.len(),
            1,
            "replacement is one session head, never additive"
        );
        if !superset {
            assert_eq!(heads[&ack.source_session_id].input_tokens, ack.input_tokens);
        }
    }
}

/// [money] Attempted typed custody spends at most one funded decode per saved
/// retry and cannot clear an independent user-policy correction grant.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn typed_archive_custody_retry_is_funded_counted_and_six_hour_paced() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    evidence.disposition = ArchiveDisposition::Held {
        cause: CodexZstCause::OwnerUnproven,
    };
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
    index.hold_compressed(
        &f.0,
        BTreeSet::from(["compressed-fixture".into()]),
        CodexZstCause::OwnerUnproven,
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let ((index, first), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(&f, index, cache.clone()))
    });
    assert_eq!(first.snapshots.len(), 1);
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read_retry"), 1);
    let attempt = index.files[&key].archive.as_ref().unwrap().decode_attempts;
    let ((mut quiet, second), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector(retained_archive_scan(&f, index, cache))
    });
    assert!(second.snapshots.is_empty());
    assert_eq!(decoded_archive_bytes(&rows), 0);
    assert_eq!(
        quiet.files[&key].archive.as_ref().unwrap().decode_attempts,
        attempt
    );
    assert!(
        quiet.accepted_snapshot_fingerprints.is_empty(),
        "no ACK from retry completion"
    );
    let entry = quiet.files.get_mut(&key).unwrap();
    entry.codex_compressed_hold = Some(CodexZstCause::OwnerUnproven);
    entry.archive.as_mut().unwrap().user_change = true;
    assert!(
        !entry.custody_retry_due(&f.0),
        "A2 cannot renew an A3 grant"
    );
}

/// [money] A prior total-size hold resumes through normal page steps and
/// retains all usage; the existing input carrier publishes only size counts.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn catchup_size_custody_pages_to_complete_usage_and_counts_decoded_size() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut bytes = synthetic_rollout();
    let padding = json!({"type":"unknown","padding":"x".repeat(1024)}).to_string() + "\n";
    for _ in 0..1280 {
        bytes.extend_from_slice(padding.as_bytes());
    }
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.hold_compressed(
        &f.0,
        BTreeSet::from(["compressed-fixture".into()]),
        CodexZstCause::CatchupTooLarge,
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut pages = 0;
    let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
        finish_selector_with(retained_archive_scan(&f, index, cache), |_| pages += 1)
    });
    assert!(pages > 1);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(result.snapshots[0].input_tokens, 750);
    assert!(index.files[&key].codex_compressed_hold.is_none());
    assert_eq!(archive_event_count(&rows, "codex_zst_first_read"), 1);
    assert!(rows
        .iter()
        .any(|row| row["counts"]["codex_zst_decoded_size"]["lt_16_mib"] == 1));
}

/// [money] An accepted plain superset ends archive custody without emitting a
/// second head; the terminal cause and the original ACK survive a cold restart.
/// A divergent resumed body keeps custody even when its final cumulative is
/// below the later history_base file's first total: the base was not emitted.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
fn accepted_plain_superset_settles_archive_dominated_without_upload() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use super::super::sampled_scan::transition_fixture::{money_oracle, scan_money, Accepted};
    for (divergent, equal) in [(false, false), (false, true), (true, false)] {
        let bytes = synthetic_rollout();
        let mut archive_rows: Vec<Value> = String::from_utf8(bytes.clone())
            .unwrap()
            .lines()
            .take(if equal { usize::MAX } else { 3 })
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if divergent {
            for (row, n) in archive_rows[1..].iter_mut().zip([50_u64, 70]) {
                let usage =
                    json!({"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10});
                row["payload"]["info"]["total_token_usage"] = usage.clone();
                row["payload"]["info"]["last_token_usage"] = usage;
            }
        }
        let subset = archive_rows
            .iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>();
        let f = ArchiveFixture::new(&zstd::stream::encode_all(subset.as_bytes(), 1).unwrap());
        let plain = f.0.with_extension("");
        let mut plain_rows: Vec<Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if divergent {
            plain_rows[0]["payload"]["history_base"] = json!({"thread_id":"compressed-fixture"});
            // Nonzero inherited base + local running usage, on every component.
            // Last-response counters stay unchanged, so emitted input stays750.
            for (field, base) in [
                ("input_tokens", 1000_u64),
                ("cached_input_tokens", 500),
                ("output_tokens", 100),
            ] {
                let mut cumulative = base;
                for row in &mut plain_rows[1..] {
                    cumulative += row["payload"]["info"]["last_token_usage"][field]
                        .as_u64()
                        .unwrap();
                    row["payload"]["info"]["total_token_usage"][field] = json!(cumulative);
                }
                assert!(
                    plain_rows[1]["payload"]["info"]["total_token_usage"][field]
                        .as_u64()
                        .unwrap()
                        >= archive_rows.last().unwrap()["payload"]["info"]["total_token_usage"]
                            [field]
                            .as_u64()
                            .unwrap()
                );
            }
        }
        fs::write(
            &plain,
            plain_rows
                .iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut member = super::super::codex_zst_refusal_tests::candidate(&plain);
        member.size_bytes = fs::metadata(&plain).unwrap().len();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([member.clone()]),
            true,
        );
        scan.state_census_complete = true;
        scan.sidecar_census_complete = true;
        let (mut index, accepted) = finish_selector(scan);
        assert_eq!(accepted.snapshots.len(), 1);
        assert_eq!(accepted.snapshots[0].input_tokens, 750);
        let mut prior = scan_money(SnapshotSource::Codex, &index, &accepted);
        let ack = accepted.snapshots[0].snapshot_fingerprint.clone();
        index.accepted_snapshot_fingerprints.insert(ack.clone());
        let plain_key = local_index_key(&plain);
        let prior_body = index.files[&plain_key].last_upload_body_witness.clone();
        let prior_head = index.files[&plain_key].last_snapshot_fingerprint.clone();
        let accepted_body = Accepted {
            body: serde_json::to_value(&accepted.snapshots[0]).unwrap(),
            witness: prior_body.clone().unwrap(),
        };
        prior
            .accepted
            .insert("compressed-fixture".into(), accepted_body.clone());
        // An independent ordinary Full supplies the emitted sibling oracle.
        // It must keep flowing beside held/terminal archive custody.
        let sibling = plain.parent().unwrap().join("rollout-healthy.jsonl");
        fs::write(
            &sibling,
            String::from_utf8(synthetic_rollout())
                .unwrap()
                .replace("compressed-fixture", "healthy"),
        )
        .unwrap();
        let sibling_key = local_index_key(&sibling);
        let mut healthy = super::super::codex_zst_refusal_tests::candidate(&sibling);
        healthy.size_bytes = fs::metadata(&sibling).unwrap().len();
        let mut cold_scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([healthy.clone()]),
            true,
        );
        cold_scan.state_census_complete = true;
        cold_scan.sidecar_census_complete = true;
        let (cold_index, cold_output) = finish_selector(cold_scan);
        assert_eq!(cold_output.snapshots.len(), 1);
        assert_eq!(cold_output.snapshots[0].input_tokens, 750);
        let cold_sibling = scan_money(SnapshotSource::Codex, &cold_index, &cold_output);
        let committed = index.clone();
        let key = local_index_key(&f.0);
        let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        evidence.header_validated =
            ValidatedHeader::from_bytes(subset.lines().next().unwrap().as_bytes());
        evidence.owner = Some("compressed-fixture".into());
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        index.hold_compressed(
            &f.0,
            BTreeSet::from(["compressed-fixture".into()]),
            CodexZstCause::ArchiveEquivalenceUnproven,
        );
        retry_due(&mut index, &key);
        let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
            let mut scan = selector_scan(
                &f,
                index,
                cache,
                VecDeque::from([member, healthy, f.candidate()]),
                true,
            );
            scan.state_census_complete = true;
            scan.sidecar_census_complete = true;
            finish_selector(scan)
        });
        assert_eq!(result.snapshots.len(), 1, "only the healthy sibling emits");
        assert_eq!(result.snapshots[0].source_session_id, "healthy");
        let mut held = scan_money(SnapshotSource::Codex, &index, &result);
        held.accepted.insert(
            "compressed-fixture".into(),
            Accepted {
                body: accepted_body.body.clone(),
                witness: index.files[&plain_key]
                    .last_upload_body_witness
                    .clone()
                    .unwrap(),
            },
        );
        // Scope the global per-file diagnostic inventory to the independently
        // scanned sibling; held-owner head/body evidence is checked below.
        held.codex_evidence["TierReplay"]
            .as_object_mut()
            .unwrap()
            .retain(|key, _| key == &sibling_key);
        assert_eq!(
            held.codex_evidence["TierReplay"].as_object().unwrap().len(),
            1
        );
        if divergent {
            money_oracle::assert_held("compressed-fixture", &prior, &held, &cold_sibling);
        } else {
            money_oracle::assert_no_smaller_reemit(
                "compressed-fixture",
                &prior,
                &held,
                &cold_sibling,
                true,
            );
        }
        let archive = index.files[&key].archive.as_ref().unwrap();
        if divergent {
            assert_eq!(
                index.files[&key].codex_compressed_hold,
                Some(CodexZstCause::ArchiveEquivalenceUnproven)
            );
            assert!(matches!(
                archive.disposition,
                ArchiveDisposition::Pending { .. }
            ));
            assert!(rows
                .iter()
                .any(|r| r["stage"] == "codex_zst_admission_alarm"
                    && r["counts"]["archive_equivalence_unproven"] == 1));
        } else {
            assert!(matches!(
                archive.disposition,
                ArchiveDisposition::Refused {
                    cause: CodexZstCause::ArchiveDominated
                }
            ));
        }
        if !divergent {
            assert!(index.files[&key].codex_compressed_hold.is_none());
            assert_eq!(result.census_residue_index_key_count, 0);
            assert_eq!(result.census_residue_archived_rollout_count, 0);
        }
        assert!(archive.body_witness.is_none());
        assert_eq!(index.files[&plain_key].last_upload_body_witness, prior_body);
        assert_eq!(
            index.files[&plain_key].last_snapshot_fingerprint,
            prior_head
        );
        assert!(index.accepted_snapshot_fingerprints.contains(&ack));
        if !divergent {
            assert!(rows
                .iter()
                .any(|r| r["counts"]["archive_terminal_residue"]["archive_dominated"] == 1));
        }
        let ((saved, quiet), rows) = crate::local_resource_diagnostics::capture(|| {
            finish_selector(retained_archive_scan(
                &f,
                serde_json::from_slice(
                    &serde_json::to_vec(&index.committable_subset_with_local_holds(
                        &committed,
                        &BTreeSet::new(),
                        &BTreeMap::new(),
                        &BTreeSet::new(),
                    ))
                    .unwrap(),
                )
                .unwrap(),
                Arc::new(sampled_scan::SharedCache::default()),
            ))
        });
        assert!(quiet.snapshots.is_empty());
        assert_eq!(
            saved.files[&plain_key].last_snapshot_fingerprint,
            prior_head
        );
        assert_eq!(saved.files[&plain_key].last_upload_body_witness, prior_body);
        let mut quiet_route = scan_money(SnapshotSource::Codex, &saved, &quiet);
        // The index stores the exact accepted witness; the historical body
        // comes from the accepted emission, never from a new held emission.
        quiet_route.accepted.insert(
            "compressed-fixture".into(),
            Accepted {
                body: accepted_body.body,
                witness: saved.files[&plain_key]
                    .last_upload_body_witness
                    .clone()
                    .unwrap(),
            },
        );
        money_oracle::assert_held("compressed-fixture", &prior, &quiet_route, &prior);
        assert_eq!(decoded_archive_bytes(&rows), 0);
        assert!(saved.accepted_snapshot_fingerprints.contains(&ack));
        if divergent {
            assert_eq!(
                saved.files[&key].codex_compressed_hold,
                Some(CodexZstCause::ArchiveEquivalenceUnproven)
            );
            assert!(matches!(
                saved.files[&key].archive.as_ref().unwrap().disposition,
                ArchiveDisposition::Pending { .. }
            ));
        } else {
            assert!(matches!(
                saved.files[&key].archive.as_ref().unwrap().disposition,
                ArchiveDisposition::Refused {
                    cause: CodexZstCause::ArchiveDominated
                }
            ));
        }
    }
}

/// [money] A permanently absent parent uses the same native disclosed loss for
/// plain and compressed children. No raw/exclusive body or ACK is invented.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
fn unresolved_archive_parent_uses_plain_native_loss_and_counted_retry() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let parent = "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb";
    let mut rows: Vec<Value> = String::from_utf8(synthetic_rollout())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    rows[0]["payload"]["forked_from_id"] = json!(parent);
    let bytes = rows
        .iter()
        .map(|row| row.to_string() + "\n")
        .collect::<String>();
    let f = ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
    let plain = f.0.with_extension("");
    fs::write(&plain, &bytes).unwrap();
    let witness = CodexParentOwnershipLedger {
        unresolvable: Some(CodexParentUnresolvable::Absent),
        ..Default::default()
    };
    let ledgers = Arc::new(Mutex::new(BTreeMap::from([(parent.to_owned(), witness)])));
    let mut parser = codex_parser(OpenedInput::plain(File::open(&plain).unwrap()), &plain);
    parser.accumulator.codex_parent_ownership_ledgers = Some(ledgers.clone());
    let expected =
        opened_object_identity(SnapshotSource::Codex, parser.reader.reader.get_mut()).unwrap();
    while !parser.step().unwrap() {}
    let native = parser
        .finish(
            &expected,
            &plain,
            NOW,
            "plain-parent-loss".into(),
            Some(&CodexTitleMetadata::default()),
            None,
            None,
        )
        .unwrap();
    assert!(native.non_progressing_residue());
    assert_eq!(
        native.codex_parent_unresolvable,
        Some(CodexParentUnresolvable::Absent)
    );
    assert!(native.snapshots.is_empty());
    fs::remove_file(&plain).unwrap();
    let (mut index, result, _, ends) =
        archive_pass_with(&f, ScanIndex::default(), true, None, &[], |scan| {
            scan.codex_parent_ownership_ledgers = Some(ledgers.clone());
        });
    assert!(result.snapshots.is_empty());
    assert!(result.ownership_incomplete_file_count > 0);
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    let key = local_index_key(&f.0);
    assert!(
        index.files[&key].codex_compressed_hold.is_none(),
        "native parent loss reaches shared settlement"
    );
    assert_pending(&index, &f.0, 1);
    assert!(index.files[&key]
        .archive
        .as_ref()
        .unwrap()
        .body_witness
        .is_none());
    assert_eq!(
        result
            .local_codex_diagnostics
            .as_ref()
            .unwrap()
            .parent_unresolvable
            .counts()[CodexParentUnresolvable::Absent.index()],
        1
    );
    assert!(!ends
        .0
        .lock()
        .unwrap()
        .contains(&super::super::line_delivery::DeliveryEnd::Complete));
    let (_, quiet, diagnostics, _) = archive_pass(&f, checkpoint(&index), true, None);
    assert!(quiet.snapshots.is_empty());
    assert_eq!(decoded_archive_bytes(&diagnostics), 0);
    retry_due(&mut index, &key);
    let (retried, loss, diagnostics, ends) =
        archive_pass_with(&f, checkpoint(&index), true, None, &[], |scan| {
            scan.codex_parent_ownership_ledgers = Some(ledgers);
        });
    // This is the ordinary due-Pending path, not terminal-custody eligibility.
    assert_eq!(
        diagnostics
            .iter()
            .filter(|r| r["stage"] == "codex_zst_input")
            .count(),
        1
    );
    assert_pending(&retried, &f.0, 2);
    assert!(loss.snapshots.is_empty());
    assert!(retried.accepted_snapshot_fingerprints.is_empty());
    assert!(retried.files[&key]
        .archive
        .as_ref()
        .unwrap()
        .body_witness
        .is_none());
    assert_eq!(
        loss.local_codex_diagnostics
            .as_ref()
            .unwrap()
            .parent_unresolvable
            .counts()[CodexParentUnresolvable::Absent.index()],
        1
    );
    assert!(!ends
        .0
        .lock()
        .unwrap()
        .contains(&super::super::line_delivery::DeliveryEnd::Complete));
}
