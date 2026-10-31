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
    assert_eq!(baseline.snapshots[0].title, ack.title);
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
        let (owner, ledger) = parsed.codex_parent_ownership_ledger.as_ref().unwrap();
        let covers = retained.covers_archive(owner, &ledger.signatures, &usage, usize::MAX);
        assert_eq!(covers, superset);
        assert!(!retained.covers_archive(
            "another-session",
            &ledger.signatures,
            &usage,
            usize::MAX
        ));
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
