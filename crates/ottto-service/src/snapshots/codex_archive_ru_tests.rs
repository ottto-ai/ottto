// R3: exercise the actual quiet, parser-error and native-finish census callers.
fn archive_ru_healthy_sibling(scan: &mut OwnedSourceScan) {
    for owner in ["compressed-fixture", "healthy-ru-sibling"] {
        scan.codex_title_metadata.state_threads.insert(
            owner.into(),
            CodexStateThread {
                tokens_used: 10,
                ..Default::default()
            },
        );
    }
}
fn assert_archive_ru_residue(result: &SourceScanResult, rows: &[Value], cause: CodexZstCause) {
    assert_eq!(result.unreadable_path_count, 0);
    assert!(result.census_complete, "{result:#?}");
    assert_eq!(result.census_residue_blocked_session_count, 1);
    let cause = serde_json::to_value(cause).unwrap();
    assert!(rows
        .iter()
        .any(|r| r["counts"]["archive_terminal_residue"][cause.as_str().unwrap()] == 1));
    assert_eq!(
        result
            .snapshots
            .iter()
            .map(|s| s.source_session_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["healthy-ru-sibling"])
    );
}

/// [behaviour] Unfunded quiet held/refused sites and an unscoped exhausted
/// Pending archive each report one archive residue under their cause, construct
/// no decoder, keep their disposition, and leave the healthy sibling's census
/// work to proceed.
#[test]
fn unfunded_archive_residue_has_no_ru_and_healthy_census_work_proceeds() {
    for (disposition, decode_attempts, cause) in [
        (
            ArchiveDisposition::Held {
                cause: CodexZstCause::OutputHeld,
            },
            0,
            CodexZstCause::OutputHeld,
        ),
        (
            ArchiveDisposition::Refused {
                cause: CodexZstCause::DecodeFailed,
            },
            0,
            CodexZstCause::DecodeFailed,
        ),
        // Without a provable retained scope the constructor defers before
        // stop_exhausted: a retained resend spends no decode budget, so an
        // unscoped pass must not hold it. The scoped DecodeBudget hold is
        // archive_interrupted_decode_budget_sticks_and_content_change_resets_attempts.
        (
            ArchiveDisposition::Pending {
                attempts: 6,
                retry_after: 0,
            },
            6,
            CodexZstCause::OutputHeld,
        ),
    ] {
        let f = ArchiveFixture::new(b"unfunded-stamp-only");
        let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        let kept = serde_json::to_value(&disposition).unwrap();
        evidence.disposition = disposition;
        evidence.decode_attempts = decode_attempts;
        let mut index = ScanIndex::default();
        index
            .files
            .entry(local_index_key(&f.0))
            .or_default()
            .archive = Some(Box::new(evidence));
        let (index, result, rows, _) =
            archive_pass_with(&f, index, false, None, &[], archive_ru_healthy_sibling);
        assert_eq!(decodes(&rows), 0, "no decoder for {cause:?}");
        assert_eq!(
            serde_json::to_value(&archive_evidence(&index, &f).disposition).unwrap(),
            kept,
            "{cause:?} site keeps its disposition"
        );
        assert_archive_ru_residue(&result, &rows, cause);
    }
}

/// [behaviour] A quiet Pending attempt without a current body is disclosed as unreadable each pass,
/// despite historical output.
#[test]
fn quiet_pending_discloses_a_bodyless_current_attempt_despite_historical_output() {
    for current_body in [None, Some("current-body".to_owned())] {
        let f = ArchiveFixture::new(b"quiet-current-stamp-only");
        let key = local_index_key(&f.0);
        let mut archive = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        assert!(
            archive.body_witness.is_none(),
            "begin clears the current body"
        );
        archive.body_witness = current_body.clone();
        assert!(archive.quiet(&File::open(&f.0).unwrap()));
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            ScanIndexEntry {
                source_file_fingerprint: "historical-file".into(),
                last_snapshot_fingerprint: Some("historical-entity".into()),
                last_upload_body_witness: Some("historical-body".into()),
                archive: Some(Box::new(archive)),
                ..Default::default()
            },
        );
        index
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from(["historical-entity".into()]));
        index
            .accepted_snapshot_fingerprints
            .insert("historical-entity".into());
        let path = f.0.parent().unwrap().join("current-pending-index.json");
        for pass in 0..3 {
            index.save(&path).unwrap();
            let (restored, origin) =
                ScanIndex::load_inner(&path, Some(SnapshotSource::Codex)).unwrap();
            assert!(matches!(origin, LoadOrigin::Loaded(_)));
            assert_eq!(
                restored.files[&key].last_snapshot_fingerprint.as_deref(),
                Some("historical-entity")
            );
            // Incomplete traversal counts survive restart and aggregate pages.
            let carried = restored
                .traversal
                .as_ref()
                .map_or(0, |traversal| traversal.counts.unreadable_path_count);
            let new_unreadable = usize::from(current_body.is_none());
            assert_eq!(carried, pass * new_unreadable);
            let (next, result, rows, _) = archive_pass(&f, restored, false, None);
            assert_eq!(decodes(&rows), 0, "quiet means no reacquisition");
            assert_eq!(
                result.unreadable_path_count,
                carried + new_unreadable,
                "each quiet pass adds one current-bodyless disclosure"
            );
            assert_eq!(result.census_complete, current_body.is_some());
            assert_eq!(result.census_residue_blocked_session_count, 0);
            assert!(result.snapshots.is_empty());
            assert!(!rows
                .iter()
                .any(|row| row["stage"] == "archive_terminal_residue"));
            let gauges = rows
                .iter()
                .filter(|row| row["stage"] == "archive_quiet_pending_unacked")
                .map(|row| &row["counts"])
                .collect::<Vec<_>>();
            assert_eq!(
                gauges,
                vec![&serde_json::json!({
                    "archive_quiet_pending_unacked_count": usize::from(current_body.is_some()),
                })],
                "one page gauge contains only the current unACKed-body count"
            );
            assert_eq!(archive_evidence(&next, &f).body_witness, current_body);
            assert_eq!(
                next.files[&key].last_upload_body_witness.as_deref(),
                Some("historical-body")
            );
            index = next;
        }
    }
}

/// [behaviour] A native-finish OutputHeld archive reports its residue while healthy census work
/// proceeds.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "funded decoder needs validated heap layout"
)]
fn native_finish_output_held_has_no_ru_and_healthy_census_work_proceeds() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut bytes = synthetic_rollout();
    bytes.extend_from_slice(b"not-json\n"); // complete frame, known owner, incomplete reduction
    let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
    let (index, result, rows, ends) = archive_pass_with(
        &f,
        ScanIndex::default(),
        true,
        None,
        &[],
        archive_ru_healthy_sibling,
    );
    let evidence = archive_evidence(&index, &f);
    assert_eq!(decodes(&rows), 1);
    assert_eq!(evidence.owner.as_deref(), Some("compressed-fixture"));
    assert!(evidence.header_validated.is_some());
    assert!(matches!(
        evidence.disposition,
        ArchiveDisposition::Held {
            cause: CodexZstCause::OutputHeld
        }
    ));
    assert!(!ends
        .0
        .lock()
        .unwrap()
        .contains(&super::super::line_delivery::DeliveryEnd::Complete));
    assert_archive_ru_residue(&result, &rows, CodexZstCause::OutputHeld);
}

/// [behaviour] Admission starvation of a new archive yields in C's header
/// path, before any parser exists: every pass stays deferred debt (no
/// unreadable count, no residue), and the archive's own twelfth yield alarms
/// once and marks it starved.
#[test]
fn parser_admission_ru_ends_at_own_twelfth_yield() {
    let _lock = ARCHIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let f = correction_archive();
    let key = local_index_key(&f.0);
    // One process cache whose single decoder is taken (where funding exists).
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let busy = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
        .ok()
        .flatten();
    let mut alarms = 0;
    for _ in 1..=12 {
        let (_, result, rows, _) = archive_pass_in(
            &f,
            ScanIndex::default(),
            Some(cache.clone()),
            None,
            &[],
            archive_ru_healthy_sibling,
        );
        assert_eq!(decodes(&rows), 0);
        assert_eq!(result.unreadable_path_count, 0);
        assert!(!result.census_complete);
        assert!(!rows
            .iter()
            .any(|r| r["stage"] == "archive_terminal_residue"));
        alarms += rows
            .iter()
            .filter(|r| r["stage"] == "codex_zst_admission_alarm")
            .count();
    }
    assert_eq!(alarms, 1);
    assert_eq!(cache.archive_starved_count(Some(&key)), 1);
    if let Some(busy) = busy {
        busy.close();
    }
}

/// [behaviour] Parser errors without an admission yield or bodyless Pending add no generic residue.
#[test]
fn parser_errors_without_admission_yield_or_bodyless_pending_have_no_generic_ru() {
    let f = ArchiveFixture::new(b"classification-only");
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    let mut census = ScanCensus::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        census.archive_parser_failure(
            None,
            SnapshotSource::Codex,
            &index,
            &f.0,
            &anyhow::anyhow!("synthetic construction failure"),
        );
    });
    assert_eq!(census.unreadable_path_count, 0);
    assert!(rows
        .iter()
        .any(|r| r["counts"]["archive_terminal_residue"]["CompressedConstructorUnfunded"] == 1));
    let mut evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
    assert!(evidence.body_witness.is_none());
    index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence.clone()));
    let mut pending = ScanCensus::default();
    pending.archive_parser_failure(
        None,
        SnapshotSource::Codex,
        &index,
        &f.0,
        &anyhow::anyhow!("synthetic pending failure"),
    );
    assert_eq!(
        pending.unreadable_path_count, 1,
        "only bodyless Pending qualifies"
    );
    evidence.body_witness = Some("a".repeat(64));
    index.files.get_mut(&key).unwrap().archive = Some(Box::new(evidence));
    let mut body_retained = ScanCensus::default();
    body_retained.archive_parser_failure(
        None,
        SnapshotSource::Codex,
        &index,
        &f.0,
        &anyhow::anyhow!("synthetic owed-body failure"),
    );
    assert_eq!(body_retained.unreadable_path_count, 0);
}

/// [behaviour] Scoped header and constructor failures keep the witness without a terminal archive
/// marker.
#[test]
fn scoped_header_and_constructor_failures_survive_witness_without_terminal_archive_marker() {
    for cause in [
        CodexZstCause::HeaderInvalid,
        CodexZstCause::ConstructorUnfunded,
    ] {
        let f = ArchiveFixture::new(b"witness-boundary-only");
        let key = local_index_key(&f.0);
        let mut index = ScanIndex::default();
        if cause == CodexZstCause::HeaderInvalid {
            // Inventory's failed first-line state; no Held/Refused marker exists.
            let mut evidence =
                ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
            evidence.disposition = ArchiveDisposition::HeaderValidated;
            evidence.header_attempted = true;
            evidence.decode_attempts = 0;
            assert!(evidence.terminal_cause().is_none());
            index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        } else {
            assert!(!index.files.contains_key(&key));
        }
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
        scan.codex_join_prepared = true;
        scan.identified_candidates.clear();
        archive_ru_healthy_sibling(&mut scan);
        scan.census.observed_index_keys.insert(key.clone());
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            if cause == CodexZstCause::HeaderInvalid {
                scan.census
                    .archive_residue(&f.0, archive_evidence(&scan.index, &f).into(), cause);
            } else {
                scan.census.archive_parser_failure(
                    None,
                    SnapshotSource::Codex,
                    &scan.index,
                    &f.0,
                    &anyhow::anyhow!("synthetic constructor failure"),
                );
            }
        });
        for step in 0..1000 {
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                OwnedSourceScanStep::Complete {
                    scan: result,
                    index,
                    ..
                } => {
                    assert_archive_ru_residue(&result, &rows, cause);
                    assert!(index
                        .scan_residue_witness
                        .as_ref()
                        .unwrap()
                        .index_keys
                        .contains(&key));
                    break;
                }
            };
            assert_ne!(step, 999, "witness census did not finish");
        }
    }
}
