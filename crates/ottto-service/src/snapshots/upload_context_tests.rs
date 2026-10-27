use super::*;

fn candidate(key: &str) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic"),
        path: PathBuf::from(key),
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: format!("source:{key}"),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    }
}

fn empty_scan(source: SnapshotSource) -> SourceScanResult {
    SourceScanResult {
        source,
        backfill_window_days: 0,
        backfill_file_limit: 0,
        discovered_file_count: 0,
        skipped_file_count_due_to_limit: 0,
        scan_cap_hit: false,
        scanned_file_count: 0,
        scanned_session_count: 0,
        semantic_noop_count: 0,
        census_complete: false,
        census_window_end: "2026-10-06T12:00:00Z".into(),
        state_census_complete: false,
        sidecar_census_complete: false,
        symlink_rejected_count: 0,
        directory_entry_cap_exceeded_count: 0,
        unreadable_path_count: 0,
        oversized_file_count: 0,
        disappeared_file_count: 0,
        malformed_json_line_count: 0,
        invalid_utf8_line_count: 0,
        over_line_cap_count: 0,
        recognized_usage_drop_count: 0,
        ownership_incomplete_file_count: 0,
        zero_snapshot_confirmed_count: 0,
        zero_snapshot_usage_evidence_count: 0,
        dropped_usage_record_count: 0,
        terminal_ownership_incomplete_file_count: 0,
        terminal_zero_snapshot_usage_evidence_count: 0,
        terminal_recognized_usage_drop_count: 0,
        terminal_dropped_usage_record_count: 0,
        terminal_over_line_cap_count: 0,
        census_residue_index_key_count: 0,
        census_residue_archived_rollout_count: 0,
        census_residue_blocked_session_count: 0,
        snapshots: Vec::new(),
        pending_finalization: Vec::new(),
        local_codex_diagnostics: None,
        codex_counting_v2: None,
        codex_join_validation: None,
        codex_legacy_join_baselines: Vec::new(),
        claude_request_census_shadow: None,
        continuation_ticket: None,
        continuation_committed: false,
    }
}

pub(crate) fn project(
    index: &mut ScanIndex,
    source: SnapshotSource,
    key: &str,
    empty: bool,
) -> SourceScanResult {
    let file = candidate(key);
    let mut scan = empty_scan(source);
    if !empty {
        for ordinal in 0..2 {
            let mut item = cache_adapter_tests::cache_fixture_item();
            item.source_session_id = format!("session-{key}-{ordinal}");
            item.source_file_fingerprint = Some(file.source_file_fingerprint.clone());
            scan.snapshots.push(item);
        }
    }
    scan.pending_finalization.push(PendingIndexFinalization {
        sampled_audit_verified: false,
        codex_pending_recovery: false,
        index_key: key.into(),
        source_file_fingerprint: file.source_file_fingerprint.clone(),
        previous_snapshot_fingerprint: None,
        previous_upload_body_witness: None,
        parse_complete: true,
        diagnostic_reason: FileReason::Complete,
        parsed_snapshot_count: scan.snapshots.len(),
        effective_upload_body_witness_revision: 0,
        upload_context_candidate: None,
    });
    index.record(file, None, ScanParseOutcome::Unknown);
    finalize_scan_after_policy(source, &mut scan, index);
    scan
}

fn acks(scan: &SourceScanResult) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let bodies = scan.pending_finalization[0]
        .upload_context_candidate
        .as_ref()
        .unwrap()
        .entities
        .clone();
    (bodies.keys().cloned().collect(), bodies)
}

pub(crate) fn accept_fixture(index: &mut ScanIndex, scan: &SourceScanResult) {
    let bodies = scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let accepted = bodies.keys().cloned().collect();
    index.record_accepted_snapshot_fingerprints(&accepted);
    index.settle_upload_contexts(scan, &accepted, &bodies, &BTreeSet::new());
}

pub(crate) fn assert_context(index: &ScanIndex, key: &str, expected: Option<&str>) {
    assert_eq!(
        index.settled_upload_context(&index.files[key]),
        expected.map(|context| Sha256::digest(context.as_bytes()).into())
    );
}

#[test]
fn context_ack_matrix_requires_every_exact_body_and_never_accepts_capture_or_holds() {
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        for outcome in [
            "accepted",
            "unchanged-stored",
            "pending",
            "conflict",
            "permanent",
            "not-stored",
            "fingerprint-only",
            "withheld",
            "request-owned",
            "telemetry-unread",
            "capture",
            "context-changed",
        ] {
            let key = "/synthetic/file.jsonl";
            let mut index = ScanIndex::default();
            index.activate_upload_context("A".into());
            let scan = project(&mut index, source, key, false);
            assert_context(&index, key, None); // Finalize never grants acceptance.
            let (mut accepted, mut bodies) = acks(&scan);
            let fp = accepted.first().unwrap().clone();
            let mut held = BTreeSet::new();
            match outcome {
                "pending" | "conflict" | "permanent" | "not-stored" => {
                    accepted.remove(&fp);
                }
                "fingerprint-only" => {
                    bodies.remove(&fp);
                }
                "withheld" => {
                    held.insert(fp.clone());
                }
                "request-owned" | "telemetry-unread" => {
                    index.claude_history_emission.files.insert(
                        candidate(key).source_file_fingerprint,
                        claude_history_upgrade::GatedHistory {
                            index_key: key.into(),
                            literal_denied: outcome == "request-owned",
                            held: (outcome == "telemetry-unread")
                                .then_some(HistoryHold::TelemetryUnread),
                            ..Default::default()
                        },
                    );
                }
                "capture" => index.files.get_mut(key).unwrap().codex_captured_uncommitted = true,
                "context-changed" => index.activate_upload_context("B".into()),
                _ => {}
            }
            if outcome == "conflict" {
                bodies.insert(fp.clone(), "different-body".into());
            }
            if outcome == "permanent" {
                index
                    .quarantined_snapshot_fingerprints
                    .insert(fp, snapshot_quarantine_record(source));
            }
            index.settle_upload_contexts(&scan, &accepted, &bodies, &held);
            assert_context(
                &index,
                key,
                matches!(outcome, "accepted" | "unchanged-stored").then_some("A"),
            );
        }
    }
}

#[test]
fn accepted_sibling_escapes_global_latch_across_restart_and_a_b_a() {
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let root =
            std::env::temp_dir().join(format!("ottto-s15a-{:?}-{}", source, std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("index.json");
        let _ = fs::remove_file(&path);
        let mut index = ScanIndex::default();
        index.activate_upload_context("A".into());
        for key in ["/synthetic/accepted.jsonl", "/synthetic/held.jsonl"] {
            let scan = project(&mut index, source, key, false);
            let (accepted, bodies) = acks(&scan);
            index.settle_upload_contexts(&scan, &accepted, &bodies, &BTreeSet::new());
        }
        index.upload_context_fingerprint = Some("A".into());
        index.activate_upload_context("B".into());
        let accepted_key = "/synthetic/accepted.jsonl";
        let held_key = "/synthetic/held.jsonl";
        let scan = project(&mut index, source, accepted_key, false);
        let (accepted, bodies) = acks(&scan);
        index.settle_upload_contexts(&scan, &accepted, &bodies, &BTreeSet::new());
        assert_context(&index, accepted_key, Some("B"));
        assert_context(&index, held_key, Some("A"));
        index.save(&path).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        loaded.activate_upload_context("B".into());
        let reasons = [accepted_key, held_key]
            .map(|key| loaded.candidate_decision_with_reason(&candidate(key)).1);
        assert_eq!(reasons, [None, Some(CandidateParseReason::UploadContext)]);
        assert_eq!(loaded.upload_context_fingerprint.as_deref(), Some("A"));
        loaded.activate_upload_context("A".into());
        assert_eq!(
            loaded
                .candidate_decision_with_reason(&candidate(accepted_key))
                .1,
            Some(CandidateParseReason::UploadContext)
        );
        assert_eq!(
            loaded.candidate_decision(&candidate(held_key)),
            CandidateDecision::Skip
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn confirmed_empty_requires_selected_decision_and_its_original_context() {
    let key = "/synthetic/empty.jsonl";
    for previously_nonempty in [false, true] {
        for changed_context in [false, true] {
            let mut previous = ScanIndex::default();
            previous.activate_upload_context("A".into());
            if previously_nonempty {
                let scan = project(&mut previous, SnapshotSource::Pi, key, false);
                let (accepted, bodies) = acks(&scan);
                previous.settle_upload_contexts(&scan, &accepted, &bodies, &BTreeSet::new());
            }
            let mut index = previous.clone();
            index.activate_upload_context("B".into());
            let scan = project(&mut index, SnapshotSource::Pi, key, true);
            let mut selected =
                index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
            if changed_context {
                selected.activate_upload_context("C".into());
            }
            selected.settle_upload_contexts(
                &scan,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &BTreeSet::new(),
            );
            assert_context(
                &selected,
                key,
                if previously_nonempty {
                    Some("A")
                } else if changed_context {
                    None
                } else {
                    Some("B")
                },
            );
            if previously_nonempty {
                assert!(!selected.confirmed_empty_files.contains(key));
                selected.activate_upload_context("B".into());
                assert_eq!(
                    selected.candidate_decision_with_reason(&candidate(key)).1,
                    Some(CandidateParseReason::UploadContext)
                );
            }
        }
    }
}

#[test]
fn legacy_context_inherits_persisted_acceptance_once_and_prunes_at_save() {
    let root = std::env::temp_dir().join(format!("ottto-s15a-migration-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.activate_upload_context("A".into());
    for key in [
        "/synthetic/accepted.jsonl",
        "/synthetic/held.jsonl",
        "/synthetic/never.jsonl",
        "/synthetic/placeholder.jsonl",
    ] {
        let scan = project(&mut index, SnapshotSource::Codex, key, false);
        let (accepted, _) = acks(&scan);
        if !key.contains("never") {
            index.record_accepted_snapshot_fingerprints(&accepted);
        }
        if key.contains("held") {
            index.files.get_mut(key).unwrap().codex_captured_uncommitted = true;
        }
        if key.contains("placeholder") {
            index
                .files
                .get_mut(key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
    }
    // Each fixture must have distinct entity IDs; explicitly remove the never-accepted file's ACKs.
    index.file_snapshot_fingerprints.insert(
        "/synthetic/never.jsonl".into(),
        BTreeSet::from(["unaccepted".into()]),
    );
    let singleton = "/synthetic/singleton.jsonl";
    let mut scan = project(&mut index, SnapshotSource::Codex, singleton, false);
    scan.snapshots.truncate(1);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
    let (accepted, _) = acks(&scan);
    index.record_accepted_snapshot_fingerprints(&accepted);
    assert_ne!(
        index.files[singleton].last_snapshot_fingerprint.as_ref(),
        accepted.first()
    );
    index.file_snapshot_fingerprints.remove(singleton);
    let missing_group = "/synthetic/missing-group-map.jsonl";
    let scan = project(&mut index, SnapshotSource::Codex, missing_group, false);
    let (accepted, _) = acks(&scan);
    index.record_accepted_snapshot_fingerprints(&accepted);
    index.file_snapshot_fingerprints.remove(missing_group);
    project(
        &mut index,
        SnapshotSource::Codex,
        "/synthetic/empty.jsonl",
        true,
    );
    index.upload_context_fingerprint = Some("A".into());
    let mut legacy = serde_json::to_value(&index).unwrap();
    legacy.as_object_mut().unwrap().remove("upload_contexts");
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert_context(&loaded, "/synthetic/accepted.jsonl", Some("A"));
    for key in [
        "/synthetic/held.jsonl",
        "/synthetic/never.jsonl",
        "/synthetic/placeholder.jsonl",
    ] {
        assert_context(&loaded, key, None);
    }
    assert_context(&loaded, missing_group, None);
    assert_context(&loaded, singleton, Some("A"));
    assert_context(&loaded, "/synthetic/empty.jsonl", Some("A"));
    loaded.activate_upload_context("B".into());
    loaded.upload_context_fingerprint = Some("B".into());
    loaded.intern_upload_context([9; 32]);
    loaded.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_context(&loaded, "/synthetic/accepted.jsonl", Some("A"));
    assert_context(&loaded, "/synthetic/held.jsonl", None);
    assert_eq!(loaded.upload_contexts.as_ref().unwrap().len(), 1);
    let mut replay = loaded;
    replay.prepare_historical_replay("replay".into());
    assert!(replay.files.contains_key("/synthetic/held.jsonl"));
    assert!(replay
        .files
        .values()
        .all(|entry| entry.settled_upload_context.is_none()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn record_and_migrate_carry_context_without_normalizing_legacy() {
    let mut index = ScanIndex::default();
    index.activate_upload_context("A".into());
    let key = "/synthetic/file.jsonl";
    let scan = project(&mut index, SnapshotSource::Codex, key, false);
    let (accepted, bodies) = acks(&scan);
    index.settle_upload_contexts(&scan, &accepted, &bodies, &BTreeSet::new());
    index.record(
        candidate(key),
        Some("changed".into()),
        ScanParseOutcome::Snapshot,
    );
    assert_context(&index, key, Some("A"));
    assert!(!index.files[key].codex_counting_v2);
    index.migrate(candidate(key));
    assert_context(&index, key, Some("A"));
    assert!(!index.files[key].codex_counting_v2);
    // A state-only row has no pending file finalization, hence no marker.
    let mut state_only = empty_scan(SnapshotSource::Codex);
    state_only.state_census_complete = true;
    let mut item = cache_adapter_tests::cache_fixture_item();
    item.source_file_fingerprint = None;
    item.provenance.collector = "codex_state_sqlite".into();
    state_only.snapshots.push(item);
    let before = index.files.len();
    finalize_scan_after_policy(SnapshotSource::Codex, &mut state_only, &mut index);
    index.settle_upload_contexts(
        &state_only,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    assert_eq!(index.files.len(), before);
    assert_eq!(index.codex_state_only_snapshot_fingerprints.len(), 1);
    assert_context(&index, key, Some("A"));
}
