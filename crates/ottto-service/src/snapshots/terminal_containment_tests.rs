use super::*;

fn witness_bytes(index: &ScanIndex) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "account_pending": index.claude_account_family_pending,
        "account_witness": index.claude_account_family_witnesses,
        "usage_pending": index.claude_usage_family_pending,
        "usage_witness": index.claude_usage_family_witnesses,
        "tombstones": index.claude_retired_family_tombstones,
        "fence": index.claude_retired_family_tombstones_uncertain,
        "holds": index.claude_account_deferred_holds,
        "accepted": index.accepted_snapshot_fingerprints,
        "incidence": index.accepted_rebuild_incidence,
        "bodies": index.files,
        "upload_context": index.upload_context_fingerprint,
    }))
    .unwrap()
}

#[test]
fn terminal_budget_rejects_whole_cohort_before_raw_retirement_and_every_fold() {
    let support = temp_dir("terminal-budget-support");
    let root = temp_dir("terminal-budget-empty-transcripts");
    let mut index = ScanIndex {
        claude_retired_family_tombstones_uncertain: true,
        upload_context_fingerprint: Some("prior".into()),
        active_upload_context_fingerprint: Some("next".into()),
        ..Default::default()
    };
    for n in 0..=CLAUDE_TERMINAL_MAX_ROOTS {
        index.claude_usage_family_pending.insert(
            format!("family-{n}"),
            ClaudeUsageFamilyPending {
                census_window_end: "2026-08-01T00:00:00Z".into(),
                member_request_id_hashes: BTreeMap::new(),
                member_occurrences: BTreeMap::new(),
                invalid: false,
                idless_revision: None,
            },
        );
    }
    index
        .accepted_snapshot_fingerprints
        .insert("prior-ack".into());
    let mut prior_body = manifest_index_entry(Some("prior-body"));
    prior_body.last_upload_body_witness = Some("prior-body-witness".into());
    index
        .files
        .insert("/opaque/retained.jsonl".into(), prior_body);
    let before = witness_bytes(&index);
    let mut scan = scan_source_roots_with_test_limit_and_claude_support(
        std::slice::from_ref(&root),
        &mut index,
        "2026-08-02T07:10:00Z",
        BACKFILL_WINDOW_DAYS,
        100,
        &support,
    )
    .unwrap();
    assert!(!scan.census_complete);
    assert!(scan.scan_cap_hit);
    assert!(
        index.traversal.is_some(),
        "rejected raw terminal keeps traversal"
    );
    assert_eq!(index.claude_terminal_fold_deferred().unwrap().roots, 65);
    assert_eq!(index.claude_terminal_fold_deferred().unwrap().cause, "preflight");
    assert_eq!(witness_bytes(&index), before);
    let (_, withheld, stats) =
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
    assert!(withheld);
    assert_eq!(stats.terminal_fold_deferred.unwrap().roots, 65);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    assert_eq!(
        witness_bytes(&index),
        before,
        "no folds, prune, tombstone, ACK or context adoption"
    );
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn terminal_budget_in_budget_is_unchanged_and_stat_only_bytes_refuse() {
    let root = temp_dir("terminal-budget-admitted");
    let support = temp_dir("terminal-budget-admitted-support");
    let mut index = ScanIndex::default();
    let scan = scan_source_roots_with_test_limit_and_claude_support(
        std::slice::from_ref(&root),
        &mut index,
        "2026-08-02T07:10:00Z",
        BACKFILL_WINDOW_DAYS,
        100,
        &support,
    )
    .unwrap();
    assert!(scan.census_complete);
    assert!(index.claude_terminal_fold_deferred().is_none());
    assert!(claude_terminal_budget(64, 1).is_none());
    assert!(claude_terminal_budget(1, CLAUDE_TERMINAL_MAX_INPUT_BYTES + 1).is_some());
    assert!(claude_terminal_budget(1, u64::MAX).is_some());
    assert!(claude_terminal_budget(1, CLAUDE_TERMINAL_MAX_EST_DECODED_BYTES / 32).is_some());
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn first_due_full_rearm_keeps_corpus_and_fence_closed() {
    let (root, _, items) = claude_account_family_fixture();
    let mut index = ScanIndex {
        claude_duplicate_request_witness_overflowed: true,
        ..Default::default()
    };
    let key = "/opaque/unobserved-root.jsonl";
    index
        .files
        .insert(key.into(), manifest_index_entry(Some("prior-body")));
    let prior = index.files[key].source_file_fingerprint.clone();
    let (_, after, counts) = claude_census_counts_run(
        &items,
        &index,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert_eq!(counts.rearm_full_suppressed, 1);
    assert!(!counts.full_rearm);
    assert!(after.claude_duplicate_request_witness_overflowed);
    assert!(!counts.coverage_complete, "suppression grants no ownership");
    assert_eq!(after.files[key].source_file_fingerprint, prior);
    assert_eq!(after.claude_duplicate_fence_rearm_attempt, 0);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn terminal_admission_counts_sparse_sidecar_metadata_without_decoding() {
    let support = temp_dir("terminal-budget-stat-only");
    let session = "stat-root";
    let path = support
        .join(crate::claude_local_otel::STORE_DIR)
        .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let size = CLAUDE_TERMINAL_MAX_INPUT_BYTES + 1;
    fs::File::create(&path).unwrap().set_len(size).unwrap();
    let mut index = ScanIndex::default();
    index.claude_usage_family_pending.insert(
        session.into(),
        ClaudeUsageFamilyPending {
            census_window_end: "old".into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
        },
    );
    index.preflight_claude_terminal_fold(Some(&support), &[]);
    let deferred = index.claude_terminal_fold_deferred().unwrap();
    assert_eq!(deferred.roots, 1);
    assert_eq!(deferred.sidecar_bytes, size);
    assert!(deferred.est_bytes > CLAUDE_TERMINAL_MAX_EST_DECODED_BYTES);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn terminal_reader_growth_refuses_before_any_staged_completion_effect() {
    for during_trace in [false, true] {
        let support = temp_dir("terminal-reader-growth-support");
        let root = temp_dir("terminal-reader-growth-transcripts");
        let mut index = ScanIndex {
            claude_retired_family_tombstones_uncertain: true,
            ..Default::default()
        };
        index.claude_usage_family_pending.insert("growing".into(), ClaudeUsageFamilyPending {
            census_window_end: "2026-08-01T00:00:00Z".into(),
            member_request_id_hashes: BTreeMap::new(), member_occurrences: BTreeMap::new(),
            invalid: false, idless_revision: None,
        });
        index.files.insert("/opaque/retained.jsonl".into(), manifest_index_entry(Some("prior-body")));
        let (api, trace) = crate::claude_local_otel::terminal_sidecar_paths_for_test(&support, "growing");
        fs::create_dir_all(api.parent().unwrap()).unwrap();
        fs::create_dir_all(trace.parent().unwrap()).unwrap();
        fs::write(&api, b"").unwrap();
        fs::write(&trace, b"\n").unwrap();
        let before = witness_bytes(&index);
        let mut scan = scan_source_roots_with_test_limit_and_claude_support(
            std::slice::from_ref(&root), &mut index, "2026-08-02T07:10:00Z", BACKFILL_WINDOW_DAYS, 100, &support,
        ).unwrap();
        assert!(index.claude_terminal_effects_staged());
        assert!(index.claude_terminal_fold_deferred().is_none(), "stat admission fits");
        assert_eq!(witness_bytes(&index), before, "raw effects are only staged");
        let _hook = crate::claude_local_otel::terminal_growth_hook_for_test(during_trace, |path| {
            use std::io::Write;
            let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(&vec![b'x'; CLAUDE_TERMINAL_MAX_INPUT_BYTES as usize + 1]).unwrap();
        });
        let (overrun, bytes) = crate::snapshot_sync::bounded_terminal_read_for_test(&support, &mut scan, &mut index);
        assert!(overrun, "growth during_trace={during_trace} exhausts the reader allowance");
        assert!(bytes <= CLAUDE_TERMINAL_MAX_INPUT_BYTES);
        assert_eq!(index.claude_terminal_fold_deferred().unwrap().cause, "read_allowance");
        assert!(!scan.census_complete);
        assert!(scan.scan_cap_hit);
        assert!(index.traversal.is_some(), "late refusal parks the existing traversal");
        assert_eq!(witness_bytes(&index), before,
            "no missing-file reconciliation, tombstone, retirement, prune, ACK carry or adoption");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(support);
    }
}

#[test]
fn terminal_containment_adds_no_persisted_fields() {
    let mut index = ScanIndex::default();
    index.preflight_claude_terminal_fold(None, &[]);
    index.note_claude_terminal_fold_offer(true);
    let value = serde_json::to_value(index).unwrap();
    let progress = &value["claude_full_rearm_progress"];
    for name in ["scoped_rearm_pending", "terminal_fold_deferred", "terminal_fold_checked", "terminal_effects", "terminal_fold_deferred_consecutive"] {
        assert!(progress.get(name).is_none(), "{name} must never persist");
    }
}

#[test]
fn admitted_terminal_commits_staged_effects_after_bounded_read() {
    let support = temp_dir("terminal-stage-commit-support");
    let root = temp_dir("terminal-stage-commit-transcripts");
    let mut index = ScanIndex::default();
    index.files.insert("/opaque/vanished.jsonl".into(), manifest_index_entry(Some("old-body")));
    let mut scan = scan_source_roots_with_test_limit_and_claude_support(
        std::slice::from_ref(&root), &mut index, "2026-08-02T07:10:00Z", BACKFILL_WINDOW_DAYS, 100, &support,
    ).unwrap();
    assert!(index.claude_terminal_effects_staged());
    assert!(index.files.contains_key("/opaque/vanished.jsonl"));
    let (overrun, bytes) = crate::snapshot_sync::bounded_terminal_read_for_test(&support, &mut scan, &mut index);
    assert!(!overrun);
    assert_eq!(bytes, 0);
    assert!(scan.census_complete);
    assert!(index.traversal.is_none());
    assert!(!index.files.contains_key("/opaque/vanished.jsonl"));
    assert!(scan.claude_request_census_shadow.is_some());
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn corrupt_small_sidecar_keeps_family_health_scoped_without_global_deferral() {
    let support = temp_dir("terminal-corrupt-health-support");
    let root = temp_dir("terminal-corrupt-health-transcripts");
    let mut index = ScanIndex::default();
    index.claude_usage_family_pending.insert("corrupt".into(), ClaudeUsageFamilyPending {
        census_window_end: "2026-08-01T00:00:00Z".into(),
        member_request_id_hashes: BTreeMap::new(), member_occurrences: BTreeMap::new(),
        invalid: false, idless_revision: None,
    });
    let (api, trace) = crate::claude_local_otel::terminal_sidecar_paths_for_test(&support, "corrupt");
    fs::create_dir_all(api.parent().unwrap()).unwrap();
    fs::create_dir_all(trace.parent().unwrap()).unwrap();
    fs::write(api, b"\xff\n").unwrap();
    fs::write(trace, b"").unwrap();
    let mut scan = scan_source_roots_with_test_limit_and_claude_support(
        std::slice::from_ref(&root), &mut index, "2026-08-02T07:10:00Z", BACKFILL_WINDOW_DAYS, 100, &support,
    ).unwrap();
    let (overrun, _) = crate::snapshot_sync::bounded_terminal_read_for_test(&support, &mut scan, &mut index);
    assert!(!overrun, "corrupt content is not an aggregate input overflow");
    assert!(index.claude_terminal_fold_deferred().is_none());
    assert!(scan.census_complete);
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn partial_deferred_page_keeps_unsettled_file_in_existing_traversal_queue() {
    let root = temp_dir("terminal-deferred-retry");
    let key = local_index_key(&root.join("retry.jsonl"));
    let previous = ScanIndex::default();
    let mut working = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("owed-body"));
    entry.source_file_fingerprint = "current-revision".into();
    working.files.insert(key.clone(), entry);
    ensure_bounded_traversal(SnapshotSource::ClaudeCode, std::slice::from_ref(&root), &mut working, "2026-08-02T07:10:00Z", BACKFILL_WINDOW_DAYS);
    let traversal = working.traversal.as_mut().unwrap();
    traversal.pending_directories.clear();
    traversal.pending_candidates.clear();
    working.claude_full_rearm_progress.terminal_fold_deferred = claude_terminal_budget(65, 0);
    let selected = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(!selected.files.contains_key(&key), "unsettled output cannot commit its file");
    let queued = &selected.traversal.as_ref().unwrap().pending_candidates;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].path, Path::new(&key));
    assert!(queued[0].census_member);
    assert!(!working.files[&key].source_file_fingerprint.is_empty(), "retry scheduling never clears the source witness");
    let accepted = working.committable_subset(&previous, &BTreeSet::from(["owed-body".into()]), &BTreeMap::new());
    assert!(accepted.traversal.as_ref().unwrap().pending_candidates.is_empty(), "settled files are not queued again");
    let held = BTreeSet::from(["owed-body".into()]);
    let borrowed = working.with_locally_held_keys_reverted(&previous, &held, &held);
    let moved = working.clone().into_locally_held_keys_reverted(&previous, &held, &held);
    for restored in [borrowed, moved] {
        assert!(!restored.files.contains_key(&key), "held output cannot commit its file");
        let pending = &restored.traversal.as_ref().unwrap().pending_candidates;
        assert_eq!(pending.len(), 1, "completed transport must keep held-file retry demand");
        assert_eq!(pending[0].path, Path::new(&key));
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn bounded_terminal_commit_preserves_a_later_effective_completion_veto() {
    let support = temp_dir("terminal-veto-support");
    let root = temp_dir("terminal-veto-transcripts");
    let mut index = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit_and_claude_support(
        std::slice::from_ref(&root), &mut index, "2026-08-02T07:10:00Z",
        BACKFILL_WINDOW_DAYS, 100, &support,
    ).unwrap();
    assert!(scan.census_complete);
    scan.census_complete = false;
    let (overrun, _) = crate::snapshot_sync::bounded_terminal_read_for_test(&support, &mut scan, &mut index);
    assert!(!overrun);
    assert!(!scan.census_complete, "raw commit cannot undo a later effective veto");
    assert!(scan.scan_cap_hit);
    assert!(scan.claude_request_census_shadow.is_none());
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(support);
}
