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
fn scoped_proof_debt_is_capped_survives_restart_and_eventually_drains() {
    let mut index = ScanIndex::default();
    for n in 0..70 {
        let key = format!("/opaque/family-{n:03}.jsonl");
        let mut entry = manifest_index_entry(Some("prior-body"));
        entry.size_bytes = 32 * 1024 * 1024;
        index
            .claude_full_rearm_progress
            .scoped_rearm_pending
            .insert(key.clone(), entry.source_file_fingerprint.clone().into());
        index.files.insert(key, entry);
    }
    let mut total = 0;
    for _ in 0..5 {
        index.begin_claude_evidence_offer();
        let counts = index.drain_claude_scoped_rearms();
        assert!(counts.files <= CLAUDE_SCOPED_REARM_MAX_FILES);
        assert!(counts.bytes <= CLAUDE_SCOPED_REARM_MAX_BYTES);
        assert_eq!(counts.families, counts.files);
        total += counts.files;
        index
            .claude_full_rearm_progress
            .scoped_rearm_pending
            .retain(|_, debt| !debt.armed);
        index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
    }
    assert_eq!(total, 70);
    assert!(index
        .claude_full_rearm_progress
        .scoped_rearm_pending
        .is_empty());
    assert!(index
        .files
        .values()
        .all(|entry| entry.source_file_fingerprint.is_empty()));
}

#[test]
fn scoped_rearm_stale_revision_and_terminal_deferral_veto_clears() {
    let mut index = ScanIndex::default();
    let key = "/opaque/family.jsonl".to_owned();
    index
        .files
        .insert(key.clone(), manifest_index_entry(Some("prior-body")));
    let prior = index.files[&key].source_file_fingerprint.clone();
    index
        .claude_full_rearm_progress
        .scoped_rearm_pending
        .insert(key.clone(), String::from("stale-revision").into());
    assert_eq!(index.drain_claude_scoped_rearms().files, 0);
    assert_eq!(index.files[&key].source_file_fingerprint, prior);
    index
        .claude_full_rearm_progress
        .scoped_rearm_pending
        .insert(key.clone(), prior.clone().into());
    index.claude_full_rearm_progress.terminal_fold_deferred = claude_terminal_budget(65, 0);
    assert_eq!(index.drain_claude_scoped_rearms().files, 0);
    assert_eq!(index.files[&key].source_file_fingerprint, prior);
    assert_eq!(
        index.claude_full_rearm_progress.scoped_rearm_pending.len(),
        1
    );
}

#[test]
fn scoped_account_reproof_observes_large_family_in_one_census_window() {
    let root = temp_dir("terminal-scoped-family-window");
    let parent = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let child_dir = root.join(parent).join("subagents");
    fs::create_dir_all(&child_dir).unwrap();
    let mut rows = Vec::new();
    for n in 0..70 {
        let agent = format!("{n:017x}");
        let request = format!("req_scoped_{n}");
        let line = serde_json::json!({
            "timestamp":"2026-08-02T07:00:00Z", "type":"assistant",
            "sessionId":parent, "agentId":agent, "isSidechain":true,
            "requestId":request,
            "message":{"model":"claude-haiku-4-5","usage":{"input_tokens":10,"output_tokens":10}}
        });
        fs::write(
            child_dir.join(format!("agent-{agent}.jsonl")),
            format!("{line}\n"),
        )
        .unwrap();
        rows.push(complete_api_row(parent, &request, n, 10, 10, 0));
    }
    let mut index = ScanIndex::default();
    // Establish the unchanged physical revisions through the real scanner.
    for _ in 0..20 {
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-08-02T07:10:00Z",
            BACKFILL_WINDOW_DAYS,
            8,
            true,
        )
        .unwrap();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        if scan.census_complete {
            break;
        }
    }
    assert_eq!(index.files.len(), 70);
    assert!(index.traversal.is_none());
    index.claude_account_family_witnesses.insert(
        parent.into(),
        ClaudeAccountFamilyWitness {
            account_identifier_hash: "a".repeat(64),
            evidence_request_count: 70,
            members: BTreeMap::new(),
            member_request_id_fingerprints: BTreeMap::from([(
                parent.into(),
                "legacy-input".into(),
            )]),
        },
    );
    let first = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut index,
        "2026-08-02T07:20:00Z",
        BACKFILL_WINDOW_DAYS,
        8,
        true,
    )
    .unwrap();
    assert!(!first.census_complete);
    apply_claude_effort_evidence_with_index(
        &mut [],
        &BTreeMap::new(),
        &mut index,
        false,
        &first.census_window_end,
    );
    assert_eq!(index.claude_scoped_rearm_counts().files, 32);
    assert_eq!(index.claude_scoped_rearm_counts().deferred, 38);
    let evidence = BTreeMap::from([(parent.to_owned(), rows)]);
    let mut window = Some(first.census_window_end);
    let mut completed = false;
    for _ in 0..20 {
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-08-02T07:20:00Z",
            BACKFILL_WINDOW_DAYS,
            8,
            true,
        )
        .unwrap();
        assert!(index.claude_scoped_rearm_counts().files <= 32);
        assert_eq!(
            window.get_or_insert(scan.census_window_end.clone()),
            &scan.census_window_end
        );
        apply_claude_effort_evidence_with_index(
            &mut scan.snapshots,
            &evidence,
            &mut index,
            scan.census_complete,
            &scan.census_window_end,
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        if scan.census_complete {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(
        index.claude_account_family_witnesses[parent].members.len(),
        70,
        "paced invalidations must not discard same-window account reproof"
    );
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
#[cfg(unix)]
fn scoped_debt_dispatch_uses_resolved_configured_root() {
    let (root, _, _) = claude_account_family_fixture();
    let alias = root.with_extension("configured-link");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    let canonical = fs::canonicalize(&root).unwrap();
    let key = local_index_key(&canonical.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl"));
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("prior-body"));
    let mut debt: ClaudeScopedRearmDebt = entry.source_file_fingerprint.clone().into();
    debt.armed = true;
    entry.source_file_fingerprint.clear();
    index.files.insert(key.clone(), entry);
    index
        .claude_full_rearm_progress
        .scoped_rearm_pending
        .insert(key, debt);
    let scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&alias),
        &mut index,
        "2026-08-02T07:20:00Z",
        BACKFILL_WINDOW_DAYS,
        100,
        true,
    )
    .unwrap();
    assert!(index
        .claude_full_rearm_progress
        .scoped_rearm_pending
        .is_empty());
    assert!(
        scan.census_complete,
        "a configured symlink cannot strand armed debt"
    );
    let _ = fs::remove_file(alias);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn selected_checkpoint_recovers_only_uncommitted_scoped_clears() {
    let key = "/opaque/family.jsonl".to_owned();
    let mut previous = ScanIndex::default();
    previous
        .files
        .insert(key.clone(), manifest_index_entry(Some("prior")));
    let expected = previous.files[&key].source_file_fingerprint.clone();
    let mut working = previous.clone();
    working
        .files
        .get_mut(&key)
        .unwrap()
        .last_snapshot_fingerprint = Some("corrected".into());
    working
        .files
        .get_mut(&key)
        .unwrap()
        .last_upload_body_witness = Some("corrected-body".into());
    working
        .claude_full_rearm_progress
        .scoped_rearm_cleared
        .insert(key.clone(), expected);
    let accepted = BTreeSet::from(["corrected".to_owned()]);
    let selected = working.committable_subset_with_local_holds(
        &previous,
        &accepted,
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    assert!(
        selected
            .claude_full_rearm_progress
            .scoped_rearm_pending
            .is_empty(),
        "an accepted correction must not be cleared again on partial save"
    );
    let held = BTreeSet::from(["corrected".to_owned()]);
    let restored =
        working.committable_subset_with_local_holds(&previous, &accepted, &BTreeMap::new(), &held);
    assert_eq!(
        restored.files[&key].last_snapshot_fingerprint.as_deref(),
        Some("prior")
    );
    assert!(
        !restored.claude_full_rearm_progress.scoped_rearm_pending[&key].armed,
        "a restored prior revision retains its owed, uncommitted clear"
    );
}

#[test]
fn owned_start_proof_corrections_share_the_scoped_allowance() {
    let mut index = ScanIndex::default();
    for n in 0..40 {
        let root = format!("owned-{n:03}");
        index.files.insert(
            format!("/opaque/{root}.jsonl"),
            manifest_index_entry(Some("prior")),
        );
        index.claude_owned_start_census.insert(
            root,
            ClaudeOwnedStartCensusWitness {
                marker_source_file_fingerprint: "marker".into(),
                verified_source_file_fingerprint: Some("verified".into()),
                emitted_source_file_fingerprint: None,
            },
        );
    }
    apply_claude_reported_usage_with_index_and_limits(
        &mut [],
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        &mut index,
        false,
        "2026-08-02T07:20:00Z",
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    );
    assert_eq!(index.claude_scoped_rearm_counts().files, 32);
    assert_eq!(index.claude_scoped_rearm_counts().deferred, 8);
    assert_eq!(
        index
            .files
            .values()
            .filter(|e| e.source_file_fingerprint.is_empty())
            .count(),
        32
    );
}
