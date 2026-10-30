use super::*;

const OFF_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const OFF_CHILD: &str = "agent-a4d1585d310070d0f";
const W1: &str = "2026-08-20T10:02:00Z";
const W2: &str = "2026-08-20T10:12:00Z";

fn off_index() -> ScanIndex {
    ScanIndex {
        claude_request_identity_contract: Some(
            claude_request_identity::cycle_contract(true).into(),
        ),
        historical_replay_generation: Some("terminal-off-generation".into()),
        upload_context_fingerprint: Some("settled-destination".into()),
        active_upload_context_fingerprint: Some("settled-destination".into()),
        ..Default::default()
    }
}
fn off_suppression_preconditions(index: &ScanIndex) {
    assert_eq!(
        index.claude_request_identity_contract.as_deref(),
        Some(claude_request_identity::cycle_contract(true))
    );
    assert!(!index.claude_request_identity_contract_changed);
    assert!(claude_redundant_stale_clear_suppressed(index));
}
fn off_line(member: &str, request: &str) -> String {
    // A copied prefix establishes a real owned-start marker; X itself is an
    // ordinary OWNED occurrence. The old fixture made X inherited and empty.
    let prefix = serde_json::json!({"timestamp":"2026-08-20T10:00:00Z","sessionId":member,"type":"assistant","forkedFrom":{"sessionId":"prior","messageUuid":"prior-message"},"requestId":"inherited","message":{"id":"inherited-message","model":"claude-opus-4-8","usage":{"input_tokens":900,"output_tokens":2}}});
    let owned = serde_json::json!({"timestamp":"2026-08-20T10:01:00Z","sessionId":member,"type":"assistant","requestId":request,"message":{"id":format!("msg-{request}"),"model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":2}}});
    format!("{prefix}\n{owned}\n")
}

fn refresh_terminal_off_discovery_at_test(
    index: &mut ScanIndex,
    roots: &[PathBuf],
    at: &str,
    overflow: bool,
) {
    refresh_terminal_off_discovery(
        index,
        roots,
        rfc3339_unix_seconds(at).unwrap(),
        overflow,
        at,
        MAX_BACKFILL_FILES_PER_SOURCE,
    );
}

fn off_scan(index: &mut ScanIndex, root: &Path, at: &str, limit: usize) -> SourceScanResult {
    assert!(
        claude_terminal_off(),
        "containment receipts require production policy"
    );
    // The production prepare activates context after every reload.
    if index.active_upload_context_fingerprint.is_none() {
        index.activate_upload_context("settled-destination".into());
    }
    let mut result = sampled_scan::with_test_now(rfc3339_unix_seconds(at).unwrap(), || {
        scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            &[root.to_owned()],
            index,
            at,
            BACKFILL_WINDOW_DAYS,
            limit,
            true,
        )
        .unwrap()
    });
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    let disposition = apply_claude_reported_usage_with_index(
        &mut result.snapshots,
        &api,
        &trace,
        index,
        result.census_complete,
        &result.census_window_end,
    );
    assert!(!disposition.duplicate_census.census_complete);
    assert!(disposition.duplicate_census.fence_after);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, index);
    result
}

fn off_accept(index: &mut ScanIndex, result: &SourceScanResult) {
    for item in &result.snapshots {
        index
            .accepted_snapshot_fingerprints
            .insert(item.snapshot_fingerprint.clone());
    }
}

#[test]
fn terminal_off_w1_w2_open_fence_skipped_duplicate_never_verifies() {
    for initially_closed in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("terminal-off-open-fence");
        let root = scratch.join("projects");
        let child_dir = root.join(OFF_ROOT).join("subagents");
        fs::create_dir_all(&child_dir).unwrap();
        let root_path = root.join(format!("{OFF_ROOT}.jsonl"));
        let child_path = child_dir.join(format!("{OFF_CHILD}.jsonl"));
        fs::write(&root_path, off_line(OFF_ROOT, "X")).unwrap();
        fs::write(
            &child_path,
            off_line(&format!("{OFF_ROOT}_{OFF_CHILD}"), "X"),
        )
        .unwrap();
        let mut index = ScanIndex {
            claude_duplicate_request_witness_overflowed: initially_closed,
            ..off_index()
        };
        // W1 is multi-page; selected save/reload retains the earlier page.
        for _ in 0..2 {
            let previous = index.clone();
            let page = off_scan(&mut index, &root, W1, 1);
            let accepted = page
                .snapshots
                .iter()
                .map(|i| i.snapshot_fingerprint.clone())
                .collect();
            index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
            off_accept(&mut index, &page);
            index = serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
        }
        let child_fingerprint = index.files[&local_index_key(&child_path)]
            .source_file_fingerprint
            .clone();
        let pending_w1 = index.claude_usage_family_pending.clone();
        assert!(pending_w1.contains_key(OFF_ROOT));
        let w1 = &pending_w1[OFF_ROOT];
        assert_eq!(w1.member_request_id_hashes.len(), 2);
        assert!(w1
            .member_request_id_hashes
            .values()
            .all(|ids| !ids.is_empty()));
        assert!(w1.member_occurrences.values().all(|rows| !rows.is_empty()));
        assert!(index.claude_owned_start_census.contains_key(OFF_ROOT));
        // Exact counterexample: only root changes; child still contains X.
        let mut text = fs::read_to_string(&root_path).unwrap();
        text.push_str("{\"type\":\"user\",\"message\":{\"content\":\"metadata only\"}}\n");
        fs::write(&root_path, text).unwrap();
        // Activation is process-local and is restored by prepare after load.
        index.activate_upload_context("settled-destination".into());
        off_suppression_preconditions(&index);
        index.traversal = None;
        index.claude_duplicate_request_witness_overflowed = initially_closed;
        let page = off_scan(&mut index, &root, W2, 10);
        assert_eq!(
            page.scanned_file_count, 1,
            "unchanged duplicate sibling skipped"
        );
        // The exact historical eligibility predicate, without the terminal
        // guard, sees X only in changed R's replacement pending. It WOULD mint
        // R's verification despite unchanged C still containing owned X.
        let eligible = claude_owned_start_eligible(
            &index,
            &complete_claude_family_members(&index),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &page.census_window_end,
        );
        assert!(eligible.iter().any(|(member, _)| member == OFF_ROOT));
        for offered_terminal in [false, true] {
            for route in ["direct", "scan", "native-observations"] {
                let mut guarded = index.clone();
                let mut guarded_page = page.clone();
                guarded_page.census_complete = offered_terminal;
                apply_claude_effort_evidence_with_index(
                    &mut guarded_page.snapshots,
                    &BTreeMap::new(),
                    &mut guarded,
                    offered_terminal,
                    &page.census_window_end,
                );
                let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
                let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
                let verdict = match route {
                    "direct" => apply_claude_reported_usage_with_index(
                        &mut guarded_page.snapshots,
                        &api,
                        &trace,
                        &mut guarded,
                        offered_terminal,
                        &page.census_window_end,
                    ),
                    "scan" => apply_claude_reported_usage_to_scan_with_identity(
                        &mut guarded_page,
                        &api,
                        &trace,
                        &mut guarded,
                        None,
                    ),
                    _ => {
                        let observations =
                            record_claude_native_observations(&guarded_page, &mut guarded);
                        apply_claude_reported_usage_to_scan_with_observations(
                            &mut guarded_page,
                            &api,
                            &trace,
                            &mut guarded,
                            None,
                            Some(observations),
                        )
                    }
                };
                assert!(!verdict.duplicate_census.census_complete, "{route}");
                assert!(verdict.duplicate_census.fence_after, "{route}");
                assert!(guarded.claude_usage_family_witnesses.is_empty(), "{route}");
                assert!(
                    guarded.claude_account_family_witnesses.is_empty(),
                    "{route}"
                );
                assert!(
                    guarded
                        .claude_owned_start_census
                        .values()
                        .all(|w| w.verified_source_file_fingerprint.is_none()),
                    "{route}"
                );
                assert!(
                    guarded_page
                        .snapshots
                        .iter()
                        .all(|item| item.cache_observations.is_none()
                            && item.context_curve.as_ref().map_or(true, |curve| !matches!(
                                curve.coverage.as_str(),
                                "complete" | "sampled"
                            ))),
                    "{route}"
                );
            }
        }

        assert!(!page.census_complete);
        assert!(claude_effective_duplicate_fence_closed(&index));
        assert_eq!(
            index.claude_duplicate_request_witness_overflowed,
            initially_closed
        );
        assert_eq!(
            index.files[&local_index_key(&child_path)].source_file_fingerprint,
            child_fingerprint
        );
        assert!(index
            .claude_owned_start_census
            .values()
            .all(|p| p.verified_source_file_fingerprint.is_none()
                && p.emitted_source_file_fingerprint.is_none()));
        assert!(
            index.claude_usage_family_witnesses.is_empty(),
            "no newly accepted unread authority"
        );
        for item in &page.snapshots {
            assert!(item.cache_observations.is_none(), "no strict cache proof");
            assert!(
                item.context_curve.as_ref().map_or(true, |curve| !matches!(
                    curve.coverage.as_str(),
                    "complete" | "sampled"
                )),
                "no strict curve proof"
            );
            assert_ne!(
                item.usage_accounting_contract.as_deref(),
                Some("session_exclusive_reported_usage:v1")
            );
        }
    }
}

#[test]
fn terminal_off_hard_reenable_requires_reconstruction_even_after_reload() {
    let mut index = off_index();
    assert!(!claude_terminal_reconstructed(&index, W2));
    assert!(!claude_terminal_authority(&index, true, W2));
    index.claude_full_rearm_progress.full_rearm_window_next = true;
    index.claude_full_rearm_progress.rebuild_read_full = true;
    let loaded: ScanIndex = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
    assert!(
        !claude_terminal_reconstructed(&loaded, W2),
        "persisted scheduling never mints the reconstruction guard"
    );
    assert!(!claude_terminal_authority(&loaded, true, W2));
}

#[test]
fn terminal_off_fresh_start_zero_parses_and_bounded_identity_samples() {
    const N: usize = 4;
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-samples");
    for n in 0..N {
        let member = format!("a{n:07}-1111-4111-8111-111111111111");
        fs::write(
            scratch.join(format!("{member}.jsonl")),
            off_line(&member, &format!("X{n}")),
        )
        .unwrap();
    }
    let mut index = ScanIndex {
        upload_context_fingerprint: Some("settled-destination".into()),
        active_upload_context_fingerprint: Some("settled-destination".into()),
        ..off_index()
    };
    let first = off_scan(&mut index, &scratch, W1, N);
    assert_eq!(first.scanned_file_count, N);
    off_accept(&mut index, &first);
    // Process reload + no retained traversal: not a cheap parking-only test.
    index = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
    index.active_upload_context_fingerprint = Some("settled-destination".into());
    off_suppression_preconditions(&index);
    index.traversal = None;
    let before = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let body_before = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let page = off_scan(&mut index, &scratch, W2, N);
    let after = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    assert_eq!(
        TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get) - body_before,
        0,
        "zero actual body/Full bytes consumed"
    );
    assert_eq!(
        page.scanned_file_count, 0,
        "no Full or other parse is started"
    );
    assert!(
        page.pending_finalization.is_empty(),
        "no parsed body is finalized"
    );
    START_IDENTITY_SAMPLES.with(|counts| {
        let counts = counts.borrow();
        assert_eq!(counts.files.len(), N);
        assert_eq!(counts.observations, N as u64);
    });
    assert_eq!(after.0 - before.0, N as u64);
    assert!(after.1 - before.1 > 0);
    assert!(after.1 - before.1 <= (N * 2 * FILE_CONTENT_SAMPLE_BYTES) as u64);
    assert!(!page.census_complete);
    assert!(index
        .files
        .values()
        .all(|e| !e.source_file_fingerprint.is_empty()));
}

#[test]
fn terminal_off_sample_mismatch_uses_ordinary_changed_file_path() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-mismatch");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let old = index.files[&local_index_key(&path)]
        .source_file_fingerprint
        .clone();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    // Same length and restored mtime: samples must detect this change.
    fs::write(&path, off_line(OFF_ROOT, "Y")).unwrap();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    off_suppression_preconditions(&index);
    index.traversal = None;
    let changed = off_scan(&mut index, &scratch, W2, 10);
    assert_eq!(changed.scanned_file_count, 1);
    assert_ne!(
        index.files[&local_index_key(&path)].source_file_fingerprint,
        old
    );
    index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after = 0;
    let quiet = off_scan(&mut index, &scratch, W2, 10);
    assert_eq!(quiet.scanned_file_count, 0, "changed file read once");
}

#[test]
fn terminal_off_offline_create_overflow_and_cadence_discover_without_restart() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-discovery");
    fs::write(
        scratch.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let window = index.traversal.as_ref().unwrap().census_window_end.clone();
    for (n, overflow, reload) in [(1, false, true), (2, true, false), (3, false, false)] {
        let member = format!("b{n:07}-1111-4111-8111-111111111111");
        let path = scratch.join(format!("{member}.jsonl"));
        fs::write(&path, off_line(&member, &format!("new{n}"))).unwrap();
        if reload {
            index = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
        }
        if n == 3 {
            // The process memo, not the skipped diagnostic scalar, owns time.
            expire_terminal_off_discovery_for_test(&index);
        }
        refresh_terminal_off_discovery_at_test(&mut index, &[scratch.to_path_buf()], W2, overflow);
        let result = off_scan(&mut index, &scratch, W2, 10);
        assert_eq!(result.scanned_file_count, 1);
        assert!(index.files.contains_key(&local_index_key(&path)));
        assert_eq!(index.traversal.as_ref().unwrap().census_window_end, window);
        off_accept(&mut index, &result);
    }
}

#[test]
fn terminal_off_selected_save_requeues_earlier_failed_page_and_keeps_clear_debt() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-requeue");
    fs::write(
        scratch.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = off_index();
    let previous = index.clone();
    let failed = off_scan(&mut index, &scratch, W1, 1);
    assert_eq!(failed.snapshots.len(), 1);
    let key = local_index_key(&scratch.join(format!("{OFF_ROOT}.jsonl")));
    let mut selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(selected
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == Path::new(&key)));
    selected = serde_json::from_value(serde_json::to_value(selected).unwrap()).unwrap();
    let retry = off_scan(&mut selected, &scratch, W2, 1);
    assert_eq!(retry.snapshots.len(), 1);
    assert_eq!(
        retry.snapshots[0].snapshot_fingerprint,
        failed.snapshots[0].snapshot_fingerprint
    );
    selected
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    selected.traversal = None;
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &mut selected,
        W2,
        BACKFILL_WINDOW_DAYS,
    );
    assert!(
        selected.files[&key].source_file_fingerprint.is_empty(),
        "explicit debt never overwritten by suppression"
    );
}

#[test]
fn terminal_off_delete_defers_all_raw_effects_and_full_rearm() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-delete");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let key = local_index_key(&path);
    let before = index.files[&key].source_file_fingerprint.clone();
    fs::remove_file(&path).unwrap();
    if let Some(t) = index.traversal.as_mut() {
        enqueue_terminal_off_retry(
            t,
            &ScanTraversalPath {
                scan_root: scratch.to_path_buf(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            true,
        );
    }
    let page = off_scan(&mut index, &scratch, W2, 10);
    assert!(
        !page.census_complete,
        "no complete source manifest can publish"
    );
    assert_eq!(
        index.files[&key].source_file_fingerprint, before,
        "exact removal withheld before raw effects"
    );
    assert!(claude_effective_duplicate_fence_closed(&index));
    assert!(
        !index.claude_duplicate_request_witness_overflowed,
        "containment does not mutate the persisted fence"
    );
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    let d = apply_claude_reported_usage_with_index(&mut [], &api, &trace, &mut index, true, W2);
    assert!(!d.duplicate_census.full_rearm);
    assert!(!d.duplicate_census.census_complete);
    assert_eq!(index.files[&key].source_file_fingerprint, before);
}

#[test]
fn terminal_off_context_change_and_contract_debt_still_select() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-context");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    index.active_upload_context_fingerprint = Some("new-destination".into());
    index.traversal = None;
    let page = off_scan(&mut index, &scratch, W2, 10);
    assert_eq!(page.scanned_file_count, 1);
    assert_ne!(
        index.upload_context_fingerprint, index.active_upload_context_fingerprint,
        "off cannot adopt a context"
    );
    index.claude_request_identity_contract_changed = true;
    index.traversal = None;
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &mut index,
        "2026-08-20T10:22:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    assert!(index.files[&local_index_key(&path)]
        .source_file_fingerprint
        .is_empty());
    assert!(
        index.claude_request_identity_contract_changed,
        "suppressed full replay never spends the latch"
    );
}

#[test]
fn terminal_off_process_state_preserves_old_decoder_shape() {
    let mut index = off_index();
    let before = serde_json::to_value(&index.claude_full_rearm_progress).unwrap();
    index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after = 12345;
    let after = serde_json::to_value(&index.claude_full_rearm_progress).unwrap();
    assert_eq!(
        before, after,
        "cadence is process-local; no new persisted key"
    );
    let loaded: ScanIndex = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
    assert_eq!(
        loaded
            .claude_full_rearm_progress
            .terminal_off_rediscovery_after,
        0
    );
}

#[test]
fn terminal_off_held_selected_save_reload_preserves_unaccepted_retry() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-held");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let previous = index.clone();
    let scan = off_scan(&mut index, &scratch, W1, 1);
    let held = scan
        .snapshots
        .iter()
        .map(|i| i.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    index = index.into_locally_held_keys_reverted(&previous, &held, &held);
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    index = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == path));
    let retry = off_scan(&mut index, &scratch, W2, 1);
    assert_eq!(retry.scanned_file_count, 1);
    assert_eq!(
        retry.snapshots[0].snapshot_fingerprint,
        scan.snapshots[0].snapshot_fingerprint
    );
    assert!(!retry.census_complete);
    assert!(
        index.accepted_snapshot_fingerprints.is_empty(),
        "a reoffer is never an ACK"
    );
}

#[cfg(unix)]
#[test]
fn terminal_off_rediscovery_reauthorizes_only_current_symlink_target() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-retarget");
    let a = scratch.join("a");
    let b = scratch.join("b");
    let configured = scratch.join("configured");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let a = fs::canonicalize(a).unwrap();
    let b = fs::canonicalize(b).unwrap();
    fs::write(
        a.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "old"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&a, &configured).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &configured, W1, 10);
    off_accept(&mut index, &first);
    fs::remove_file(&configured).unwrap();
    std::os::unix::fs::symlink(&b, &configured).unwrap();
    let old_extra = a.join("b2222222-2222-4222-8222-222222222222.jsonl");
    let new = b.join("c3333333-3333-4333-8333-333333333333.jsonl");
    fs::write(
        &old_extra,
        off_line("b2222222-2222-4222-8222-222222222222", "unauthorized"),
    )
    .unwrap();
    fs::write(
        &new,
        off_line("c3333333-3333-4333-8333-333333333333", "authorized"),
    )
    .unwrap();
    // A live cancellation replay is an independent selection queue.
    index
        .claude_stale_family_carry
        .replay
        .push(ScanTraversalPath {
            scan_root: a.clone(),
            path: old_extra.clone(),
            census_member: true,
            watcher_hint: false,
        });
    // Not due by cadence; root authorization must nevertheless change now.
    index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after = u64::MAX;
    let page = off_scan(&mut index, &configured, W2, 10);
    assert_eq!(page.scanned_file_count, 1);
    assert!(index.claude_stale_family_carry.replay.is_empty());
    assert!(index.files.contains_key(&local_index_key(&new)));
    assert!(!index.files.contains_key(&local_index_key(&old_extra)));
    assert!(
        index
            .files
            .contains_key(&local_index_key(&a.join(format!("{OFF_ROOT}.jsonl")))),
        "accepted old custody survives scope invalidation"
    );
    assert_eq!(index.traversal.as_ref().unwrap().scan_roots, vec![b]);
}

#[test]
fn terminal_off_fresh_context_reselection_is_disclosed_until_adoption() {
    // TODO R1: provided by the source-general upload-context receipt PR
    // (e1/upload-context-receipt); consume it here after merge.

    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-fresh-context");
    fs::write(
        scratch.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = ScanIndex {
        active_upload_context_fingerprint: Some("new-destination".into()),
        ..Default::default()
    };
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    index
        .claude_full_rearm_progress
        .terminal_off_rediscovery_after = 0;
    let second = off_scan(&mut index, &scratch, W2, 10);
    assert_eq!(
        second.scanned_file_count, 1,
        "deliberate UploadContext selection while terminal adoption is withheld"
    );
    assert!(index.upload_context_fingerprint.is_none());
    assert!(index.active_upload_context_fingerprint.is_some());
    assert!(!second.census_complete);
}

#[test]
fn terminal_off_save_preserves_persisted_fence_and_closes_effective_fence() {
    for closed in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("terminal-off-fence-save");
        fs::write(
            scratch.join(format!("{OFF_ROOT}.jsonl")),
            off_line(OFF_ROOT, "X"),
        )
        .unwrap();
        let mut index = off_index();
        index.claude_duplicate_request_witness_overflowed = closed;
        let page = off_scan(&mut index, &scratch, W1, 1);
        assert!(!page.census_complete);
        assert!(claude_effective_duplicate_fence_closed(&index));
        let encoded = serde_json::to_value(&index).unwrap();
        assert_eq!(
            encoded["claude_duplicate_request_witness_overflowed"],
            closed
        );
        let loaded: ScanIndex = serde_json::from_value(encoded).unwrap();
        assert_eq!(loaded.claude_duplicate_request_witness_overflowed, closed);
        assert!(claude_effective_duplicate_fence_closed(&loaded));
    }
}

#[test]
fn terminal_off_old_reader_owned_start_correction_quiesces_with_custody() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-owed-start");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let key = local_index_key(&path);
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 1);
    off_accept(&mut index, &first);
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(!fingerprint.is_empty());
    let witness = index.claude_owned_start_census.get_mut(OFF_ROOT).unwrap();
    witness.verified_source_file_fingerprint = Some(fingerprint.clone());
    witness.emitted_source_file_fingerprint = None;
    // The old emitter already owed one defensive re-read. Preserve that debt;
    // only avoid issuing it again after the ordinary read has discharged it.
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let old = serde_json::to_value(&index).unwrap();
    index = serde_json::from_value(old).unwrap();
    index.active_upload_context_fingerprint = Some("settled-destination".into());
    let before = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
    for pass in 0..4 {
        index.traversal = None;
        off_suppression_preconditions(&index);
        let bytes_before = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
        let scan = off_scan(&mut index, &scratch, W2, 1);
        assert_eq!(scan.scanned_file_count, usize::from(pass == 0));
        if pass > 0 {
            assert_eq!(
                TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get),
                bytes_before
            );
        }
        off_accept(&mut index, &scan);
        let witness = &index.claude_owned_start_census[OFF_ROOT];
        assert_eq!(
            witness.verified_source_file_fingerprint.as_ref(),
            Some(&fingerprint)
        );
        assert!(witness.emitted_source_file_fingerprint.is_none());
        assert_eq!(index.files[&key].source_file_fingerprint, fingerprint);
        assert!(!scan.census_complete);
        index = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
        index.active_upload_context_fingerprint = Some("settled-destination".into());
    }
    assert!(TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get) > before);
}

#[cfg(unix)]
#[test]
fn terminal_off_ctime_only_counts_one_file_two_observations_per_walk() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-ctime");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    // Both head and tail are paid, including the second ctime validation.
    let mut contents = off_line(OFF_ROOT, "X");
    contents.push_str(&format!(
        "{{\"type\":\"user\",\"padding\":\"{}\"}}\n",
        "x".repeat(20_000)
    ));
    fs::write(&path, contents).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 1);
    off_accept(&mut index, &first);
    let key = local_index_key(&path);
    assert_ne!(index.files[&key].opened_birth_nanos, 0);
    let metadata = fs::metadata(&path).unwrap();
    fs::set_permissions(
        &path,
        fs::Permissions::from_mode(metadata.permissions().mode() ^ 0o100),
    )
    .unwrap();
    let live = fs::metadata(&path).unwrap();
    let changed = (live.ctime() as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(live.ctime_nsec() as u64);
    assert_ne!(
        changed, index.files[&key].opened_changed_nanos,
        "fixture must move ctime"
    );
    off_suppression_preconditions(&index);
    index.traversal = None;
    let body_before = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let quiet = off_scan(&mut index, &scratch, W2, 1);
    assert_eq!(quiet.scanned_file_count, 0);
    assert_eq!(
        TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get),
        body_before
    );
    START_IDENTITY_SAMPLES.with(|counts| {
        let counts = counts.borrow();
        assert_eq!(counts.files.len(), 1);
        assert_eq!(counts.observations, 2);
        assert!(counts.bytes <= 4 * FILE_CONTENT_SAMPLE_BYTES as u64);
    });
    reset_start_identity_samples();
    START_IDENTITY_SAMPLES.with(|counts| assert_eq!(counts.borrow().observations, 0));
}

#[test]
fn terminal_off_retention_gauges_never_grant_custody_credit() {
    let mut index = off_index();
    let clock = rfc3339_unix_seconds(W1).unwrap();
    index
        .snapshot_activity_at
        .insert("f".repeat(64), Some(W1.into()));
    index.accepted_snapshot_fingerprints.insert("f".repeat(64));
    let before = serde_json::to_value(&index).unwrap();
    let debt = index.terminal_off_retention(clock + 100);
    assert_eq!(debt.accepted_index_acks.items, 1);
    assert_eq!(debt.accepted_index_acks.oldest_age_seconds, Some(100));
    assert_eq!(debt.manifest_withheld.items, 1);
    assert_eq!(debt.manifest_withheld.unknown_age, 1);
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        before,
        "diagnostics cannot create ACK, settlement, proof or tombstone authority"
    );
    assert!(!claude_terminal_authority(&index, true, W2));
    assert!(index.claude_usage_family_witnesses.is_empty());
}

#[test]
fn terminal_off_unproven_pending_is_counted_without_settlement_or_proof() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-pending-gauge");
    let root = scratch.join("projects");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = off_index();
    let scan = off_scan(&mut index, &root, W1, 8);
    assert!(!scan.census_complete);
    let debt = index.terminal_off_retention(rfc3339_unix_seconds(W2).unwrap());
    assert!(debt.delayed_proof_families.items > 0);
    assert!(debt.delayed_proof_families.oldest_age_seconds.is_some());
    assert_eq!(
        debt.owed_correction_members.items, 0,
        "pending evidence never invents a grant"
    );
    assert_eq!(
        debt.accepted_index_acks.items, 0,
        "retention never invents an ACK"
    );
    assert!(index.claude_usage_family_witnesses.is_empty());
    let before = serde_json::to_value(&index).unwrap();
    let _ = index.terminal_off_retention(rfc3339_unix_seconds(W2).unwrap() + 100);
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
}

#[test]
fn terminal_off_pending_behind_old_witness_is_still_counted_and_unproven() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-old-proof-gauge");
    let root = scratch.join("projects");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = off_index();
    let scan = off_scan(&mut index, &root, W1, 8);
    assert!(!scan.census_complete);
    let revision = index
        .files
        .values()
        .next()
        .unwrap()
        .source_file_fingerprint
        .clone();
    index.insert_unproven_terminal_claude_authority_for_test(OFF_ROOT, &revision);
    assert!(index.claude_usage_family_witnesses.contains_key(OFF_ROOT));
    let before = serde_json::to_value(&index).unwrap();
    let debt = index.terminal_off_retention(rfc3339_unix_seconds(W2).unwrap());
    assert_eq!(debt.delayed_proof_families.items, 1);
    assert_eq!(debt.accepted_index_acks.items, 0);
    assert_eq!(debt.owed_correction_members.items, 0);
    assert!(!claude_terminal_authority(&index, true, W2));
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
}

#[test]
fn terminal_off_cancellation_replay_precedes_repeated_held_fifo_on_one_file_pages() {
    let path = |name: &str| ScanTraversalPath {
        scan_root: PathBuf::from("synthetic"),
        path: PathBuf::from(name),
        census_member: true,
        watcher_hint: false,
    };
    let mut replay = vec![path("cancel-A"), path("cancel-B")];
    let mut queue = std::collections::VecDeque::from([path("held")]);
    let mut served = Vec::new();
    for _ in 0..3 {
        let mut selected = Vec::new();
        terminal_off_replay_before_fifo(&mut replay, &mut selected, 1);
        while selected.is_empty() {
            selected.push(queue.pop_front().unwrap());
        }
        assert_eq!(selected.len(), 1, "unchanged one-file budget");
        let chosen = selected.pop().unwrap();
        if chosen.path == Path::new("held") {
            queue.push_back(chosen.clone());
        }
        served.push(chosen.path);
    }
    assert_eq!(
        served,
        [
            PathBuf::from("cancel-A"),
            PathBuf::from("cancel-B"),
            PathBuf::from("held")
        ]
    );
    assert!(
        replay.is_empty(),
        "funded cancellation obligations drain, allowing G1 retries"
    );
    assert_eq!(queue.len(), 1, "held custody remains queued, never settled");
}

#[test]
fn terminal_off_rediscovery_deadline_survives_two_save_load_cycles() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-reload-cadence");
    fs::write(
        scratch.join(format!("{OFF_ROOT}.jsonl")),
        off_line(OFF_ROOT, "X"),
    )
    .unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let scope = terminal_off_rediscovery_scope(&index).unwrap();
    let due = TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow()[&scope]);
    let index_path = scratch.join("index.json");
    for at in ["2026-08-20T10:03:00Z", "2026-08-20T10:04:00Z"] {
        index.save(&index_path).unwrap();
        index = ScanIndex::load(&index_path).unwrap();
        index.activate_upload_context("settled-destination".into());
        assert_eq!(
            index
                .claude_full_rearm_progress
                .terminal_off_rediscovery_after,
            0
        );
        let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
        refresh_terminal_off_discovery_at_test(&mut index, &[scratch.to_path_buf()], at, false);
        assert!(
            index
                .traversal
                .as_ref()
                .unwrap()
                .pending_directories
                .is_empty(),
            "reload before due must not rewalk"
        );
        assert_eq!(
            START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
            samples
        );
        assert_eq!(
            TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow()[&scope]),
            due
        );
    }
    refresh_terminal_off_discovery_at_test(
        &mut index,
        &[scratch.to_path_buf()],
        "2026-08-20T10:07:00Z",
        false,
    );
    assert_eq!(
        index.traversal.as_ref().unwrap().pending_directories.len(),
        1,
        "due metadata walk"
    );
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .clear();
    refresh_terminal_off_discovery_at_test(
        &mut index,
        &[scratch.to_path_buf()],
        "2026-08-20T10:07:01Z",
        true,
    );
    assert_eq!(
        index.traversal.as_ref().unwrap().pending_directories.len(),
        1,
        "watcher loss bypasses cadence"
    );
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .clear();
    index.activate_upload_context("different-destination".into());
    refresh_terminal_off_discovery_at_test(
        &mut index,
        &[scratch.to_path_buf()],
        "2026-08-20T10:07:02Z",
        false,
    );
    assert_eq!(
        index.traversal.as_ref().unwrap().pending_directories.len(),
        1,
        "destination scopes cannot share scheduling suppression"
    );
    assert!(!first.census_complete);
}

#[test]
fn terminal_off_rediscovery_memo_is_bounded_and_eviction_fails_toward_rewalk() {
    TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow_mut().clear());
    for n in 0..TERMINAL_OFF_REDISCOVERY_SCOPES + 1 {
        assert!(terminal_off_rediscovery_due(
            format!("scope-{n}"),
            n as u64,
            false
        ));
    }
    TERMINAL_OFF_REDISCOVERY.with(|memo| {
        assert_eq!(memo.borrow().len(), TERMINAL_OFF_REDISCOVERY_SCOPES);
        assert!(!memo.borrow().contains_key("scope-0"));
    });
    assert!(terminal_off_rediscovery_due("scope-0".into(), 100, false));
}

#[test]
fn terminal_off_service_round_preserves_failed_page_retry_without_minting_completion() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-service-frontier");
    let other = "b1111111-1111-4111-8111-111111111111";
    for session in [OFF_ROOT, other] {
        fs::write(
            scratch.join(format!("{session}.jsonl")),
            off_line(session, session),
        )
        .unwrap();
    }
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 1);
    let mut parsed = first
        .snapshots
        .iter()
        .map(|item| item.source_session_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(parsed.len(), 1);
    let admitted = index.claude_full_rearm_progress.terminal_off_admitted[0].clone();
    enqueue_terminal_off_retry(index.traversal.as_mut().unwrap(), &admitted, true);
    assert!(
        !index.terminal_off_service_round_serviced_for_test(&parsed),
        "unread queued member is not serviced"
    );
    let second = off_scan(&mut index, &scratch, W1, 1);
    parsed.extend(
        second
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone()),
    );
    assert_eq!(parsed.len(), 2);
    assert!(index.terminal_off_service_round_serviced_for_test(&parsed));
    assert!(
        !index.scan_traversal_exhausted_for_test(),
        "failed-page demand stays queued"
    );
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == admitted.path && p.census_member));
    assert!(!first.census_complete && !second.census_complete);
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    assert!(!claude_terminal_authority(&index, true, W1));
}

#[test]
fn terminal_off_idle_cadence_never_parks_already_owed_read_work() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-cadence-owed");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let key = local_index_key(&path);
    let mut settled = off_index();
    let first = off_scan(&mut settled, &scratch, W1, 10);
    off_accept(&mut settled, &first);
    let at = "2026-08-20T10:03:00Z";
    refresh_terminal_off_discovery_at_test(&mut settled, &[scratch.to_path_buf()], at, false);
    assert!(settled
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty());
    let mut future = settled.clone();
    future
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(rfc3339_unix_seconds(at).unwrap() + 100);
    refresh_terminal_off_discovery_at_test(&mut future, &[scratch.to_path_buf()], at, false);
    assert!(
        future
            .traversal
            .as_ref()
            .unwrap()
            .pending_directories
            .is_empty(),
        "future marker debt does not bypass idle cadence"
    );
    let before = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let accepted = settled.accepted_snapshot_fingerprints.clone();
    for cause in [
        "audit",
        "contract",
        "cleared",
        "history",
        "context",
        "legacy_identity",
    ] {
        let mut index = settled.clone();
        match cause {
            "audit" => index
                .files
                .get_mut(&key)
                .unwrap()
                .set_unverified_deadline(1),
            "contract" => {
                index
                    .terminal_contract_retries
                    .insert("exact-entity".into(), "body".into());
            }
            "cleared" => index
                .files
                .get_mut(&key)
                .unwrap()
                .source_file_fingerprint
                .clear(),
            "history" => {
                index.active_effective_upload_body_witness_revision = u64::MAX;
            }
            "context" => {
                index.active_upload_context_fingerprint = Some("new-context".into());
            }
            "legacy_identity" => {
                index.files.get_mut(&key).unwrap().scan_identity_version =
                    Some("claude_code_jsonl:v29".into());
            }
            _ => unreachable!(),
        }
        refresh_terminal_off_discovery_at_test(&mut index, &[scratch.to_path_buf()], at, false);
        assert_eq!(
            index.traversal.as_ref().unwrap().pending_directories.len(),
            1,
            "{cause}: only bounded metadata scheduling wakes"
        );
        assert_eq!(
            START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
            before,
            "no identity/body work before ordinary selection"
        );
        assert_eq!(
            index.accepted_snapshot_fingerprints, accepted,
            "no new ACK credit"
        );
        assert!(
            !claude_terminal_authority(&index, true, W1),
            "no proof/completion credit"
        );
    }
}

#[test]
fn terminal_off_counterfactual_preview_preserves_the_actual_discovery_turn() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-preview-turn");
    let mut index = off_index();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &mut index,
        W1,
        183,
    );
    let scope = terminal_off_rediscovery_scope(&index).unwrap();
    expire_terminal_off_discovery_for_test(&index);
    {
        let _preview = TerminalOffDiscoveryPreviewForTest::begin();
        assert!(terminal_off_rediscovery_due(scope.clone(), 100, false));
        assert!(!terminal_off_rediscovery_due(scope.clone(), 101, false));
    }
    assert!(
        terminal_off_rediscovery_due(scope, 100, false),
        "the control clone did not consume the real owner's turn"
    );
}

#[test]
fn terminal_off_unhinted_append_waits_for_real_cadence_then_is_discovered() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-unhinted-cadence");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let key = local_index_key(&path);
    let before = index.files[&key].source_file_fingerprint.clone();
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let bytes = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
    // No watcher notification, memo expiry shortcut or source re-arm. Only
    // the normal captured audit clock can discover this physical append.
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    use std::io::Write;
    file.write_all(off_line(OFF_ROOT, "Y").as_bytes()).unwrap();
    drop(file);
    for at in ["2026-08-20T10:03:00Z", "2026-08-20T10:06:59Z"] {
        index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        let quiet = off_scan(&mut index, &scratch, at, 10);
        assert_eq!(quiet.scanned_file_count, 0);
        assert_eq!(index.files[&key].source_file_fingerprint, before);
        assert_eq!(
            START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
            samples
        );
        assert_eq!(
            TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get),
            bytes
        );
    }
    let changed = off_scan(&mut index, &scratch, "2026-08-20T10:07:00Z", 10);
    assert_eq!(changed.scanned_file_count, 1);
    assert_ne!(index.files[&key].source_file_fingerprint, before);
    assert!(TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get) > bytes);
    assert!(!changed.census_complete);
}

#[test]
fn terminal_off_captured_audit_clock_survives_yields_and_owns_rediscovery_deadline() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-page-clock");
    let path = scratch.join(format!("{OFF_ROOT}.jsonl"));
    fs::write(&path, off_line(OFF_ROOT, "X")).unwrap();
    let mut index = off_index();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let now = rfc3339_unix_seconds(W1).unwrap() + 1;
    index
        .files
        .get_mut(&local_index_key(&path))
        .unwrap()
        .set_unverified_deadline(now + 1);
    expire_terminal_off_discovery_for_test(&index);
    // Deliberately unrelated census time: it cannot own audit scheduling.
    let page = sampled_scan::with_test_now(now, || {
        OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            &[scratch.to_path_buf()],
            index,
            W2,
            BACKFILL_WINDOW_DAYS,
            10,
            true,
            None,
            &[],
            false,
            false,
        )
    });
    assert_eq!(page.audit_now, now);
    let scope = terminal_off_rediscovery_scope(&page.index).unwrap();
    assert_eq!(
        TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow()[&scope]),
        now + 300
    );
    let result = sampled_scan::with_test_now(now + 400, || {
        let mut page = page;
        loop {
            assert_eq!(
                page.audit_now, now,
                "cooperative steps retain the page clock"
            );
            match page.step(None) {
                OwnedSourceScanStep::Pending(next) => page = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => break (index, scan),
            }
        }
    });
    assert_eq!(
        result.1.scanned_file_count, 0,
        "future audit was not due at selection"
    );
    assert_eq!(
        result.0.files[&local_index_key(&path)]
            .audit_obligation(now)
            .unwrap()
            .due_unix_seconds,
        now + 1
    );
    assert!(!result.1.census_complete);
    let mut index = result.0;
    let due = sampled_scan::with_test_now(now + 400, || {
        scan_source_roots(
            SnapshotSource::ClaudeCode,
            &[scratch.to_path_buf()],
            &mut index,
            W2,
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    });
    assert_eq!(
        due.scanned_file_count, 1,
        "next page captures a new due clock"
    );
}

#[test]
fn terminal_off_empty_context_memo_is_bounded_counts_eviction_and_never_grants_credit() {
    let mut memo = TerminalOffEmptyContexts::default();
    let first = [0u8; 32];
    memo.remember(first);
    for n in 1..=TERMINAL_OFF_EMPTY_CONTEXT_KEYS {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(n as u64).to_be_bytes());
        memo.remember(key);
    }
    assert_eq!(memo.keys.len(), TERMINAL_OFF_EMPTY_CONTEXT_KEYS);
    assert_eq!(memo.order.len(), TERMINAL_OFF_EMPTY_CONTEXT_KEYS);
    assert_eq!(memo.evictions, 1);
    assert!(
        !memo.keys.contains(&first),
        "eviction permits another ordinary context read"
    );
    memo.remember(first);
    assert!(memo.keys.contains(&first));
    assert_eq!(memo.evictions, 2);
    assert_eq!(memo.keys.len(), TERMINAL_OFF_EMPTY_CONTEXT_KEYS);
}
