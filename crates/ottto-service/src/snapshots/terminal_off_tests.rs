use super::*;

const OFF_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const OFF_CHILD: &str = "agent-a4d1585d310070d0f";
const W1: &str = "2026-08-20T10:02:00Z";
const W2: &str = "2026-08-20T10:12:00Z";

fn off_line(member: &str, request: &str) -> String {
    format!("{{\"timestamp\":\"2026-08-20T10:01:00Z\",\"sessionId\":\"{member}\",\"type\":\"assistant\",\"forkedFrom\":{{\"sessionId\":\"prior\",\"messageUuid\":\"prior-message\"}},\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg-{request}\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":2}}}}}}\n")
}

fn off_scan(index: &mut ScanIndex, root: &Path, at: &str, limit: usize) -> SourceScanResult {
    let mut result = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root.to_owned()],
        index,
        at,
        BACKFILL_WINDOW_DAYS,
        limit,
        true,
    )
    .unwrap();
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
            ..Default::default()
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
        // Exact counterexample: only root changes; child still contains X.
        let mut text = fs::read_to_string(&root_path).unwrap();
        text.push_str("{\"type\":\"user\",\"message\":{\"content\":\"metadata only\"}}\n");
        fs::write(&root_path, text).unwrap();
        index.traversal = None;
        index.claude_duplicate_request_witness_overflowed = initially_closed;
        let page = off_scan(&mut index, &root, W2, 10);
        assert_eq!(
            page.scanned_file_count, 1,
            "unchanged duplicate sibling skipped"
        );
        assert!(!page.census_complete);
        assert!(index.claude_duplicate_request_witness_overflowed);
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
    let mut index = ScanIndex::default();
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
        ..Default::default()
    };
    let first = off_scan(&mut index, &scratch, W1, N);
    assert_eq!(first.scanned_file_count, N);
    off_accept(&mut index, &first);
    // Process reload + no retained traversal: not a cheap parking-only test.
    index = serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
    index.active_upload_context_fingerprint = Some("settled-destination".into());
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
    let mut index = ScanIndex::default();
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
    index.traversal = None;
    let changed = off_scan(&mut index, &scratch, W2, 10);
    assert_eq!(changed.scanned_file_count, 1);
    assert_ne!(
        index.files[&local_index_key(&path)].source_file_fingerprint,
        old
    );
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
    let mut index = ScanIndex::default();
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
            index
                .claude_full_rearm_progress
                .terminal_off_rediscovery_after = 0;
        }
        refresh_terminal_off_discovery(&mut index, &[scratch.to_path_buf()], W2, overflow);
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
    let mut index = ScanIndex::default();
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
    let mut index = ScanIndex::default();
    let first = off_scan(&mut index, &scratch, W1, 10);
    off_accept(&mut index, &first);
    let key = local_index_key(&path);
    let before = index.files[&key].source_file_fingerprint.clone();
    fs::remove_file(&path).unwrap();
    if let Some(t) = index.traversal.as_mut() {
        enqueue_terminal_off_retry(t, &key);
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
    assert!(index.claude_duplicate_request_witness_overflowed);
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
    let mut index = ScanIndex::default();
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
        W2,
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
    let mut index = ScanIndex::default();
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
    let mut index = ScanIndex::default();
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
    let mut index = ScanIndex::default();
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
