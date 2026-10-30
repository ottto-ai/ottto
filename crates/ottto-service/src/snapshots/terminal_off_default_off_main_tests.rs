use super::*;

#[test]
fn default_off_main_one_sided_claude_title_shapes_preserve_account_only_mapping() {
    let (home, _transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-one-sided",
            "no-title-session",
            "{\"cliSessionId\":\"no-title-session\",\"sessionId\":\"desktop-session\"}",
            "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"no-title-session\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
        );
    let store_dir = home
        .join("Library")
        .join("Application Support")
        .join("Claude")
        .join("claude-code-sessions")
        .join("account-ctx")
        .join("workspace");
    fs::write(
        store_dir.join("desktop-only.json"),
        "{\"sessionId\":\"desktop-only\",\"title\":\"Desktop only title\"}",
    )
    .expect("write desktop-only title");

    let mut index = ScanIndex::default();
    let scan = scan_source_roots(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&projects_root),
        &mut index,
        "2026-07-10T10:04:00Z",
        BACKFILL_WINDOW_DAYS,
    )
    .expect("scan one-sided optional title shapes");
    assert!(scan.sidecar_census_complete);
    assert!(scan.census_complete);
    assert_eq!(index.claude_desktop_title_files.len(), 1);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(scan.snapshots[0].session_display_name.is_none());
    let expected_hash = ottto_core::billing_identity_hash("anthropic", "account", "account-ctx")
        .expect("account hash");
    assert!(scan.snapshots[0]
        .model_usage
        .iter()
        .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str())));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn default_off_main_terminal_dispositions_are_pruned_when_their_file_moves_or_disappears() {
    let source = SnapshotSource::ClaudeCode;
    let root = temp_dir("terminal-disposition-prune");
    let original = root.join("session-a.jsonl");
    let moved = root.join("session-b.jsonl");
    let mut bytes = b"{\"type\":\"assistant\",\"sessionId\":\"019e2700-7777-7000-9000-777777777777\",\"uuid\":\"019e2700-7777-7000-9000-7777777777a1\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":12,\"output_tokens\":4,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n".to_vec();
    bytes.extend_from_slice(b"{\"type\":\"assistant\",\"ignored\":\"");
    bytes.extend(std::iter::repeat_n(b'x', MAX_JSONL_LINE_BYTES + 1));
    bytes.extend_from_slice(b"\"}\n");
    fs::write(&original, &bytes).expect("write over-cap fixture");

    let traverse = |index: &mut ScanIndex, at: &str| {
        let mut result = scan_source_roots_with_limit(
            source,
            std::slice::from_ref(&root),
            index,
            at,
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("traversal completes");
        assert!(result.census_complete);
        finalize_scan_after_policy(source, &mut result, index);
        result
    };

    let mut index = ScanIndex::default();
    let first = traverse(&mut index, "2026-07-22T08:02:00Z");
    assert_eq!(first.scanned_file_count, 1);
    assert_eq!(first.over_line_cap_count, 1);
    assert_eq!(index.terminal_jsonl_dispositions.len(), 1);
    assert!(index
        .terminal_jsonl_dispositions
        .contains_key(&local_index_key(&original)));

    // Moved path: the same bytes are a new object. The new key is recorded
    // and the old key must NOT be carried forward beside it.
    fs::rename(&original, &moved).expect("rename terminal fixture");
    let after_move = traverse(&mut index, "2026-07-22T08:07:00Z");
    assert_eq!(
        after_move.scanned_file_count, 1,
        "moved object is read once"
    );
    assert_eq!(
        after_move.over_line_cap_count, 1,
        "loss is not double-counted"
    );
    assert_eq!(
        index.terminal_jsonl_dispositions.len(),
        1,
        "the renamed-away key is pruned, not accumulated"
    );
    assert!(index
        .terminal_jsonl_dispositions
        .contains_key(&local_index_key(&moved)));
    assert_eq!(index.files.len(), 1);

    // Deleted path: nothing indexed corresponds to the disposition at all.
    fs::remove_file(&moved).expect("remove terminal fixture");
    let after_delete = traverse(&mut index, "2026-07-22T08:12:00Z");
    assert_eq!(after_delete.scanned_file_count, 0);
    assert!(
        index.terminal_jsonl_dispositions.is_empty(),
        "a deleted file leaves no durable disposition behind"
    );
    assert!(index.files.is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn default_off_shared_scanner_pages_decisions_census_and_counters_match_main() {
    assert!(!claude_terminal_off(), "fixture starts at release default");
    let _off = ClaudeTerminalOffForTest::disabled();
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-default-main-identity");
    for (session, request) in [
        ("a1111111-1111-4111-8111-111111111111", "one"),
        ("b2222222-2222-4222-8222-222222222222", "two"),
    ] {
        fs::write(scratch.join(format!("{session}.jsonl")), format!("{}\n",
            json!({"type":"assistant","sessionId":session,"timestamp":"2026-08-20T10:01:00Z","requestId":request,"message":{"id":request,"model":"claude-sonnet-4-6","usage":{"input_tokens":12,"output_tokens":4}}}))).unwrap();
    }
    let run = || {
        let mut index = ScanIndex::default();
        index.initialize_current_claude_contract_for_test();
        let mut pages = Vec::new();
        let (_, diagnostics) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..2 {
                let scan = scan_source_roots_with_limit(
                    SnapshotSource::ClaudeCode,
                    &[scratch.to_path_buf()],
                    &mut index,
                    "2026-08-20T10:02:00Z",
                    183,
                    1,
                    false,
                )
                .unwrap();
                let decisions = index
                    .files
                    .keys()
                    .map(|key| {
                        let candidate = candidate_from_traversal_path(
                            SnapshotSource::ClaudeCode,
                            ScanTraversalPath {
                                scan_root: scratch.to_path_buf(),
                                path: PathBuf::from(key),
                                census_member: true,
                                watcher_hint: false,
                            },
                            &mut ScanCensus::default(),
                            None,
                            183,
                            &index.files,
                        )
                        .unwrap();
                        format!(
                            "{:?}",
                            index.candidate_decision_with_reason_at(&candidate, 1787220120)
                        )
                    })
                    .collect::<Vec<_>>();
                pages.push((
                    scan.discovered_file_count,
                    scan.scanned_file_count,
                    scan.scan_cap_hit,
                    scan.census_complete,
                    serde_json::to_value(&scan.snapshots).unwrap(),
                    decisions,
                ));
            }
        });
        assert!(
            diagnostics.iter().all(|r| !r["stage"]
                .as_str()
                .unwrap_or("")
                .starts_with("terminal_off")),
            "OFF allocates no discovery/retention service"
        );
        pages
    };
    let main_default = sampled_scan::with_test_now(1787220120, run);
    let reference = {
        let _on = ClaudeTerminalOffForTest::enabled();
        let _historical = ClaudeCompletionPathsForTest::enable();
        sampled_scan::with_test_now(1787220120, run)
    };
    assert_eq!(
        main_default, reference,
        "same ordinary selection, bodies, page shapes, census and counts"
    );
    assert_eq!(main_default.iter().map(|p| p.1).sum::<usize>(), 2);
    assert!(
        main_default.last().unwrap().3,
        "ordinary main terminal completes"
    );
    let mut index = ScanIndex::default();
    let before = serde_json::to_value(&index).unwrap();
    refresh_terminal_off_discovery(
        &mut index,
        &[scratch.to_path_buf()],
        1787220120,
        true,
        "2026-08-20T10:02:00Z",
        1,
    );
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        before,
        "OFF entry point is inert even without a traversal"
    );
    assert!(claude_terminal_authority(&index, true, "any-window"));
    assert!(!claude_terminal_authority(&index, false, "any-window"));
}
