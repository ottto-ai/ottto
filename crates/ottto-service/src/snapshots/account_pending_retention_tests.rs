// Included in snapshots::tests to exercise the production retirement path and
// its existing accepted-account fixtures without exporting fixture helpers.
mod decoder_0_1_201 {
    include!("account_pending_decoder_0_1_201.rs");
}

fn retention_fixture() -> (PathBuf, String, ScanIndex) {
    let (dir, root, items) = claude_account_family_fixture(false);
    let evidence = claude_account_family_evidence(&root, &vec!["a".repeat(64); 5]);
    let mut index = d2_family_index(&dir, &root);
    apply_claude_effort_evidence_with_index(
        &mut items.clone(),
        &evidence,
        &mut index,
        true,
        "2026-08-02T07:20:00Z",
    );
    d2_finalize_identity_revisions(&mut index);
    let pending = index.claude_account_family_pending.get_mut(&root).unwrap();
    let mut history = pending.current.clone();
    // Leave a historical-only member: its newest historical revision must win.
    let member = pending.members.keys().next().unwrap().clone();
    pending.members.remove(&member);
    pending.member_requests.remove(&member);
    pending.previous_windows = (0..6)
        .map(|minute| {
            history.census_window_end = format!("2026-08-02T07:0{minute}:00Z");
            history.clone()
        })
        .collect();
    (dir, root, index)
}

fn retention_decision(mut index: ScanIndex, root: &str) -> (bool, serde_json::Value) {
    index.retire_committed_claude_account_pending_windows();
    (
        index.claude_account_family_pending.contains_key(root),
        serde_json::to_value(&index.claude_account_family_witnesses).unwrap(),
    )
}

#[test]
fn account_window_collapse_replays_real_retirement_and_holds() {
    let (dir, root, base) = retention_fixture();
    for blocker in [
        "none", "withheld", "unacked", "revision", "account", "invalid", "absent",
    ] {
        let mut before = base.clone();
        let key = before.files.keys().next().unwrap().clone();
        let pending = before.claude_account_family_pending.get_mut(&root).unwrap();
        for window in &mut pending.previous_windows {
            match blocker {
                "revision" => {
                    for requests in window.member_requests.values_mut() {
                        requests.identity_revision = None;
                    }
                }
                "account" => window.account_identifier_hash = "b".repeat(64),
                "invalid" => window.invalid = true,
                "absent" => {
                    window.members.insert("unconfirmed-absent".into(), 1);
                }
                _ => {}
            }
        }
        match blocker {
            "withheld" => {
                before
                    .claude_account_deferred_holds
                    .insert(key, "fixture".into());
            }
            "unacked" => before.accepted_snapshot_fingerprints.clear(),
            _ => {}
        }
        let mut after = before.clone();
        after.collapse_account_pending_windows();
        assert_eq!(
            after.claude_account_family_pending[&root]
                .previous_windows
                .len(),
            2
        );
        assert_eq!(
            claude_pending_family_session_ids(&before),
            claude_pending_family_session_ids(&after),
            "scheduling {blocker}"
        );
        let expected = retention_decision(before, &root);
        assert_eq!(expected.0, blocker != "none", "nonvacuous {blocker}");
        assert_eq!(retention_decision(after, &root), expected, "{blocker}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn account_window_runs_preserve_a_b_a_and_revision_only_changes() {
    let (dir, root, base) = retention_fixture();
    for change in [
        "account",
        "revision",
        "invalid",
        "members",
        "count",
        "complete",
        "version",
        "request_set",
        "member_count",
    ] {
        let mut index = base.clone();
        let windows = &mut index
            .claude_account_family_pending
            .get_mut(&root)
            .unwrap()
            .previous_windows;
        let seed = windows[0].clone();
        *windows = (0..9)
            .map(|minute| {
                let mut window = seed.clone();
                window.census_window_end = format!("2026-08-02T07:0{minute}:00Z");
                if (3..6).contains(&minute) {
                    match change {
                        "account" => window.account_identifier_hash = "b".repeat(64),
                        "revision" => {
                            window
                                .member_requests
                                .values_mut()
                                .next()
                                .unwrap()
                                .identity_revision = Some("c".repeat(64))
                        }
                        "invalid" => window.invalid = true,
                        "count" => window.evidence_request_count += 1,
                        "complete" => window.census_complete = !window.census_complete,
                        "version" => window.version.push_str("-future"),
                        "request_set" => {
                            window
                                .member_requests
                                .values_mut()
                                .next()
                                .unwrap()
                                .fingerprint = "d".repeat(64)
                        }
                        "member_count" => *window.members.values_mut().next().unwrap() += 1,
                        "members" => {
                            let member = window.members.keys().next().unwrap().clone();
                            window.members.remove(&member);
                        }
                        _ => unreachable!(),
                    }
                }
                window
            })
            .collect();
        let original = windows.clone();
        index.collapse_account_pending_windows();
        let collapsed = &index.claude_account_family_pending[&root].previous_windows;
        assert_eq!(
            collapsed,
            &[
                original[0].clone(),
                original[2].clone(),
                original[3].clone(),
                original[5].clone(),
                original[6].clone(),
                original[8].clone()
            ],
            "{change}"
        );
        let once = index.claude_account_family_pending.clone();
        index.collapse_account_pending_windows();
        assert_eq!(index.claude_account_family_pending, once);
        assert_eq!(index.claude_account_window_retention.windows_collapsed, 0);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn account_window_unsafe_boundaries_are_untouched() {
    let (dir, root, base) = retention_fixture();
    for boundary in [
        "unparsable",
        "2026-08-02T07:20:00Z",
        "2026-08-02T07:21:00Z",
        "2026-08-02T07:00:00Z",
    ] {
        let mut index = base.clone();
        index
            .claude_account_family_pending
            .get_mut(&root)
            .unwrap()
            .previous_windows[2]
            .census_window_end = boundary.into();
        let before = index.claude_account_family_pending.clone();
        index.collapse_account_pending_windows();
        assert_eq!(index.claude_account_family_pending, before);
        assert_eq!(index.claude_account_window_retention.windows_collapsed, 0);
        assert_eq!(index.claude_account_window_retention.roots_refused, 1);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn account_window_load_crash_retry_normal_save_and_old_decoder() {
    let (dir, root, mut original) = retention_fixture();
    // Hold the family so normal save cannot retire it before the load fixture.
    original
        .claude_account_family_pending
        .get_mut(&root)
        .unwrap()
        .invalid = true;
    let path = dir.join("retention-index.json");
    original.save(&path).unwrap();
    let disk_before = fs::read(&path).unwrap();
    let generation = original.generation;
    let first = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode))
        .unwrap()
        .0;
    assert_eq!(first.claude_account_window_retention.windows_collapsed, 4);
    assert_eq!(first.claude_account_window_retention.roots_collapsed, 1);
    assert_eq!(first.claude_account_window_retention.roots_refused, 0);
    assert_eq!(
        first.claude_account_window_retention.window_bytes_saved,
        first.claude_account_window_retention.window_bytes_before
            - first.claude_account_window_retention.window_bytes_after
    );
    assert!(
        first.claude_account_window_retention.window_bytes_before
            > first.claude_account_window_retention.window_bytes_after
    );
    let collapsed = first.claude_account_family_pending.clone();
    drop(first); // Process loss before save: no alternate rewrite or disk mutation.
    assert_eq!(fs::read(&path).unwrap(), disk_before);
    let mut retry = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode))
        .unwrap()
        .0;
    assert_eq!(retry.claude_account_family_pending, collapsed);
    assert_eq!(retry.claude_account_window_retention.windows_collapsed, 4);
    assert_eq!(retry.generation, generation);
    retry.save(&path).unwrap();
    assert_eq!(retry.generation, generation + 1);
    let again = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode))
        .unwrap()
        .0;
    assert_eq!(again.claude_account_family_pending, collapsed);
    assert_eq!(again.claude_account_window_retention.windows_collapsed, 0);
    let serialized = serde_json::to_value(&again).unwrap();
    let pending = &serialized["claude_account_family_pending"][&root];
    decoder_0_1_201::assert_reads(&serde_json::to_vec(pending).unwrap(), pending);
    assert_eq!(serialized["schema_version"], SCAN_INDEX_SCHEMA_VERSION);
    assert!(serialized.get("claude_account_window_retention").is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn account_window_collapse_preserves_every_other_index_field_and_scan_identity() {
    let (dir, root, mut index) = retention_fixture();
    let mut before = serde_json::to_value(&index).unwrap();
    // Drop the transcript fixture directory BEFORE collapsing. Collapse has
    // only the in-RAM index and cannot obtain replacement evidence from files.
    fs::remove_dir_all(dir).unwrap();
    index.collapse_account_pending_windows();
    let mut after = serde_json::to_value(&index).unwrap();
    assert_eq!(index.claude_account_window_retention.windows_collapsed, 4);
    before["claude_account_family_pending"][&root]
        .as_object_mut()
        .unwrap()
        .remove("previous_windows");
    after["claude_account_family_pending"][&root]
        .as_object_mut()
        .unwrap()
        .remove("previous_windows");
    // Includes file/source fingerprints, scan identities, accepted/upload
    // witnesses, obligations, current evidence, generation and parser contracts.
    assert_eq!(before, after);
}

#[test]
fn account_window_opaque_holds_preserve_history_and_its_save_budget() {
    let (dir, root, index) = retention_fixture();
    let mut wire = serde_json::to_value(&index).unwrap();
    wire["files"]["/synthetic/opaque.jsonl"] = json!({"size_bytes": []});
    let path = dir.join("opaque-index.json");
    fs::write(&path, serde_json::to_vec_pretty(&wire).unwrap()).unwrap();
    let mut loaded = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode))
        .unwrap()
        .0;
    assert!(!loaded.decode_holds.is_empty());
    assert_eq!(
        loaded.claude_account_family_pending,
        index.claude_account_family_pending
    );
    assert_eq!(loaded.claude_account_window_retention.roots_refused, 1);
    assert_eq!(loaded.claude_account_window_retention.windows_collapsed, 0);
    assert_eq!(loaded.claude_account_window_retention.window_bytes_saved, 0);
    lenient_decode::check_held_output(&loaded).unwrap();
    loaded
        .claude_account_family_pending
        .get_mut(&root)
        .unwrap()
        .invalid = true;
    loaded.save(&path).unwrap();
    let again = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode))
        .unwrap()
        .0;
    assert_eq!(
        again.claude_account_family_pending[&root]
            .previous_windows
            .len(),
        6
    );
    assert!(!again.decode_holds.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
