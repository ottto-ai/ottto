// Included in stale_family_carry_tests: use its native carry/window builders.
// These exercise the scheduling transition only. The shared acquisition
// transition fixture (a predecessor) owns restore+Tail, money and raw I/O.
fn rebind_loaded(index: &ScanIndex) -> ScanIndex {
    let scratch = crate::test_scratch::ScratchDir::new("carry-rebind");
    let path = scratch.join("index.json");
    fs::write(&path, serde_json::to_vec(index).unwrap()).unwrap();
    ScanIndex::load(&path).unwrap()
}

fn rebind_active(window: bool, capped: bool) -> ScanIndex {
    let mut index = if window {
        window_index()
    } else {
        carry_index()
    };
    let unwitnessed = carry_key(CARRY_UNWITNESSED, None);
    let revision = index.files[&unwitnessed].source_file_fingerprint.clone();
    let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 1);
    if capped {
        assert!(window);
        index
            .files
            .get_mut(&unwitnessed)
            .unwrap()
            .source_file_fingerprint = revision;
        index
            .claude_usage_family_pending
            .get_mut(CARRY_UNWITNESSED)
            .unwrap()
            .census_window_end = CARRY_RETRY.into();
        window_needs_clean_followup(&mut index);
        let row = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["stale_rearm_capped_files"], 1);
        assert!(index
            .claude_stale_family_carry
            .capped_roots
            .contains(CARRY_UNWITNESSED));
    }
    assert!(index.claude_stale_family_carry.roots.contains(CARRY_ROOT));
    index
        .claude_stale_family_carry
        .replay
        .push(carry_replayed(&carry_key(CARRY_OTHER, None)));
    let traversal = index.traversal.as_mut().unwrap();
    traversal.observed_index_keys.extend(carry_family_keys());
    traversal
        .pending_candidates
        .push_back(carry_replayed(&unwitnessed));
    traversal
        .pending_directories
        .push_back(carry_replayed(CARRY_SCAN_ROOT));
    rebind_loaded(&index)
}

// A failing seam at the real candidate-open boundary (before OS open or
// samples/prefetch), rather than a parser-consumption zero. This proves only
// ensure_bounded_traversal's call graph, not a later acquisition pass.
fn rebind_forbid_open<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            CLAUDE_CARRY_FORBID_OPEN_FOR_TEST.with(|f| f.set(self.0));
        }
    }
    let _reset = Reset(CLAUDE_CARRY_FORBID_OPEN_FOR_TEST.with(|f| f.replace(true)));
    f()
}

fn rebind_no_open(index: &mut ScanIndex) -> (TraversalProgress, Vec<serde_json::Value>) {
    rebind_forbid_open(|| {
        crate::local_resource_diagnostics::capture(|| {
            ensure_bounded_traversal(
                SnapshotSource::ClaudeCode,
                &[],
                index,
                CARRY_RESUME,
                BACKFILL_WINDOW_DAYS,
            )
        })
    })
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_no_open_oracle_rejects_the_real_candidate_open_callback() {
    let fixture = scoped_retry_fixture(0, 1, false);
    let candidate = &fixture.candidates[0];
    let panic = std::panic::catch_unwind(|| {
        rebind_forbid_open(|| {
            let _ = open_candidate_beneath_root(candidate);
        })
    })
    .expect_err("the real acquisition callback must trip the oracle");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(message.contains("carry transition opened transcript"));
    assert!(!CLAUDE_CARRY_FORBID_OPEN_FOR_TEST.with(std::cell::Cell::get));
}

fn rebind_counts(rows: &[serde_json::Value], event: &str) -> Vec<serde_json::Value> {
    rows.iter()
        .filter(|row| row["counts"]["event"] == event)
        .map(|row| row["counts"].clone())
        .collect()
}

fn assert_rebind_preserved(before: &ScanIndex, after: &ScanIndex) {
    let before = serde_json::to_value(before).unwrap();
    let after = serde_json::to_value(after).unwrap();
    // Independent post-transition observations of position, accepted body,
    // proof/census and all fingerprints; no expected witness copied by driver.
    for field in [
        "traversal",
        "files",
        "claude_request_census",
        "claude_usage_family_pending",
        "claude_usage_family_witnesses",
        "accepted_snapshot_fingerprints",
        "session_account_bindings",
    ] {
        assert_eq!(before[field], after[field], "{field}");
    }
    let mut carry = after["claude_stale_family_carry"].clone();
    carry["origin"]["process"] = before["claude_stale_family_carry"]["origin"]["process"].clone();
    assert_eq!(carry, before["claude_stale_family_carry"]);
    let mut progress = after["claude_full_rearm_progress"].clone();
    if progress["full_rearm_window"].is_object() {
        progress["full_rearm_window"]["process"] =
            before["claude_full_rearm_progress"]["full_rearm_window"]["process"].clone();
    }
    assert_eq!(progress, before["claude_full_rearm_progress"]);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_restart_roots_replay_and_admission_rebind_without_open() {
    let _old = ClaudeCarryProcessForTest::new(101);
    let mut index = rebind_active(false, false);
    index
        .claude_stale_family_carry
        .origin
        .as_mut()
        .unwrap()
        .admission = Some(
        serde_json::from_value(serde_json::json!({
            "after_root": null, "upper_root": CARRY_ROOT, "complete": false,
            "progressed": true, "served_before": 7
        }))
        .unwrap(),
    );
    let before = index.clone();
    let _new = ClaudeCarryProcessForTest::new(103);
    let (progress, rows) = rebind_no_open(&mut index);
    assert_eq!(progress, TraversalProgress::Resumed);
    assert_rebind_preserved(&before, &index);
    assert_eq!(
        index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .process,
        103
    );
    let counts = rebind_counts(&rows, "carry_rebind");
    assert_eq!(counts.len(), 1);
    assert_eq!(counts[0]["reason"], "process_only");
    assert_eq!(counts[0]["count"], 1);
    assert_eq!(
        counts[0]["carry_at_start"]["process_changed_since_last_start"],
        true
    );
    assert_eq!(counts[0]["carry_at_start"]["admission_progressed"], true);
    assert!(rebind_counts(&rows, "base_rewind").is_empty());
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_restart_window_and_capped_rebind_without_read_proof() {
    let _old = ClaudeCarryProcessForTest::new(201);
    for capped in [false, true] {
        let mut index = rebind_active(true, capped);
        assert!(!index.claude_full_rearm_progress.rebuild_read_full);
        assert!(index
            .claude_full_rearm_progress
            .complete_rebuild_read
            .is_none());
        let before = index.clone();
        let _new = ClaudeCarryProcessForTest::new(203);
        let (progress, rows) = rebind_no_open(&mut index);
        assert_eq!(progress, TraversalProgress::Resumed);
        assert_rebind_preserved(&before, &index);
        assert_eq!(
            index
                .claude_full_rearm_progress
                .full_rearm_window
                .as_ref()
                .unwrap()
                .process,
            203
        );
        assert_eq!(
            rebind_counts(&rows, "carry_rebind")[0]["carry_at_start"]["window"],
            true
        );
        assert!(!index.claude_full_rearm_progress.rebuild_read_full);
        assert!(index
            .claude_full_rearm_progress
            .complete_rebuild_read
            .is_none());
        // No new process-bound traversal/read proof was minted.
        assert_eq!(
            index.claude_full_rearm_progress.traversal_origin,
            before.claude_full_rearm_progress.traversal_origin
        );
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_restart_missing_context_and_inconsistent_window_keep_base() {
    let _old = ClaudeCarryProcessForTest::new(301);
    let original = rebind_active(true, true);
    for cause in [
        "missing",
        "context",
        "traversal_context",
        "window",
        "capped",
        "next",
        "member_digest",
        "missing_window",
        "empty_window",
    ] {
        let mut index = original.clone();
        match cause {
            "missing" => index.claude_stale_family_carry.origin = None,
            "context" => {
                index
                    .claude_stale_family_carry
                    .origin
                    .as_mut()
                    .unwrap()
                    .context_fingerprint = "other-context".into()
            }
            "traversal_context" => {
                index.traversal.as_mut().unwrap().context_fingerprint = "other-context".into()
            }
            "window" => {
                index
                    .claude_full_rearm_progress
                    .full_rearm_window
                    .as_mut()
                    .unwrap()
                    .process = 999
            }
            "capped" => {
                index
                    .claude_stale_family_carry
                    .origin
                    .as_mut()
                    .unwrap()
                    .full_rearm_window = false
            }
            "next" => index.claude_full_rearm_progress.full_rearm_window_next = true,
            "member_digest" => index
                .claude_full_rearm_progress
                .full_rearm_window
                .as_mut()
                .unwrap()
                .member_digests
                .clear(),
            "missing_window" => index.claude_full_rearm_progress.full_rearm_window = None,
            "empty_window" => index
                .claude_full_rearm_progress
                .full_rearm_window
                .as_mut()
                .unwrap()
                .window_ends
                .clear(),
            _ => unreachable!(),
        }
        let _new = ClaudeCarryProcessForTest::new(303);
        let (progress, rows) = rebind_no_open(&mut index);
        assert_eq!(progress, TraversalProgress::Started, "{cause}");
        assert!(rebind_counts(&rows, "carry_rebind").is_empty(), "{cause}");
        let rewinds = rebind_counts(&rows, "base_rewind");
        assert_eq!(rewinds.len(), 1, "{cause}");
        let expected = match cause {
            "traversal_context" => "context",
            "capped" | "next" | "member_digest" | "missing_window" | "empty_window" => "window",
            other => other,
        };
        assert_eq!(rewinds[0]["reason"], expected, "{cause}");
        for key in carry_family_keys() {
            assert!(
                index.files[&key].source_file_fingerprint.is_empty(),
                "{cause}"
            );
        }
        assert_eq!(
            index.traversal.as_ref().unwrap().census_window_end,
            CARRY_RESUME
        );
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .observed_index_keys
            .is_empty());
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_restart_refund_refusal_uses_existing_before_and_after_pass_paths() {
    let _old = ClaudeCarryProcessForTest::new(401);
    for passed in [false, true] {
        let mut index = rebind_active(false, false);
        if !passed {
            index
                .traversal
                .as_mut()
                .unwrap()
                .observed_index_keys
                .clear();
        }
        let uncarries = claude_stale_family_carry_refund_uncarries_for_test();
        let _new = ClaudeCarryProcessForTest::new(403);
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
        let (progress, rows) = rebind_no_open(&mut index);
        assert_eq!(rebind_counts(&rows, "carry_rebind").len(), 1);
        assert_eq!(rebind_counts(&rows, "base_rewind")[0]["reason"], "refund");
        assert_eq!(
            claude_stale_family_carry_refund_uncarries_for_test(),
            uncarries + 1
        );
        assert_eq!(
            progress,
            if passed {
                TraversalProgress::Started
            } else {
                TraversalProgress::Resumed
            }
        );
        assert!(index.claude_stale_family_carry.roots.is_empty());
        for key in carry_family_keys() {
            assert!(index.files[&key].source_file_fingerprint.is_empty());
        }
        // Acquisition is not invoked here. Its restore+Tail/zero-Full row is
        // owned by 5b-A1; do not claim M1's cleared-selection Full is repaired.
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn r2_carry_two_restarts_keep_the_same_obligations_and_position() {
    let _old = ClaudeCarryProcessForTest::new(501);
    let mut index = rebind_active(false, false);
    let original = index.clone();
    let queued = index.claude_stale_family_carry.replay.len();
    for process in [503, 505] {
        let _new = ClaudeCarryProcessForTest::new(process);
        index = rebind_loaded(&index);
        let (progress, rows) = rebind_no_open(&mut index);
        assert_eq!(progress, TraversalProgress::Resumed);
        assert_eq!(rebind_counts(&rows, "carry_rebind").len(), 1);
        assert_rebind_preserved(&original, &index);
        assert_eq!(index.claude_stale_family_carry.replay.len(), queued);
        assert_eq!(
            index
                .claude_stale_family_carry
                .origin
                .as_ref()
                .unwrap()
                .process,
            process
        );
        // One additional resume in that process does not count/rebind again.
        let (_, rows) = rebind_no_open(&mut index);
        assert!(rebind_counts(&rows, "carry_rebind").is_empty());
    }
}
