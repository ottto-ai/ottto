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
    pending.previous_windows = ArchivedWindows::Resident(
        (0..6)
            .map(|minute| {
                history.census_window_end = format!("2026-08-02T07:0{minute}:00Z");
                history.clone()
            })
            .collect(),
    );
    (dir, root, index)
}

/// The v2 hydrate's view of `index`: each archive folded cold, as stored.
fn cold(mut index: ScanIndex) -> ScanIndex {
    for pending in index.claude_account_family_pending.values_mut() {
        let windows = std::mem::take(pending.previous_windows.resident_mut());
        let stored = windows.len() as u64;
        let mut fold = account_pending_retention::ColdFold::default();
        windows.into_iter().for_each(|window| fold.push(window));
        pending.previous_windows = fold.finish((stored != 0).then_some(stored));
    }
    index
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
        for window in pending.previous_windows.resident_mut() {
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
                .resident()
                .len(),
            1
        );
        assert_eq!(
            claude_pending_family_session_ids(&before),
            claude_pending_family_session_ids(&after),
            "scheduling {blocker}"
        );
        // [money] Cold arm: the v2 summary schedules and retires alike.
        let cold_before = cold(before.clone());
        assert_eq!(
            claude_pending_family_session_ids(&cold_before),
            claude_pending_family_session_ids(&before),
            "cold scheduling {blocker}"
        );
        let cold_decision = retention_decision(cold_before, &root);
        let expected = retention_decision(before, &root);
        assert_eq!(expected.0, blocker != "none", "nonvacuous {blocker}");
        assert_eq!(retention_decision(after, &root), expected, "{blocker}");
        assert_eq!(cold_decision, expected, "cold {blocker}");
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
        "version",
        "request_set",
        "member_count",
    ] {
        let mut index = base.clone();
        let windows = index
            .claude_account_family_pending
            .get_mut(&root)
            .unwrap()
            .previous_windows
            .resident_mut();
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
        let collapsed = index.claude_account_family_pending[&root]
            .previous_windows
            .resident();
        assert_eq!(
            collapsed,
            &[
                original[2].clone(),
                original[5].clone(),
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

/// [money] A v1 or resident history with the former rule's second endpoints
/// and census-completion flips collapses to each run's newest window, with
/// the same summary, scheduling and retirement as the uncollapsed history,
/// resident and cold. The completion flag of an archived window splits no
/// run. An account change only in older windows still retires; an
/// unconfirmed member only in them still holds.
#[test]
fn account_window_collapse_keeps_each_runs_newest_across_completion_flips() {
    let (dir, root, base) = retention_fixture();
    for change in ["account", "absent"] {
        let mut before = base.clone();
        let windows = before
            .claude_account_family_pending
            .get_mut(&root)
            .unwrap()
            .previous_windows
            .resident_mut();
        let seed = windows[0].clone();
        // A A' A A' A A' (completion flipping), B B', A.
        *windows = (0..9)
            .map(|minute| {
                let mut window = seed.clone();
                window.census_window_end = format!("2026-08-02T07:0{minute}:00Z");
                window.census_complete = minute % 2 == 0;
                if (6..8).contains(&minute) {
                    match change {
                        "account" => window.account_identifier_hash = "b".repeat(64),
                        _ => {
                            window.members.insert("unconfirmed-absent".into(), 1);
                        }
                    }
                }
                window
            })
            .collect();
        let original = windows.clone();
        let mut after = before.clone();
        after.collapse_account_pending_windows();
        let pending = &after.claude_account_family_pending[&root];
        assert_eq!(
            pending.previous_windows.resident(),
            &[
                original[5].clone(),
                original[7].clone(),
                original[8].clone()
            ],
            "{change}"
        );
        assert_eq!(after.claude_account_window_retention.windows_collapsed, 6);
        assert_eq!(after.claude_account_window_retention.roots_refused, 0);
        assert!(
            pending.history_summary()
                == before.claude_account_family_pending[&root].history_summary(),
            "{change}"
        );
        assert_eq!(
            claude_pending_family_session_ids(&before),
            claude_pending_family_session_ids(&after),
            "scheduling {change}"
        );
        let expected = retention_decision(before.clone(), &root);
        assert_eq!(expected.0, change == "absent", "nonvacuous {change}");
        assert_eq!(retention_decision(after, &root), expected, "{change}");
        assert_eq!(
            retention_decision(cold(before), &root),
            expected,
            "cold {change}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// [money] Unsafe archived boundaries: the load walk refuses a resident
/// family and never walks a cold one; neither changes.
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
            .previous_windows
            .resident_mut()[2]
            .census_window_end = boundary.into();
        // Cold arm: never walked, nothing changes; `uncollapsed` counts the
        // interior windows of equal-evidence runs, boundaries unchecked.
        for (cold_arm, mut index) in [(false, index.clone()), (true, cold(index))] {
            let before = index.claude_account_family_pending.clone();
            index.collapse_account_pending_windows();
            assert_eq!(index.claude_account_family_pending, before);
            assert_eq!(index.claude_account_window_retention.windows_collapsed, 0);
            let refused = u64::from(!cold_arm);
            assert_eq!(index.claude_account_window_retention.roots_refused, refused);
            let uncollapsed = index.claude_account_family_pending[&root]
                .previous_windows
                .uncollapsed();
            assert_eq!(uncollapsed != 0, cold_arm);
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

/// [money] Retirement over the archived boundaries the load collapse refuses.
/// Unparsable, equal-to-current and after-current boundaries refuse: the
/// family keeps every window and its current. An out-of-order but older
/// boundary retires; that pins main's retirement behaviour, because refusing
/// out-of-order archives is the load-time collapse's job. Two archived windows
/// at one boundary give the historical-only member the first window's
/// evidence, so a bad account, invalid flag or revision refuses only when it
/// comes first. The unmodified family is the retiring control.
#[test]
fn account_window_boundaries_keep_retirement_outcomes() {
    let (dir, root, base) = retention_fixture();
    for (boundary, retires) in [
        ("control", true),
        ("unparsable", false),
        ("2026-08-02T07:20:00Z", false),
        ("2026-08-02T07:21:00Z", false),
        ("2026-08-02T07:00:00Z", true),
        ("tie account first", false),
        ("tie account second", true),
        ("tie invalid first", false),
        ("tie invalid second", true),
        ("tie revision first", false),
        ("tie revision second", true),
    ] {
        let mut index = base.clone();
        let pending = index.claude_account_family_pending.get_mut(&root).unwrap();
        if let Some((change, order)) = boundary
            .strip_prefix("tie ")
            .and_then(|tie| tie.split_once(' '))
        {
            let member = pending.previous_windows.resident()[5]
                .members
                .keys()
                .find(|member| !pending.members.contains_key(*member))
                .unwrap()
                .clone();
            let windows = pending.previous_windows.resident_mut();
            windows[4].census_window_end = windows[5].census_window_end.clone();
            let window = &mut windows[if order == "first" { 4 } else { 5 }];
            match change {
                "account" => window.account_identifier_hash = "b".repeat(64),
                "invalid" => window.invalid = true,
                _ => {
                    window
                        .member_requests
                        .get_mut(&member)
                        .unwrap()
                        .identity_revision = Some("c".repeat(64))
                }
            }
        } else if boundary != "control" {
            pending.previous_windows.resident_mut()[2].census_window_end = boundary.into();
        }
        let before = pending.clone();
        // Cold arm: the same outcome from the cold summary.
        let mut cold_index = cold(index.clone());
        cold_index.retire_committed_claude_account_pending_windows();
        assert_eq!(
            cold_index.claude_account_family_pending.contains_key(&root),
            !retires,
            "cold {boundary}"
        );
        index.retire_committed_claude_account_pending_windows();
        assert_eq!(
            index.claude_account_family_pending.get(&root),
            (!retires).then_some(&before),
            "{boundary}"
        );
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
    assert_eq!(first.claude_account_window_retention.windows_collapsed, 5);
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
    assert_eq!(retry.claude_account_window_retention.windows_collapsed, 5);
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
    assert_eq!(index.claude_account_window_retention.windows_collapsed, 5);
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
    let (reopened, counts) = state_v2::compact_reopened_for_test(&loaded);
    assert_eq!(
        counts,
        json!({"windows_removed": 0, "families_refused": 0, "families_done": 0})
    );
    assert_eq!(
        serde_json::to_vec(&reopened.claude_account_family_pending).unwrap(),
        serde_json::to_vec(&loaded.claude_account_family_pending).unwrap()
    );
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
            .resident()
            .len(),
        6
    );
    assert!(!again.decode_holds.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

/// Everything account placement reads from a family's archived windows:
/// the sessions scheduled for evidence reads (`has_history`), then the
/// save's retirement (`history_summary`), its witnesses, the sessions
/// scheduled afterwards and the family's surviving current window.
type Placement = (
    Vec<String>,
    bool,
    serde_json::Value,
    Vec<String>,
    Option<serde_json::Value>,
);
fn placement(mut index: ScanIndex, root: &str) -> Placement {
    let scheduled = claude_pending_family_session_ids(&index);
    index.retire_committed_claude_account_pending_windows();
    let pending = index.claude_account_family_pending.get(root);
    (
        scheduled,
        pending.is_some(),
        serde_json::to_value(&index.claude_account_family_witnesses).unwrap(),
        claude_pending_family_session_ids(&index),
        pending.map(|pending| serde_json::to_value(&pending.current).unwrap()),
    )
}

/// [money] Placement parity, two-endpoint retention vs one window per run.
/// Literal legacy histories keep both endpoints of each run, splitting on
/// completion flips. Check written-out newest-only results from `archive` and
/// load collapse, then compare real placement through resident and cold views.
#[test]
fn account_window_placement_parity_with_two_endpoint_retention() {
    let (dir, root, base) = retention_fixture();
    let seed = base.claude_account_family_pending[&root]
        .previous_windows
        .resident()[0]
        .clone();
    let current_end = base.claude_account_family_pending[&root]
        .census_window_end
        .clone();
    let window = |minute: u32, complete, account: char, invalid| {
        let mut window = seed.clone();
        window.census_window_end = format!("2026-08-02T07:{minute:02}:00Z");
        window.census_complete = complete;
        window.account_identifier_hash = account.to_string().repeat(64);
        window.invalid = invalid;
        window
    };
    let a = |minute| window(minute, true, 'a', false);
    let b = |minute| window(minute, true, 'b', false);
    let invalid = |minute| window(minute, true, 'b', true);
    let mut absent = a(3);
    absent.members.insert("unconfirmed-absent".into(), 1);
    // Keep this historical-only member's evidence canonical for the v2 store;
    // its absence remains unconfirmed and must independently prevent retirement.
    let mut requests =
        ClaudeAccountRequestSet::from_full_hashes(&BTreeSet::from(["f".repeat(64)])).unwrap();
    requests.identity_revision = seed
        .member_requests
        .values()
        .next()
        .unwrap()
        .identity_revision
        .clone();
    absent
        .member_requests
        .insert("unconfirmed-absent".into(), requests);
    absent.evidence_request_count += 1;
    assert!(claude_family_request_ids_are_disjoint(&absent));
    for (history, windows, newest, retires) in [
        (
            "repeats_flips_a_b_a",
            // Old: A[0,2], incomplete A[3], A[4], B[5,7], A[8,9].
            vec![
                a(0),
                a(2),
                window(3, false, 'a', false),
                a(4),
                b(5),
                b(7),
                a(8),
                a(9),
            ],
            vec![a(4), b(7), a(9)],
            true,
        ),
        (
            "invalid_switch_mid",
            vec![a(0), a(2), invalid(3), invalid(5), a(6), a(8)],
            vec![a(2), invalid(5), a(8)],
            true,
        ),
        (
            "invalid_switch_last",
            vec![a(0), a(2), invalid(3), invalid(5)],
            vec![a(2), invalid(5)],
            false,
        ),
        (
            "absent_older",
            vec![a(0), a(2), absent.clone(), a(4), a(6)],
            vec![a(2), absent, a(6)],
            false,
        ),
    ] {
        let with_archive = |archive: Vec<ClaudeAccountFamilyPendingWindow>| {
            let mut index = base.clone();
            *index
                .claude_account_family_pending
                .get_mut(&root)
                .unwrap()
                .previous_windows
                .resident_mut() = archive;
            index
        };
        let legacy = with_archive(windows.clone());
        // Rollovers: each window is the current one until the next replaces it.
        let mut new_rolled = with_archive(Vec::new());
        let pending = new_rolled
            .claude_account_family_pending
            .get_mut(&root)
            .unwrap();
        let final_current = std::mem::replace(&mut pending.current, windows[0].clone());
        for next in windows[1..].iter().chain([&final_current]) {
            let old = std::mem::replace(&mut pending.current, next.clone());
            pending.archive(old, true);
        }
        assert_eq!(pending.census_window_end, current_end);
        assert_eq!(pending.previous_windows.resident(), &newest, "{history}");
        let mut new_collapsed = legacy.clone();
        new_collapsed.collapse_account_pending_windows();
        assert_eq!(
            new_collapsed.claude_account_window_retention.roots_refused,
            0
        );
        assert_eq!(
            new_collapsed.claude_account_family_pending[&root]
                .previous_windows
                .resident(),
            &newest,
            "{history}"
        );

        let summary = legacy.claude_account_family_pending[&root].history_summary();
        let (reopened, counts) = state_v2::compact_reopened_for_test(&legacy);
        assert_eq!(counts["windows_removed"], windows.len() - newest.len());
        assert_eq!(counts["families_done"], 1);
        assert_eq!(counts["families_refused"], 0);
        assert_eq!(
            reopened.claude_account_family_pending[&root]
                .previous_windows
                .resident(),
            &newest
        );
        let expected = placement(legacy.clone(), &root);
        assert_eq!(!expected.1, retires, "nonvacuous {history}");
        for (arm, index) in [
            ("v2 compacted reopened", reopened),
            ("new rolled", new_rolled.clone()),
            ("new collapsed", new_collapsed),
            ("cold legacy", cold(legacy)),
            ("cold new rolled", cold(new_rolled)),
        ] {
            assert!(
                index.claude_account_family_pending[&root].history_summary() == summary,
                "{history} {arm} summary"
            );
            assert_eq!(placement(index, &root), expected, "{history} {arm}");
        }
    }
    fs::remove_dir_all(dir).unwrap();
}
