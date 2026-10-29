// Synthetic corpus and frozen-index inventory replay. Like #891's account
// window replay, both arms call production decisions on the same input state.
use super::*;
use usage_pending_guard::{Unknown, Verdict};

fn route(index: &ScanIndex, roots: &BTreeSet<String>, route: usize) -> BTreeSet<String> {
    match route {
        0 => claude_fence_closed_retry_carry(index, roots, true, false, true).roots,
        1 => claude_stream_accepted_retry_carry(index, roots)
            .map(|c| c.roots)
            .unwrap_or_default(),
        _ => {
            claude_retry_admit_batch(index, roots, None, CARRY_RETRY)
                .0
                .roots
        }
    }
}

#[test]
fn phase1_three_states_on_ordinary_streaming_batch_keep_independent_acceptance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for route_id in 0..3 {
        for state in 0..3 {
            let mut fixture = retry_durable_fixture(0, 1);
            let root = fixture.roots[0].clone();
            if state == 1 {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .member_occurrences
                    .values_mut()
                    .next()
                    .unwrap()
                    .values_mut()
                    .next()
                    .unwrap()
                    .output_tokens += 1;
            } else if state == 2 {
                fixture.index.claude_usage_family_witnesses.remove(&root);
            }
            let expected = [
                Verdict::Match,
                Verdict::Mismatch,
                Verdict::Unknown(Unknown::MissingWitness),
            ][state];
            assert_eq!(
                usage_pending_guard::verdict(&fixture.index, &root),
                expected
            );
            let roots = BTreeSet::from([root.clone()]);
            let before = serde_json::to_value(&fixture.index).unwrap();
            fixture.index.refresh_usage_guard_holds();
            assert_eq!(
                serde_json::to_value(&fixture.index).unwrap(),
                before,
                "runtime only"
            );
            let new = route(&fixture.index, &roots, route_id);
            let old = usage_pending_guard::replay_old(|| route(&fixture.index, &roots, route_id));
            if state == 2 {
                assert!(new.is_empty(), "Unknown never carries route={route_id}");
                assert!(fixture.index.usage_guard_holds.holds(&root));
            } else {
                assert_eq!(new, old, "known route={route_id}");
                assert!(
                    new.contains(&root),
                    "existing independent ACK route stays independent"
                );
            }
            let pending = fixture.index.claude_usage_family_pending.clone();
            let files = serde_json::to_value(&fixture.index.files).unwrap();
            if state == 2 {
                carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
                assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), files);
                assert_eq!(fixture.index.claude_usage_family_pending, pending);
                assert!(fixture.index.claude_stale_family_carry.replay.is_empty());
                let counts = stale_carry_diagnostics::take_for_test().unwrap().json();
                assert_eq!(
                    serde_json::from_str::<Value>(&counts).unwrap()["unknown_missing_witness"],
                    1
                );
                assert_eq!(
                    replay_and_rearm_claude_family(
                        &mut fixture.index,
                        &root,
                        "",
                        &VecDeque::new(),
                        true
                    ),
                    (0, 0)
                );
                assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), files);
            }
        }
    }
}

#[test]
fn phase1_known_guard_matches_old_and_missing_inventory_is_unknown() {
    let mut index = carry_index();
    let pending = &index.claude_usage_family_pending[CARRY_ROOT];
    let witness = &index.claude_usage_family_witnesses[CARRY_ROOT];
    let members = carry_family_members();
    assert!(claude_stale_pending_matches_witness(
        pending, witness, &members
    ));
    assert_eq!(
        usage_pending_guard::check(pending, Some(witness), |m| members.contains(m)),
        Verdict::Match
    );
    for modality in 0..9 {
        let mut changed = pending.clone();
        let occurrence = changed
            .member_occurrences
            .values_mut()
            .next()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        match modality {
            0 => occurrence.sequence += 1,
            1 => occurrence.input_tokens += 1,
            2 => occurrence.output_tokens += 1,
            3 => occurrence.cache_read_tokens += 1,
            4 => occurrence.cache_creation_5m_tokens += 1,
            5 => occurrence.cache_creation_1h_tokens += 1,
            6 => occurrence.reasoning_output_tokens += 1,
            7 => occurrence.model = Some("different-model".into()),
            _ => occurrence.speed_mode = Some("fast".into()),
        }
        assert!(!claude_stale_pending_matches_witness(
            &changed, witness, &members
        ));
        assert_eq!(
            usage_pending_guard::check(&changed, Some(witness), |m| members.contains(m)),
            Verdict::Mismatch
        );
    }
    index
        .files
        .remove(&carry_key(CARRY_ROOT, Some(CARRY_AGENT)));
    assert_eq!(
        usage_pending_guard::verdict(&index, CARRY_ROOT),
        Verdict::Unknown(Unknown::IncompleteMember)
    );
    index.refresh_usage_guard_holds();
    assert!(index.usage_guard_holds.holds(CARRY_ROOT));
}

#[test]
fn phase1_key_only_child_holds_prefix_owner_without_owner_names() {
    let mut index = carry_index();
    carry_family(&mut index, CARRY_UNWITNESSED, &[None], true);
    let hash = index.claude_usage_family_pending[CARRY_ROOT]
        .membership()
        .values()
        .next()
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .clone();
    let child = index
        .claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap();
    child.member_occurrences.clear();
    let child_witness = index
        .claude_usage_family_witnesses
        .get_mut(CARRY_UNWITNESSED)
        .unwrap();
    child_witness.legacy_owner_roots.clear();
    child_witness
        .legacy_excluded_request_id_hashes
        .insert(CARRY_UNWITNESSED.into(), BTreeSet::from([hash]));
    index.refresh_usage_guard_holds();
    assert_eq!(
        index.usage_guard_reason(CARRY_UNWITNESSED),
        Some(Unknown::CompactedOrigin)
    );
    assert_eq!(
        index.usage_guard_reason(CARRY_ROOT),
        Some(Unknown::Dependency)
    );
    assert!(!index.usage_guard_holds.holds(CARRY_OTHER));
    let before = serde_json::to_value(&index.files).unwrap();
    assert_eq!(
        replay_and_rearm_claude_family(&mut index, CARRY_ROOT, "", &VecDeque::new(), true),
        (0, 0)
    );
    assert_eq!(serde_json::to_value(&index.files).unwrap(), before);
}

#[test]
fn phase1_old_file_growth_discovery_survives_unknown_resolution_and_restart_twice() {
    let mut fixture = retry_durable_fixture(0, 1);
    let root = fixture.roots[0].clone();
    let witness = fixture
        .index
        .claude_usage_family_witnesses
        .remove(&root)
        .unwrap();
    let path = fixture.candidates[0].path.clone();
    let key = local_index_key(&path);
    fixture.index.refresh_usage_guard_holds();
    // Force the discovery-age gate, independently of real wall time.
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .unwrap();
    let before = fixture.index.files[&key].source_file_fingerprint.clone();
    fixture.index.files.get_mut(&key).unwrap().size_bytes = 0;
    for resolved in [false, true] {
        if resolved {
            fixture
                .index
                .claude_usage_family_witnesses
                .insert(root.clone(), witness.clone());
        }
        for _ in 0..2 {
            let bytes = serde_json::to_vec(&fixture.index).unwrap();
            fixture.index = lenient_decode::read_bounded(&bytes).unwrap();
            fixture.index.refresh_usage_guard_holds();
            let mut census = ScanCensus::default();
            let candidate = candidate_from_traversal_path(
                SnapshotSource::ClaudeCode,
                ScanTraversalPath {
                    scan_root: path.parent().unwrap().to_path_buf(),
                    path: path.clone(),
                    census_member: true,
                    watcher_hint: false,
                },
                &mut census,
                Some(2_000_000_000),
                1,
                &fixture.index.files,
                Some(&fixture.index.usage_guard_holds),
            )
            .expect("held/resolving old growth remains discoverable");
            assert!(census.removed_index_keys.is_empty());
            let candidate = open_and_identify_scan_candidate(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                Some(2_000_000_000),
                1,
                &fixture.index.files,
                Some(&fixture.index.usage_guard_holds),
            )
            .unwrap()
            .0;
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                fixture.index.usage_guard_observe_growth(&candidate)
            });
            if !resolved {
                assert!(rows
                    .iter()
                    .any(|r| r["counts"]["unknown_growth_bytes_observed"]
                        .as_u64()
                        .unwrap_or(0)
                        > 0));
            }
            assert_eq!(fixture.index.files[&key].source_file_fingerprint, before);
        }
    }
}

#[test]
fn phase1_mutation_rebuilds_dependent_hold_before_cancellation() {
    let mut index = carry_index();
    carry_family(&mut index, CARRY_UNWITNESSED, &[None], true);
    index
        .claude_usage_family_witnesses
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .legacy_owner_roots
        .insert(CARRY_ROOT.into());
    index.refresh_usage_guard_holds();
    assert!(!index.usage_guard_holds.holds(CARRY_ROOT));
    index.claude_usage_family_witnesses.remove(CARRY_ROOT);
    let before = serde_json::to_value(&index.files).unwrap();
    // The mutable transaction rebuilds the full closure, not a cached positive.
    assert_eq!(
        replay_and_rearm_claude_family(&mut index, CARRY_UNWITNESSED, "", &VecDeque::new(), true),
        (0, 0)
    );
    assert_eq!(
        index.usage_guard_reason(CARRY_UNWITNESSED),
        Some(Unknown::Dependency)
    );
    assert_eq!(serde_json::to_value(&index.files).unwrap(), before);
}

#[test]
fn phase1_unknown_dependency_scope_counts_global_once() {
    let mut index = carry_index();
    let witness = index
        .claude_usage_family_witnesses
        .get_mut(CARRY_ROOT)
        .unwrap();
    witness.member_occurrence_fingerprints.clear();
    witness
        .legacy_excluded_request_id_hashes
        .insert(CARRY_ROOT.into(), BTreeSet::from(["f".repeat(64)]));
    index.refresh_usage_guard_holds();
    assert!(index.usage_guard_holds.global());
    let roots = index.claude_usage_family_pending.keys().cloned().collect();
    let mut counts = StaleCarryRejectionCounts::default();
    counts.observe_unknown(&index, &roots);
    let value = serde_json::to_value(counts).unwrap();
    assert_eq!(value["unknown_global"], 1);
    for (key, count) in value.as_object().unwrap() {
        if key.starts_with("unknown_") && key != "unknown_global" {
            assert_eq!(count, 0);
        }
    }
}

/// Counts-only inventory comparison entry. Supply one frozen ScanIndex, or a
/// directory of ordered *.json checkpoint copies. This never opens transcripts,
/// saves state, uploads, or repairs the input. A single selected generation has
/// no historical decisions: that limitation is printed, never called 0-diff.
#[test]
#[ignore = "authorized CI replay on a frozen ScanIndex copy only"]
fn phase1_replay_frozen_scan_index_guard_comparison() {
    let input = std::env::var_os("OTTTO_E7_USAGE_GUARD_FROZEN_INDEX")
        .map(PathBuf::from)
        .expect("frozen ScanIndex env var required");
    let paths = if input.is_dir() {
        let mut paths = fs::read_dir(&input)
            .expect("frozen checkpoint directory unavailable")
            .map(|entry| entry.expect("frozen checkpoint entry unavailable").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        paths.sort();
        paths
    } else {
        vec![input]
    };
    assert!(!paths.is_empty(), "no frozen checkpoint copies");
    let mut matrix = [[[0_u64; 3]; 2]; 3];
    let mut carry_matrix = [[[0_u64; 2]; 2]; 3];
    let mut recorded = [0_u64; 2];
    let mut known_diffs = 0_u64;
    let mut old_true_unknown = 0_u64;
    let mut global_unknown = 0_u64;
    let mut checkpoints = 0_u64;
    for path in paths {
        let file = File::open(path).expect("frozen checkpoint unavailable");
        let mut index =
            lenient_decode::read(BufReader::new(file), "e7_guard_replay", "claude_code")
                .unwrap_or_else(|_| {
                    panic!("frozen checkpoint decode refused; no repair attempted")
                });
        index.refresh_usage_guard_holds();
        checkpoints += 1;
        global_unknown += u64::from(index.usage_guard_holds.global());
        let roots = index
            .claude_usage_family_pending
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for root in &roots {
            recorded[usize::from(index.claude_stale_family_carry.contains(root))] += 1;
        }
        for route_id in 0..3 {
            let new_carry = route(&index, &roots, route_id);
            let old_carry = usage_pending_guard::replay_old(|| route(&index, &roots, route_id));
            for root in &roots {
                let old = usage_pending_guard::replay_old(|| {
                    usage_pending_guard::verdict(&index, root) == Verdict::Match
                });
                let new = usage_pending_guard::verdict(&index, root);
                let state = match new {
                    Verdict::Match => 0,
                    Verdict::Mismatch => 1,
                    Verdict::Unknown(_) => 2,
                };
                matrix[route_id][usize::from(old)][state] += 1;
                carry_matrix[route_id][usize::from(old_carry.contains(root))]
                    [usize::from(new_carry.contains(root))] += 1;
                known_diffs += u64::from(state != 2 && old != (state == 0));
                old_true_unknown += u64::from(old && state == 2);
            }
        }
    }
    println!(
        "{}",
        json!({"checkpoints":checkpoints,"guard_old_bool_new_match_mismatch_unknown_by_route":matrix,
        "final_carry_old_new_by_route":carry_matrix,"recorded_selected_carry_false_true":recorded,
        "known_guard_differences":known_diffs,"old_true_unknown":old_true_unknown,"global_unknown":global_unknown,
        "historical_decision_log_unavailable":1,"acquisition_money_replay_unavailable":1,
        "activation_zero_diff_proven":false})
    );
    assert_eq!(known_diffs, 0, "known guard differences; counts only");
}
