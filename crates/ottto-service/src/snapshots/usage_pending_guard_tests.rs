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

/// Production builds holds inside the retry traversal, whose window is newer
/// than the failed window the fixtures accumulated their pending in.
fn retry_under_way(index: &mut ScanIndex) {
    if let Some(traversal) = index.traversal.as_mut() {
        traversal.census_window_end = CARRY_RETRY.into();
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
            fixture.index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
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
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert!(index.usage_guard_holds.holds(CARRY_ROOT));
}

#[test]
fn phase1_key_only_child_holds_prefix_owner_without_owner_names() {
    let mut index = carry_index();
    retry_under_way(&mut index);
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
    retry_under_way(&mut fixture.index);
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
    retry_under_way(&mut index);
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
    retry_under_way(&mut index);
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

#[test]
fn phase1_current_window_accumulation_is_not_stale_proof() {
    let mut index = carry_index();
    // A paged re-read of this window has recorded only the root member so far.
    let pending = index
        .claude_usage_family_pending
        .get_mut(CARRY_ROOT)
        .unwrap();
    let agent = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
    pending.member_request_id_hashes.remove(&agent);
    pending.member_occurrences.remove(&agent);
    assert_eq!(
        usage_pending_guard::verdict(&index, CARRY_ROOT),
        Verdict::Unknown(Unknown::IncompleteMember)
    );
    // The traversal accumulating this window keeps its owed sibling reads.
    index.refresh_usage_guard_holds();
    assert!(!index.usage_guard_holds.holds(CARRY_ROOT));
    let sibling = carry_key(CARRY_ROOT, Some(CARRY_AGENT));
    assert!(!index.usage_guard_holds.holds_path(Path::new(&sibling)));
    assert!(index.usage_guard_holds.retains_path(Path::new(&sibling)));
    assert_eq!(index.usage_guard_reason(CARRY_ROOT), None);
    // The same record is stale proof once a newer traversal starts.
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert_eq!(
        index.usage_guard_reason(CARRY_ROOT),
        Some(Unknown::IncompleteMember)
    );
}

#[test]
fn phase1_refused_held_read_is_a_scoped_residue_not_a_red_census() {
    // Lead B 4d: the refusal takes no census, so no unreadable cause can turn
    // the census red; it is counted per family as held_read_refused.
    let path = PathBuf::from(carry_key(CARRY_ROOT, None));
    let (_, rows) =
        crate::local_resource_diagnostics::capture(|| usage_pending_guard::full_blocked(&path));
    assert!(rows.iter().any(|row| row["counts"]["unknown_full_blocked"] == 1
        && row["counts"]["held_read_refused_families"] == 1));
}

fn held_family_index() -> (ScanIndex, String, Vec<SnapshotItem>) {
    let (dir, root, items) = claude_account_family_fixture();
    let mut index = d2_family_index(&dir, &root);
    accumulate_claude_usage_family_pending_with_limit(
        &items,
        &mut index.claude_usage_family_pending,
        CARRY_FAILED,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    assert_eq!(index.claude_usage_family_pending[&root].member_occurrences.len(), 2);
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert_eq!(
        index.usage_guard_reason(&root),
        Some(Unknown::MissingWitness)
    );
    (index, root, items)
}

fn accumulate_guarded(index: &mut ScanIndex, items: &[SnapshotItem]) -> ClaudeDuplicateCensusCounts {
    accumulate_claude_usage_family_pending_guarded(
        items,
        &mut index.claude_usage_family_pending,
        CARRY_RETRY,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &mut index.usage_guard_holds,
    )
}

#[test]
fn phase1_held_member_growth_keeps_siblings_and_rewindows_after_resolution() {
    let (mut index, root, items) = held_family_index();
    let before = index.claude_usage_family_pending[&root].clone();
    // A member Tail while held does not re-window the family.
    let (counts, rows) =
        crate::local_resource_diagnostics::capture(|| accumulate_guarded(&mut index, &items[..1]));
    assert_eq!(counts.page_invalidated_cap_count, 0);
    assert_eq!(index.claude_usage_family_pending[&root], before, "byte-identical");
    assert!(rows
        .iter()
        .any(|row| row["counts"]["held_member_growth_slots"] == 1));
    // Resolution: a known (mismatching) witness ends the Unknown hold.
    let members = before.membership().keys().cloned().collect::<Vec<_>>();
    index.claude_usage_family_witnesses.insert(
        root.clone(),
        ClaudeUsageFamilyWitness {
            evidence_fingerprint: "e".repeat(64),
            member_request_id_fingerprints: members
                .iter()
                .map(|member| (member.clone(), "0".repeat(64)))
                .collect(),
            member_occurrence_fingerprints: members
                .iter()
                .map(|member| (member.clone(), "0".repeat(64)))
                .collect(),
            assigned_request_id_fingerprints: BTreeMap::new(),
            legacy_excluded_request_id_hashes: BTreeMap::new(),
            legacy_exclusion_evidence_fingerprint: None,
            legacy_owner_roots: BTreeSet::new(),
        },
    );
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert_eq!(index.usage_guard_reason(&root), None);
    // The next member read re-windows, joined by the slot recorded while held.
    accumulate_guarded(&mut index, &items[1..]);
    let after = &index.claude_usage_family_pending[&root];
    assert_eq!(after.census_window_end, CARRY_RETRY);
    assert!(!after.invalid);
    assert_eq!(after.member_occurrences.len(), 2);
    assert_eq!(
        after.member_occurrences[&items[0].source_session_id],
        before.member_occurrences[&items[0].source_session_id]
    );
}

#[test]
fn unread_scope_marks_clear_on_recorded_growth_and_saturate_conservatively() {
    let (mut index, root, items) = held_family_index();
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).is_empty());
    let parent = index
        .files
        .keys()
        .find(|key| {
            claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| member.root == root && member.subagent_stem.is_none())
        })
        .cloned()
        .unwrap();
    index.usage_guard_full_blocked(Path::new(&parent));
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).contains(&root));
    // A projection install keeps the mark while the family stays held.
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).contains(&root));
    // Growth of the same member from another path (a twin) reads nothing.
    accumulate_guarded(&mut index, &items[..1]);
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).contains(&root));
    // This key's own published parse, then its growth in the held slot.
    index.usage_guard_note_read(Path::new(&parent));
    accumulate_guarded(&mut index, &items[..1]);
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).is_empty());
    // Past the per-family bound the family stays unread until the hold ends.
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        for n in 0..=usage_pending_guard::HELD_UNREAD_KEYS_PER_FAMILY {
            let key = carry_key(&root, Some(&format!("agent-{n:04}")));
            index.usage_guard_full_blocked(Path::new(&key));
        }
    });
    assert!(rows
        .iter()
        .any(|row| row["counts"]["held_unread_saturated"] == 1));
    accumulate_guarded(&mut index, &items[1..]);
    assert!(usage_pending_guard::unread_scope(&index, CARRY_RETRY).contains(&root));
}

#[test]
fn phase1_held_growth_is_offered_to_the_prover_as_current_pending() {
    // A missing witness resolves only from this window's complete held
    // growth; the prover sees it as ordinary current-window pending.
    let (mut index, root, items) = held_family_index();
    accumulate_guarded(&mut index, &items);
    let growth = index.usage_guard_holds.growth_pending(&root, CARRY_RETRY);
    assert_eq!(growth.census_window_end, CARRY_RETRY);
    assert!(!growth.invalid);
    let before = &index.claude_usage_family_pending[&root];
    assert_eq!(
        growth.membership().keys().collect::<Vec<_>>(),
        before.membership().keys().collect::<Vec<_>>()
    );
    assert_eq!(growth.member_occurrences, before.member_occurrences);
    for member in growth.membership().keys() {
        assert!(growth
            .membership()
            .get(member)
            .unwrap()
            .iter()
            .eq(growth.member_occurrences[member].keys()));
    }
    assert!(index
        .usage_guard_holds
        .growth_pending(&root, CARRY_FAILED)
        .member_occurrences
        .is_empty());
    assert_eq!(index.usage_guard_holds.growth_hashes().count(), 5);
}

#[test]
fn phase1_held_member_growth_over_cap_takes_the_counted_resource_path() {
    let (mut index, root, items) = held_family_index();
    // Member bound: the 257th distinct member is refused.
    for member in 0..usage_pending_guard::HELD_GROWTH_MAX_MEMBERS {
        assert_eq!(
            index.usage_guard_holds.record_member_growth(
                "other",
                &format!("member-{member}"),
                CARRY_RETRY,
                BTreeMap::new()
            ),
            usage_pending_guard::Growth::Recorded
        );
    }
    let (growth, rows) = crate::local_resource_diagnostics::capture(|| {
        index.usage_guard_holds.record_member_growth(
            "other",
            "member-over",
            CARRY_RETRY,
            BTreeMap::new(),
        )
    });
    assert_eq!(growth, usage_pending_guard::Growth::OverCap);
    assert!(rows
        .iter()
        .any(|row| row["counts"]["held_member_growth_over_cap"] == 1));
    index.usage_guard_holds.take_member_growth("other", "");
    // Occurrence bound, then the accumulator's existing counted cap path:
    // the held family is invalidated (and so re-read), never dropped silently.
    let big = (0..usage_pending_guard::HELD_GROWTH_MAX_OCCURRENCES)
        .map(|n| (format!("{n:064x}"), carry_occurrence(n as u64, 1)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        index
            .usage_guard_holds
            .record_member_growth("other", "member-big", CARRY_RETRY, big),
        usage_pending_guard::Growth::Recorded
    );
    let counts = accumulate_guarded(&mut index, &items[..1]);
    assert_eq!(counts.page_invalidated_cap_count, 1);
    assert!(index.claude_usage_family_pending[&root].invalid);
}

#[test]
fn phase1_runtime_custody_survives_the_per_cycle_index_reload() {
    let path = Path::new("/synthetic/e7-usage-guard-custody/index.json");
    let mut index = ScanIndex::default();
    index.usage_guard_adopt_custody(path);
    index.usage_guard_pace_for_test(["/paced/key".to_string()]);
    // Any projection install hands custody to the process owner.
    index.refresh_usage_guard_holds_at(None);
    let mut reloaded = ScanIndex::default();
    reloaded.usage_guard_adopt_custody(path);
    reloaded.usage_guard_mark_audited("/paced/key");
    assert!(reloaded.usage_guard_audit_satisfied("/paced/key", 0));
    // Another index file has its own custody.
    let mut other = ScanIndex::default();
    other.usage_guard_adopt_custody(Path::new("/synthetic/e7-usage-guard-custody/other.json"));
    other.usage_guard_mark_audited("/paced/key");
    assert!(!other.usage_guard_audit_satisfied("/paced/key", 0));
}

#[test]
fn phase1_withheld_growth_over_cap_invalidates_instead_of_dropping_keys() {
    let (mut index, root, items) = held_family_index();
    let big = (0..usage_pending_guard::HELD_GROWTH_MAX_OCCURRENCES)
        .map(|n| (format!("{n:064x}"), carry_occurrence(n as u64, 1)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        index
            .usage_guard_holds
            .record_member_growth("other", "member-big", CARRY_RETRY, big),
        usage_pending_guard::Growth::Recorded
    );
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.usage_guard_record_withheld(&items[..1], CARRY_RETRY)
    });
    assert!(rows
        .iter()
        .any(|row| row["counts"]["withheld_full_invalidated_families"] == 1));
    assert!(index.claude_usage_family_pending[&root].invalid);
}

#[test]
fn phase1_withheld_full_needs_real_growth_and_is_paced_per_key() {
    let mut fixture = retry_durable_fixture(0, 1);
    let root = fixture.roots[0].clone();
    fixture.index.claude_usage_family_witnesses.remove(&root);
    retry_under_way(&mut fixture.index);
    fixture.index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert!(fixture.index.usage_guard_holds.holds(&root));
    let mut candidate = fixture.candidates[0].clone();
    let key = local_index_key(&candidate.path);
    // Idle or mtime-only: no real growth, no Full.
    candidate.size_bytes = fixture.index.files[&key].size_bytes;
    assert!(!fixture.index.usage_guard_admit_withheld_full(&candidate));
    candidate.size_bytes += 1;
    let (admitted, rows) = crate::local_resource_diagnostics::capture(|| {
        fixture.index.usage_guard_admit_withheld_full(&candidate)
    });
    assert!(admitted);
    assert!(rows.iter().any(|row| row["counts"]["withheld_full"] == 1
        && row["counts"]["withheld_full_missing_witness"] == 1
        && row["counts"]["pace_evicted"] == 0));
    assert!(fixture.index.usage_guard_is_withheld(&key));
    // Only a completed withheld Full satisfies the audits due by its stamp.
    assert!(!fixture.index.usage_guard_audit_satisfied(&key, 0));
    fixture.index.usage_guard_mark_audited(&key);
    assert!(fixture.index.usage_guard_audit_satisfied(&key, 0));
    assert!(!fixture.index.usage_guard_audit_satisfied(&key, u64::MAX));
    // The entry stays indexed as committed; nothing re-arms it.
    assert!(!fixture.index.files[&key].source_file_fingerprint.is_empty());
    // One per key per 6 h, across the projection rebuilds of later visits.
    assert!(fixture.index.usage_guard_take_withheld(&key));
    fixture.index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    let (admitted, rows) = crate::local_resource_diagnostics::capture(|| {
        fixture.index.usage_guard_admit_withheld_full(&candidate)
    });
    assert!(!admitted);
    assert!(rows
        .iter()
        .any(|row| row["counts"]["withheld_full_paced"] == 1));
    // Rule 7: a full pace map evicts its oldest stamp and lets the read happen.
    fixture.index.usage_guard_pace_for_test(
        (0..usage_pending_guard::WITHHELD_FULL_PACE_BOUND).map(|n| format!("/paced/{n}")),
    );
    let (admitted, rows) = crate::local_resource_diagnostics::capture(|| {
        fixture.index.usage_guard_admit_withheld_full(&candidate)
    });
    assert!(admitted);
    assert!(rows.iter().any(|row| row["counts"]["pace_evicted"] == 1));
    // A new withheld Full has not completed yet: its audit is owed again.
    assert!(!fixture.index.usage_guard_audit_satisfied(&key, 0));
    // An unheld family never takes the withheld Full.
    let mut known = retry_durable_fixture(0, 1);
    known.index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    let mut grown = known.candidates[0].clone();
    grown.size_bytes += 1;
    assert!(!known.index.usage_guard_admit_withheld_full(&grown));
}

/// How the owned-start family relates to the held family, and how complete
/// the held family's coverage is.
#[derive(Clone, Copy, Default)]
struct Beside {
    /// The held family's old-window proof shares the owned request key.
    overlap: bool,
    /// The held family has an indexed sibling absent from its pending.
    unread_sibling: bool,
    /// A read of the held family's root file was refused (paced or blocked).
    refused_read: bool,
    /// The owned-start session is also a member of the held family.
    shares_member: bool,
    /// E2's copy proof names the held family's root file as its original.
    fork_child: bool,
    /// A pending-free (retired) root's live census record holds the owned
    /// request: the census-prefix veto (Lead B round 8).
    retired_census: bool,
    /// The census-prefix index cap for this fold (None: production).
    census_cap: Option<usize>,
}

/// An owned start of a family beside an Unknown-held stale family. Returns
/// its posture admission and the unread-scope veto count.
fn owned_start_beside(beside: Beside) -> (Option<&'static str>, u64) {
    let (admission, vetoes, _, _) = owned_start_beside_rows(beside);
    (admission, vetoes)
}

fn owned_start_beside_rows(
    beside: Beside,
) -> (Option<&'static str>, u64, Vec<serde_json::Value>, ScanIndex) {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let path = temp_file("claude-held-unrelated-owned-start");
    let source_session_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .expect("fixture stem")
        .to_string();
    fs::write(
        &path,
        format!(
            "{{\"timestamp\":\"2026-08-20T11:01:00Z\",\"sessionId\":\"{source_session_id}\",\"type\":\"assistant\",\"requestId\":\"req_owned\",\"message\":{{\"id\":\"msg_owned\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":2}}}}}}\n"
        ),
    )
    .expect("write fixture");
    let mut items =
        parse_claude_code_jsonl_file(&path, "2026-08-20T11:02:00Z", "source".to_string())
            .expect("parse");
    let mut api = complete_api_row(&source_session_id, "req_owned", 1, 10, 2, 0);
    api.client_request_id.clear();
    api.cost_usd_micros = None;
    api.event_sequence = None;
    api.app_version.clear();
    api.fingerprint.clear();
    api.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&api).expect("serialize API evidence"))
    );
    let mut trace = complete_trace_row(&source_session_id, "req_owned", "");
    trace.client_request_id.clear();
    trace.fingerprint.clear();
    trace.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&trace).expect("serialize trace evidence"))
    );
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(&path),
        manifest_index_entry(Some("unresolved")),
    );
    // An unrelated Unknown-held family: stale pending, no witness, indexed.
    let held = CARRY_ROOT;
    let hash = if beside.overlap {
        format!("{:x}", Sha256::digest(b"req_owned"))
    } else {
        "a".repeat(64)
    };
    index
        .files
        .insert(carry_key(held, None), manifest_index_entry(Some("held")));
    if beside.unread_sibling {
        index.files.insert(
            carry_key(held, Some(CARRY_AGENT)),
            manifest_index_entry(Some("held-sibling")),
        );
    }
    index.claude_usage_family_pending.insert(
        held.into(),
        ClaudeUsageFamilyPending {
            derived_request_members: BTreeSet::new(),
            census_window_end: "2026-08-20T10:00:00Z".into(),
            member_request_id_hashes: BTreeMap::from([(
                carry_member(held, None),
                BTreeSet::from([hash.clone()]),
            )]),
            member_occurrences: BTreeMap::from([(
                carry_member(held, None),
                BTreeMap::from([(hash, carry_occurrence(0, 10))]),
            )]),
            invalid: false,
            idless_revision: None,
        },
    );
    if beside.shares_member {
        index
            .claude_usage_family_pending
            .get_mut(held)
            .unwrap()
            .member_request_id_hashes
            .insert(source_session_id.clone(), BTreeSet::new());
    }
    if beside.fork_child {
        items[0]
            .claude_money
            .get_or_insert_with(|| {
                Box::new(claude_request_money::e2::FileFold::new(
                    Default::default(),
                    None,
                    Default::default(),
                    None,
                ))
            })
            .set_fork_parent_for_test(carry_key(held, None));
    }
    if beside.refused_read {
        index.refresh_usage_guard_holds_at(Some("2026-08-20T11:02:00Z"));
        index.usage_guard_full_blocked(Path::new(&carry_key(held, None)));
    }
    if beside.retired_census {
        // CARRY_OTHER keeps no usage pending: only its census record.
        let _ = index.claude_request_census_mut_for_test().insert(
            carry_key(CARRY_OTHER, None),
            claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                claude_request_census::ClaudeRequestCensusShape::Exact,
                vec![claude_request_census::claude_request_hash("req_owned")],
            ),
        );
    }
    let before = index.claude_usage_family_pending[held].clone();
    let fold = |index: &mut ScanIndex, items: &mut Vec<SnapshotItem>| {
        apply_claude_reported_usage_with_index(
        items,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(source_session_id.clone(), vec![api])]),
            health: Default::default(),
        },
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(source_session_id, vec![trace])]),
            ..Default::default()
        },
        index,
        true,
        "2026-08-20T11:02:00Z",
        )
    };
    let (disposition, rows) = crate::local_resource_diagnostics::capture(|| match beside.census_cap {
        Some(cap) => {
            usage_census_prefix::with_cap_for_test(cap, || fold(&mut index, &mut items))
        }
        None => fold(&mut index, &mut items),
    });
    assert!(index.usage_guard_reason(held).is_some());
    assert_eq!(
        items[0].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    // The held family keeps its scoped, byte-identical proof through the terminal.
    assert_eq!(index.claude_usage_family_pending[held], before);
    let admission = disposition.posture_admission(&items[0].source_session_id);
    let vetoes = rows
        .iter()
        .filter_map(|row| row["counts"]["held_unread_scope_veto_families"].as_u64())
        .sum();
    let _ = fs::remove_file(path);
    (admission, vetoes, rows, index)
}

#[test]
fn phase1_held_stale_family_does_not_block_an_unrelated_owned_start() {
    // Lead B 4c: the hold is scoped; an unrelated owned start stays strict.
    assert_eq!(owned_start_beside(Beside::default()), (Some("strict"), 0));
}

#[test]
fn phase1_held_stale_family_still_vetoes_a_family_sharing_its_request() {
    // Its request keys left duplicate detection with the census veto, so
    // they veto an overlapping family's strict posture directly.
    let (admission, _) = owned_start_beside(Beside {
        overlap: true,
        ..Beside::default()
    });
    assert_ne!(admission, Some("strict"));
}

#[test]
fn unread_scope_held_family_with_unread_sibling_vetoes_a_same_root_family() {
    // (a) Coverage incomplete: a family sharing the held family's root or a
    // member file cannot be proven duplicate-free by request keys.
    let (admission, vetoes) = owned_start_beside(Beside {
        unread_sibling: true,
        shares_member: true,
        ..Beside::default()
    });
    assert_ne!(admission, Some("strict"));
    assert_eq!(vetoes, 1);
}

#[test]
fn unread_scope_held_family_with_unread_sibling_vetoes_a_cross_root_fork_child() {
    // (b) E2's copy proof links the owned-start family to the held root.
    for unread in [
        Beside {
            unread_sibling: true,
            ..Beside::default()
        },
        Beside {
            refused_read: true,
            ..Beside::default()
        },
    ] {
        let (admission, vetoes) = owned_start_beside(Beside {
            fork_child: true,
            ..unread
        });
        assert_ne!(admission, Some("strict"));
        assert_eq!(vetoes, 1);
    }
}

#[test]
fn unread_scope_held_family_with_unread_sibling_leaves_an_unrelated_family() {
    // (c) No root, member file or lineage edge: unaffected.
    for unread in [
        Beside {
            unread_sibling: true,
            ..Beside::default()
        },
        Beside {
            refused_read: true,
            ..Beside::default()
        },
    ] {
        assert_eq!(owned_start_beside(unread), (Some("strict"), 0));
    }
}

#[test]
fn unread_scope_complete_coverage_narrows_back_to_the_request_key_veto() {
    // Coverage complete: the fork child is vetoed only by a shared request.
    let fork_child = Beside {
        fork_child: true,
        ..Beside::default()
    };
    assert_eq!(owned_start_beside(fork_child), (Some("strict"), 0));
    let (admission, vetoes) = owned_start_beside(Beside {
        overlap: true,
        ..fork_child
    });
    assert_ne!(admission, Some("strict"));
    assert_eq!(vetoes, 0);
}

#[test]
fn census_prefix_veto_overflow_holds() {
    // Lead B round 8: a pending-free root's live census record holding the
    // owned request vetoes its strict posture (a prefix hit, counted).
    let (admission, _, rows, index) = owned_start_beside_rows(Beside {
        retired_census: true,
        ..Beside::default()
    });
    assert_ne!(admission, Some("strict"));
    assert!(rows
        .iter()
        .any(|row| row["counts"]["census_prefix_vetoed_hashes"] == 1));
    assert!(!index.usage_guard_holds.global());
    // Past the cap the index is Unknown, never a dropped hash: it holds
    // globally (B3) and vetoes every family, counted as overflow.
    let (admission, _, rows, index) = owned_start_beside_rows(Beside {
        retired_census: true,
        census_cap: Some(0),
        ..Beside::default()
    });
    assert_ne!(admission, Some("strict"));
    assert!(rows
        .iter()
        .any(|row| row["counts"]["census_prefix_overflow"] == 1));
    assert!(index.usage_guard_holds.global());
    assert_eq!(
        usage_census_prefix::current(&index).verdict(CARRY_ROOT, [0]),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert!(usage_pending_guard::fork_lineage_incomplete(&index));
    // Without the record the same owned start stays strict.
    assert_eq!(owned_start_beside(Beside::default()), (Some("strict"), 0));
}

fn retirement_attempt(index: &mut ScanIndex) -> serde_json::Value {
    let (prepared, rows) = crate::local_resource_diagnostics::capture(|| {
        index.prepare_claude_usage_pending_settlement()
    });
    prepared.finish(index, false);
    rows.into_iter()
        .find(|row| row["stage"] == "claude_usage_pending_settlement_attempt")
        .map(|row| row["counts"].clone())
        .expect("settlement attempt row")
}

#[test]
fn fork_lineage_unknown_refuses_retirement_while_any_family_incomplete() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Lead B round 8 (b'+c, part c): while ANY Claude family's coverage is
    // incomplete, no family retires, an unrelated one included; each
    // considered family is counted retire_refused{fork_lineage_unknown}.
    let (mut index, root, items) = held_family_index();
    let pending = index.claude_usage_family_pending[&root].clone();
    index
        .claude_usage_family_pending
        .insert(CARRY_OTHER.to_owned(), pending);
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert!(!usage_pending_guard::fork_lineage_incomplete(&index));
    let counts = retirement_attempt(&mut index);
    assert!(counts["retire_refused"]["fork_lineage_unknown"].is_null());
    assert_eq!(counts["retired"]["families"], 0);
    let parent = index
        .files
        .keys()
        .find(|key| {
            claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| member.root == root && member.subagent_stem.is_none())
        })
        .cloned()
        .unwrap();
    // (1) A paced or refused read of the held family.
    let mut refused = index.clone();
    refused.usage_guard_full_blocked(Path::new(&parent));
    // (2) Held growth recorded in its runtime slot, not yet merged.
    let mut growth = index.clone();
    accumulate_guarded(&mut growth, &items[..1]);
    // (3) An indexed sibling missing from the held family's evidence.
    let mut sibling = index.clone();
    sibling.files.insert(
        local_index_key(
            &Path::new(&parent)
                .with_extension("")
                .join("subagents")
                .join("agent-missing.jsonl"),
        ),
        manifest_index_entry(Some("missing-sibling")),
    );
    for (label, mut incomplete) in [("refused", refused), ("growth", growth), ("sibling", sibling)]
    {
        assert!(
            usage_pending_guard::fork_lineage_incomplete(&incomplete),
            "{label}"
        );
        let counts = retirement_attempt(&mut incomplete);
        assert_eq!(
            counts["retire_refused"]["fork_lineage_unknown"]["families"],
            2,
            "{label}: the unrelated family is held back too"
        );
        assert_eq!(counts["retired"]["families"], 0, "{label}");
    }
}

/// A due, bounded quarantine record over CARRY_ROOT bound to its witness.
fn quarantine_carry_root(index: &mut ScanIndex) {
    let witness = &index.claude_usage_family_witnesses[CARRY_ROOT];
    let record = ClaudeUsageAuthorityQuarantineRecord {
        contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
        proven_witness_fingerprint: claude_usage_family_witness_fingerprint(witness),
        member_source_file_fingerprints: carry_family_members()
            .into_iter()
            .zip(["f".repeat(64), "f".repeat(64)])
            .collect(),
        failed_reconstruction_count: 1,
        disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
        retry_after_unix_seconds: 0,
        proof_correction: None,
    };
    index
        .claude_usage_authority_quarantine
        .insert(CARRY_ROOT.into(), record);
}

/// CARRY_ROOT's state after a retry start, minus the wall-clock deadline.
fn quarantined_root_state(index: &ScanIndex) -> serde_json::Value {
    let mut record = serde_json::to_value(index.claude_usage_authority_quarantine.get(CARRY_ROOT))
        .unwrap();
    if let Some(record) = record.as_object_mut() {
        record.remove("retry_after_unix_seconds");
    }
    json!({
        "files": carry_family_keys()
            .iter()
            .map(|key| serde_json::to_value(index.files.get(key)).unwrap())
            .collect::<Vec<_>>(),
        "pending": serde_json::to_value(index.claude_usage_family_pending.get(CARRY_ROOT)).unwrap(),
        "quarantine": record,
    })
}

#[test]
fn quarantined_root_never_becomes_held_through_dependency_closure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Review r89 HIGH: a family under authority quarantine keeps its
    // quarantine rules (re-arm, retry, prune/rebind) even when a held,
    // witnessless family reaches it by a shared request or a legacy owner
    // edge. Traversal still passes through it; only a decode hold holds it.
    for edge in ["shared_request", "legacy_owner"] {
        let mut index = carry_index();
        retry_under_way(&mut index);
        quarantine_carry_root(&mut index);
        let unwitnessed = index
            .claude_usage_family_pending
            .get_mut(CARRY_UNWITNESSED)
            .unwrap();
        unwitnessed.invalid = false;
        if edge == "shared_request" {
            let member = carry_member(CARRY_UNWITNESSED, None);
            let shared = index.claude_usage_family_pending[CARRY_ROOT]
                .membership()
                .values()
                .next()
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .clone();
            let unwitnessed = index
                .claude_usage_family_pending
                .get_mut(CARRY_UNWITNESSED)
                .unwrap();
            unwitnessed
                .member_request_id_hashes
                .get_mut(&member)
                .unwrap()
                .insert(shared.clone());
            unwitnessed
                .member_occurrences
                .get_mut(&member)
                .unwrap()
                .insert(shared, carry_occurrence(1, 10));
        } else {
            index
                .claude_usage_family_witnesses
                .get_mut(CARRY_ROOT)
                .unwrap()
                .legacy_owner_roots
                .insert(CARRY_UNWITNESSED.into());
        }
        let old = {
            let mut old = index.clone();
            usage_pending_guard::replay_old(|| carry_start(&mut old, CARRY_RETRY, BACKFILL_WINDOW_DAYS));
            quarantined_root_state(&old)
        };
        index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
        assert_eq!(
            index.usage_guard_reason(CARRY_UNWITNESSED),
            Some(Unknown::MissingWitness),
            "{edge}"
        );
        assert_eq!(index.usage_guard_reason(CARRY_ROOT), None, "{edge}");
        assert!(!index.usage_guard_holds.holds(CARRY_ROOT), "{edge}");
        carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(
            quarantined_root_state(&index),
            old,
            "{edge}: the quarantined family's retry start is the pre-B3 one"
        );
    }
}

#[test]
fn census_prefix_over_budget_record_is_unknown_under_the_byte_budget() {
    // Review r89 MEDIUM: a pending-free record whose hashes the census
    // dropped proves no absence. Far under the byte budget, the index is
    // still Unknown, never Clear.
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![claude_request_census::claude_request_hash("req_other")],
        ),
    );
    let clear = usage_census_prefix::CensusPrefixIndex::build(&index);
    assert!(!clear.unknown());
    assert_eq!(
        clear.verdict(CARRY_ROOT, [claude_request_census::claude_request_hash("req_owned")]),
        usage_census_prefix::CensusPrefixVerdict::Clear
    );
    assert!(clear.bytes() < usage_census_prefix::CENSUS_PREFIX_MAX_BYTES);
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_UNWITNESSED, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"b".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::OverBudget,
            vec![],
        ),
    );
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&index)
    });
    assert!(built.unknown());
    assert_eq!(
        built.verdict(CARRY_ROOT, [claude_request_census::claude_request_hash("req_owned")]),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert!(rows.iter().any(|row| {
        row["counts"]["census_prefix_over_budget_records"] == 1
            && row["counts"]["census_prefix_overflow"] == 0
    }));
    // A family with usage pending keeps its own record out of the index.
    index.claude_usage_family_pending.insert(
        CARRY_UNWITNESSED.into(),
        ClaudeUsageFamilyPending {
            derived_request_members: BTreeSet::new(),
            census_window_end: CARRY_FAILED.into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
        },
    );
    assert!(!usage_census_prefix::CensusPrefixIndex::build(&index).unknown());
}

#[test]
fn census_prefix_overbudget_gauge_counts_blocked_roots_and_alarms_hourly() {
    // Lead B 2026-10-30 (B): the census-prefix row counts the OverBudget
    // records that make the index Unknown and the usage-pending roots whose
    // retirement that refuses, with the local hourly alarm. Counts only.
    const PENDING_ROOT: &str = "d4444444-4444-4444-8444-444444444444";
    let pending = |window: &str| ClaudeUsageFamilyPending {
        derived_request_members: BTreeSet::new(),
        census_window_end: window.into(),
        member_request_id_hashes: BTreeMap::new(),
        member_occurrences: BTreeMap::new(),
        invalid: false,
        idless_revision: None,
    };
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![claude_request_census::claude_request_hash("req_other")],
        ),
    );
    index
        .claude_usage_family_pending
        .insert(CARRY_ROOT.into(), pending(CARRY_FAILED));
    index
        .claude_usage_family_pending
        .insert(PENDING_ROOT.into(), pending(CARRY_RETRY));
    let gauge = |rows: &[serde_json::Value]| {
        let row = rows
            .iter()
            .find(|row| {
                row["stage"] == "claude_census_prefix_veto"
                    && row["counts"]["census_prefix_unknown"].is_u64()
            })
            .expect("census-prefix build row");
        (
            row["counts"]["census_prefix_unknown_overbudget_records"].clone(),
            row["counts"]["census_prefix_unknown_blocked_roots"].clone(),
        )
    };
    let alarms = |rows: &[serde_json::Value]| {
        rows.iter()
            .filter(|row| row["stage"] == "census_prefix_unknown_overbudget_alarm")
            .count()
    };
    // No OverBudget record: zero, and no alarm.
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&index)
    });
    assert!(!built.unknown());
    assert_eq!(gauge(&rows), (json!(0), json!(0)));
    assert_eq!(alarms(&rows), 0);
    // One pending-free OverBudget record: Unknown, both pending roots blocked.
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_UNWITNESSED, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"b".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::OverBudget,
            vec![],
        ),
    );
    // An OverBudget record of a root with usage pending is out of the index.
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(PENDING_ROOT, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"c".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::OverBudget,
            vec![],
        ),
    );
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&index)
    });
    assert!(built.unknown());
    assert_eq!(gauge(&rows), (json!(1), json!(2)));
    assert_eq!(alarms(&rows), 1);
    let alarm = rows
        .iter()
        .find(|row| row["stage"] == "census_prefix_unknown_overbudget_alarm")
        .unwrap();
    assert_eq!(
        alarm["counts"]["census_prefix_unknown_overbudget_records"],
        1
    );
    assert_eq!(alarm["counts"]["census_prefix_unknown_blocked_roots"], 2);
    // Privacy: every count is a number (the peak may be null); no root, key,
    // request id or fingerprint reaches a row.
    for row in &rows {
        for value in row["counts"].as_object().unwrap().values() {
            assert!(value.is_u64() || value.is_null(), "{row}");
        }
        let text = row.to_string();
        for secret in [
            CARRY_ROOT,
            CARRY_OTHER,
            CARRY_UNWITNESSED,
            PENDING_ROOT,
            "req_other",
            ".jsonl",
            "aaaaaaaa",
            "bbbbbbbb",
            "cccccccc",
        ] {
            assert!(!text.contains(secret), "{row}");
        }
    }
    // At most hourly.
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&index)
    });
    assert_eq!(gauge(&rows), (json!(1), json!(2)));
    assert_eq!(alarms(&rows), 0);
}

/// Lead B 2026-10-30 (r16) fixtures: the build row's lost-record counts.
fn census_prefix_lost_gauge(rows: &[serde_json::Value]) -> (serde_json::Value, serde_json::Value) {
    let row = rows
        .iter()
        .find(|row| {
            row["stage"] == "claude_census_prefix_veto"
                && row["counts"]["census_prefix_unknown"].is_u64()
        })
        .expect("census-prefix build row");
    (
        row["counts"]["census_prefix_unknown_refused_records"].clone(),
        row["counts"]["census_prefix_unknown_overbudget_records"].clone(),
    )
}

/// Counts only: every count is a number (the peak may be null), and no
/// root, key, request id or fingerprint reaches a row.
fn assert_census_prefix_rows_private(rows: &[serde_json::Value], secrets: &[&str]) {
    for row in rows {
        for value in row["counts"].as_object().unwrap().values() {
            assert!(value.is_u64() || value.is_null(), "{row}");
        }
        let text = row.to_string();
        for secret in secrets {
            assert!(!text.contains(secret), "{row}");
        }
    }
}

#[test]
fn census_prefix_refused_insert_is_unknown_never_clear_for_a_copy() {
    // Lead B 2026-10-30 (r16, blocking): a record the census refuses (not
    // even its tombstone fits) leaves its file's prefixes missing. Missing is
    // not empty: the veto must hold an untagged copy of that file, never
    // answer Clear.
    let copy = [claude_request_census::claude_request_hash("req_copy")];
    let source_key = carry_key(CARRY_UNWITNESSED, None);
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![claude_request_census::claude_request_hash("req_other")],
        ),
    );
    // Before the refusal the index is Known and cached for this window.
    let cached = index.refresh_claude_census_prefix(CARRY_FAILED, true);
    assert!(!cached.unknown());
    assert!(!usage_pending_guard::fork_lineage_incomplete(&index));
    // The census is full: the source file's own record is refused.
    index
        .claude_request_census_mut_for_test()
        .fill_serialized_budget_for_test();
    let path = PathBuf::from(&source_key);
    claude_request_census::record_claude_request_census(
        &mut index,
        claude_request_census::ClaudeRequestCensusParse {
            path: &path,
            index_key: &source_key,
            source_file_fingerprint: &"b".repeat(64),
            census_window_end: CARRY_FAILED,
            complete: true,
            lossy: false,
            source_verified: true,
            itemless_request_hashes: copy.to_vec(),
            opened_birth: None,
            modified_unix_seconds: 1,
        },
        &[],
    );
    assert!(index
        .claude_request_census_for_test()
        .record_for_test(&source_key)
        .is_none());
    assert_eq!(
        usage_census_prefix::lost_records(&index),
        usage_census_prefix::LostRecords {
            records: 1,
            saturated: false
        }
    );
    // The cached Known index is stale.
    assert!(cached.stale(&index));
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&index)
    });
    assert!(built.unknown());
    assert_eq!(
        built.verdict(CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert_eq!(census_prefix_lost_gauge(&rows), (json!(1), json!(0)));
    let alarm = rows
        .iter()
        .find(|row| row["stage"] == "census_prefix_unknown_overbudget_alarm")
        .expect("same hourly alarm as OverBudget");
    assert_eq!(alarm["counts"]["census_prefix_unknown_refused_records"], 1);
    assert_census_prefix_rows_private(
        &rows,
        &[
            CARRY_ROOT,
            CARRY_OTHER,
            CARRY_UNWITNESSED,
            "req_copy",
            "req_other",
            ".jsonl",
            "aaaaaaaa",
            "bbbbbbbb",
        ],
    );
    // Every reader answers Unknown, and no family's pending may retire.
    assert_eq!(
        usage_census_prefix::census_prefix_verdict(&index, CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert!(usage_pending_guard::fork_lineage_incomplete(&index));
    // Same scope as OverBudget: a root with usage pending is out of the index.
    index.claude_usage_family_pending.insert(
        CARRY_UNWITNESSED.into(),
        ClaudeUsageFamilyPending {
            derived_request_members: BTreeSet::new(),
            census_window_end: CARRY_FAILED.into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
        },
    );
    assert!(!usage_census_prefix::lost_records(&index).unknown());
    index.claude_usage_family_pending.remove(CARRY_UNWITNESSED);
    assert!(usage_census_prefix::CensusPrefixIndex::build(&index).unknown());
    // A key neither indexed nor walked has vanished and hides nothing: the
    // complete terminal's prune clears its mark.
    claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        CARRY_FAILED,
    );
    assert!(index.claude_request_census_for_test().lost().is_empty());
    assert!(!usage_census_prefix::lost_records(&index).unknown());
    let known = usage_census_prefix::CensusPrefixIndex::build(&index);
    assert!(!known.unknown());
    assert_eq!(
        known.verdict(CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Clear
    );
}

#[test]
fn census_prefix_decoder_dropped_record_is_unknown_across_reloads() {
    // Lead B 2026-10-30 (r16, blocking): a persisted record the decoder
    // drops leaves its file's prefixes missing, also after the next save
    // writes the census without it. The veto holds the copy, never Clear.
    let copy = [claude_request_census::claude_request_hash("req_copy")];
    let source_key = carry_key(CARRY_UNWITNESSED, None);
    let scratch = crate::test_scratch::ScratchDir::new("census-prefix-decoder-drop");
    let path = scratch.join("index.json");
    let mut index = ScanIndex::default();
    for (root, seed, request) in [
        (CARRY_OTHER, 'a', "req_other"),
        (CARRY_UNWITNESSED, 'b', "req_copy"),
    ] {
        let _ = index.claude_request_census_mut_for_test().insert(
            carry_key(root, None),
            claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
                &seed.to_string().repeat(64),
                1,
                claude_request_census::ClaudeRequestCensusShape::Exact,
                vec![claude_request_census::claude_request_hash(request)],
            ),
        );
    }
    let mut json = serde_json::to_value(&index).expect("index value");
    // Intact, the source's record holds the copy's request: Held.
    std::fs::write(&path, json.to_string()).expect("write index");
    let intact = ScanIndex::load(&path).expect("load index");
    assert_eq!(
        usage_census_prefix::CensusPrefixIndex::build(&intact).verdict(CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Held
    );
    // A malformed persisted record (unknown shape) is dropped on decode.
    json["claude_request_census"][source_key.as_str()]["s"] = json!("multi_item");
    std::fs::write(&path, json.to_string()).expect("write index");
    let mut loaded = ScanIndex::load(&path).expect("load index");
    assert!(loaded
        .claude_request_census_for_test()
        .record_for_test(&source_key)
        .is_none());
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&loaded)
    });
    assert!(built.unknown());
    assert_eq!(
        built.verdict(CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert_eq!(census_prefix_lost_gauge(&rows), (json!(1), json!(0)));
    assert!(rows.iter().any(
        |row| row["stage"] == "census_prefix_unknown_overbudget_alarm"
            && row["counts"]["census_prefix_unknown_refused_records"] == 1
    ));
    assert_census_prefix_rows_private(
        &rows,
        &[
            CARRY_ROOT,
            CARRY_OTHER,
            CARRY_UNWITNESSED,
            "req_copy",
            "req_other",
            ".jsonl",
            "aaaaaaaa",
            "bbbbbbbb",
        ],
    );
    // The mark lives in the census itself: the daemon load's custody
    // adoption neither needs nor takes it.
    loaded.usage_guard_adopt_custody(&path);
    assert!(loaded
        .claude_request_census_for_test()
        .lost()
        .keys()
        .eq([&source_key]));
    assert_eq!(
        usage_census_prefix::census_prefix_verdict(&loaded, CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert!(usage_pending_guard::fork_lineage_incomplete(&loaded));
    // Lead B r18: decoder drop -> save -> restart. The save drops the record
    // for good and persists the mark with the census; a fresh process (a
    // plain load: no usage-guard runtime, no custody) is still Unknown.
    loaded.save(&path).expect("save index");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read index")).expect("index json");
    assert!(saved["claude_request_census"]
        .get(source_key.as_str())
        .is_none());
    assert_eq!(
        saved["claude_request_census"][claude_request_census::CLAUDE_CENSUS_LOST_KEY],
        json!({"lk": [source_key]})
    );
    let restarted = ScanIndex::load(&path).expect("load index");
    assert_eq!(
        usage_census_prefix::lost_records(&restarted),
        usage_census_prefix::LostRecords {
            records: 1,
            saturated: false
        }
    );
    assert_eq!(
        usage_census_prefix::census_prefix_verdict(&restarted, CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert!(usage_pending_guard::fork_lineage_incomplete(&restarted));
    // A census the decoder loses whole hides every prefix: saturated.
    let lost = claude_request_census::ClaudeRequestCensus::lost_whole();
    assert!(lost.lost().saturated());
    let mut whole = ScanIndex::default();
    *whole.claude_request_census_mut_for_test() = lost;
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&whole)
    });
    assert!(built.unknown());
    assert!(rows.iter().any(|row| {
        row["stage"] == "claude_census_prefix_veto"
            && row["counts"]["census_prefix_unknown_refused_saturated"] == 1
    }));
}

/// Lead B r18: the census of `index` as persisted JSON.
fn census_json(index: &ScanIndex) -> serde_json::Value {
    serde_json::to_value(index).expect("index json")["claude_request_census"].clone()
}

#[test]
fn census_prefix_refused_insert_stays_unknown_after_a_restart() {
    // Lead B r18 (option 3): refused insert -> save -> restart. The mark is
    // saved with the census in the save that drops the record, so a fresh
    // process (no usage-guard runtime or custody) is still Unknown.
    let copy = [claude_request_census::claude_request_hash("req_copy")];
    let source_key = carry_key(CARRY_UNWITNESSED, None);
    let scratch = crate::test_scratch::ScratchDir::new("census-prefix-refused-restart");
    let path = scratch.join("index.json");
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![claude_request_census::claude_request_hash("req_other")],
        ),
    );
    index
        .claude_request_census_mut_for_test()
        .fill_serialized_budget_for_test();
    let source = PathBuf::from(&source_key);
    let (refused_fingerprint, stored_fingerprint) = ("b".repeat(64), "c".repeat(64));
    let (refused_fingerprint, stored_fingerprint) =
        (refused_fingerprint.as_str(), stored_fingerprint.as_str());
    let parse = |fingerprint| claude_request_census::ClaudeRequestCensusParse {
        path: &source,
        index_key: &source_key,
        source_file_fingerprint: fingerprint,
        census_window_end: CARRY_FAILED,
        complete: true,
        lossy: false,
        source_verified: true,
        itemless_request_hashes: copy.to_vec(),
        opened_birth: None,
        modified_unix_seconds: 1,
    };
    claude_request_census::record_claude_request_census(
        &mut index,
        parse(refused_fingerprint),
        &[],
    );
    assert!(usage_census_prefix::lost_records(&index).unknown());
    index.save(&path).expect("save index");
    assert_eq!(
        census_json(&ScanIndex::load(&path).expect("load index"))
            [claude_request_census::CLAUDE_CENSUS_LOST_KEY],
        json!({"lk": [source_key]})
    );
    // Restart: a plain load has a fresh usage-guard runtime and no custody.
    let mut restarted = ScanIndex::load(&path).expect("load index");
    assert!(restarted
        .claude_request_census_for_test()
        .record_for_test(&source_key)
        .is_none());
    assert_eq!(
        usage_census_prefix::lost_records(&restarted),
        usage_census_prefix::LostRecords {
            records: 1,
            saturated: false
        }
    );
    let (built, rows) = crate::local_resource_diagnostics::capture(|| {
        usage_census_prefix::CensusPrefixIndex::build(&restarted)
    });
    assert!(built.unknown());
    assert_eq!(
        built.verdict(CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Unknown
    );
    assert_eq!(census_prefix_lost_gauge(&rows), (json!(1), json!(0)));
    assert!(rows.iter().any(
        |row| row["stage"] == "census_prefix_unknown_overbudget_alarm"
            && row["counts"]["census_prefix_unknown_refused_records"] == 1
    ));
    assert_census_prefix_rows_private(
        &rows,
        &[CARRY_ROOT, CARRY_OTHER, CARRY_UNWITNESSED, "req_copy", ".jsonl"],
    );
    assert!(usage_pending_guard::fork_lineage_incomplete(&restarted));
    // Clear rule unchanged: the key's record stored again (the reloaded
    // census has room) forgets the mark, persistently.
    claude_request_census::record_claude_request_census(
        &mut restarted,
        parse(stored_fingerprint),
        &[],
    );
    assert!(restarted.claude_request_census_for_test().lost().is_empty());
    assert_eq!(
        usage_census_prefix::census_prefix_verdict(&restarted, CARRY_ROOT, copy),
        usage_census_prefix::CensusPrefixVerdict::Held
    );
    restarted.save(&path).expect("save index");
    let saved = census_json(&ScanIndex::load(&path).expect("load index"));
    assert!(saved
        .get(claude_request_census::CLAUDE_CENSUS_LOST_KEY)
        .is_none());
}

#[test]
fn census_lost_set_corrupt_on_disk_is_saturated_counted_and_alarmed() {
    // Lead B r18: an unreadable, oversized, malformed or over-count persisted
    // mark set reads as saturated (source-wide Unknown), never as empty.
    let copy = [claude_request_census::claude_request_hash("req_copy")];
    let scratch = crate::test_scratch::ScratchDir::new("census-lost-corrupt");
    let path = scratch.join("index.json");
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![claude_request_census::claude_request_hash("req_other")],
        ),
    );
    let base = serde_json::to_value(&index).expect("index json");
    let over_count = (0..=claude_request_census::MAX_CLAUDE_CENSUS_LOST_KEYS)
        .map(|n| format!("/lost/projects/{n}.jsonl"))
        .collect::<Vec<_>>();
    let oversized = "x".repeat(claude_request_census::MAX_CLAUDE_CENSUS_LOST_BYTES);
    let mut corrupt = [
        json!("lost"),
        json!(7),
        json!(null),
        json!([]),
        json!([carry_key(CARRY_UNWITNESSED, None)]),
        json!({"lk": carry_key(CARRY_UNWITNESSED, None)}),
        json!({"lk": [7]}),
        json!({"lk": [{"k": 1}]}),
        json!({"ls": "yes"}),
        json!({"ls": 1}),
        json!({"ls": true, "lt": "soon"}),
        json!({"ls": true, "lt": -1}),
        json!({"lk": over_count}),
        json!({"pad": oversized}),
    ]
    .into_iter()
    .map(|lost| {
        let mut value = base.clone();
        value["claude_request_census"][claude_request_census::CLAUDE_CENSUS_LOST_KEY] = lost;
        value.to_string()
    })
    .collect::<Vec<_>>();
    // A duplicate field inside the set, and a second copy of the set.
    let lost_key = claude_request_census::CLAUDE_CENSUS_LOST_KEY;
    let census_key = "\"claude_request_census\":{";
    let text = base.to_string();
    assert!(text.contains(census_key));
    corrupt.push(text.replacen(
        census_key,
        &format!("{census_key}\"{lost_key}\":{{\"lk\":[],\"lk\":[]}},"),
        1,
    ));
    corrupt.push(text.replacen(
        census_key,
        &format!("{census_key}\"{lost_key}\":{{}},\"{lost_key}\":{{}},"),
        1,
    ));
    for (case, json) in corrupt.iter().enumerate() {
        std::fs::write(&path, json).expect("write index");
        let loaded = ScanIndex::load(&path).expect("a corrupt set never refuses the index");
        // The records themselves are intact.
        assert!(
            loaded
                .claude_request_census_for_test()
                .get(&carry_key(CARRY_OTHER, None))
                .is_some(),
            "case {case}"
        );
        assert!(
            loaded.claude_request_census_for_test().lost().saturated(),
            "case {case}"
        );
        assert_eq!(
            usage_census_prefix::lost_records(&loaded),
            usage_census_prefix::LostRecords {
                records: 0,
                saturated: true
            },
            "case {case}"
        );
        let (built, rows) = crate::local_resource_diagnostics::capture(|| {
            usage_census_prefix::CensusPrefixIndex::build(&loaded)
        });
        assert!(built.unknown(), "case {case}");
        assert_eq!(
            built.verdict(CARRY_ROOT, copy),
            usage_census_prefix::CensusPrefixVerdict::Unknown
        );
        assert!(
            rows.iter().any(|row| {
                row["stage"] == "claude_census_prefix_veto"
                    && row["counts"]["census_prefix_unknown_refused_saturated"] == 1
            }),
            "case {case}"
        );
        // The alarm is hourly (per test thread): the first case raises it.
        if case == 0 {
            assert!(rows.iter().any(|row| {
                row["stage"] == "census_prefix_unknown_overbudget_alarm"
                    && row["counts"]["census_prefix_unknown_refused_saturated"] == 1
            }));
        }
        assert_census_prefix_rows_private(&rows, &[CARRY_OTHER, "req_other", ".jsonl"]);
        assert!(usage_pending_guard::fork_lineage_incomplete(&loaded));
        // Saturation persists through the next save.
        assert_eq!(
            census_json(&loaded)[lost_key],
            json!({"ls": true}),
            "case {case}"
        );
    }
}

#[test]
fn census_lost_set_wire_round_trip_and_byte_bound() {
    use claude_request_census::{
        ClaudeRequestCensus, CLAUDE_CENSUS_LOST_KEY, MAX_CLAUDE_CENSUS_LOST_BYTES,
        MAX_CLAUDE_CENSUS_LOST_KEYS,
    };
    let record = claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
        &"a".repeat(64),
        1,
        claude_request_census::ClaudeRequestCensusShape::Exact,
        vec![claude_request_census::claude_request_hash("req_other")],
    );
    let other = carry_key(CARRY_OTHER, None);
    let mut census = ClaudeRequestCensus::default();
    let _ = census.insert(other.clone(), record.clone());
    // No mark: the records-only bytes, unchanged for 0.1.201-0.1.203.
    let records_only = serde_json::to_string(&census).expect("census json");
    assert!(!records_only.contains(CLAUDE_CENSUS_LOST_KEY));
    // Keys round-trip; keys of no transcript member are never marked.
    let lost = [
        carry_key(CARRY_UNWITNESSED, None),
        carry_key(CARRY_ROOT, Some(CARRY_AGENT)),
    ];
    for key in &lost {
        census.mark_lost(key);
    }
    census.mark_lost("/lost/projects/not-a-transcript.json");
    let value = serde_json::to_value(&census).expect("census json");
    let mut sorted = lost.clone();
    sorted.sort();
    assert_eq!(value[CLAUDE_CENSUS_LOST_KEY], json!({"lk": sorted}));
    // The census decoder buffers raw JSON: decode from text, as a load does.
    let decode = |value: &serde_json::Value| {
        serde_json::from_str::<ClaudeRequestCensus>(&value.to_string()).expect("census")
    };
    let decoded = decode(&value);
    assert!(decoded.lost().keys().eq(sorted.iter()));
    assert!(!decoded.lost().saturated());
    assert_eq!(decoded.get(&other), Some(&record));
    assert_eq!(decoded.record_count(), 1);
    // Forward tolerant: an unknown field inside the set is skipped.
    let mut value = serde_json::to_value(&census).expect("census json");
    value[CLAUDE_CENSUS_LOST_KEY]["future"] = json!([1, "x"]);
    let decoded = decode(&value);
    assert!(decoded.lost().keys().eq(sorted.iter()));
    // Saturated round-trips as the flag alone.
    let saturated = ClaudeRequestCensus::lost_whole();
    let value = serde_json::to_value(&saturated).expect("census json");
    let mut expected = serde_json::Map::new();
    expected.insert(CLAUDE_CENSUS_LOST_KEY.to_owned(), json!({"ls": true}));
    assert_eq!(value, serde_json::Value::Object(expected));
    let decoded = decode(&value);
    assert!(decoded.lost().saturated());
    assert!(!decoded.is_unwritten());

    // Byte bound (the raw-decode headroom is a const assertion beside
    // MAX_CLAUDE_CENSUS_LOST_BYTES).
    let key_of = |n: usize, len: usize| {
        let tail = format!("/{n:04}.jsonl");
        let head = "/lost/projects/";
        format!("{head}{}{tail}", "x".repeat(len - head.len() - tail.len()))
    };
    // 256 keys of maximum length (4 KiB): the set holds as many as fit the
    // wire bound, then saturates; never past either bound.
    let mut largest = ClaudeRequestCensus::default();
    let mut kept = 0;
    for n in 0..MAX_CLAUDE_CENSUS_LOST_KEYS {
        let key = key_of(n, 4096);
        assert_eq!(key.len(), 4096);
        largest.mark_lost(&key);
        if largest.lost().saturated() {
            break;
        }
        kept += 1;
    }
    assert!(largest.lost().saturated());
    assert!((250..MAX_CLAUDE_CENSUS_LOST_KEYS).contains(&kept), "{kept}");
    assert_eq!(
        serde_json::to_value(&largest).unwrap()[CLAUDE_CENSUS_LOST_KEY],
        json!({"ls": true})
    );
    // The fullest set before saturation is within the bound; one more
    // maximum-length key would not be.
    let mut fullest = ClaudeRequestCensus::default();
    for n in 0..kept {
        fullest.mark_lost(&key_of(n, 4096));
    }
    assert!(!fullest.lost().saturated());
    let wire = serde_json::to_string(&fullest.lost()).unwrap();
    assert!(wire.len() <= MAX_CLAUDE_CENSUS_LOST_BYTES, "{}", wire.len());
    assert!(wire.len() + 4096 + 3 > MAX_CLAUDE_CENSUS_LOST_BYTES);
    assert_eq!(decode(&serde_json::to_value(&fullest).unwrap()).lost().keys().count(), kept);
    // Short keys: 256 fit, the 257th saturates.
    let mut short = ClaudeRequestCensus::default();
    for n in 0..MAX_CLAUDE_CENSUS_LOST_KEYS {
        short.mark_lost(&key_of(n, 32));
    }
    assert!(!short.lost().saturated());
    assert_eq!(short.lost().keys().count(), MAX_CLAUDE_CENSUS_LOST_KEYS);
    let decoded = decode(&serde_json::to_value(&short).unwrap());
    assert_eq!(decoded.lost().keys().count(), MAX_CLAUDE_CENSUS_LOST_KEYS);
    assert!(!decoded.lost().saturated());
    short.mark_lost(&key_of(MAX_CLAUDE_CENSUS_LOST_KEYS, 32));
    assert!(short.lost().saturated());
    // A key past 4 KiB saturates rather than being kept.
    let mut long = ClaudeRequestCensus::default();
    long.mark_lost(&key_of(0, 4097));
    assert!(long.lost().saturated());
}

#[test]
fn census_lost_saturation_clears_only_when_every_transcript_key_has_a_record() {
    // Lead B r18 proposal: a persisted saturated flag clears at a complete
    // terminal once every indexed or walked transcript key has a record (or
    // is idle past the retirement cutoff). One key without either keeps it.
    let window = rfc3339_unix_seconds(CARRY_FAILED).expect("window");
    let recent = |entry: &mut ScanIndexEntry| entry.modified_unix_seconds = window - 60;
    let keys = [
        carry_key(CARRY_OTHER, None),
        carry_key(CARRY_ROOT, None),
        carry_key(CARRY_UNWITNESSED, None),
    ];
    let mut index = ScanIndex::default();
    *index.claude_request_census_mut_for_test() =
        claude_request_census::ClaudeRequestCensus::lost_whole();
    for (n, key) in keys.iter().enumerate() {
        let mut entry = manifest_index_entry(Some("snapshot"));
        recent(&mut entry);
        index.files.insert(key.clone(), entry);
        if n < 2 {
            let _ = index.claude_request_census_mut_for_test().insert(
                key.clone(),
                claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
                    &char::from(b'a' + n as u8).to_string().repeat(64),
                    1,
                    claude_request_census::ClaudeRequestCensusShape::Exact,
                    vec![n as u64],
                ),
            );
        }
    }
    let settle = |index: &mut ScanIndex, walked: &BTreeSet<String>| {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            claude_request_census::settle_claude_request_census_terminal(
                index,
                walked,
                &BTreeSet::new(),
                CARRY_FAILED,
            )
        });
        let row = rows
            .iter()
            .find(|row| row["stage"] == "claude_census_lost_saturated")
            .expect("saturated settle row")
            .clone();
        assert_census_prefix_rows_private(
            std::slice::from_ref(&row),
            &[CARRY_ROOT, CARRY_OTHER, CARRY_UNWITNESSED, ".jsonl"],
        );
        (
            row["counts"]["census_lost_saturated_unrecorded_keys"].clone(),
            row["counts"]["census_lost_saturated_cleared"].clone(),
        )
    };
    // One recent transcript without a record: still saturated.
    assert_eq!(settle(&mut index, &BTreeSet::new()), (json!(1), json!(0)));
    assert!(index.claude_request_census_for_test().lost().saturated());
    // An invalidated record is no record either.
    let _ = index.claude_request_census_mut_for_test().insert(
        keys[2].clone(),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"c".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![2],
        ),
    );
    index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(&keys[2]);
    // A walked transcript that is not indexed yet and has no record blocks too.
    let walked = BTreeSet::from([carry_key(CARRY_ROOT, Some(CARRY_AGENT))]);
    let (unrecorded, cleared) = settle(&mut index, &walked);
    assert_eq!(cleared, json!(0));
    assert!(unrecorded.as_u64().is_some_and(|n| n >= 1));
    assert!(index.claude_request_census_for_test().lost().saturated());
    // Idle past the retirement cutoff, a missing record holds no prefix.
    index
        .files
        .get_mut(&keys[2])
        .expect("entry")
        .modified_unix_seconds = 2;
    assert_eq!(settle(&mut index, &BTreeSet::new()), (json!(0), json!(1)));
    assert!(index.claude_request_census_for_test().lost().is_empty());
    assert!(!usage_census_prefix::lost_records(&index).unknown());
    // Not saturated: no settle row.
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        claude_request_census::settle_claude_request_census_terminal(
            &mut index,
            &BTreeSet::new(),
            &BTreeSet::new(),
            CARRY_FAILED,
        )
    });
    assert!(!rows
        .iter()
        .any(|row| row["stage"] == "claude_census_lost_saturated"));
}

#[test]
fn census_lost_saturation_episode_age_persists_and_reports_on_clear() {
    // Lead B r19: the saturated row carries the episode's age, also when it
    // clears. The start is the first complete terminal that found the set
    // saturated, persisted as `lt` beside the flag (a restart keeps it).
    use claude_request_census::{ClaudeRequestCensus, CLAUDE_CENSUS_LOST_KEY};
    let failed = rfc3339_unix_seconds(CARRY_FAILED).expect("window");
    let key = carry_key(CARRY_OTHER, None);
    let mut index = ScanIndex::default();
    *index.claude_request_census_mut_for_test() = ClaudeRequestCensus::lost_whole();
    let mut entry = manifest_index_entry(Some("snapshot"));
    entry.modified_unix_seconds = failed - 60;
    index.files.insert(key.clone(), entry);
    let settle = |index: &mut ScanIndex, at: &str| {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            claude_request_census::settle_claude_request_census_terminal(
                index,
                &BTreeSet::new(),
                &BTreeSet::new(),
                at,
            )
        });
        let row = rows
            .iter()
            .find(|row| row["stage"] == "claude_census_lost_saturated")
            .expect("saturated settle row")
            .clone();
        assert_census_prefix_rows_private(
            std::slice::from_ref(&row),
            &[CARRY_OTHER, ".jsonl", "/carry"],
        );
        (
            row["counts"]["census_lost_saturated_cleared"].clone(),
            row["counts"]["census_lost_saturated_age_seconds"].clone(),
        )
    };
    // A fresh saturation has no start until a complete terminal sees it.
    assert_eq!(census_json(&index)[CLAUDE_CENSUS_LOST_KEY], json!({"ls": true}));
    assert_eq!(settle(&mut index, CARRY_FAILED), (json!(0), json!(0)));
    assert_eq!(
        census_json(&index)[CLAUDE_CENSUS_LOST_KEY],
        json!({"ls": true, "lt": failed})
    );
    // The start survives a save and reload (decode of the census value).
    let reloaded = serde_json::from_str::<ClaudeRequestCensus>(
        &serde_json::to_string(index.claude_request_census_for_test()).expect("census json"),
    )
    .expect("census");
    assert!(reloaded.lost().saturated());
    *index.claude_request_census_mut_for_test() = reloaded;
    assert_eq!(settle(&mut index, CARRY_RETRY), (json!(0), json!(600)));
    assert_eq!(
        census_json(&index)[CLAUDE_CENSUS_LOST_KEY],
        json!({"ls": true, "lt": failed})
    );
    // The clearing terminal reports the whole episode, then nothing persists.
    let _ = index.claude_request_census_mut_for_test().insert(
        key.clone(),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![1],
        ),
    );
    assert_eq!(settle(&mut index, CARRY_SECOND_RETRY), (json!(1), json!(1200)));
    assert!(index.claude_request_census_for_test().lost().is_empty());
    assert!(census_json(&index).get(CLAUDE_CENSUS_LOST_KEY).is_none());
    // A persisted start older than this process is carried, not restarted.
    let decoded = serde_json::from_str::<ClaudeRequestCensus>(
        &json!({ CLAUDE_CENSUS_LOST_KEY: {"ls": true, "lt": failed - 100} }).to_string(),
    )
    .expect("census");
    // The key has no record in the decoded census: still saturated.
    *index.claude_request_census_mut_for_test() = decoded;
    assert_eq!(settle(&mut index, CARRY_FAILED), (json!(0), json!(100)));
    // A start in the future (a clock step back) reads as age zero.
    *index.claude_request_census_mut_for_test() = serde_json::from_str::<ClaudeRequestCensus>(
        &json!({ CLAUDE_CENSUS_LOST_KEY: {"ls": true, "lt": failed + 100} }).to_string(),
    )
    .expect("census");
    assert_eq!(settle(&mut index, CARRY_FAILED), (json!(0), json!(0)));
}

#[test]
fn census_upgrade_gauge_counts_unrecorded_pending_free_keys_once() {
    // Lead B r18 ruling 2: the pre-#915 upgrade gap is disclosed and measured
    // once per process, on the first load whose census holds no loss marks.
    // Pending-free transcript keys of the D1 coverage set with no census
    // record, in one unclassified bucket (no exact evidence tells "parsed
    // since D1" apart). Counts only.
    use std::sync::atomic::{AtomicBool, Ordering};
    const RECORDED: &str = "d4444444-4444-4444-8444-444444444444";
    const EMPTY: &str = "e5555555-5555-4555-8555-555555555555";
    const STUB: &str = "f6666666-6666-4666-8666-666666666666";
    // CARRY_OTHER: pending-free, committed, no record. CARRY_ROOT (two
    // members) and CARRY_UNWITNESSED have usage pending: out of scope.
    let mut index = carry_index();
    for root in [RECORDED, EMPTY, STUB] {
        carry_file(&mut index, root, None);
    }
    index.confirmed_empty_files.insert(carry_key(EMPTY, None));
    index
        .files
        .insert("/carry/projects/notes.txt".into(), manifest_index_entry(None));
    let record = |seed: &str| {
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &seed.repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![7],
        )
    };
    let census = index.claude_request_census_mut_for_test();
    let _ = census.insert(carry_key(RECORDED, None), record("a"));
    // A birth stub is no record.
    let _ = census.insert(carry_key(STUB, None), record("b"));
    census.invalidate_keeping_birth_for_test(&carry_key(STUB, None));
    let gauge = |index: &ScanIndex, fired: &AtomicBool| {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            claude_request_census::note_census_upgrade_unrecorded_once(index, fired)
        });
        let rows = rows
            .into_iter()
            .filter(|row| row["stage"] == "claude_census_upgrade_unrecorded")
            .collect::<Vec<_>>();
        assert_census_prefix_rows_private(
            &rows,
            &[
                CARRY_ROOT,
                CARRY_OTHER,
                CARRY_UNWITNESSED,
                RECORDED,
                EMPTY,
                STUB,
                ".jsonl",
                "/carry",
                "notes",
            ],
        );
        rows
    };
    let fired = AtomicBool::new(false);
    let rows = gauge(&index, &fired);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["counts"],
        json!({
            "census_upgrade_pending_free_keys": 3,
            "census_upgrade_unrecorded_unclassified": 2,
        })
    );
    // Once per process.
    assert!(gauge(&index, &fired).is_empty());
    // A census with loss marks was written under #915: no gauge, and the
    // once-flag stays unspent until a load without marks.
    let fresh = AtomicBool::new(false);
    let mut marked = index.clone();
    marked
        .claude_request_census_mut_for_test()
        .mark_lost(&carry_key(CARRY_OTHER, None));
    assert!(gauge(&marked, &fresh).is_empty());
    assert!(!fresh.load(Ordering::Relaxed));
    let mut saturated = index.clone();
    *saturated.claude_request_census_mut_for_test() =
        claude_request_census::ClaudeRequestCensus::lost_whole();
    assert!(gauge(&saturated, &fresh).is_empty());
    assert!(!fresh.load(Ordering::Relaxed));
    assert_eq!(gauge(&index, &fresh).len(), 1);
}

#[test]
fn fork_lineage_unknown_is_source_wide_beside_an_unrelated_qualified_family() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Review r89 MEDIUM: the retirement gate is source-wide. An incomplete
    // current-window, Match or quarantined family, or a refused read of a
    // family that is not held, refuses an unrelated qualified family too.
    let mut base = carry_index();
    retry_under_way(&mut base);
    base.claude_usage_family_pending.remove(CARRY_UNWITNESSED);
    carry_family(&mut base, CARRY_OTHER, &[None], true);
    base.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert_eq!(
        usage_pending_guard::verdict(&base, CARRY_ROOT),
        Verdict::Match
    );
    assert!(!base.usage_guard_holds.holds(CARRY_ROOT));
    assert!(!usage_pending_guard::fork_lineage_incomplete(&base));
    let counts = retirement_attempt(&mut base.clone());
    assert!(counts["retire_refused"]["fork_lineage_unknown"].is_null());
    let sibling = |index: &mut ScanIndex| {
        index.files.insert(
            carry_key(CARRY_ROOT, Some("agent-b5e1b2c3d4e5f6072")),
            manifest_index_entry(Some("unread-sibling")),
        );
    };
    let mut current = base.clone();
    current
        .claude_usage_family_pending
        .get_mut(CARRY_ROOT)
        .unwrap()
        .census_window_end = CARRY_RETRY.into();
    sibling(&mut current);
    let mut matched = base.clone();
    sibling(&mut matched);
    let mut quarantined = base.clone();
    quarantine_carry_root(&mut quarantined);
    sibling(&mut quarantined);
    let mut refused = base.clone();
    refused.usage_guard_full_blocked(Path::new(&carry_key(CARRY_ROOT, None)));
    for (label, mut incomplete) in [
        ("current", current),
        ("match", matched),
        ("quarantined", quarantined),
        ("refused_unheld", refused),
    ] {
        incomplete.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
        assert!(
            !incomplete.usage_guard_holds.holds(CARRY_ROOT),
            "{label}: no scoped hold is needed"
        );
        assert!(
            usage_pending_guard::fork_lineage_incomplete(&incomplete),
            "{label}"
        );
        let counts = retirement_attempt(&mut incomplete);
        assert_eq!(
            counts["retire_refused"]["fork_lineage_unknown"]["families"],
            2,
            "{label}: the unrelated qualified family is held back too"
        );
        assert_eq!(counts["retired"]["families"], 0, "{label}");
        assert!(
            incomplete.claude_usage_family_pending.contains_key(CARRY_OTHER),
            "{label}: the unrelated qualified family is refused"
        );
    }
}

#[test]
fn owned_start_correction_waits_for_a_held_family() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Review r89 note (approved: "Unknown hold instead of carry/re-arm"):
    // an outstanding owned-start correction does not clear a held family's
    // fingerprints; it stays owed until the hold ends.
    let (mut index, root, _) = held_family_index();
    index.claude_owned_start_census.insert(
        root.clone(),
        ClaudeOwnedStartCensusWitness {
            marker_source_file_fingerprint: "m".repeat(64),
            verified_source_file_fingerprint: Some("v".repeat(64)),
            emitted_source_file_fingerprint: None,
        },
    );
    let parent = index
        .files
        .keys()
        .find(|key| {
            claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| member.root == root && member.subagent_stem.is_none())
        })
        .cloned()
        .unwrap();
    let before = index.files[&parent].source_file_fingerprint.clone();
    assert!(!before.is_empty());
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        apply_claude_reported_usage_with_index(&mut Vec::new(), &api, &trace, &mut index, false, CARRY_RETRY)
    });
    assert!(index.usage_guard_holds.holds(&root));
    assert_eq!(index.files[&parent].source_file_fingerprint, before);
    assert!(rows
        .iter()
        .any(|row| row["counts"]["owned_start_correction_held_files"] == 1));
    assert!(index.claude_owned_start_census[&root]
        .emitted_source_file_fingerprint
        .is_none());
}

#[test]
fn held_no_witness_gauge_counts_and_alarms_hourly() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Lead B round 10: gauge usage_held_no_witness{families, bytes,
    // oldest_age} with the local hourly alarm pattern.
    let (index, root, _) = held_family_index();
    let window = rfc3339_unix_seconds(CARRY_FAILED).unwrap();
    let young = "2026-08-02T08:10:00Z";
    let (gauge, rows) =
        crate::local_resource_diagnostics::capture(|| index.usage_guard_gauge_held_no_witness(young));
    assert_eq!(gauge.families, 1);
    assert_eq!(
        gauge.bytes,
        usage_pending_retention::pending_bytes(&index.claude_usage_family_pending[&root]).unwrap()
    );
    assert!(gauge.bytes > 0);
    assert_eq!(gauge.oldest_age_seconds, 3_600);
    assert!(rows.iter().any(|row| row["stage"] == "usage_held_no_witness"
        && row["counts"]["families"] == 1));
    assert!(!rows.iter().any(|row| row["stage"] == "usage_held_no_witness_alarm"));
    let old = "2026-08-09T07:10:00Z";
    let (gauge, rows) =
        crate::local_resource_diagnostics::capture(|| index.usage_guard_gauge_held_no_witness(old));
    assert_eq!(
        gauge.oldest_age_seconds,
        rfc3339_unix_seconds(old).unwrap() - window
    );
    assert!(gauge.oldest_age_seconds >= usage_pending_guard::HELD_NO_WITNESS_ALARM_AGE_SECONDS);
    assert!(rows.iter().any(|row| row["stage"] == "usage_held_no_witness_alarm"));
    // At most hourly.
    let (_, rows) =
        crate::local_resource_diagnostics::capture(|| index.usage_guard_gauge_held_no_witness(old));
    assert!(!rows.iter().any(|row| row["stage"] == "usage_held_no_witness_alarm"));
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
    // Lead B 4a: retry start no longer compacts. Index 0 is today (no
    // compaction), index 1 simulates the removed compaction of old-carried
    // and invalid (capped) roots on the same frozen input.
    let mut occurrences = [0_u64; 2];
    let mut over_cap_checkpoints = [0_u64; 2];
    let mut cap_headroom_min = [u64::MAX; 2];
    let mut invalid_families = [0_u64; 2];
    let mut compacted_families = 0_u64;
    // Lead B round 8: the fork-lineage retirement gate and the census-prefix
    // index on the same frozen input. Runtime unread marks and held growth
    // do not survive a reload, so only global holds, Unknown prefix indexes
    // and missing siblings of held families can fire it here.
    let mut fork_lineage_unknown_checkpoints = 0_u64;
    let mut fork_lineage_unknown_families = 0_u64;
    let mut census_prefix_entries_max = 0_u64;
    let mut census_prefix_unknown = 0_u64;
    let mut census_prefix_bytes_max = 0_u64;
    for path in paths {
        let file = File::open(path).expect("frozen checkpoint unavailable");
        let mut index =
            lenient_decode::read(BufReader::new(file), "e7_guard_replay", "claude_code")
                .unwrap_or_else(|_| {
                    panic!("frozen checkpoint decode refused; no repair attempted")
                });
        // Model the next traversal start as production runs it: the
        // census-prefix refresh (runtime only) before the hold projection,
        // so a prefix Unknown reaches the projection and the fork gate.
        // Every retained pending is stale.
        let prefixes = index.refresh_claude_census_prefix("9999-12-31T23:59:59Z", false);
        index.refresh_usage_guard_holds_at(None);
        checkpoints += 1;
        global_unknown += u64::from(index.usage_guard_holds.global());
        census_prefix_entries_max = census_prefix_entries_max.max(prefixes.len() as u64);
        census_prefix_bytes_max = census_prefix_bytes_max.max(prefixes.bytes() as u64);
        census_prefix_unknown += u64::from(prefixes.unknown());
        if usage_pending_guard::fork_lineage_incomplete(&index) {
            fork_lineage_unknown_checkpoints += 1;
            fork_lineage_unknown_families += index.claude_usage_family_pending.len() as u64;
        }
        let roots = index
            .claude_usage_family_pending
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for root in &roots {
            recorded[usize::from(index.claude_stale_family_carry.contains(root))] += 1;
        }
        let old_carry = usage_pending_guard::replay_old(|| route(&index, &roots, 0));
        let mut totals = [0_u64; 2];
        for (root, pending) in &index.claude_usage_family_pending {
            let count = pending
                .member_occurrences
                .values()
                .map(|occurrences| occurrences.len() as u64)
                .sum::<u64>();
            let compacted = old_carry.contains(root) || pending.invalid;
            compacted_families += u64::from(compacted);
            totals[0] += count;
            totals[1] += if compacted { 0 } else { count };
            for family in &mut invalid_families {
                *family += u64::from(pending.invalid);
            }
        }
        for with in 0..2 {
            occurrences[with] += totals[with];
            let cap = MAX_CLAUDE_PENDING_USAGE_OCCURRENCES as u64;
            over_cap_checkpoints[with] += u64::from(totals[with] > cap);
            cap_headroom_min[with] = cap_headroom_min[with].min(cap.saturating_sub(totals[with]));
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
        "pending_occurrences_without_with_compaction":occurrences,
        "over_cap_checkpoints_without_with_compaction":over_cap_checkpoints,
        "min_cap_headroom_without_with_compaction":cap_headroom_min,
        "invalid_families_without_with_compaction":invalid_families,
        "compaction_simulated_families":compacted_families,
        "pending_occurrence_cap":MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        "historical_decision_log_unavailable":1,"acquisition_money_replay_unavailable":1,
        "activation_zero_diff_proven":false,
        "fork_lineage_unknown_checkpoints":fork_lineage_unknown_checkpoints,
        "retire_refused_fork_lineage_unknown_families":fork_lineage_unknown_families,
        "fork_lineage_runtime_marks_unavailable":1,
        "census_prefix_entries_max":census_prefix_entries_max,
        "census_prefix_bytes_max":census_prefix_bytes_max,
        "census_prefix_byte_budget":usage_census_prefix::CENSUS_PREFIX_MAX_BYTES,
        "census_prefix_unknown_checkpoints":census_prefix_unknown})
    );
    assert_eq!(known_diffs, 0, "known guard differences; counts only");
}

#[test]
fn census_prefix_peak_budget_charges_live_cloned_baseline_before_scratch() {
    let mut index = ScanIndex::default();
    let _ = index.claude_request_census_mut_for_test().insert(
        carry_key(CARRY_OTHER, None),
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64), 1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            (0..8192).collect(),
        ),
    );
    // One build fits; two array pairs alone do not. Keep the exact normal
    // sync preparation ownership: the committed ScanIndex baseline is cloned.
    usage_census_prefix::with_cap_for_test(120_000, || {
        let first = index.refresh_claude_census_prefix(CARRY_FAILED, false);
        assert!(!first.unknown());
        assert!(first.bytes() > 90_000);
        drop(first);
        let baseline = index.clone();
        let (next, rows) = crate::local_resource_diagnostics::capture(||
            index.refresh_claude_census_prefix(CARRY_RETRY, false));
        assert!(next.unknown(), "baseline allocation remains charged");
        assert!(index.usage_guard_holds.global());
        assert!(rows.iter().any(|r| r["counts"]["census_prefix_overflow"] == 1));
        assert!(!baseline.usage_guard_census_prefix().unwrap().unknown());
        drop(next);
        drop(baseline);
        // A new complete pass retries admission after the last owner releases.
        assert!(!index.refresh_claude_census_prefix(CARRY_RETRY, true).unknown());
    });
    let (small, rows) = crate::local_resource_diagnostics::capture(||
        usage_census_prefix::CensusPrefixIndex::build_within(&index, 1));
    assert!(small.unknown());
    assert_eq!(small.bytes(), 0);
    assert!(rows.iter().any(|r| r["counts"]["census_prefix_build_peak_bytes"].as_u64().unwrap_or(0) > 1));
}

#[cfg(unix)]
#[test]
fn unheld_production_open_refusal_blocks_unrelated_retirement_with_or_without_pending() {
    for with_pending in [false, true] {
        let dir = temp_dir("unheld-open-refusal");
        let family = if with_pending { CARRY_ROOT } else { "pending-free-copy" };
        let path = dir.join(format!("{family}.jsonl"));
        fs::write(&path, "{}\n").unwrap();
        let mut index = carry_index();
        retry_under_way(&mut index);
        index.claude_usage_family_pending.remove(CARRY_UNWITNESSED);
        carry_family(&mut index, CARRY_OTHER, &[None], true);
        if with_pending {
            // Same Match family and complete indexed membership, now at the
            // actual selected file path; stale proof cannot see unread growth.
            let entry = index.files.remove(&carry_key(CARRY_ROOT, None)).unwrap();
            index.files.insert(local_index_key(&path), entry);
        }
        index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
        assert!(!index.usage_guard_holds.holds(family));
        assert!(!usage_pending_guard::fork_lineage_incomplete(&index));
        let mut state = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode, std::slice::from_ref(&dir), index,
            CARRY_RETRY, BACKFILL_WINDOW_DAYS, 16, true, None, &[], false, true,
        );
        assert!(state.identified_candidates.iter().any(|c| c.path == path));
        // Selection/stat succeeded; the production no-follow open must fail.
        // Unlike chmod, this remains deterministic for privileged CI users.
        fs::remove_file(&path).unwrap();
        let target = dir.join("target");
        fs::write(&target, "{}\n").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let mut reached = false;
        for _ in 0..32 {
            state = match state.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                OwnedSourceScanStep::Complete { .. } => panic!("open failure not observed"),
            };
            if state.census.unreadable_path_count > 0 {
                reached = true;
                assert!(!state.index.usage_guard_holds.holds(family));
                assert!(usage_pending_guard::fork_lineage_incomplete(&state.index));
                let counts = retirement_attempt(&mut state.index);
                assert!(counts["retire_refused"]["fork_lineage_unknown"]["families"].as_u64().unwrap() >= 1);
                assert_eq!(counts["retired"]["families"], 0);
                assert!(state.index.claude_usage_family_pending.contains_key(CARRY_OTHER));
                break;
            }
        }
        assert!(reached, "real unheld acquisition failure reached the gate");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn size_limit_growth_of_complete_indexed_family_blocks_unrelated_retirement() {
    // Review r12 MEDIUM: Match family B has complete indexed membership and
    // grows past the source size limit. Discovery refuses it on size, with
    // no unreadable/disappeared count and no read; that refusal must still
    // feed the source-wide gate, so unrelated qualified family A is held.
    let dir = temp_dir("size-limit-growth-refusal");
    let path = dir.join(format!("{CARRY_ROOT}.jsonl"));
    fs::write(&path, "{}\n").unwrap();
    let mut index = carry_index();
    retry_under_way(&mut index);
    index.claude_usage_family_pending.remove(CARRY_UNWITNESSED);
    carry_family(&mut index, CARRY_OTHER, &[None], true);
    let entry = index.files.remove(&carry_key(CARRY_ROOT, None)).unwrap();
    index.files.insert(local_index_key(&path), entry);
    index.refresh_usage_guard_holds_at(Some(CARRY_RETRY));
    assert!(!index.usage_guard_holds.holds(CARRY_ROOT));
    assert!(!usage_pending_guard::fork_lineage_incomplete(&index));
    // Sparse growth: logical length over the cap, negligible bytes on disk.
    File::options().write(true).open(&path).unwrap()
        .set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1).unwrap();
    let mut state = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode, std::slice::from_ref(&dir), index,
        CARRY_RETRY, BACKFILL_WINDOW_DAYS, 16, true, None, &[], false, true,
    );
    let traversal = state.index.traversal.as_ref().unwrap();
    assert_eq!(traversal.counts.oversized_file_count, 1);
    assert_eq!(traversal.counts.unreadable_path_count, 0);
    assert_eq!(traversal.counts.disappeared_file_count, 0);
    assert!(!state.identified_candidates.iter().any(|c| c.path == path), "no read");
    assert!(state.index.usage_guard_refused_for_test(&path));
    assert!(!state.index.usage_guard_holds.holds(CARRY_ROOT));
    assert!(usage_pending_guard::fork_lineage_incomplete(&state.index));
    let counts = retirement_attempt(&mut state.index);
    assert!(counts["retire_refused"]["fork_lineage_unknown"]["families"].as_u64().unwrap() >= 1);
    assert_eq!(counts["retired"]["families"], 0);
    assert!(state.index.claude_usage_family_pending.contains_key(CARRY_OTHER));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn size_limit_candidate_and_open_exits_mark_refusal_but_exclusions_do_not() {
    let dir = temp_dir("size-limit-refusal-exits");
    let path = dir.join("oversized-copy.jsonl");
    File::create(&path).unwrap().set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1).unwrap();
    let pending = |path: &Path, member, watcher_hint| ScanTraversalPath {
        scan_root: dir.clone(), path: path.to_path_buf(), census_member: member, watcher_hint,
    };
    // Candidate stat: a census member (counted) and an uncounted re-read.
    for member in [true, false] {
        let mut index = ScanIndex::default();
        let mut census = ScanCensus::default();
        assert!(index.usage_guard_traversal_candidate(
            SnapshotSource::ClaudeCode, disappearance_diagnostics::Site::CandidateWalk,
            pending(&path, member, false), &mut census, None, BACKFILL_WINDOW_DAYS,
        ).is_none());
        assert_eq!(census.oversized_file_count, usize::from(member));
        assert!(index.usage_guard_refused_for_test(&path), "member={member}");
    }
    // Open: the candidate was stat'ed at its oversized length.
    let candidate = {
        let small = dir.join("small-copy.jsonl");
        fs::write(&small, "{}\n").unwrap();
        let mut census = ScanCensus::default();
        let mut candidate = ScanIndex::default().usage_guard_traversal_candidate(
            SnapshotSource::ClaudeCode, disappearance_diagnostics::Site::CandidateWalk,
            pending(&small, true, false), &mut census, None, BACKFILL_WINDOW_DAYS,
        ).unwrap();
        candidate.path = path.clone();
        candidate.size_bytes = MAX_CLAUDE_JSONL_FILE_BYTES + 1;
        candidate
    };
    let mut index = ScanIndex::default();
    let mut census = ScanCensus::default();
    assert!(index.usage_guard_open_candidate(
        SnapshotSource::ClaudeCode, candidate, &mut census, None, BACKFILL_WINDOW_DAYS, false, None,
    ).is_none());
    assert_eq!(census.oversized_file_count, 1);
    assert!(index.usage_guard_refused_for_test(&path));
    // A remove hint for a vanished file and a window exit hide no data.
    let vanished = dir.join("vanished-copy.jsonl");
    let aged = dir.join("aged-copy.jsonl");
    fs::write(&aged, "{}\n").unwrap();
    File::options().write(true).open(&aged).unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)))
        .unwrap();
    for (excluded, watcher_hint) in [(&vanished, true), (&aged, false)] {
        let mut index = ScanIndex::default();
        let mut census = ScanCensus::default();
        assert!(index.usage_guard_traversal_candidate(
            SnapshotSource::ClaudeCode, disappearance_diagnostics::Site::CandidateWalk,
            pending(excluded, true, watcher_hint), &mut census, Some(2_000_000_000), 1,
        ).is_none());
        assert!(!index.usage_guard_refused_for_test(excluded), "{}", excluded.display());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn source_wide_open_refusal_recovers_on_verified_unchanged_reopen_without_rearm() {
    let root = temp_dir("sourcewide-open-recovery");
    let path = root.join("recovered.jsonl");
    let at = OffsetDateTime::now_utc();
    let stamp = |minutes| (at + time::Duration::minutes(minutes)).format(&Rfc3339).unwrap();
    fs::write(&path, format!("{}\n", json!({"timestamp":stamp(0),"type":"assistant",
        "sessionId":"recovered","requestId":"req_recovered","message":{
            "id":"msg_recovered","model":"claude-opus-4-8",
            "usage":{"input_tokens":100,"output_tokens":2}}}))).unwrap();
    let mut index = ScanIndex::default();
    let mut baseline = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode, std::slice::from_ref(&root), &mut index,
        &stamp(0), BACKFILL_WINDOW_DAYS, 16, false,
    ).unwrap();
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut baseline, &mut index);
    let key = local_index_key(&path);
    assert_eq!(baseline.snapshots.len(), 1);
    index.record_accepted_snapshot_fingerprints(&baseline.snapshots.iter()
        .map(|s| s.snapshot_fingerprint.clone()).collect());
    let record = index.claude_request_census.get(&key).unwrap();
    assert!(record.can_bind_recomposed_body() && !record.unverified_or_twin());
    assert!(claude_request_census::fingerprint_matches(record, &index.files[&key].source_file_fingerprint));
    let retained = index.files[&key].source_file_fingerprint.clone();
    let mut state = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode, std::slice::from_ref(&root), index,
        &stamp(1), BACKFILL_WINDOW_DAYS, 16, false, None, &[], false, true,
    );
    assert!(state.identified_candidates.iter().any(|c| c.path == path));
    // Preserve the exact original object while making the real no-follow
    // open fail. Replacing the symlink with that object restores its data.
    let parked = root.join("parked");
    fs::rename(&path, &parked).unwrap();
    std::os::unix::fs::symlink(&parked, &path).unwrap();
    let failed_index = loop {
        match state.step(None) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => {
                assert!(scan.unreadable_path_count > 0);
                break index;
            }
        }
    };
    assert!(usage_pending_guard::fork_lineage_incomplete(&failed_index));
    fs::remove_file(&path).unwrap();
    fs::rename(&parked, &path).unwrap();
    let mut index = failed_index;
    let (scan, rows) = crate::local_resource_diagnostics::capture(||
        scan_source_roots_with_limit(SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root), &mut index, &stamp(10),
            BACKFILL_WINDOW_DAYS, 16, false).unwrap());
    assert_eq!(scan.scanned_file_count, 0, "verified unchanged reopen needs no parse");
    assert!(rows.iter().any(|r| r["counts"]["fork_lineage_refused_reopen_recovered_files"] == 1));
    assert_eq!(index.files[&key].source_file_fingerprint, retained);
    assert!(!usage_pending_guard::fork_lineage_incomplete(&index));
    fs::remove_dir_all(root).unwrap();
}
