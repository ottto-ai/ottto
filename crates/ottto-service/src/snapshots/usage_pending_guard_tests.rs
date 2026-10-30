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
    for path in paths {
        let file = File::open(path).expect("frozen checkpoint unavailable");
        let mut index =
            lenient_decode::read(BufReader::new(file), "e7_guard_replay", "claude_code")
                .unwrap_or_else(|_| {
                    panic!("frozen checkpoint decode refused; no repair attempted")
                });
        // Model the next traversal start: every retained pending is stale.
        index.refresh_usage_guard_holds_at(None);
        checkpoints += 1;
        global_unknown += u64::from(index.usage_guard_holds.global());
        let prefixes = usage_census_prefix::CensusPrefixIndex::build(&index);
        census_prefix_entries_max = census_prefix_entries_max.max(prefixes.len() as u64);
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
        "census_prefix_cap":usage_census_prefix::CENSUS_PREFIX_MAX_ENTRIES,
        "census_prefix_unknown_checkpoints":census_prefix_unknown})
    );
    assert_eq!(known_diffs, 0, "known guard differences; counts only");
}
