// C1b: the same-context red-retry carry of unchanged, witnessed Claude
// families. Each test builds a persisted index directly: a closed duplicate
// fence, a red traversal whose retry is due, a witnessed family whose pending
// from the failed window matches its witness exactly, an unwitnessed family
// from the same window, and an unrelated committed file. It then runs the
// real traversal start (`ensure_bounded_traversal`) and reads its count-only
// `starting` row. A BASE arm runs the same start under
// `KeepStaleClaudeFamilyRearmForTest`, which carries nothing. Fixtures are
// synthetic and content-free.
use super::*;

const CARRY_FAILED: &str = "2026-08-02T07:10:00Z";
const CARRY_RETRY: &str = "2026-08-02T07:20:00Z";
const CARRY_SECOND_RETRY: &str = "2026-08-02T07:30:00Z";
const CARRY_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const CARRY_AGENT: &str = "agent-a4d1585d310070d0f";
const CARRY_UNWITNESSED: &str = "b2222222-2222-4222-8222-222222222222";
const CARRY_OTHER: &str = "c3333333-3333-4333-8333-333333333333";

fn carry_key(root: &str, subagent: Option<&str>) -> String {
    match subagent {
        Some(stem) => format!("/carry/projects/{root}/subagents/{stem}.jsonl"),
        None => format!("/carry/projects/{root}.jsonl"),
    }
}

fn carry_member(root: &str, subagent: Option<&str>) -> String {
    subagent.map_or_else(|| root.to_string(), |stem| format!("{root}_{stem}"))
}

fn carry_occurrence(sequence: u64, output_tokens: u64) -> ClaudeTranscriptUsageOccurrenceWitness {
    ClaudeTranscriptUsageOccurrenceWitness {
        sequence,
        input_tokens: 10,
        output_tokens,
        cache_read_tokens: 0,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        model: Some("model-a".to_string()),
        speed_mode: None,
        reasoning_effort: None,
    }
}

/// One committed, accepted file for a family member.
fn carry_file(index: &mut ScanIndex, root: &str, subagent: Option<&str>) -> String {
    let key = carry_key(root, subagent);
    let member = carry_member(root, subagent);
    let body = format!("body-{member}");
    let mut entry = manifest_index_entry(Some(&body));
    entry.source_file_fingerprint = format!("rev-{member}");
    index.files.insert(key.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from([body.clone()]));
    index.accepted_snapshot_fingerprints.insert(body);
    key
}

/// A family whose every member was parsed in the failed window, one request
/// per member (request hash `seed`, `seed + 1`, ...). A witnessed family's
/// witness matches that pending exactly.
fn carry_family(index: &mut ScanIndex, root: &str, subagents: &[Option<&str>], witnessed: bool) {
    let mut pending = ClaudeUsageFamilyPending {
        census_window_end: CARRY_FAILED.to_string(),
        member_request_id_hashes: BTreeMap::new(),
        member_occurrences: BTreeMap::new(),
        invalid: false,
    };
    let mut witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: "e".repeat(64),
        member_request_id_fingerprints: BTreeMap::new(),
        member_occurrence_fingerprints: BTreeMap::new(),
        assigned_request_id_fingerprints: BTreeMap::new(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    for (sequence, subagent) in subagents.iter().enumerate() {
        carry_file(index, root, *subagent);
        let member = carry_member(root, *subagent);
        let hash = format!("{root}-{sequence}").replace('-', "0");
        let hashes = BTreeSet::from([hash.clone()]);
        let occurrences = BTreeMap::from([(hash, carry_occurrence(sequence as u64, 10))]);
        witness
            .member_request_id_fingerprints
            .insert(member.clone(), claude_request_id_set_fingerprint(&hashes));
        witness.member_occurrence_fingerprints.insert(
            member.clone(),
            claude_occurrence_map_fingerprint(&occurrences),
        );
        pending
            .member_request_id_hashes
            .insert(member.clone(), hashes);
        pending.member_occurrences.insert(member, occurrences);
    }
    index
        .claude_usage_family_pending
        .insert(root.to_string(), pending);
    if witnessed {
        index
            .claude_usage_family_witnesses
            .insert(root.to_string(), witness);
    }
}

/// The traversal that started at `at` ended red, and its retry is due one
/// minute later.
fn carry_red(index: &mut ScanIndex, at: &str, attempt: u8) {
    let traversal = index.traversal.as_mut().expect("the failed traversal");
    traversal.pending_directories.clear();
    traversal.pending_candidates.clear();
    traversal.counts.malformed_json_line_count = 1;
    traversal.unhealthy_retry_attempt = attempt;
    traversal.unhealthy_retry_not_before_unix_seconds =
        rfc3339_unix_seconds(at).map(|seconds| seconds + 60);
}

/// The failed window: a closed fence, an unrelated committed file, the
/// witnessed family (root plus one subagent) and the unwitnessed family.
fn carry_index() -> ScanIndex {
    let mut index = ScanIndex {
        claude_request_identity_contract: Some(
            crate::snapshots::claude_request_identity::COLLECTOR.to_string(),
        ),
        claude_duplicate_request_witness_overflowed: true,
        ..ScanIndex::default()
    };
    carry_file(&mut index, CARRY_OTHER, None);
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        CARRY_FAILED,
        BACKFILL_WINDOW_DAYS,
    );
    carry_family(&mut index, CARRY_ROOT, &[None, Some(CARRY_AGENT)], true);
    carry_family(&mut index, CARRY_UNWITNESSED, &[None], false);
    carry_red(&mut index, CARRY_FAILED, 1);
    index
}

/// The `starting` row's counts, without the process-lifetime totals that
/// concurrent tests may move.
fn carry_start(index: &mut ScanIndex, at: &str, days: u64) -> serde_json::Value {
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        ensure_bounded_traversal(SnapshotSource::ClaudeCode, &[], index, at, days)
    });
    let mut counts = rows
        .into_iter()
        .find(|row| row["counts"]["event"] == "starting")
        .map(|row| row["counts"].clone())
        .expect("the traversal start emits one starting row");
    counts
        .as_object_mut()
        .unwrap()
        .remove("disappearance_process_totals_v1");
    counts
}

fn carry_family_keys() -> [String; 2] {
    [
        carry_key(CARRY_ROOT, None),
        carry_key(CARRY_ROOT, Some(CARRY_AGENT)),
    ]
}

fn carry_family_members() -> BTreeSet<String> {
    BTreeSet::from([
        carry_member(CARRY_ROOT, None),
        carry_member(CARRY_ROOT, Some(CARRY_AGENT)),
    ])
}

/// Runs one retry start in a fix arm and a BASE arm from the same mutated
/// failed window.
fn carry_arms(
    mutate: &dyn Fn(&mut ScanIndex),
    days: u64,
) -> (
    (ScanIndex, serde_json::Value),
    (ScanIndex, serde_json::Value),
) {
    let mut fix = carry_index();
    mutate(&mut fix);
    let fix_row = carry_start(&mut fix, CARRY_RETRY, days);
    let mut base = carry_index();
    mutate(&mut base);
    let base_row = {
        let _base = KeepStaleClaudeFamilyRearmForTest::new();
        carry_start(&mut base, CARRY_RETRY, days)
    };
    ((fix, fix_row), (base, base_row))
}

/// T1, positive: a same-context red retry with the fence already closed keeps
/// the witnessed family's committed revisions, compacts its old-window
/// pending to member keys only, and re-arms the unwitnessed family exactly as
/// BASE does. The row stays count-only.
#[test]
fn c1b_unchanged_witnessed_family_is_carried_and_compacted_at_red_retry() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let ((fix, row), (base, base_row)) = carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS);
    let before = carry_index();
    for arm_row in [&row, &base_row] {
        assert_eq!(arm_row["reason"], "terminal_unhealthy_retry");
        assert_eq!(arm_row["stale_pending_families"], 2);
    }
    // Preconditions on BASE: both stale families re-arm whole.
    assert_eq!(base_row["rearmed_index_files"], 3);
    for key in carry_family_keys() {
        assert!(base.files[&key].source_file_fingerprint.is_empty());
    }
    // FLIPS: the witnessed family is carried, not re-armed.
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 2);
    assert_eq!(
        row["rearmed_index_files"], 1,
        "only the unwitnessed family re-arms"
    );
    for key in carry_family_keys() {
        assert_eq!(
            fix.files[&key].source_file_fingerprint,
            before.files[&key].source_file_fingerprint
        );
    }
    let unwitnessed = carry_key(CARRY_UNWITNESSED, None);
    assert!(fix.files[&unwitnessed].source_file_fingerprint.is_empty());
    assert_eq!(
        fix.claude_usage_family_pending[CARRY_UNWITNESSED],
        before.claude_usage_family_pending[CARRY_UNWITNESSED]
    );
    let pending = &fix.claude_usage_family_pending[CARRY_ROOT];
    assert_eq!(pending.census_window_end, CARRY_FAILED, "the old window");
    assert!(!pending.invalid);
    assert!(pending.member_occurrences.is_empty());
    assert_eq!(
        pending
            .member_request_id_hashes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        carry_family_members()
    );
    assert!(pending
        .member_request_id_hashes
        .values()
        .all(BTreeSet::is_empty));
    assert_eq!(
        fix.claude_usage_family_witnesses,
        before.claude_usage_family_witnesses
    );
    let other = carry_key(CARRY_OTHER, None);
    assert_eq!(
        fix.files[&other].source_file_fingerprint,
        before.files[&other].source_file_fingerprint
    );
    let serialized = row.to_string();
    for forbidden in [CARRY_ROOT, CARRY_AGENT, "rev-", "body-", "/carry/"] {
        assert!(!serialized.contains(forbidden), "{forbidden}");
    }
}

/// T2, red chain: the compacted entry is carried again at the next red retry
/// (the tripwire is vacuous on it) with no re-arm of its family.
#[test]
fn c1b_compacted_family_is_carried_again_across_a_red_chain() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = carry_index();
    carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    // The retry re-read the unwitnessed family and ended red again.
    let unwitnessed = carry_key(CARRY_UNWITNESSED, None);
    index
        .files
        .get_mut(&unwitnessed)
        .unwrap()
        .source_file_fingerprint = "rev-reread".to_string();
    index
        .claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .census_window_end = CARRY_RETRY.to_string();
    carry_red(&mut index, CARRY_RETRY, 2);
    let compacted = index.claude_usage_family_pending[CARRY_ROOT].clone();
    let before = index.clone();
    let row = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["reason"], "terminal_unhealthy_retry");
    assert_eq!(row["stale_pending_families"], 2);
    // FLIPS: BASE re-arms the family at the first retry already.
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 2);
    assert_eq!(row["rearmed_index_files"], 1);
    for key in carry_family_keys() {
        assert_eq!(
            index.files[&key].source_file_fingerprint,
            before.files[&key].source_file_fingerprint
        );
        assert!(!index.files[&key].source_file_fingerprint.is_empty());
    }
    assert_eq!(index.claude_usage_family_pending[CARRY_ROOT], compacted);
}

/// T3, cap budget: compacted carried entries hold no occurrences, so the
/// shared pending budget counts only the re-armed family's.
#[test]
fn c1b_compaction_releases_the_pending_occurrence_budget() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let ((mut fix, _), (mut base, _)) = carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS);
    let budget = |index: &mut ScanIndex| {
        accumulate_claude_usage_family_pending_with_limit(
            &[],
            &mut index.claude_usage_family_pending,
            CARRY_RETRY,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        )
        .pending_occurrence_count
    };
    assert_eq!(budget(&mut base), 3, "BASE keeps every stale occurrence");
    // FLIPS: BASE keeps the witnessed family's two occurrences.
    assert_eq!(budget(&mut fix), 1);
}

/// Q3 residual: every indexed member is stale, so today's re-arm reaches all
/// of them; a full retry could reopen the fence only if every stale family is
/// valid. With the unwitnessed family invalid, the witnessed one is carried.
#[test]
fn c1b_invalid_stale_family_cannot_reopen_so_the_witnessed_family_is_carried() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mutate = |index: &mut ScanIndex| {
        index.files.remove(&carry_key(CARRY_OTHER, None));
        let pending = index
            .claude_usage_family_pending
            .get_mut(CARRY_UNWITNESSED)
            .unwrap();
        pending.member_request_id_hashes.clear();
        pending.member_occurrences.clear();
        pending.invalid = true;
    };
    let ((fix, row), (_, base_row)) = carry_arms(&mutate, BACKFILL_WINDOW_DAYS);
    assert_eq!(base_row["rearmed_index_files"], 3);
    // FLIPS: BASE re-arms every member.
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["rearmed_index_files"], 1);
    for key in carry_family_keys() {
        assert!(!fix.files[&key].source_file_fingerprint.is_empty());
    }
}

/// A negative control: the mutated failed window re-arms exactly as BASE,
/// byte for byte, row included.
struct CarryControl {
    name: &'static str,
    days: u64,
    mutate: Box<dyn Fn(&mut ScanIndex)>,
}

fn carry_control(name: &'static str, mutate: impl Fn(&mut ScanIndex) + 'static) -> CarryControl {
    CarryControl {
        name,
        days: BACKFILL_WINDOW_DAYS,
        mutate: Box::new(mutate),
    }
}

fn carry_unbound_quarantine(index: &mut ScanIndex, proof_correction: bool) {
    let member = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
    index.claude_usage_authority_quarantine.insert(
        CARRY_ROOT.to_string(),
        ClaudeUsageAuthorityQuarantineRecord {
            proof_correction: proof_correction.then(|| ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: "f".repeat(64),
                owed_member_ids: BTreeSet::from([member.clone()]),
            }),
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            // Bound to no retained witness, so the family stays stale.
            proven_witness_fingerprint: "0".repeat(64),
            member_source_file_fingerprints: BTreeMap::from([(member, "rev".to_string())]),
            failed_reconstruction_count: 1,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
            retry_after_unix_seconds: u64::MAX,
        },
    );
}

fn carry_controls() -> Vec<CarryControl> {
    let agent_key = carry_key(CARRY_ROOT, Some(CARRY_AGENT));
    let agent = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
    let mut controls = vec![
        carry_control("fence_open", |index| {
            index.claude_duplicate_request_witness_overflowed = false;
        }),
        carry_control("no_retained_traversal", |index| index.traversal = None),
        carry_control("prior_unsettled_upload", |index| {
            index.bounded_sweep_had_unsettled_upload = true;
        }),
        carry_control("identity_contract_latched", |index| {
            index.claude_request_identity_contract_changed = true;
        }),
        carry_control("identity_contract_unknown", |index| {
            index.claude_request_identity_contract = None;
        }),
        carry_control("accepted_ledger_old_version", |index| {
            index.accepted_snapshot_fingerprint_ledger_version = 1;
        }),
        carry_control("accepted_ledger_rebuilding", |index| {
            index.legacy_settlement_reconcile_after_fingerprint = Some("rebuild".to_string());
        }),
        carry_control("upload_context_not_active", |index| {
            index.upload_context_fingerprint = Some("older-context".to_string());
        }),
        carry_control("full_retry_could_reopen", |index| {
            index.files.remove(&carry_key(CARRY_OTHER, None));
        }),
        carry_control("no_witness", |index| {
            index.claude_usage_family_witnesses.remove(CARRY_ROOT);
        }),
        carry_control("authority_quarantine", |index| {
            carry_unbound_quarantine(index, false);
        }),
        carry_control("authority_correction_debt", |index| {
            carry_unbound_quarantine(index, true);
        }),
        carry_control("invalid_pending", |index| {
            let pending = index
                .claude_usage_family_pending
                .get_mut(CARRY_ROOT)
                .unwrap();
            pending.member_request_id_hashes.clear();
            pending.member_occurrences.clear();
            pending.invalid = true;
        }),
        carry_control("witness_legacy_owner", |index| {
            index
                .claude_usage_family_witnesses
                .get_mut(CARRY_ROOT)
                .unwrap()
                .legacy_owner_roots
                .insert(CARRY_OTHER.to_string());
        }),
        carry_control("witness_legacy_exclusion_evidence", |index| {
            index
                .claude_usage_family_witnesses
                .get_mut(CARRY_ROOT)
                .unwrap()
                .legacy_exclusion_evidence_fingerprint = Some("d".repeat(64));
        }),
        carry_control("old_witness_without_occurrences", |index| {
            index
                .claude_usage_family_witnesses
                .get_mut(CARRY_ROOT)
                .unwrap()
                .member_occurrence_fingerprints
                .clear();
        }),
        carry_control("missing_root_file", |index| {
            index.files.remove(&carry_key(CARRY_ROOT, None));
        }),
    ];
    controls.push(carry_control("another_witness_names_it_legacy_owner", {
        move |index: &mut ScanIndex| {
            let mut other = index.claude_usage_family_witnesses[CARRY_ROOT].clone();
            other.legacy_owner_roots.insert(CARRY_ROOT.to_string());
            index
                .claude_usage_family_witnesses
                .insert(CARRY_OTHER.to_string(), other);
        }
    }));
    controls.push(carry_control("shares_a_legacy_excluded_prefix", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            let hashes = index.claude_usage_family_pending[CARRY_ROOT].member_request_id_hashes
                [&agent]
                .clone();
            let mut other = index.claude_usage_family_witnesses[CARRY_ROOT].clone();
            other
                .legacy_excluded_request_id_hashes
                .insert(CARRY_OTHER.to_string(), hashes);
            index
                .claude_usage_family_witnesses
                .insert(CARRY_OTHER.to_string(), other);
        }
    }));
    controls.push(carry_control("duplicate_request_owner", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            let hash = index.claude_usage_family_pending[CARRY_ROOT].member_request_id_hashes
                [&agent]
                .first()
                .unwrap()
                .clone();
            index
                .claude_duplicate_request_owners
                .insert(hash, BTreeSet::new());
        }
    }));
    // An unproven fork read in the failed window copied the root's first
    // request: its legacy exclusion needs the root's sequence in its window.
    controls.push(carry_control("unproven_fork_copies_a_request", |index| {
        let root = carry_member(CARRY_ROOT, None);
        let hash = index.claude_usage_family_pending[CARRY_ROOT].member_request_id_hashes[&root]
            .first()
            .unwrap()
            .clone();
        let fork = index
            .claude_usage_family_pending
            .get_mut(CARRY_UNWITNESSED)
            .unwrap();
        fork.member_request_id_hashes
            .get_mut(CARRY_UNWITNESSED)
            .unwrap()
            .insert(hash.clone());
        fork.member_occurrences
            .get_mut(CARRY_UNWITNESSED)
            .unwrap()
            .insert(hash, carry_occurrence(0, 10));
    }));
    controls.push(carry_control("owned_start_census", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            index.claude_owned_start_census.insert(
                agent.clone(),
                ClaudeOwnedStartCensusWitness {
                    marker_source_file_fingerprint: "rev".to_string(),
                    verified_source_file_fingerprint: None,
                    emitted_source_file_fingerprint: None,
                },
            );
        }
    }));
    controls.push(carry_control("empty_fingerprint_member", {
        let agent_key = agent_key.clone();
        move |index: &mut ScanIndex| {
            index
                .files
                .get_mut(&agent_key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
    }));
    controls.push(carry_control("unaccepted_entity", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            index
                .accepted_snapshot_fingerprints
                .remove(&format!("body-{agent}"));
        }
    }));
    controls.push(carry_control("no_committed_snapshot", {
        let agent_key = agent_key.clone();
        move |index: &mut ScanIndex| {
            index
                .files
                .get_mut(&agent_key)
                .unwrap()
                .last_snapshot_fingerprint = None;
        }
    }));
    controls.push(carry_control("account_deferred_hold", {
        let agent_key = agent_key.clone();
        move |index: &mut ScanIndex| {
            index
                .claude_account_deferred_holds
                .insert(agent_key.clone(), "rev".to_string());
        }
    }));
    controls.push(carry_control("tripwire_request_hash", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            let pending = index
                .claude_usage_family_pending
                .get_mut(CARRY_ROOT)
                .unwrap();
            let occurrence = carry_occurrence(1, 10);
            pending
                .member_request_id_hashes
                .insert(agent.clone(), BTreeSet::from(["9".repeat(64)]));
            pending.member_occurrences.insert(
                agent.clone(),
                BTreeMap::from([("9".repeat(64), occurrence)]),
            );
        }
    }));
    controls.push(carry_control("tripwire_occurrence", {
        let agent = agent.clone();
        move |index: &mut ScanIndex| {
            let pending = index
                .claude_usage_family_pending
                .get_mut(CARRY_ROOT)
                .unwrap();
            for occurrence in pending
                .member_occurrences
                .get_mut(&agent)
                .unwrap()
                .values_mut()
            {
                occurrence.output_tokens += 1;
            }
        }
    }));
    controls.push(carry_control(
        "pending_member_outside_membership",
        |index| {
            let pending = index
                .claude_usage_family_pending
                .get_mut(CARRY_ROOT)
                .unwrap();
            pending
                .member_request_id_hashes
                .insert(format!("{CARRY_ROOT}_agent-gone"), BTreeSet::new());
        },
    ));
    controls.push(carry_control("new_child_outside_witness", |index| {
        carry_file(index, CARRY_ROOT, Some("agent-b7c2696e421181e1a"));
    }));
    controls.push(carry_control("twin_member_key", {
        let agent_key = agent_key.clone();
        move |index: &mut ScanIndex| {
            let entry = index.files[&agent_key].clone();
            index.files.insert(
                agent_key.replace("/carry/projects/", "/carry/other-project/"),
                entry,
            );
        }
    }));
    controls.push(CarryControl {
        name: "context_changed",
        days: BACKFILL_WINDOW_DAYS + 1,
        mutate: Box::new(|_| {}),
    });
    controls
}

/// Negative controls: each one re-arms the witnessed family whole and leaves
/// the index and the row identical to BASE.
#[test]
fn c1b_negative_controls_rearm_exactly_like_base() {
    for control in carry_controls() {
        let ((fix, row), (base, base_row)) = carry_arms(&*control.mutate, control.days);
        assert_eq!(row, base_row, "{}: the row is BASE's", control.name);
        assert_eq!(
            serde_json::to_value(&fix).unwrap(),
            serde_json::to_value(&base).unwrap(),
            "{}: the index is BASE's",
            control.name
        );
        for key in carry_family_keys() {
            if let Some(entry) = fix.files.get(&key) {
                assert!(
                    entry.source_file_fingerprint.is_empty(),
                    "{}: {key} re-arms",
                    control.name
                );
            }
        }
        assert!(
            !fix.bounded_sweep_had_unsettled_upload,
            "{}: the start still resets the marker",
            control.name
        );
    }
}

/// F1, refused admission: the carry check prices its scratch before it
/// allocates any. A refused price, here forced, keeps the BASE start byte for
/// byte, row and transition counters included, and is counted once.
#[test]
fn c1b_refused_carry_scratch_admission_keeps_the_base_start() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let refusals = claude_stale_family_carry_budget_fallbacks_for_test();
    let ((fix, row), (base, base_row)) = {
        let _refuse = RefuseClaudeStaleFamilyCarryBudgetForTest::new();
        carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS)
    };
    assert_eq!(
        claude_stale_family_carry_budget_fallbacks_for_test(),
        refusals + 1,
        "the fix arm's refusal is counted; BASE never prices"
    );
    assert_eq!(row, base_row, "the row is BASE's");
    assert_eq!(row["carried_pending_families"], 0);
    assert_eq!(row["carried_index_files"], 0);
    assert_eq!(row["rearmed_index_files"], 3);
    assert_eq!(
        serde_json::to_value(&fix).unwrap(),
        serde_json::to_value(&base).unwrap(),
        "the index is BASE's"
    );
}

/// F1, priced refusal: the request-owner map alone prices at (N + 1) * 704
/// bytes on the supported layout, so a stale window holding 12,000 pending
/// request hashes is refused under the 8 MiB parked budget (8,448,704 bytes
/// before any other collection) while 1,000 is admitted. The refused start is
/// BASE's; the admitted one carries the witnessed family.
#[test]
fn c1b_carry_scratch_price_refuses_a_large_stale_window() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    assert_eq!(
        crate::heap_layout_bound::tree_node_bytes::<&str, &str>(),
        Some(704)
    );
    let unwitnessed_hashes = |count: usize| {
        move |index: &mut ScanIndex| {
            let pending = index
                .claude_usage_family_pending
                .get_mut(CARRY_UNWITNESSED)
                .unwrap();
            pending.member_occurrences.clear();
            pending.member_request_id_hashes.insert(
                carry_member(CARRY_UNWITNESSED, None),
                (0..count).map(|n| format!("{n:064x}")).collect(),
            );
        }
    };
    let refusals = claude_stale_family_carry_budget_fallbacks_for_test();
    let ((_, admitted_row), _) = carry_arms(&unwitnessed_hashes(1_000), BACKFILL_WINDOW_DAYS);
    assert_eq!(admitted_row["carried_pending_families"], 1, "admitted");
    assert_eq!(
        claude_stale_family_carry_budget_fallbacks_for_test(),
        refusals
    );
    let ((fix, row), (base, base_row)) =
        carry_arms(&unwitnessed_hashes(12_000), BACKFILL_WINDOW_DAYS);
    assert_eq!(
        claude_stale_family_carry_budget_fallbacks_for_test(),
        refusals + 1
    );
    assert_eq!(row, base_row, "the refused start is BASE's");
    assert_eq!(row["carried_pending_families"], 0);
    assert_eq!(
        serde_json::to_value(&fix).unwrap(),
        serde_json::to_value(&base).unwrap()
    );
}

/// F1, admitted: the fixture's carry scratch prices far under the parked
/// budget, so nothing is refused and the witnessed family is carried.
#[test]
fn c1b_admitted_carry_scratch_carries_the_witnessed_family() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let index = carry_index();
    let stale = index
        .claude_usage_family_pending
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(claude_stale_family_carry_scratch_admitted(
        &index, &stale, 0
    ));
    let refusals = claude_stale_family_carry_budget_fallbacks_for_test();
    let ((fix, row), _) = carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS);
    assert_eq!(
        claude_stale_family_carry_budget_fallbacks_for_test(),
        refusals
    );
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 2);
    for key in carry_family_keys() {
        assert!(!fix.files[&key].source_file_fingerprint.is_empty());
    }
}

/// F1, layout: the carry check is admitted exactly on the supported layout.
/// Elsewhere it refuses, so every red retry start is BASE's.
#[test]
fn c1b_carry_scratch_admission_follows_the_supported_layout() {
    let index = carry_index();
    let stale = index
        .claude_usage_family_pending
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claude_stale_family_carry_scratch_admitted(&index, &stale, 0),
        crate::heap_layout_bound::layout_supported()
    );
    if !crate::heap_layout_bound::layout_supported() {
        let ((fix, row), (base, base_row)) = carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS);
        assert_eq!(row, base_row);
        assert_eq!(
            serde_json::to_value(&fix).unwrap(),
            serde_json::to_value(&base).unwrap()
        );
    }
}

const CARRY_SCAN_ROOT: &str = "/carry/projects";

/// A carried retry start, then a later page of that window on which the
/// carried family's root file is about to be parsed: its subagent member was
/// already passed (observed under the scan root, not pending) and `queued`
/// unrelated candidates, at least one, are still pending, so the walk has not
/// ended. The queue is filled to its capacity, so queueing the passed member
/// there would grow it.
fn carry_cancel_index(queued: usize) -> ScanIndex {
    let mut index = carry_index();
    carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    let traversal = index.traversal.as_mut().expect("the retry traversal");
    assert_eq!(traversal.census_window_end, CARRY_RETRY);
    traversal.scan_roots = vec![PathBuf::from(CARRY_SCAN_ROOT)];
    traversal.observed_index_keys.extend(carry_family_keys());
    traversal.pending_candidates = VecDeque::with_capacity(queued.max(1));
    carry_fill_queue(&mut index);
    index
}

/// Fill the candidate queue to its capacity with unrelated candidates.
fn carry_fill_queue(index: &mut ScanIndex) {
    let pending = &mut index.traversal.as_mut().unwrap().pending_candidates;
    while pending.is_empty() || pending.len() < pending.capacity() {
        pending.push_back(ScanTraversalPath {
            scan_root: PathBuf::new(),
            path: PathBuf::new(),
            census_member: true,
            watcher_hint: false,
        });
    }
}

fn carry_cancel(index: &mut ScanIndex) {
    let [root_key, _] = carry_family_keys();
    cancel_claude_family_carry_for_member_parse(
        index,
        CARRY_RETRY,
        Path::new(&root_key),
        &[],
        &VecDeque::new(),
    );
}

/// N1: a member-only list line excludes the whole carried family, so the
/// root's adoption never reaches the C1b cancel and the listed member keeps
/// its revision.
#[test]
fn c1b_member_only_reemission_line_excludes_the_carried_family_root() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = carry_cancel_index(1);
    let support = temp_dir("member-only-reemission");
    let path = ReemissionExclusions::path(&support);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let agent = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
    fs::write(&path, format!("{:x}\n", Sha256::digest(agent.as_bytes()))).unwrap();
    index.load_claude_reemission_exclusions(&support);
    let [root_key, agent_key] = carry_family_keys();
    let before = index.files[&agent_key].source_file_fingerprint.clone();
    // The root is excluded although only the member is listed.
    assert!(index
        .claude_reemission_exclusions
        .excludes(CARRY_ROOT, None));
    // Unrelated families stay unlisted.
    assert!(!index
        .claude_reemission_exclusions
        .excludes(CARRY_OTHER, None));
    // The carry is intact and the member is not re-armed.
    assert!(index.claude_stale_family_carry.roots.contains(CARRY_ROOT));
    assert_eq!(index.files[&agent_key].source_file_fingerprint, before);
    let _ = (root_key, fs::remove_dir_all(support));
}

/// R1, admitted: a parse of a carried family's member on a non-terminal page
/// clears the other member's revision and queues it, once, into the replay
/// buffer the carry funded, never into the candidate queue. The parsed member
/// keeps its revision for the caller; nothing is refused or held.
#[test]
fn c1b_admitted_carry_cancellation_rearms_and_queues_the_passed_member() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = carry_cancel_index(1);
    let before = index.clone();
    let queued = before.traversal.as_ref().unwrap().pending_candidates.len();
    let cancellations = claude_stale_family_carry_cancellations_for_test();
    let refusals = claude_stale_family_carry_cancellation_refusals_for_test();
    let holds = claude_stale_family_carry_terminal_holds_for_test();
    carry_cancel(&mut index);
    assert_eq!(
        claude_stale_family_carry_cancellations_for_test(),
        cancellations + 1
    );
    assert_eq!(
        claude_stale_family_carry_cancellation_refusals_for_test(),
        refusals
    );
    assert_eq!(claude_stale_family_carry_terminal_holds_for_test(), holds);
    let [root_key, agent_key] = carry_family_keys();
    assert_eq!(
        index.files[&root_key].source_file_fingerprint,
        before.files[&root_key].source_file_fingerprint
    );
    assert!(!before.files[&agent_key].source_file_fingerprint.is_empty());
    assert!(index.files[&agent_key].source_file_fingerprint.is_empty());
    for key in [
        carry_key(CARRY_OTHER, None),
        carry_key(CARRY_UNWITNESSED, None),
    ] {
        assert_eq!(
            index.files[&key].source_file_fingerprint,
            before.files[&key].source_file_fingerprint
        );
    }
    assert_eq!(
        index.traversal.as_ref().unwrap().pending_candidates.len(),
        queued
    );
    assert_eq!(
        index.claude_stale_family_carry.replay,
        vec![carry_replayed(&agent_key)]
    );
    // The family is no longer carried, so a second parse cancels nothing.
    carry_cancel(&mut index);
    assert_eq!(
        claude_stale_family_carry_cancellations_for_test(),
        cancellations + 1
    );
    assert_eq!(index.claude_stale_family_carry.replay.len(), 1);
}

/// The replay entry a cancel queues for a passed member.
fn carry_replayed(key: &str) -> ScanTraversalPath {
    ScanTraversalPath {
        scan_root: PathBuf::from(CARRY_SCAN_ROOT),
        path: PathBuf::from(key),
        census_member: true,
        watcher_hint: false,
    }
}

/// R1, price boundary: queueing grows the candidate queue only beyond its
/// spare capacity, charged as the old and the new buffer at once, and the
/// queued paths are charged at their byte lengths, all under the 8 MiB parked
/// budget. Each boundary is admitted at the budget and refused one byte or
/// one slot past it; an overflow is refused.
#[test]
fn c1b_carry_cancellation_price_admits_up_to_the_parked_budget() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let budget = crate::source_rotation::PARKED_BUDGET;
    let slot = std::mem::size_of::<ScanTraversalPath>();
    assert!(claude_family_carry_cancellation_admitted(0, 0, 0, 0));
    assert!(claude_family_carry_cancellation_admitted(
        0,
        0,
        1,
        budget - slot
    ));
    assert!(!claude_family_carry_cancellation_admitted(
        0,
        0,
        1,
        budget - slot + 1
    ));
    // Spare capacity is free; a full queue charges both buffers.
    assert!(claude_family_carry_cancellation_admitted(3, 4, 1, budget));
    assert!(!claude_family_carry_cancellation_admitted(4, 4, 1, budget));
    let full = (budget / slot - 1) / 2;
    assert!(claude_family_carry_cancellation_admitted(full, full, 1, 0));
    assert!(!claude_family_carry_cancellation_admitted(
        full + 1,
        full + 1,
        1,
        0
    ));
    assert!(!claude_family_carry_cancellation_admitted(
        usize::MAX,
        0,
        1,
        0
    ));
    assert!(!claude_family_carry_cancellation_admitted(
        0,
        0,
        0,
        usize::MAX
    ));
}

const CARRY_RESUME: &str = "2026-08-02T07:25:00Z";

/// A page of the retry window resuming its traversal after a save and load.
fn carry_reload(index: ScanIndex) -> ScanIndex {
    serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap()
}

fn carry_resume(index: &mut ScanIndex) {
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        index,
        CARRY_RESUME,
        BACKFILL_WINDOW_DAYS,
    );
}

/// A carried family's cancel behind a full candidate backlog: the passed
/// member goes only into the replay buffer the carry funded. Neither the
/// candidate queue nor that buffer is reallocated, and nothing is refused or
/// held.
fn carry_assert_cancel_uses_only_the_funded_buffer(index: &mut ScanIndex) {
    let [root_key, agent_key] = carry_family_keys();
    let traversal = index.traversal.as_ref().unwrap();
    assert_eq!(traversal.census_window_end, CARRY_RETRY);
    let queue = &traversal.pending_candidates;
    let (queued, queue_capacity) = (queue.len(), queue.capacity());
    assert_eq!(queued, queue_capacity, "the queue is full");
    let carry = &index.claude_stale_family_carry;
    assert_eq!(carry.roots, BTreeSet::from([CARRY_ROOT.to_string()]));
    assert!(carry.replay.is_empty());
    let replay_capacity = carry.replay.capacity();
    assert!(replay_capacity >= 2, "both members' replay is reserved");
    let before = index.clone();
    let cancellations = claude_stale_family_carry_cancellations_for_test();
    let refusals = claude_stale_family_carry_cancellation_refusals_for_test();
    let holds = claude_stale_family_carry_terminal_holds_for_test();
    carry_cancel(index);
    assert_eq!(
        claude_stale_family_carry_cancellations_for_test(),
        cancellations + 1
    );
    assert_eq!(
        claude_stale_family_carry_cancellation_refusals_for_test(),
        refusals
    );
    assert_eq!(claude_stale_family_carry_terminal_holds_for_test(), holds);
    assert_eq!(
        index.files[&root_key].source_file_fingerprint,
        before.files[&root_key].source_file_fingerprint
    );
    assert!(index.files[&agent_key].source_file_fingerprint.is_empty());
    let queue = &index.traversal.as_ref().unwrap().pending_candidates;
    assert_eq!(
        (queue.len(), queue.capacity()),
        (queued, queue_capacity),
        "the candidate queue is untouched"
    );
    assert!(queue
        .iter()
        .eq(before.traversal.as_ref().unwrap().pending_candidates.iter()));
    let carry = &index.claude_stale_family_carry;
    assert_eq!(carry.replay, vec![carry_replayed(&agent_key)]);
    assert_eq!(
        carry.replay.capacity(),
        replay_capacity,
        "the funded buffer did not grow"
    );
    assert!(carry.roots.is_empty(), "the family left the carry");
}

/// R1, funded buffer: behind a full candidate backlog whose growth alone
/// would exceed the parked budget, a parse of a carried family's member on a
/// non-terminal page cancels the carry from the buffer the start funded.
#[test]
fn c1b_carry_cancellation_behind_a_large_backlog_uses_only_the_funded_buffer() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let slot = std::mem::size_of::<ScanTraversalPath>();
    let mut index = carry_cancel_index(crate::source_rotation::PARKED_BUDGET / slot / 2 + 1);
    carry_assert_cancel_uses_only_the_funded_buffer(&mut index);
}

/// R1, after a reload: a saved and loaded buffer keeps no spare capacity, so
/// the page that resumes the traversal reserves it again before it selects
/// anything, and the same cancel behind the same backlog still uses only
/// that buffer.
#[test]
fn c1b_carry_cancellation_after_a_reload_uses_only_the_refunded_buffer() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let slot = std::mem::size_of::<ScanTraversalPath>();
    let mut index = carry_reload(carry_cancel_index(
        crate::source_rotation::PARKED_BUDGET / slot / 2 + 1,
    ));
    assert_eq!(index.claude_stale_family_carry.replay.capacity(), 0);
    carry_fill_queue(&mut index);
    let uncarries = claude_stale_family_carry_refund_uncarries_for_test();
    carry_resume(&mut index);
    assert_eq!(
        claude_stale_family_carry_refund_uncarries_for_test(),
        uncarries
    );
    carry_assert_cancel_uses_only_the_funded_buffer(&mut index);
}

const CARRY_SECOND_WITNESSED: &str = "d4444444-4444-4444-8444-444444444444";

/// A carried family's funded worst case: every indexed member queued again,
/// two buffer slots each (a reload re-reserves the buffer beside its loaded
/// copy) plus a scan root and a member path no longer than its key.
fn carry_worst_case(keys: &[String]) -> usize {
    keys.iter()
        .map(|key| 2 * std::mem::size_of::<ScanTraversalPath>() + 2 * key.len())
        .sum()
}

/// R1, carry-time funding boundary: with a second witnessed family, each
/// carried family's worst-case cancellation is funded cumulatively in root
/// order. At exactly both worst cases both are carried; one byte less drops
/// the later family; a budget that fits only the smaller, later family drops
/// the earlier one and still carries it. Every dropped family is counted once
/// and re-armed as BASE re-arms it.
#[test]
fn c1b_carry_funds_each_family_cancellation_up_to_the_budget() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let first = carry_worst_case(&carry_family_keys());
    let second_key = carry_key(CARRY_SECOND_WITNESSED, None);
    let second = carry_worst_case(std::slice::from_ref(&second_key));
    assert!(second < first);
    let with_second = |index: &mut ScanIndex| {
        carry_family(index, CARRY_SECOND_WITNESSED, &[None], true);
    };
    let start = |budget: usize| {
        let unfunded = claude_stale_family_carry_unfunded_families_for_test();
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(budget);
        let ((fix, row), _) = carry_arms(&with_second, BACKFILL_WINDOW_DAYS);
        let dropped = claude_stale_family_carry_unfunded_families_for_test() - unfunded;
        let carried = |key: &String| !fix.files[key].source_file_fingerprint.is_empty();
        let first_carried = carry_family_keys().iter().all(carried);
        assert!(first_carried || !carry_family_keys().iter().any(carried));
        (row, dropped, first_carried, carried(&second_key))
    };
    let (row, dropped, first_carried, second_carried) = start(first + second);
    assert_eq!(row["carried_pending_families"], 2);
    assert_eq!((dropped, first_carried, second_carried), (0, true, true));
    let (row, dropped, first_carried, second_carried) = start(first + second - 1);
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 2);
    assert_eq!((dropped, first_carried, second_carried), (1, true, false));
    let (row, dropped, first_carried, second_carried) = start(second);
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 1);
    assert_eq!((dropped, first_carried, second_carried), (1, false, true));
}

/// R1, carry-time refusal: when no carried family's worst-case cancellation
/// is funded, none is carried and the start is BASE's byte for byte, row and
/// transition counters included, with each dropped family counted once.
#[test]
fn c1b_unfunded_carry_keeps_the_base_start() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let first = carry_worst_case(&carry_family_keys());
    let unfunded = claude_stale_family_carry_unfunded_families_for_test();
    let ((fix, row), (base, base_row)) = {
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(first - 1);
        carry_arms(&|_| {}, BACKFILL_WINDOW_DAYS)
    };
    assert_eq!(
        claude_stale_family_carry_unfunded_families_for_test(),
        unfunded + 1,
        "the fix arm's dropped family is counted; BASE never funds"
    );
    assert_eq!(row, base_row, "the row is BASE's");
    assert_eq!(row["carried_pending_families"], 0);
    assert_eq!(row["rearmed_index_files"], 3);
    assert_eq!(
        serde_json::to_value(&fix).unwrap(),
        serde_json::to_value(&base).unwrap(),
        "the index is BASE's"
    );
}

/// The retry start in a fix or a BASE arm, resumed by a later page after a
/// save and load. The walk has queued an unrelated candidate and, unless
/// `passed`, has not reached the carried family yet.
fn carry_resumed_index(base: bool, passed: bool) -> ScanIndex {
    let mut index = carry_index();
    {
        let _base = base.then(KeepStaleClaudeFamilyRearmForTest::new);
        carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    }
    let traversal = index.traversal.as_mut().expect("the retry traversal");
    traversal.scan_roots = vec![PathBuf::from(CARRY_SCAN_ROOT)];
    if passed {
        traversal.observed_index_keys.extend(carry_family_keys());
    }
    traversal.pending_candidates.push_back(ScanTraversalPath {
        scan_root: PathBuf::new(),
        path: PathBuf::new(),
        census_member: true,
        watcher_hint: false,
    });
    carry_reload(index)
}

/// R1, re-funding refused at a reload before the walk passed any member: the
/// family is uncarried in place, every member's revision cleared, and the
/// index equals a real BASE arm resumed the same way, apart from the carried
/// pending the start compacted, which credits no evidence and which this
/// window's reads replace. Counted once.
#[test]
fn c1b_unfunded_replay_at_a_reload_uncarries_to_the_base_start() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let uncarries = claude_stale_family_carry_refund_uncarries_for_test();
    let mut fix = carry_resumed_index(false, false);
    assert_eq!(
        fix.claude_stale_family_carry.roots,
        BTreeSet::from([CARRY_ROOT.to_string()])
    );
    for key in carry_family_keys() {
        assert!(!fix.files[&key].source_file_fingerprint.is_empty());
    }
    {
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
        carry_resume(&mut fix);
    }
    let mut base = carry_resumed_index(true, false);
    carry_resume(&mut base);
    assert_eq!(
        claude_stale_family_carry_refund_uncarries_for_test(),
        uncarries + 1
    );
    assert_eq!(
        fix.traversal.as_ref().unwrap().census_window_end,
        CARRY_RETRY,
        "uncarried in place, before any member is passed"
    );
    assert!(fix.claude_stale_family_carry.is_empty());
    for key in carry_family_keys() {
        assert!(fix.files[&key].source_file_fingerprint.is_empty());
    }
    assert!(fix.claude_usage_family_pending[CARRY_ROOT]
        .member_occurrences
        .is_empty());
    let mut fix_value = serde_json::to_value(&fix).unwrap();
    let mut base_value = serde_json::to_value(&base).unwrap();
    for value in [&mut fix_value, &mut base_value] {
        value["claude_usage_family_pending"]
            .as_object_mut()
            .unwrap()
            .remove(CARRY_ROOT);
    }
    assert_eq!(fix_value, base_value, "the index is BASE's");
}

/// R1, re-funding refused at a reload after the walk passed a carried member:
/// uncarrying in place would leave that member unread in this window, so the
/// traversal starts again with the family re-armed and nothing carried, and
/// the uncarry precedes every pass of the new walk.
#[test]
fn c1b_unfunded_replay_after_a_passed_member_restarts_the_traversal() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let uncarries = claude_stale_family_carry_refund_uncarries_for_test();
    let mut index = carry_resumed_index(false, true);
    {
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
        carry_resume(&mut index);
    }
    assert_eq!(
        claude_stale_family_carry_refund_uncarries_for_test(),
        uncarries + 1
    );
    let traversal = index.traversal.as_ref().expect("a new traversal");
    assert_eq!(traversal.census_window_end, CARRY_RESUME, "a fresh start");
    assert!(traversal.observed_index_keys.is_empty());
    assert!(index.claude_stale_family_carry.is_empty());
    for key in carry_family_keys() {
        assert!(index.files[&key].source_file_fingerprint.is_empty());
    }
}

/// R2, defensive reset: factored out of the cancel, whose debug assertion
/// rules it out. It re-arms every member, the parsed one included, queues the
/// passed member into the funded replay buffer without growing it or the
/// candidate queue, drops the family from the carry and is counted. The
/// family is then no longer carried, so a later parse cancels nothing.
#[test]
fn c1b_defensive_carry_reset_rearms_every_member_and_replays_the_passed_one() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = carry_cancel_index(1);
    let [root_key, agent_key] = carry_family_keys();
    let before = index.clone();
    let queue = &before.traversal.as_ref().unwrap().pending_candidates;
    let (queued, queue_capacity) = (queue.len(), queue.capacity());
    let replay_capacity = index.claude_stale_family_carry.replay.capacity();
    let cancellations = claude_stale_family_carry_cancellations_for_test();
    let refusals = claude_stale_family_carry_cancellation_refusals_for_test();
    claude_family_carry_defensive_reset(&mut index, CARRY_ROOT, &root_key, &VecDeque::new());
    assert_eq!(
        claude_stale_family_carry_cancellation_refusals_for_test(),
        refusals + 1
    );
    for key in carry_family_keys() {
        assert!(
            index.files[&key].source_file_fingerprint.is_empty(),
            "{key} is re-armed"
        );
    }
    for key in [
        carry_key(CARRY_OTHER, None),
        carry_key(CARRY_UNWITNESSED, None),
    ] {
        assert_eq!(
            index.files[&key].source_file_fingerprint,
            before.files[&key].source_file_fingerprint
        );
    }
    let queue = &index.traversal.as_ref().unwrap().pending_candidates;
    assert_eq!((queue.len(), queue.capacity()), (queued, queue_capacity));
    let carry = &index.claude_stale_family_carry;
    assert_eq!(carry.replay, vec![carry_replayed(&agent_key)]);
    assert_eq!(carry.replay.capacity(), replay_capacity);
    assert!(carry.roots.is_empty());
    carry_cancel(&mut index);
    assert_eq!(
        claude_stale_family_carry_cancellations_for_test(),
        cancellations
    );
    assert_eq!(
        claude_stale_family_carry_cancellation_refusals_for_test(),
        refusals + 1
    );
    assert_eq!(index.claude_stale_family_carry.replay.len(), 1);
}

// Fix 2: after a full re-arm terminal, the traversal that re-read every
// family (started at CARRY_FAILED) finished needing a clean follow-up. Its
// follow-up carries the unchanged witnessed family under the C1b family
// checks instead of re-reading it whole again, and re-reads the families it
// cannot carry at most once per fence deadline.

/// The fence deadline the full-rearm window's stale re-arms count against.
const WINDOW_DEADLINE: u64 = 1_785_700_000;

fn window_needs_clean_followup(index: &mut ScanIndex) {
    index.traversal = None;
    index.bounded_sweep_had_unsettled_upload = true;
}

/// A closed fence whose last complete terminal was a full re-arm: the
/// traversal it opened read both families and finished needing a clean
/// follow-up.
fn window_index() -> ScanIndex {
    let mut index = ScanIndex {
        claude_request_identity_contract: Some(
            crate::snapshots::claude_request_identity::COLLECTOR.to_string(),
        ),
        claude_duplicate_request_witness_overflowed: true,
        claude_duplicate_fence_next_full_rearm_unix_seconds: Some(WINDOW_DEADLINE),
        ..ScanIndex::default()
    };
    index.claude_full_rearm_progress.full_rearm_window_next = true;
    index.claude_full_rearm_progress.full_rearm_window = Some(ClaudeFullRearmWindow {
        context_fingerprint: scan_traversal_context_fingerprint(
            SnapshotSource::ClaudeCode,
            &[],
            &index,
            BACKFILL_WINDOW_DAYS,
        ),
        process: claude_full_rearm_process(),
        window_ends: BTreeSet::new(),
        member_digests: BTreeMap::new(),
    });
    carry_file(&mut index, CARRY_OTHER, None);
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        CARRY_FAILED,
        BACKFILL_WINDOW_DAYS,
    );
    carry_family(&mut index, CARRY_ROOT, &[None, Some(CARRY_AGENT)], true);
    carry_family(&mut index, CARRY_UNWITNESSED, &[None], false);
    window_needs_clean_followup(&mut index);
    index
}

fn window_indexed_ids(index: &ScanIndex) -> BTreeSet<String> {
    index
        .files
        .keys()
        .filter_map(|key| claude_index_path_family_member(Path::new(key)))
        .flat_map(|(root, member)| [root, member])
        .collect()
}

/// Carried and capped pending is compacted to member keys: it credits
/// nothing and keeps the next complete census invalid.
fn assert_compacted_and_invalid(index: &ScanIndex, root: &str) {
    let pending = &index.claude_usage_family_pending[root];
    assert!(pending.member_occurrences.is_empty(), "{root}");
    assert!(!pending.member_request_id_hashes.is_empty(), "{root}");
    assert!(pending
        .member_request_id_hashes
        .values()
        .all(BTreeSet::is_empty));
    assert!(claude_stale_pending_keeps_census_invalid(
        index,
        root,
        pending,
        true,
        &window_indexed_ids(index)
    ));
}

/// Positive: the first clean follow-up carries the witnessed family and
/// re-reads the unwitnessed one, where BASE re-reads both; the second
/// follow-up within the same fence deadline re-reads neither. A new deadline
/// allows one more stale re-arm.
#[test]
fn fix2_clean_followup_carries_window_families_and_caps_stale_rearms() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fix = window_index();
    let window = fix
        .claude_full_rearm_progress
        .full_rearm_window
        .clone()
        .expect("the start after a full re-arm opens a window");
    assert_eq!(
        window.window_ends,
        BTreeSet::from([CARRY_FAILED.to_string()])
    );
    assert!(!fix.claude_full_rearm_progress.full_rearm_window_next);
    let before = fix.clone();
    let mut base = window_index();
    let row = carry_start(&mut fix, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    let base_row = {
        let _base = KeepStaleClaudeFamilyRearmForTest::new();
        carry_start(&mut base, CARRY_RETRY, BACKFILL_WINDOW_DAYS)
    };
    for arm_row in [&row, &base_row] {
        assert_eq!(arm_row["prior_unsettled_upload"], true);
        assert_eq!(arm_row["stale_pending_families"], 2);
    }
    // Preconditions on BASE: the clean follow-up re-arms both families.
    assert_eq!(base_row["rearmed_index_files"], 3);
    assert_eq!(base_row["carried_pending_families"], 0);
    // FLIPS: the witnessed family is carried.
    assert_eq!(row["rearm_window_families"], 2);
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["carried_index_files"], 2);
    assert_eq!(row["rearm_window_carried_families"], 1);
    assert_eq!(row["rearmed_index_files"], 1);
    assert_eq!(row["rearm_window_rearmed_files"], 1);
    assert!(row.get("stale_rearm_capped_families").is_none());
    for key in carry_family_keys() {
        assert_eq!(
            fix.files[&key].source_file_fingerprint,
            before.files[&key].source_file_fingerprint
        );
    }
    let unwitnessed = carry_key(CARRY_UNWITNESSED, None);
    assert!(fix.files[&unwitnessed].source_file_fingerprint.is_empty());
    assert_compacted_and_invalid(&fix, CARRY_ROOT);
    assert_eq!(
        fix.claude_usage_family_witnesses,
        before.claude_usage_family_witnesses
    );
    let progress = &fix.claude_full_rearm_progress;
    assert_eq!(progress.stale_rearm_fence_deadline, Some(WINDOW_DEADLINE));
    assert_eq!(progress.stale_rearms_at_deadline, 1);
    assert_eq!(
        progress.full_rearm_window.as_ref().unwrap().window_ends,
        BTreeSet::from([CARRY_FAILED.to_string(), CARRY_RETRY.to_string()])
    );

    // The follow-up re-read the unwitnessed family and again needed a clean
    // follow-up. Its one stale re-arm for this deadline already ran.
    fix.files
        .get_mut(&unwitnessed)
        .unwrap()
        .source_file_fingerprint = before.files[&unwitnessed].source_file_fingerprint.clone();
    fix.claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .census_window_end = CARRY_RETRY.to_string();
    window_needs_clean_followup(&mut fix);
    let second = fix.clone();
    let row = carry_start(&mut fix, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearm_window_families"], 2);
    assert_eq!(row["carried_pending_families"], 1);
    assert_eq!(row["rearmed_index_files"], 0, "no second stale re-arm");
    assert_eq!(row["stale_rearm_capped_families"], 1);
    assert_eq!(row["stale_rearm_capped_files"], 1);
    assert_eq!(
        fix.files[&unwitnessed].source_file_fingerprint,
        before.files[&unwitnessed].source_file_fingerprint
    );
    for root in [CARRY_ROOT, CARRY_UNWITNESSED] {
        assert_compacted_and_invalid(&fix, root);
    }
    assert_eq!(fix.claude_full_rearm_progress.stale_rearms_at_deadline, 1);
    let serialized = row.to_string();
    for forbidden in [CARRY_ROOT, CARRY_UNWITNESSED, "rev-", "body-", "/carry/"] {
        assert!(!serialized.contains(forbidden), "{forbidden}");
    }

    // A new fence deadline allows one more stale re-arm.
    let mut next = second.clone();
    next.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(WINDOW_DEADLINE + 86_400);
    let row = carry_start(&mut next, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearmed_index_files"], 1);
    assert!(row.get("stale_rearm_capped_families").is_none());
    assert!(next.files[&unwitnessed].source_file_fingerprint.is_empty());

    // The cap never holds a family whose member is not accepted, nor any
    // family while the contract-5 latch is set.
    let mut unaccepted = second.clone();
    unaccepted
        .accepted_snapshot_fingerprints
        .remove(&format!("body-{}", carry_member(CARRY_UNWITNESSED, None)));
    let row = carry_start(&mut unaccepted, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearmed_index_files"], 1);
    assert!(row.get("stale_rearm_capped_families").is_none());
    let mut latched = second;
    latched.claude_request_identity_contract_changed = true;
    let row = carry_start(&mut latched, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearmed_index_files"], 3, "BASE: nothing carried");
    assert!(row.get("stale_rearm_capped_families").is_none());
}

/// Another upload context, a daemon restart (another process), or no window
/// at all takes BASE's whole re-arm at the clean follow-up.
#[test]
fn fix2_window_from_another_context_or_process_is_base() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    type WindowMutation = (&'static str, fn(&mut ScanIndex));
    let mutations: [WindowMutation; 3] = [
        ("context", |index| {
            index
                .claude_full_rearm_progress
                .full_rearm_window
                .as_mut()
                .unwrap()
                .context_fingerprint = "another-context".to_string();
        }),
        ("process", |index| {
            let window = index
                .claude_full_rearm_progress
                .full_rearm_window
                .as_mut()
                .unwrap();
            window.process = window.process.wrapping_add(2);
        }),
        ("no_window", |index| {
            index.claude_full_rearm_progress.full_rearm_window = None;
        }),
    ];
    for (case, mutate) in mutations {
        let mut index = window_index();
        mutate(&mut index);
        let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["rearmed_index_files"], 3, "{case}");
        assert_eq!(row["carried_pending_families"], 0, "{case}");
        assert!(row.get("rearm_window_families").is_none(), "{case}");
        assert!(
            index.claude_full_rearm_progress.full_rearm_window.is_none(),
            "{case}: the window is dropped"
        );
    }
}

/// Reuse C1b's boundary controls at the clean-follow-up entry. Only the two
/// entry conditions intentionally changed by Fix 2 are omitted.
#[test]
fn fix2_clean_followup_preserves_c1b_family_refusals() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for control in carry_controls() {
        if matches!(
            control.name,
            "no_retained_traversal" | "prior_unsettled_upload"
        ) {
            continue;
        }
        let mut fix = window_index();
        (control.mutate)(&mut fix);
        let mut base = fix.clone();
        let row = carry_start(&mut fix, CARRY_RETRY, control.days);
        let _base_row = {
            let _base = KeepStaleClaudeFamilyRearmForTest::new();
            carry_start(&mut base, CARRY_RETRY, control.days)
        };
        assert_eq!(row["carried_pending_families"], 0, "{}", control.name);
        for (key, entry) in &fix.files {
            assert_eq!(
                entry.source_file_fingerprint, base.files[key].source_file_fingerprint,
                "{}: {key}",
                control.name
            );
        }
    }
}

#[test]
fn fix2_restart_before_the_first_window_start_is_base() {
    let mut index = window_index();
    index.claude_full_rearm_progress.full_rearm_window_next = true;
    index
        .claude_full_rearm_progress
        .full_rearm_window
        .as_mut()
        .unwrap()
        .process = claude_full_rearm_process().wrapping_add(2);
    let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearmed_index_files"], 3);
    assert_eq!(row["carried_pending_families"], 0);
    assert!(index.claude_full_rearm_progress.full_rearm_window.is_none());
}

#[test]
fn fix2_capped_family_member_change_cancels_and_requeues_passed_member() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let agent = "agent-b7c2696e421181e1a";
    let mut index = window_index();
    carry_family(&mut index, CARRY_UNWITNESSED, &[None, Some(agent)], false);
    let before = index.files.clone();
    let first = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(first["rearm_window_rearmed_files"], 2);
    for (key, entry) in &mut index.files {
        entry.source_file_fingerprint = before[key].source_file_fingerprint.clone();
    }
    index
        .claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .census_window_end = CARRY_RETRY.to_string();
    window_needs_clean_followup(&mut index);
    let ready = index.clone();
    let second = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(second["stale_rearm_capped_files"], 2);
    assert_compacted_and_invalid(&index, CARRY_UNWITNESSED);
    let child = carry_key(CARRY_UNWITNESSED, Some(agent));
    let root = carry_key(CARRY_UNWITNESSED, None);
    let traversal = index.traversal.as_mut().unwrap();
    traversal.scan_roots = vec![PathBuf::from(CARRY_SCAN_ROOT)];
    traversal.observed_index_keys.insert(child.clone());
    carry_fill_queue(&mut index);
    cancel_claude_family_carry_for_member_parse(
        &mut index,
        CARRY_SECOND_RETRY,
        Path::new(&root),
        &[],
        &VecDeque::new(),
    );
    assert!(!index
        .claude_stale_family_carry
        .roots
        .contains(CARRY_UNWITNESSED));
    assert!(index.files[&child].source_file_fingerprint.is_empty());
    assert_eq!(index.claude_stale_family_carry.replay.len(), 1);
    assert_eq!(
        index.claude_stale_family_carry.replay[0].path,
        PathBuf::from(child)
    );

    // A changed committed revision fails the cap before the scan too.
    let mut changed = ready.clone();
    changed
        .files
        .get_mut(&root)
        .unwrap()
        .source_file_fingerprint
        .push_str("-changed");
    let row = carry_start(&mut changed, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["rearm_window_rearmed_files"], 2);
    assert!(row.get("stale_rearm_capped_files").is_none());

    // Authority correction debt and account holds remain outside the cap.
    for account_hold in [false, true] {
        let mut held = ready.clone();
        if account_hold {
            held.claude_account_deferred_holds
                .insert(root.clone(), "rev".to_string());
        } else {
            carry_unbound_quarantine(&mut held, true);
            let record = held
                .claude_usage_authority_quarantine
                .remove(CARRY_ROOT)
                .unwrap();
            held.claude_usage_authority_quarantine
                .insert(CARRY_UNWITNESSED.to_string(), record);
        }
        let row = carry_start(&mut held, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["rearm_window_rearmed_files"], 2);
        assert!(row.get("stale_rearm_capped_files").is_none());
    }
}

#[test]
fn fix2_restart_during_a_carried_window_restores_base_before_resuming() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = window_index();
    carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert!(index.claude_stale_family_carry.roots.contains(CARRY_ROOT));
    index
        .claude_full_rearm_progress
        .full_rearm_window
        .as_mut()
        .unwrap()
        .process = claude_full_rearm_process().wrapping_add(2);
    let row = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 0);
    assert!(index.claude_full_rearm_progress.full_rearm_window.is_none());
    for key in carry_family_keys() {
        assert!(index.files[&key].source_file_fingerprint.is_empty());
    }
}

#[test]
fn fix2_unhealthy_retry_also_honors_the_same_deadline_cap() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = window_index();
    let key = carry_key(CARRY_UNWITNESSED, None);
    let revision = index.files[&key].source_file_fingerprint.clone();
    let first = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(first["rearm_window_rearmed_files"], 1);
    index.files.get_mut(&key).unwrap().source_file_fingerprint = revision;
    index
        .claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .census_window_end = CARRY_RETRY.to_string();
    carry_red(&mut index, CARRY_RETRY, 1);
    assert!(!index.bounded_sweep_had_unsettled_upload);
    let second = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(second["reason"], "terminal_unhealthy_retry");
    assert_eq!(second["carried_pending_families"], 1);
    assert_eq!(second["stale_rearm_capped_files"], 1);
    assert_eq!(second["rearmed_index_files"], 0);
    assert_compacted_and_invalid(&index, CARRY_UNWITNESSED);
    assert_eq!(index.claude_full_rearm_progress.stale_rearms_at_deadline, 1);
}
