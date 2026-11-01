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
        idless_revision: None,
        identity_contract: None,
        contract_unproven: false,
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

/// A carried family's funded worst case: every indexed member queued again,
/// two buffer slots each (a reload re-reserves the buffer beside its loaded
/// copy) plus a scan root and a member path no longer than its key.
fn carry_worst_case(keys: &[String]) -> usize {
    keys.iter()
        .map(|key| 2 * std::mem::size_of::<ScanTraversalPath>() + 2 * key.len())
        .sum()
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

/// Exercise refund even where native carry funding is unavailable.
#[test]
fn unfunded_replay_clears_fingerprints_on_every_platform() {
    let mut fix = carry_index();
    fix.claude_stale_family_carry
        .roots
        .insert(CARRY_ROOT.to_owned());
    let mut base = fix.clone();
    for key in carry_family_keys() {
        base.files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    base.claude_stale_family_carry.roots.clear();
    {
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
        assert!(refund_claude_stale_family_carry(&mut fix));
    }
    let fix_value = serde_json::to_value(&fix).unwrap();
    assert_eq!(fix_value, serde_json::to_value(&base).unwrap());
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
        usage_pending::UsageView::Full(pending),
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

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
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

/// Persist a real active Fix 2 carry, both with and without its capped
/// fallback. Losing scheduling state or retained provenance must restore
/// BASE before the matching mid-walk checkpoint can select any candidate.
#[test]
fn fix2_persisted_carry_with_lost_progress_or_origin_restarts_as_base() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = temp_dir("fix2-carry-lost-provenance");
    let path = dir.join("scan-index.json");
    for capped in [false, true] {
        let mut active = window_index();
        let unwitnessed = carry_key(CARRY_UNWITNESSED, None);
        let revision = active.files[&unwitnessed].source_file_fingerprint.clone();
        let first = carry_start(&mut active, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(first["carried_pending_families"], 1);
        if capped {
            active
                .files
                .get_mut(&unwitnessed)
                .unwrap()
                .source_file_fingerprint = revision;
            active
                .claude_usage_family_pending
                .get_mut(CARRY_UNWITNESSED)
                .unwrap()
                .census_window_end = CARRY_RETRY.to_string();
            window_needs_clean_followup(&mut active);
            let row = carry_start(&mut active, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
            assert_eq!(row["stale_rearm_capped_files"], 1);
            assert!(active
                .claude_stale_family_carry
                .capped_roots
                .contains(CARRY_UNWITNESSED));
        }
        assert!(active.claude_stale_family_carry.roots.contains(CARRY_ROOT));
        let retained = active.claude_stale_family_carry.roots.clone();
        for key in carry_family_keys() {
            assert!(!active.files[&key].source_file_fingerprint.is_empty());
        }
        // A still-active checkpoint has already passed a member and has a
        // pending candidate. A resume would retain its old census window.
        let traversal = active.traversal.as_mut().unwrap();
        traversal
            .observed_index_keys
            .insert(carry_key(CARRY_ROOT, None));
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: PathBuf::from(CARRY_SCAN_ROOT),
            path: PathBuf::from(carry_key(CARRY_OTHER, None)),
            census_member: true,
            watcher_hint: false,
        });
        let saved = serde_json::to_value(&active).unwrap();
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut valid = ScanIndex::load(&path).unwrap();
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut valid,
            "2026-08-02T07:40:00Z",
            BACKFILL_WINDOW_DAYS,
        );
        assert_eq!(valid.claude_stale_family_carry.roots, retained);
        assert_eq!(
            valid.traversal.as_ref().unwrap().census_window_end,
            active.traversal.as_ref().unwrap().census_window_end
        );
        for key in carry_family_keys() {
            assert_eq!(
                valid.files[&key].source_file_fingerprint,
                active.files[&key].source_file_fingerprint
            );
        }
        for cause in [
            "missing-progress",
            "malformed-progress",
            "empty-progress",
            "missing-origin",
            "malformed-origin",
            "other-process",
            "other-context",
        ] {
            let mut value = saved.clone();
            match cause {
                "missing-progress" => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .remove("claude_full_rearm_progress");
                }
                "malformed-progress" => value["claude_full_rearm_progress"] = serde_json::json!(42),
                "empty-progress" => value["claude_full_rearm_progress"] = serde_json::json!({}),
                // Simulate an older decoder dropping unknown origin fields.
                "missing-origin" => {
                    value["claude_stale_family_carry"]
                        .as_object_mut()
                        .unwrap()
                        .remove("origin");
                }
                "malformed-origin" => {
                    value["claude_stale_family_carry"]["origin"] =
                        serde_json::json!({"process": "bad"})
                }
                "other-process" => {
                    value["claude_stale_family_carry"]["origin"]["process"] =
                        serde_json::json!(claude_full_rearm_process().wrapping_add(2))
                }
                "other-context" => {
                    value["claude_stale_family_carry"]["origin"]["context_fingerprint"] =
                        serde_json::json!("another-context")
                }
                _ => unreachable!(),
            }
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let mut loaded =
                ScanIndex::load(&path).expect("malformed cost state never quarantines the index");
            assert!(path.exists());
            assert_eq!(loaded.files.len(), active.files.len());
            assert_eq!(loaded.claude_stale_family_carry.roots, retained);
            let row = carry_start(&mut loaded, "2026-08-02T07:40:00Z", BACKFILL_WINDOW_DAYS);
            assert_eq!(row["carried_pending_families"], 0, "{capped}/{cause}");
            assert!(
                loaded.claude_stale_family_carry.is_empty(),
                "{capped}/{cause}"
            );
            let traversal = loaded.traversal.as_ref().unwrap();
            assert_eq!(
                traversal.census_window_end, "2026-08-02T07:40:00Z",
                "{capped}/{cause}"
            );
            assert!(traversal.observed_index_keys.is_empty(), "{capped}/{cause}");
            assert!(traversal.pending_candidates.is_empty(), "{capped}/{cause}");
            for (key, entry) in &loaded.files {
                if claude_index_path_member_ref(Path::new(key))
                    .is_some_and(|member| retained.contains(member.root))
                {
                    assert!(
                        entry.source_file_fingerprint.is_empty(),
                        "{capped}/{cause}: {key}"
                    );
                }
            }
        }
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn fix2_cap_keeps_the_full_retry_that_can_reopen_the_fence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut index = window_index();
    index.files.remove(&carry_key(CARRY_OTHER, None));
    let before = index.files.clone();
    let first = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(first["rearmed_index_files"], 3);
    assert_eq!(first["carried_pending_families"], 0);
    assert_eq!(index.claude_full_rearm_progress.stale_rearms_at_deadline, 1);
    // Both families were read successfully but an unrelated transient page
    // error requires another walk. The consumed allowance cannot hold them.
    for (key, entry) in &mut index.files {
        entry.source_file_fingerprint = before[key].source_file_fingerprint.clone();
    }
    for pending in index.claude_usage_family_pending.values_mut() {
        pending.census_window_end = CARRY_RETRY.to_string();
    }
    window_needs_clean_followup(&mut index);
    let mut base = index.clone();
    let base_row = {
        let _base = KeepStaleClaudeFamilyRearmForTest::new();
        carry_start(&mut base, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS)
    };
    let row = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(base_row["rearmed_index_files"], 3);
    assert_eq!(row["rearmed_index_files"], base_row["rearmed_index_files"]);
    assert_eq!(row["carried_pending_families"], 0);
    assert!(row.get("stale_rearm_capped_families").is_none());
    for (key, entry) in &index.files {
        assert!(entry.source_file_fingerprint.is_empty(), "{key}");
        assert_eq!(
            entry.source_file_fingerprint,
            base.files[key].source_file_fingerprint
        );
    }
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn new_carry_writer_exposes_only_c1b_roots_to_old_shape_reader() {
    #[derive(serde::Deserialize)]
    struct OldCarry {
        #[serde(default)]
        roots: BTreeSet<String>,
    }
    let mut index = window_index();
    let revision = index.files[&carry_key(CARRY_UNWITNESSED, None)]
        .source_file_fingerprint
        .clone();
    carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    index
        .files
        .get_mut(&carry_key(CARRY_UNWITNESSED, None))
        .unwrap()
        .source_file_fingerprint = revision;
    index
        .claude_usage_family_pending
        .get_mut(CARRY_UNWITNESSED)
        .unwrap()
        .census_window_end = CARRY_RETRY.to_string();
    window_needs_clean_followup(&mut index);
    let row = carry_start(&mut index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["stale_rearm_capped_files"], 1);
    assert!(index
        .claude_stale_family_carry
        .capped_roots
        .contains(CARRY_UNWITNESSED));
    assert!(!index
        .claude_stale_family_carry
        .roots
        .contains(CARRY_UNWITNESSED));
    let bytes = serde_json::to_vec(&index.claude_stale_family_carry).unwrap();
    let old: OldCarry = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(old.roots, BTreeSet::from([CARRY_ROOT.to_string()]));
    let decoded: ClaudeStaleFamilyCarry = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.contains(CARRY_ROOT));
    assert!(decoded.contains(CARRY_UNWITNESSED));
    // Decode an actual #720 shape (union in roots), then rewrite it safely.
    let mut legacy = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    legacy["roots"] = serde_json::json!([CARRY_ROOT, CARRY_UNWITNESSED]);
    let decoded: ClaudeStaleFamilyCarry = serde_json::from_value(legacy).unwrap();
    assert!(decoded.roots.contains(CARRY_UNWITNESSED));
    assert!(decoded.contains(CARRY_UNWITNESSED));
    let old: OldCarry = serde_json::from_slice(&serde_json::to_vec(&decoded).unwrap()).unwrap();
    assert_eq!(old.roots, BTreeSet::from([CARRY_ROOT.to_string()]));
}

/// Source-only reproduction of the hold/unsettled retry shape. The optional
/// acquisition cache is deliberately empty: StateMissing denotes that fact,
/// independently of the durable ScanIndex. No provider state is read.
#[test]
fn unhealthy_retry_with_held_families_rearms_healthy_history_reproduction() {
    use crate::transcript_acquisition::{FullReason, ReadMode, Scope};

    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    struct SyntheticFiles(PathBuf);
    impl Drop for SyntheticFiles {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let dir = SyntheticFiles(std::env::temp_dir().join(format!(
        "ottto-unhealthy-retry-repro-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
    )));
    std::fs::create_dir_all(&dir.0).unwrap();
    const HELD: usize = 9;
    const HEALTHY: usize = 32;
    // The unrelated committed file makes the existing reachability guard
    // false, isolating prior_unsettled_upload in the first two arms. The
    // third arm shows the separate reachable-full-retry veto without it.
    for (unsettled, unrelated, expected_healthy_full) in [
        (true, true, HEALTHY),
        (false, true, 0),
        (false, false, HEALTHY),
    ] {
        let mut index = ScanIndex {
            claude_request_identity_contract: Some(claude_request_identity::COLLECTOR.to_string()),
            claude_duplicate_request_witness_overflowed: true,
            ..ScanIndex::default()
        };
        if unrelated {
            carry_file(&mut index, CARRY_OTHER, None);
        }
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut index,
            CARRY_FAILED,
            BACKFILL_WINDOW_DAYS,
        );
        let mut roots = Vec::new();
        for number in 0..HELD + HEALTHY {
            let root = format!("d{number:07}-1111-4111-8111-111111111111");
            carry_family(&mut index, &root, &[None], true);
            roots.push(root);
        }
        // Supply current index metadata, accepted bodies and well-formed
        // revisions. Only traversal-start rearming may select healthy files.
        let mut candidates = Vec::new();
        let old_files = std::mem::take(&mut index.files);
        let old_bodies = std::mem::take(&mut index.file_snapshot_fingerprints);
        for (old_key, mut entry) in old_files {
            let name = Path::new(&old_key).file_name().unwrap();
            let path = dir.0.join(name);
            std::fs::write(&path, b"{}\n").unwrap();
            let key = local_index_key(&path);
            entry.source_file_fingerprint = format!("{:x}", Sha256::digest(key.as_bytes()));
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
            entry.size_bytes = 3;
            for body in &old_bodies[&old_key] {
                index
                    .snapshot_activity_at
                    .insert(body.clone(), Some(CARRY_FAILED.to_string()));
            }
            let mut candidate = test_candidate(path);
            candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
            candidate.size_bytes = entry.size_bytes;
            candidate.modified_unix_seconds = entry.modified_unix_seconds;
            candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap();
            index.files.insert(key.clone(), entry);
            index
                .file_snapshot_fingerprints
                .insert(key, old_bodies[&old_key].clone());
            candidates.push(candidate);
        }
        for root in roots.iter().take(HELD) {
            let key = local_index_key(&dir.0.join(format!("{root}.jsonl")));
            index.bind_retry_pending_claude_authority_for_test(
                root,
                BTreeMap::from([(
                    root.clone(),
                    index.files[&key].source_file_fingerprint.clone(),
                )]),
            );
        }
        carry_red(&mut index, CARRY_FAILED, 7);
        if unsettled {
            index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
        }
        let records = index.claude_usage_authority_quarantine.clone();
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["reason"], "terminal_unhealthy_retry");
        assert_eq!(row["stale_pending_families"], HEALTHY);
        assert_eq!(row["rearmed_index_files"], expected_healthy_full);
        assert_eq!(index.claude_usage_authority_pending_count(), HELD);
        assert_eq!(index.claude_usage_authority_quarantine, records);
        assert_eq!(index.accepted_snapshot_fingerprints, accepted);
        assert!(!index.claude_request_identity_contract_changed);
        let mut healthy_full = 0;
        let mut held_reads_before_deadline = 0;
        for candidate in &candidates {
            let root = claude_index_path_member_ref(&candidate.path).unwrap().root;
            let held = records.contains_key(root);
            let (decision, reason) = index.candidate_decision_with_reason_at(candidate, 0);
            if held {
                held_reads_before_deadline += usize::from(decision == CandidateDecision::Parse);
                continue;
            }
            if decision != CandidateDecision::Parse {
                assert_eq!(decision, CandidateDecision::Skip);
                continue;
            }
            assert_eq!(reason, Some(CandidateParseReason::Rearmed));
            let file = File::open(&candidate.path).unwrap();
            let mut parser = OwnedJsonlParser::new(
                file,
                &candidate.path,
                SnapshotSource::ClaudeCode,
                apply_claude_code_line,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                parser
                    .prepare_acquisition(
                        None,
                        &Scope("synthetic-unhealthy-retry".into()),
                        None,
                        100
                    )
                    .unwrap(),
                ReadMode::Full(FullReason::StateMissing),
            );
            while !parser.step().unwrap() {}
            healthy_full += 1;
        }
        assert_eq!(healthy_full, expected_healthy_full);
        assert_eq!(held_reads_before_deadline, 0);
        // Control: the held families still select when their own deadline is
        // due. This changes no binding, accepted body or identity latch.
        for record in index.claude_usage_authority_quarantine.values_mut() {
            record.retry_after_unix_seconds = 0;
        }
        let held_reads_when_due = candidates
            .iter()
            .filter(|candidate| {
                let root = claude_index_path_member_ref(&candidate.path).unwrap().root;
                records.contains_key(root)
                    && index.candidate_decision_with_reason_at(candidate, 0)
                        == (
                            CandidateDecision::Parse,
                            Some(CandidateParseReason::AuthorityQuarantine),
                        )
            })
            .count();
        assert_eq!(held_reads_when_due, HELD);
        eprintln!("UNHEALTHY_RETRY_REPRO held={HELD} healthy={HEALTHY} unsettled={unsettled} unrelated={unrelated} healthy_full={healthy_full} held_reads_before_deadline={held_reads_before_deadline} held_reads_when_due={held_reads_when_due}");
    }
}

pub(super) fn scoped_retry_record(
    key: &str,
    value: serde_json::Value,
) -> claude_request_census::ClaudeRequestCensusRecord {
    let census: claude_request_census::ClaudeRequestCensus =
        serde_json::from_value(serde_json::json!({ key: value })).unwrap();
    census
        .get(key)
        .expect("valid synthetic request record")
        .clone()
}

/// Complete durable request evidence and an accepted head for this exact
/// scan identity. The legacy reproduction above intentionally lacks these
/// records and remains unchanged: missing evidence still takes BASE.
fn scoped_retry_accept_member(index: &mut ScanIndex, key: &str) -> CandidateFile {
    let entry = index.files.get_mut(key).unwrap();
    entry.source_file_fingerprint = format!("{:x}", Sha256::digest(key.as_bytes()));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    let mut group = Sha256::new();
    update_length_prefixed(&mut group, b"snapshot_file_entity_set:v1");
    for fingerprint in &index.file_snapshot_fingerprints[key] {
        update_length_prefixed(&mut group, fingerprint.as_bytes());
    }
    entry.last_snapshot_fingerprint = Some(format!("{:x}", group.finalize()));
    entry.last_upload_body_witness = Some("a".repeat(64));
    let mut candidate = test_candidate(PathBuf::from(key));
    candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
    // Native candidates also carry a nonempty legacy digest. An empty
    // fixture digest would make a re-armed old-version entry migrate.
    candidate.legacy_source_file_fingerprint = entry.source_file_fingerprint.clone();
    candidate.size_bytes = entry.size_bytes;
    candidate.modified_unix_seconds = entry.modified_unix_seconds;
    candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap();
    let record = scoped_retry_record(
        key,
        serde_json::json!({
            "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
            "fp": entry.source_file_fingerprint,
            "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "s": "exact", "h": "0000000000000001",
            // Native opened-file records retain birth through invalidation.
            // Without birth the existing invalidator removes the record, so
            // that fixture would test allowed absence instead of damage.
            "bi": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "bd": 1, "bn": 1,
        }),
    );
    index.claude_request_census.insert(key.to_string(), record);
    for body in &index.file_snapshot_fingerprints[key] {
        index
            .snapshot_activity_at
            .insert(body.clone(), Some(CARRY_FAILED.to_string()));
    }
    index.session_account_bindings.insert(
        key.to_string(),
        SessionAccountBinding {
            account_identifier_hash: "a".repeat(64),
            workspace_identifier_hash: Some("b".repeat(64)),
        },
    );
    candidate
}

struct ScopedRetryFixture {
    _scratch: crate::test_scratch::ScratchDir,
    index: ScanIndex,
    candidates: Vec<CandidateFile>,
    roots: Vec<String>,
}

fn scoped_retry_fixture(held: usize, healthy: usize, unrelated: bool) -> ScopedRetryFixture {
    let scratch = crate::test_scratch::ScratchDir::new("scoped-unhealthy-retry");
    let support = scratch.join("support");
    let list = ReemissionExclusions::path(&support);
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    std::fs::write(list, b"").unwrap();
    let mut index = ScanIndex {
        claude_request_identity_contract: Some(claude_request_identity::COLLECTOR.to_string()),
        claude_duplicate_request_witness_overflowed: true,
        claude_reemission_exclusions: ReemissionExclusions::load(&support),
        claude_duplicate_fence_next_full_rearm_unix_seconds: rfc3339_unix_seconds(CARRY_FAILED)
            .map(|now| now + 86_400),
        ..ScanIndex::default()
    };
    if unrelated {
        carry_file(&mut index, CARRY_OTHER, None);
    }
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        CARRY_FAILED,
        BACKFILL_WINDOW_DAYS,
    );
    let mut roots = Vec::new();
    for number in 0..held + healthy {
        let root = format!("d{number:07}-1111-4111-8111-111111111111");
        carry_family(&mut index, &root, &[None], true);
        roots.push(root);
    }
    let mut candidates = Vec::new();
    let old_files = std::mem::take(&mut index.files);
    let old_bodies = std::mem::take(&mut index.file_snapshot_fingerprints);
    for (old_key, entry) in old_files {
        let path = scratch.join(Path::new(&old_key).file_name().unwrap());
        std::fs::write(&path, b"{}\n").unwrap();
        let key = local_index_key(&path);
        index.files.insert(key.clone(), entry);
        index
            .file_snapshot_fingerprints
            .insert(key.clone(), old_bodies[&old_key].clone());
        candidates.push(scoped_retry_accept_member(&mut index, &key));
    }
    for root in roots.iter().take(held) {
        let key = local_index_key(&scratch.join(format!("{root}.jsonl")));
        index.bind_retry_pending_claude_authority_for_test(
            root,
            BTreeMap::from([(
                root.clone(),
                index.files[&key].source_file_fingerprint.clone(),
            )]),
        );
    }
    carry_red(&mut index, CARRY_FAILED, 7);
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
    ScopedRetryFixture {
        _scratch: scratch,
        index,
        candidates,
        roots,
    }
}

/// Count actual native Full reads, not just fingerprint clears. The optional
/// reduction cache is cold, exactly as in the unchanged reproduction.
fn scoped_retry_full_reads(index: &ScanIndex, candidates: &[CandidateFile]) -> usize {
    use crate::transcript_acquisition::{FullReason, ReadMode, Scope};
    candidates
        .iter()
        .filter(|candidate| {
            if index.candidate_decision_with_reason_at(candidate, 0).0 != CandidateDecision::Parse {
                return false;
            }
            let mut parser = OwnedJsonlParser::new(
                File::open(&candidate.path).unwrap(),
                &candidate.path,
                SnapshotSource::ClaudeCode,
                apply_claude_code_line,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                parser
                    .prepare_acquisition(None, &Scope("scoped-retry".into()), None, 100)
                    .unwrap(),
                ReadMode::Full(FullReason::StateMissing)
            );
            while !parser.step().unwrap() {}
            true
        })
        .count()
}

/// SOURCE (a)-(e), B1/B3: each healthy file's own accepted evidence removes
/// both global vetoes. Saved request evidence, authority witnesses, accepted
/// heads and account bindings are byte-identical, including across reload.
#[test]
fn scoped_unhealthy_retry_reads_zero_of_32_healthy_files_and_keeps_evidence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for unrelated in [true, false] {
        let mut fixture = scoped_retry_fixture(9, 32, unrelated);
        let before = serde_json::to_value(&fixture.index).unwrap();
        let mut base = fixture.index.clone();
        {
            let _base = KeepStaleClaudeFamilyRearmForTest::new();
            carry_start(&mut base, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        }
        assert_eq!(scoped_retry_full_reads(&base, &fixture.candidates), 32);
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["prior_unsettled_upload"], true);
        assert_eq!(row["carried_pending_families"], 32);
        assert_eq!(row["rearmed_index_files"], 0);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &fixture.candidates),
            0
        );
        let saved: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&fixture.index).unwrap()).unwrap();
        let after = serde_json::to_value(&saved).unwrap();
        for field in [
            "claude_request_census",
            "session_account_bindings",
            "claude_usage_family_witnesses",
            "claude_usage_authority_quarantine",
            "accepted_snapshot_fingerprints",
            "file_snapshot_fingerprints",
        ] {
            assert_eq!(
                serde_json::to_vec(&after[field]).unwrap(),
                serde_json::to_vec(&before[field]).unwrap(),
                "{field}"
            );
        }
        assert!(saved.claude_duplicate_request_witness_overflowed);
        assert_eq!(saved.claude_usage_authority_pending_count(), 9);
        for root in fixture.roots.iter().skip(9) {
            assert_compacted_and_invalid(&saved, root);
        }
        eprintln!("SCOPED_UNHEALTHY_RETRY held=9 healthy=32 unrelated={unrelated} base_full=32 healthy_full=0");
    }
}

/// SOURCE (c)/(d): overdue RetryPending work runs on this next cycle, while
/// healthy siblings remain unread. Terminal holds retain disclosure/bindings
/// and retry a changed revision, without an early terminal conversion.
#[test]
fn scoped_unhealthy_retry_runs_overdue_holds_next_cycle_and_preserves_terminal_holds() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = scoped_retry_fixture(9, 32, false);
    fixture
        .index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds =
        rfc3339_unix_seconds(CARRY_RETRY).map(|now| now + UNHEALTHY_SCAN_RETRY_MAX_SECONDS);
    // Control: neither the traversal nor a family's own retry is due yet.
    let before_wait = serde_json::to_value(&fixture.index).unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut fixture.index,
            CARRY_RETRY,
            BACKFILL_WINDOW_DAYS,
        );
    });
    assert!(!rows.iter().any(|row| row["counts"]["event"] == "starting"));
    assert_eq!(serde_json::to_value(&fixture.index).unwrap(), before_wait);
    for record in fixture.index.claude_usage_authority_quarantine.values_mut() {
        record.retry_after_unix_seconds = rfc3339_unix_seconds(CARRY_FAILED).unwrap() + 1;
    }
    let terminal = fixture.roots[0].clone();
    let record = fixture
        .index
        .claude_usage_authority_quarantine
        .get_mut(&terminal)
        .unwrap();
    record.disposition = ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
    record.failed_reconstruction_count = MAX_CLAUDE_USAGE_AUTHORITY_FAILURES;
    let holds = fixture.index.claude_usage_authority_quarantine.clone();
    let bindings = fixture.index.session_account_bindings.clone();
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 32);
    assert_eq!(row["rearmed_index_files"], 0);
    assert_eq!(
        scoped_retry_full_reads(&fixture.index, &fixture.candidates),
        8
    );
    assert_eq!(fixture.index.claude_usage_authority_pending_count(), 8);
    assert_eq!(
        fixture.index.claude_usage_authority_terminal_entity_count(),
        1
    );
    assert_eq!(fixture.index.claude_usage_authority_quarantine, holds);
    assert_eq!(fixture.index.session_account_bindings, bindings);
    // Third cycle: the served family yielded no item (e.g. deleted while
    // red), so its record/deadline did not advance. Persist that checkpoint
    // and require the hourly backoff rather than another deadline wake.
    std::fs::remove_file(
        &fixture
            .candidates
            .iter()
            .find(|candidate| {
                claude_index_path_member_ref(&candidate.path).unwrap().root == fixture.roots[1]
            })
            .unwrap()
            .path,
    )
    .unwrap();
    carry_red(&mut fixture.index, CARRY_RETRY, 7);
    fixture
        .index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds =
        rfc3339_unix_seconds(CARRY_RETRY).map(|now| now + UNHEALTHY_SCAN_RETRY_MAX_SECONDS);
    fixture.index = carry_reload(fixture.index);
    // The production cycle reloads this runtime-only protection policy
    // before scanning (snapshot_sync::sync_source). Keep that same installed
    // synthetic list across index reload; no acceptance is reconstructed.
    fixture
        .index
        .load_claude_reemission_exclusions(&fixture._scratch.join("support"));
    let waiting = serde_json::to_value(&fixture.index).unwrap();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut fixture.index,
            CARRY_RESUME,
            BACKFILL_WINDOW_DAYS,
        );
    });
    assert!(!rows.iter().any(|row| row["counts"]["event"] == "starting"));
    assert_eq!(serde_json::to_value(&fixture.index).unwrap(), waiting);
    let hourly = OffsetDateTime::from_unix_timestamp(
        (rfc3339_unix_seconds(CARRY_RETRY).unwrap() + UNHEALTHY_SCAN_RETRY_MAX_SECONDS) as i64,
    )
    .unwrap()
    .format(&Rfc3339)
    .unwrap();
    let third = carry_start(&mut fixture.index, &hourly, BACKFILL_WINDOW_DAYS);
    assert_eq!(third["reason"], "terminal_unhealthy_retry");
    assert_eq!(third["carried_pending_families"], 32);
    assert_eq!(third["rearmed_index_files"], 0);
    assert_eq!(fixture.index.claude_usage_authority_quarantine, holds);
    assert_eq!(fixture.index.session_account_bindings, bindings);
    let candidate = fixture
        .candidates
        .iter_mut()
        .find(|candidate| claude_index_path_member_ref(&candidate.path).unwrap().root == terminal)
        .unwrap();
    assert_eq!(
        fixture.index.candidate_decision_at(candidate, 0),
        CandidateDecision::Skip
    );
    candidate.source_file_fingerprint = "f".repeat(64);
    assert_eq!(
        fixture
            .index
            .candidate_decision_with_reason_at(candidate, 0),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
}

/// A restart after a red terminal discards the process-local carry decision,
/// then recomputes from durable acceptance, fingerprints and witnesses. A
/// context change, mid-walk checkpoint or lost acceptance still keeps BASE.
#[test]
fn scoped_unhealthy_retry_restart_recomputes_terminal_carry_from_durable_state() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "restart",
        "context",
        "mid_walk",
        "missing_ack",
        "invalid_pending",
        "missing_body_ack",
        "list_missing",
    ] {
        let mut fixture = scoped_retry_fixture(9, 32, false);
        let first = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(first["carried_pending_families"], 32);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &fixture.candidates),
            0
        );
        carry_red(&mut fixture.index, CARRY_RETRY, 7);
        fixture
            .index
            .mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
        fixture.index = carry_reload(fixture.index);
        assert!(fixture
            .index
            .claude_reemission_exclusions
            .holds_without_list(None));
        fixture
            .index
            .load_claude_reemission_exclusions(&fixture._scratch.join("support"));
        assert!(!fixture
            .index
            .claude_reemission_exclusions
            .holds_without_list(None));
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_mut()
            .unwrap()
            .process = claude_full_rearm_process().wrapping_add(2);
        match case {
            "mid_walk" => fixture
                .index
                .traversal
                .as_mut()
                .unwrap()
                .pending_candidates
                .push_back(carry_replayed(&local_index_key(
                    &fixture.candidates[0].path,
                ))),
            "missing_ack" => fixture.index.accepted_snapshot_fingerprints.clear(),
            "list_missing" => {
                fixture.index.claude_reemission_exclusions = ReemissionExclusions::default()
            }
            "invalid_pending" => {
                for root in fixture.roots.iter().skip(9) {
                    fixture
                        .index
                        .claude_usage_family_pending
                        .get_mut(root)
                        .unwrap()
                        .invalid = true;
                }
            }
            "missing_body_ack" => {
                for entry in fixture.index.files.values_mut() {
                    entry.last_upload_body_witness = None;
                }
            }
            _ => (),
        }
        let before = serde_json::to_value(&fixture.index).unwrap();
        if case == "restart" {
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    &[],
                    &mut fixture.index,
                    CARRY_RETRY,
                    BACKFILL_WINDOW_DAYS,
                );
            });
            assert!(!rows.iter().any(|row| row["counts"]["event"] == "starting"));
            assert!(fixture.index.claude_stale_family_carry.is_empty());
            assert_eq!(
                serde_json::to_value(&fixture.index).unwrap()["files"],
                before["files"]
            );
            assert_eq!(
                scoped_retry_full_reads(&fixture.index, &fixture.candidates),
                0
            );
        }
        let days = BACKFILL_WINDOW_DAYS + u64::from(case == "context");
        let row = carry_start(&mut fixture.index, CARRY_SECOND_RETRY, days);
        let healthy_full = scoped_retry_full_reads(&fixture.index, &fixture.candidates);
        if case == "restart" {
            assert_eq!(row["reason"], "terminal_unhealthy_retry");
            assert_eq!(row["carried_pending_families"], 32);
            assert_eq!(row["rearmed_index_files"], 0);
            assert_eq!(healthy_full, 0);
            assert_eq!(
                fixture
                    .index
                    .claude_stale_family_carry
                    .origin
                    .as_ref()
                    .unwrap()
                    .process,
                claude_full_rearm_process()
            );
            let after = serde_json::to_value(carry_reload(fixture.index.clone())).unwrap();
            for field in [
                "claude_request_census",
                "session_account_bindings",
                "claude_usage_family_witnesses",
                "claude_usage_authority_quarantine",
                "accepted_snapshot_fingerprints",
                "file_snapshot_fingerprints",
            ] {
                assert_eq!(
                    serde_json::to_vec(&before[field]).unwrap(),
                    serde_json::to_vec(&after[field]).unwrap(),
                    "{field}"
                );
            }
            for root in fixture.roots.iter().skip(9) {
                assert_compacted_and_invalid(&fixture.index, root);
            }
        } else {
            assert_eq!(row["carried_pending_families"], 0, "{case}");
            if !matches!(case, "context" | "mid_walk") {
                assert_eq!(row["rearmed_index_files"], 32, "{case}");
            }
            assert_eq!(healthy_full, 32, "{case}");
        }
    }
}

/// Each refusal affects only its own family. None is hidden by the acceptance
/// of a sibling, even with a global unsettled sweep and plausible full retry.
#[test]
fn scoped_unhealthy_retry_refuses_missing_mismatched_or_incomplete_family_evidence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "missing_ack",
        "mismatched_ack",
        "missing_record",
        "damaged_record",
        "damaged_record_after_reload",
        "old_version",
        "record_revision",
        "identity_incomplete",
        "lossy",
        "unverified",
        "twin",
        "retired",
        "scan_version",
        "empty_revision",
        "invalid_pending",
        "witness_mismatch",
        "no_witness",
        "account_hold",
        "authority_hold",
        "protected_root",
        "list_missing",
    ] {
        let mut fixture = scoped_retry_fixture(1, 2, false);
        let root = fixture.roots[1].clone();
        let key = local_index_key(&fixture._scratch.join(format!("{root}.jsonl")));
        // These historical local-witness controls remain refusal tests only
        // with missing body ACK state. Local witness absence/mismatch alone
        // is accepted by SOURCE; the positive test below isolates that rule.
        if matches!(case, "missing_record" | "witness_mismatch" | "no_witness") {
            fixture
                .index
                .files
                .get_mut(&key)
                .unwrap()
                .last_upload_body_witness = None;
        }
        match case {
            "missing_ack" => {
                let head = fixture.index.file_snapshot_fingerprints[&key]
                    .first()
                    .unwrap();
                fixture.index.accepted_snapshot_fingerprints.remove(head);
            }
            "mismatched_ack" => {
                fixture
                    .index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .last_snapshot_fingerprint = Some("other-head".into())
            }
            "missing_record" => fixture.index.claude_request_census.remove(&key),
            "damaged_record" | "damaged_record_after_reload" => {
                fixture
                    .index
                    .claude_request_census
                    .invalidate_keeping_birth(&key);
                assert!(fixture.index.claude_request_census.get(&key).is_none());
                assert!(fixture
                    .index
                    .claude_request_census
                    .retry_carry_record(&key)
                    .unwrap()
                    .is_birth_stub());
                if case == "damaged_record_after_reload" {
                    fixture.index.claude_request_census = serde_json::from_slice(
                        &serde_json::to_vec(&fixture.index.claude_request_census).unwrap(),
                    )
                    .unwrap();
                }
            }
            "scan_version" => {
                fixture
                    .index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .scan_identity_version = Some("old-scan".into())
            }
            "empty_revision" => fixture
                .index
                .files
                .get_mut(&key)
                .unwrap()
                .source_file_fingerprint
                .clear(),
            "invalid_pending" => {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .invalid = true
            }
            "witness_mismatch" => {
                fixture
                    .index
                    .claude_usage_family_witnesses
                    .get_mut(&root)
                    .unwrap()
                    .member_occurrence_fingerprints
                    .insert(root.clone(), "f".repeat(64));
            }
            "no_witness" => {
                fixture.index.claude_usage_family_witnesses.remove(&root);
            }
            "account_hold" => {
                fixture
                    .index
                    .claude_account_deferred_holds
                    .insert(key.clone(), "held".into());
            }
            "authority_hold" => {
                fixture.index.bind_retry_pending_claude_authority_for_test(
                    &root,
                    BTreeMap::from([(
                        root.clone(),
                        fixture.index.files[&key].source_file_fingerprint.clone(),
                    )]),
                );
                fixture
                    .index
                    .claude_usage_authority_quarantine
                    .get_mut(&root)
                    .unwrap()
                    .retry_after_unix_seconds = 0;
            }
            "protected_root" => {
                fixture.index.claude_reemission_exclusions = ReemissionExclusions::parse(
                    format!("{:x}\n", Sha256::digest(root.as_bytes())).as_bytes(),
                )
            }
            "list_missing" => {
                fixture.index.claude_reemission_exclusions = ReemissionExclusions::default()
            }
            _ => {
                let mut record =
                    serde_json::to_value(fixture.index.claude_request_census.get(&key).unwrap())
                        .unwrap();
                match case {
                    "old_version" => {
                        record["v"] = serde_json::json!(
                            claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION + 1
                        )
                    }
                    "record_revision" => record["fp"] = serde_json::json!("e".repeat(64)),
                    "identity_incomplete" => record["s"] = serde_json::json!("identity_incomplete"),
                    "lossy" => record["s"] = serde_json::json!("lossy"),
                    "unverified" => record["u"] = serde_json::json!(true),
                    "twin" => record["tw"] = serde_json::json!(true),
                    "retired" => {
                        record["r"] = serde_json::json!(1);
                        record.as_object_mut().unwrap().remove("b");
                    }
                    _ => unreachable!(),
                }
                fixture
                    .index
                    .claude_request_census
                    .insert(key.clone(), scoped_retry_record(&key, record));
            }
        }
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert!(
            !fixture.index.claude_stale_family_carry.contains(&root),
            "{case}"
        );
        let candidate = fixture
            .candidates
            .iter()
            .find(|candidate| local_index_key(&candidate.path) == key)
            .unwrap();
        assert_eq!(
            fixture.index.candidate_decision_at(candidate, 0),
            CandidateDecision::Parse,
            "{case}"
        );
        if case != "list_missing" {
            assert_eq!(
                row["carried_pending_families"], 1,
                "{case}: healthy sibling is independent"
            );
        }
    }
}

#[test]
fn accepted_retry_carries_without_otel_census_or_fence_deadline() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for deadline in [None, Some(0), Some(u64::MAX)] {
        let mut fixture = scoped_retry_fixture(0, 1, false);
        fixture.index.claude_usage_family_witnesses.clear();
        fixture.index.claude_request_census = claude_request_census::ClaudeRequestCensus::default();
        fixture.index.claude_duplicate_request_witness_overflowed = false;
        fixture
            .index
            .claude_duplicate_fence_next_full_rearm_unix_seconds = deadline;
        let before = serde_json::to_value(&fixture.index).unwrap();
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["carried_pending_families"], 1);
        assert_eq!(row["rearmed_index_files"], 0);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &fixture.candidates),
            0
        );
        let after = serde_json::to_value(&fixture.index).unwrap();
        for field in [
            "files",
            "session_account_bindings",
            "accepted_snapshot_fingerprints",
            "file_snapshot_fingerprints",
            "claude_usage_family_witnesses",
            "claude_request_census",
        ] {
            assert_eq!(before[field], after[field], "{field}");
        }
    }
}

#[test]
fn accepted_idless_retry_preserves_invalid_evidence_and_refuses_second_causes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "idless",
        "message_only",
        "second_cause",
        "member_changed",
        "occurrence_mismatch",
        "lossy",
        "changed",
        "version",
        "parser",
        "decode",
    ] {
        let mut fixture = scoped_retry_fixture(0, 1, false);
        let root = fixture.roots[0].clone();
        let candidate = &mut fixture.candidates[0];
        let key = local_index_key(&candidate.path);
        std::fs::write(&candidate.path, format!("{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{root}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n")).unwrap();
        if case == "message_only" {
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&candidate.path).unwrap()).unwrap();
            value["message"]["id"] = serde_json::json!("msg-without-request-id");
            std::fs::write(
                &candidate.path,
                serde_json::to_string(&value).unwrap() + "\n",
            )
            .unwrap();
        }
        let items = parse_claude_code_jsonl_file(
            &candidate.path,
            CARRY_FAILED,
            candidate.source_file_fingerprint.clone(),
        )
        .unwrap();
        fixture.index.claude_usage_family_pending.clear();
        accumulate_claude_usage_family_pending_with_limit(
            &items,
            &mut fixture.index.claude_usage_family_pending,
            CARRY_FAILED,
            100,
        )
        .unwrap();
        assert!(fixture.index.claude_usage_family_pending[&root].invalid);
        assert!(fixture.index.claude_usage_family_pending[&root]
            .idless_revision
            .is_some());
        let mut record =
            serde_json::to_value(fixture.index.claude_request_census.get(&key).unwrap()).unwrap();
        record["s"] = serde_json::json!("identity_incomplete");
        fixture
            .index
            .claude_request_census
            .insert(key.clone(), scoped_retry_record(&key, record));
        match case {
            "second_cause" => {
                let pending = fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap();
                let mut retained = 0;
                invalidate_claude_usage_family_pending(pending, &mut retained);
            }
            "member_changed" | "occurrence_mismatch" => {
                let mut second = items[0].clone();
                if case == "member_changed" {
                    second.source_session_id += "_agent-secondary";
                } else {
                    second.claude_usage_request_ids.insert("other".into());
                }
                accumulate_claude_usage_family_pending_with_limit(
                    &[second],
                    &mut fixture.index.claude_usage_family_pending,
                    CARRY_FAILED,
                    100,
                )
                .unwrap();
            }
            "lossy" => {
                let mut value =
                    serde_json::to_value(fixture.index.claude_request_census.get(&key).unwrap())
                        .unwrap();
                value["s"] = serde_json::json!("lossy");
                fixture
                    .index
                    .claude_request_census
                    .insert(key.clone(), scoped_retry_record(&key, value));
            }
            "changed" => candidate.source_file_fingerprint = "e".repeat(64),
            "version" => {
                fixture
                    .index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .scan_identity_version = Some("old".into())
            }
            "parser" => {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .idless_revision = Some([1; 32])
            }
            "decode" => fixture.index.claude_request_census.remove(&key),
            _ => (),
        }
        let before = serde_json::to_value(&fixture.index).unwrap();
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        if matches!(case, "idless" | "message_only") {
            assert_eq!(row["carried_pending_families"], 1);
            assert_eq!(
                scoped_retry_full_reads(&fixture.index, &fixture.candidates),
                0
            );
            let after = serde_json::to_value(&fixture.index).unwrap();
            for field in [
                "claude_usage_family_pending",
                "claude_request_census",
                "files",
                "session_account_bindings",
                "accepted_snapshot_fingerprints",
                "file_snapshot_fingerprints",
            ] {
                assert_eq!(before[field], after[field], "{field}");
            }
            assert!(fixture.index.claude_duplicate_request_witness_overflowed);
        } else {
            assert_eq!(
                fixture
                    .index
                    .candidate_decision_at(&fixture.candidates[0], 0),
                CandidateDecision::Parse,
                "{case}"
            );
            if case != "changed" {
                assert_eq!(row["carried_pending_families"], 0, "{case}");
            }
        }
        assert!(fixture.index.claude_usage_family_pending[&root].invalid);
    }
}

/// A new scan fingerprint (sidecar evidence included), truncation and object
/// replacement independently select a carried member at unchanged mtime.
#[test]
fn scoped_unhealthy_retry_changed_members_and_due_replays_keep_base() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "sidecar_fingerprint",
        "replacement",
        "truncation",
        "audit",
        "identity_latch",
    ] {
        let mut fixture = scoped_retry_fixture(1, 2, false);
        match case {
            "identity_latch" => fixture.index.claude_request_identity_contract_changed = true,
            "daily_replay" => {
                fixture
                    .index
                    .claude_duplicate_fence_next_full_rearm_unix_seconds =
                    rfc3339_unix_seconds(CARRY_RETRY)
            }
            "missing_replay" => {
                fixture
                    .index
                    .claude_duplicate_fence_next_full_rearm_unix_seconds = None
            }
            "invalid_replay" => {
                fixture
                    .index
                    .claude_duplicate_fence_next_full_rearm_unix_seconds = Some(u64::MAX)
            }
            _ => (),
        }
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        let candidate = fixture
            .candidates
            .iter_mut()
            .find(|candidate| {
                claude_index_path_member_ref(&candidate.path).unwrap().root == fixture.roots[1]
            })
            .unwrap();
        match case {
            "sidecar_fingerprint" | "replacement" => {
                candidate.source_file_fingerprint = "e".repeat(64)
            }
            "truncation" => candidate.size_bytes = 0,
            "audit" => {
                fixture
                    .index
                    .files
                    .get_mut(&local_index_key(&candidate.path))
                    .unwrap()
                    .set_unverified_deadline(0);
            }
            _ => assert_eq!(row["carried_pending_families"], 0),
        }
        assert_eq!(
            fixture.index.candidate_decision_at(candidate, 1),
            CandidateDecision::Parse,
            "{case}"
        );
        if case == "identity_latch" {
            assert!(fixture.index.claude_request_identity_contract_changed);
        }
    }
}

#[test]
fn scoped_unhealthy_retry_changed_member_cancels_only_its_funded_family() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for debt in [false, true] {
        let mut index = carry_index();
        index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
        index.claude_duplicate_fence_next_full_rearm_unix_seconds =
            rfc3339_unix_seconds(CARRY_FAILED).map(|now| now + 86_400);
        let [root_key, agent_key] = carry_family_keys();
        let mut changed = scoped_retry_accept_member(&mut index, &root_key);
        scoped_retry_accept_member(&mut index, &agent_key);
        if debt {
            index.claude_request_identity_contract_changed = true;
        } else {
            index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
        }
        let before = index.clone();
        let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["carried_pending_families"], 1);
        let traversal = index.traversal.as_mut().unwrap();
        traversal.scan_roots = vec![PathBuf::from(CARRY_SCAN_ROOT)];
        traversal.observed_index_keys.extend(carry_family_keys());
        carry_fill_queue(&mut index);
        // New evidence changes the existing scan identity, independently of
        // mtime. Normal candidate selection reaches the existing cancellation.
        changed.source_file_fingerprint = "e".repeat(64);
        assert_eq!(
            index.candidate_decision_with_reason_at(&changed, 0),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::SourceChanged)
            )
        );
        carry_cancel(&mut index);
        assert!(!index.claude_stale_family_carry.contains(CARRY_ROOT));
        assert!(index.files[&agent_key].source_file_fingerprint.is_empty());
        assert_eq!(
            index.claude_stale_family_carry.replay,
            vec![carry_replayed(&agent_key)]
        );
        assert_eq!(
            index.claude_usage_family_witnesses,
            before.claude_usage_family_witnesses
        );
        assert_eq!(
            index.session_account_bindings,
            before.session_account_bindings
        );
        assert_eq!(
            serde_json::to_value(&index.files[&carry_key(CARRY_OTHER, None)]).unwrap(),
            serde_json::to_value(&before.files[&carry_key(CARRY_OTHER, None)]).unwrap()
        );
    }
}

#[test]
fn scoped_unhealthy_retry_preserves_member_protection_and_scratch_refusal() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for protected in [true, false] {
        let mut index = carry_index();
        index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
        index.claude_duplicate_fence_next_full_rearm_unix_seconds =
            rfc3339_unix_seconds(CARRY_FAILED).map(|now| now + 86_400);
        for key in carry_family_keys() {
            scoped_retry_accept_member(&mut index, &key);
        }
        index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
        if protected {
            let member = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
            index.claude_reemission_exclusions = ReemissionExclusions::parse(
                format!("{:x}\n", Sha256::digest(member.as_bytes())).as_bytes(),
            );
        }
        let _refused = (!protected).then(RefuseClaudeStaleFamilyCarryBudgetForTest::new);
        let row = carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["carried_pending_families"], 0);
        for key in carry_family_keys() {
            assert!(index.files[&key].source_file_fingerprint.is_empty());
        }
    }
}

#[test]
fn scoped_retry_preserves_actual_rearms_and_selection() {
    // Portable CI exercises BASE fallback; macOS exercises the funded carry.
    let supported = crate::heap_layout_bound::layout_supported();
    let mut fixture = scoped_retry_fixture(3, 320, true);
    for root in fixture.roots.iter().take(3) {
        fixture
            .index
            .claude_usage_authority_quarantine
            .get_mut(root)
            .unwrap()
            .proven_witness_fingerprint = "stale-binding".into();
    }
    let before = serde_json::to_value(&fixture.index.claude_usage_authority_quarantine).unwrap();
    let mut unobserved = fixture.index.clone();
    {
        carry_start(&mut unobserved, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    }
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    let actual = fixture
        .index
        .files
        .iter()
        .filter(|(_, entry)| entry.source_file_fingerprint.is_empty())
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        row["rearmed_index_files"].as_u64(),
        Some(actual.len() as u64)
    );
    if supported {
        let held = fixture
            .roots
            .iter()
            .take(3)
            .map(|root| local_index_key(&fixture._scratch.join(format!("{root}.jsonl"))))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, held);
        assert_eq!(row["carried_pending_families"], 320);
    } else {
        assert_eq!(actual.len(), 323);
        assert_eq!(row["carried_pending_families"], 0);
    }
    assert_eq!(
        serde_json::to_value(&fixture.index.files).unwrap(),
        serde_json::to_value(&unobserved.files).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&fixture.index.claude_usage_authority_quarantine).unwrap(),
        before
    );

    if supported {
        // Invalid carry provenance re-arms its actual roots plus a replay-only
        // key outside them. The consumed replay ordering cannot affect reads.
        let extra = fixture
            .candidates
            .iter()
            .find(|candidate| {
                claude_index_path_member_ref(&candidate.path).unwrap().root == CARRY_OTHER
            })
            .unwrap();
        fixture
            .index
            .claude_stale_family_carry
            .replay
            .push(carry_replayed(&local_index_key(&extra.path)));
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_mut()
            .unwrap()
            .process = claude_full_rearm_process().wrapping_add(1);
        fixture
            .index
            .traversal
            .as_mut()
            .unwrap()
            .pending_candidates
            .push_back(carry_replayed(&local_index_key(
                &fixture.candidates[0].path,
            )));
        let mut unobserved = fixture.index.clone();
        {
            carry_start(&mut unobserved, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
        }
        carry_start(&mut fixture.index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
        assert!(fixture
            .index
            .files
            .values()
            .all(|entry| entry.source_file_fingerprint.is_empty()));
        assert_eq!(
            serde_json::to_value(&fixture.index.files).unwrap(),
            serde_json::to_value(&unobserved.files).unwrap()
        );
    }
}

#[test]
fn scaled_accepted_history_carries_6356_families_through_retry_deadline_expiry() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const HEALTHY: usize = 6356;
    let mut fixture = scoped_retry_fixture(1, HEALTHY, false);
    let held = fixture.roots[0].clone();
    fixture
        .index
        .claude_usage_family_witnesses
        .retain(|root, _| root == &held);
    let healthy = fixture
        .candidates
        .iter()
        .filter(|candidate| claude_index_path_member_ref(&candidate.path).unwrap().root != held)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(healthy.len(), HEALTHY);
    let stale = fixture
        .index
        .claude_usage_family_pending
        .keys()
        .cloned()
        .collect();
    assert!(
        !claude_stale_family_carry_scratch_admitted(&fixture.index, &stale, 0),
        "the former whole-graph gate actually refuses this scale"
    );
    fixture
        .index
        .claude_duplicate_fence_next_full_rearm_unix_seconds =
        rfc3339_unix_seconds(CARRY_SECOND_RETRY);
    let before = serde_json::to_value(&fixture.index).unwrap();
    for at in [CARRY_RETRY, CARRY_SECOND_RETRY, "2026-08-03T07:31:00Z"] {
        // Starting a retry frees old pending payload and retained carry.
        // Count born-in-scope pointers so those pre-existing frees cannot
        // hide a peak or make the signed net-allocation probe negative.
        let (row, allocations) = crate::retry_allocation_probe::measure_caller_thread(|| {
            carry_start(&mut fixture.index, at, BACKFILL_WINDOW_DAYS)
        });
        assert!(
            allocations.requested_peak <= crate::source_rotation::PARKED_BUDGET,
            "bounded start scratch: {}",
            allocations.requested_peak
        );
        assert_eq!(row["reason"], "terminal_unhealthy_retry");
        assert_eq!(row["carried_pending_families"], HEALTHY);
        assert_eq!(row["rearmed_index_files"], 0);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &healthy),
            0,
            "cold acquisition state, including after the fence deadline"
        );
        assert!(fixture
            .index
            .claude_full_rearm_progress
            .full_rearm_window
            .is_none());
        assert_eq!(fixture.index.claude_usage_authority_pending_count(), 1);
        assert!(fixture.index.claude_duplicate_request_witness_overflowed);
        for field in [
            "session_account_bindings",
            "accepted_snapshot_fingerprints",
            "file_snapshot_fingerprints",
            "claude_usage_authority_quarantine",
        ] {
            assert_eq!(
                serde_json::to_value(&fixture.index).unwrap()[field],
                before[field],
                "{field}"
            );
        }
        // A red terminal persists between unhealthy retries; local process
        // acquisition cache is never populated for these healthy files.
        fixture
            .index
            .traversal
            .as_mut()
            .unwrap()
            .pending_directories
            .clear();
        fixture
            .index
            .traversal
            .as_mut()
            .unwrap()
            .pending_candidates
            .clear();
        carry_red(&mut fixture.index, at, 7);
        fixture
            .index
            .traversal
            .as_mut()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds = rfc3339_unix_seconds(at);
        let exclusions = fixture.index.claude_reemission_exclusions.clone();
        fixture.index = carry_reload(fixture.index);
        fixture.index.claude_reemission_exclusions = exclusions;
    }
    // The unrelated held debt still retries when due, without charging any
    // healthy history a read. Authority custody and the fence stay intact.
    fixture
        .index
        .claude_usage_authority_quarantine
        .get_mut(&held)
        .unwrap()
        .retry_after_unix_seconds = 0;
    let held_candidates = fixture
        .candidates
        .iter()
        .filter(|c| claude_index_path_member_ref(&c.path).unwrap().root == held)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(scoped_retry_full_reads(&fixture.index, &held_candidates), 1);
    // A refused Fix 2 window remains BASE. Dropping its over-budget window
    // scratch must not accidentally make it look like a non-window retry.
    let context = fixture
        .index
        .traversal
        .as_ref()
        .unwrap()
        .context_fingerprint
        .clone();
    fixture.index.claude_full_rearm_progress.full_rearm_window = Some(ClaudeFullRearmWindow {
        context_fingerprint: context,
        process: claude_full_rearm_process(),
        window_ends: BTreeSet::from([CARRY_FAILED.to_string()]),
        member_digests: BTreeMap::new(),
    });
    let row = carry_start(
        &mut fixture.index,
        "2026-08-03T08:32:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    assert_eq!(row["carried_pending_families"], 0);
    assert!(healthy
        .iter()
        .all(|c| fixture.index.files[&local_index_key(&c.path)]
            .source_file_fingerprint
            .is_empty()));
}

#[test]
fn streaming_accepted_carry_matches_the_existing_family_refusals() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for damage in [
        "none",
        "duplicate_path",
        "missing_ack",
        "account_hold",
        "retained_stub",
        "missing_root",
        "foreign_member",
        "invalid_pending",
    ] {
        let mut fixture = scoped_retry_fixture(1, 4, false);
        let root = fixture.roots[1].clone();
        let key = local_index_key(&fixture._scratch.join(format!("{root}.jsonl")));
        match damage {
            "duplicate_path" => {
                let duplicate = format!("/another-project/{root}.jsonl");
                fixture
                    .index
                    .files
                    .insert(duplicate.clone(), fixture.index.files[&key].clone());
                fixture.index.file_snapshot_fingerprints.insert(
                    duplicate,
                    fixture.index.file_snapshot_fingerprints[&key].clone(),
                );
            }
            "missing_ack" => {
                let body = fixture.index.file_snapshot_fingerprints[&key]
                    .iter()
                    .next()
                    .unwrap()
                    .clone();
                fixture.index.accepted_snapshot_fingerprints.remove(&body);
            }
            "account_hold" => {
                fixture
                    .index
                    .claude_account_deferred_holds
                    .insert(key.clone(), "held".into());
            }
            "retained_stub" => {
                fixture
                    .index
                    .claude_request_census
                    .invalidate_keeping_birth(&key);
            }
            "missing_root" => {
                fixture.index.files.remove(&key);
            }
            "foreign_member" => {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .member_request_id_hashes
                    .insert("foreign".into(), BTreeSet::new());
            }
            "invalid_pending" => {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .invalid = true;
            }
            _ => {}
        }
        let stale = fixture
            .index
            .claude_usage_family_pending
            .keys()
            .cloned()
            .collect();
        let legacy = claude_fence_closed_retry_carry(&fixture.index, &stale, true, true, true);
        let streaming = claude_stream_accepted_retry_carry(&fixture.index, &stale).unwrap();
        assert_eq!(streaming.roots, legacy.roots, "{damage}");
        assert_eq!(
            streaming.roots.len(),
            if damage == "none" { 4 } else { 3 },
            "{damage}"
        );
    }
}

#[test]
fn accepted_carry_streams_when_request_graph_refuses_even_a_small_family_set() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = scoped_retry_fixture(0, 2, false);
    let root = fixture.roots[0].clone();
    let pending = fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap();
    pending.member_occurrences.clear();
    pending
        .member_request_id_hashes
        .insert(root, (0..12000).map(|n| format!("{n:064x}")).collect());
    let stale = fixture
        .index
        .claude_usage_family_pending
        .keys()
        .cloned()
        .collect();
    assert!(!claude_stale_family_carry_scratch_admitted(
        &fixture.index,
        &stale,
        0
    ));
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    let counts = stale_carry_diagnostics::take_for_test().unwrap();
    assert_eq!(
        counts.ordinary_scratch, 0,
        "streaming rescued the refused ordinary scratch"
    );
    assert_eq!(counts.rejected(), 0);
    assert_eq!(counts.eligible_before_funding, 2);
    assert_eq!(counts.final_carried, 2);
    assert_eq!(row["carried_pending_families"], 2);
    assert_eq!(row["rearmed_index_files"], 0);
    assert_eq!(
        scoped_retry_full_reads(&fixture.index, &fixture.candidates),
        0
    );
}

#[test]
fn scaled_retry_defers_without_clearing_when_cancellation_cannot_be_funded() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = scoped_retry_fixture(1, 6356, false);
    let files = serde_json::to_value(&fixture.index.files).unwrap();
    let pending = fixture.index.claude_usage_family_pending.clone();
    let bindings = fixture.index.session_account_bindings.clone();
    let old_window = fixture
        .index
        .traversal
        .as_ref()
        .unwrap()
        .census_window_end
        .clone();
    let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut fixture.index,
            CARRY_RETRY,
            BACKFILL_WINDOW_DAYS,
        )
    });
    assert!(!rows.iter().any(|r| r["counts"]["event"] == "starting"));
    assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), files);
    assert_eq!(fixture.index.claude_usage_family_pending, pending);
    assert_eq!(fixture.index.session_account_bindings, bindings);
    assert_eq!(
        fixture.index.traversal.as_ref().unwrap().census_window_end,
        old_window
    );
    assert_eq!(
        scoped_retry_full_reads(&fixture.index, &fixture.candidates),
        0
    );
}

#[test]
fn deferred_retry_resumes_after_transient_funding_refusal() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = scoped_retry_fixture(0, 6356, false);
    let before = serde_json::to_value(&fixture.index.files).unwrap();
    {
        let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut fixture.index,
            CARRY_RETRY,
            BACKFILL_WINDOW_DAYS,
        );
        assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), before);
    }
    let exclusions = fixture.index.claude_reemission_exclusions.clone();
    fixture.index = carry_reload(fixture.index);
    fixture.index.claude_reemission_exclusions = exclusions;
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 6356);
    assert_eq!(
        scoped_retry_full_reads(&fixture.index, &fixture.candidates),
        0
    );
}

include!("retry_admission_tests.rs");

// E3 PR1: exact accepted bodies may wait on global contract correction only.
fn contract_debt_fixture(healthy: usize) -> ScopedRetryFixture {
    let mut fixture = retry_durable_fixture(0, healthy);
    fixture.index.bounded_sweep_had_unsettled_upload = false;
    fixture.index.bounded_sweep_unsettled_causes = 0;
    fixture.index.claude_request_identity_contract_changed = true;
    fixture.index.active_effective_upload_body_witness_revision = 3;
    fixture
        .index
        .active_effective_upload_body_witness_revision_monotone = true;
    for entry in fixture.index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 3;
    }
    fixture
}

#[test]
fn contract_debt_defers_exact_acks_on_ordinary_streaming_and_batch_routes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for route in ["ordinary", "streaming", "batch"] {
        let mut fixture = contract_debt_fixture(3);
        let stale = fixture.roots.iter().cloned().collect();
        let before = serde_json::to_value(&fixture.index.files).unwrap();
        let accepted = fixture.index.accepted_snapshot_fingerprints.clone();
        let carry = match route {
            "ordinary" => {
                claude_fence_closed_retry_carry(&fixture.index, &stale, true, false, true)
            }
            "streaming" => claude_stream_accepted_retry_carry(&fixture.index, &stale).unwrap(),
            _ => claude_retry_admit_batch(&fixture.index, &stale, None, CARRY_RETRY).0,
        };
        assert_eq!(carry.roots, stale, "{route}");
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(scope.finish().contract.deferred_by_contract_debt, 3);
        assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), before);
        assert_eq!(fixture.index.accepted_snapshot_fingerprints, accepted);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &fixture.candidates),
            0
        );
        assert!(fixture.index.claude_request_identity_contract_changed);
        assert!(fixture.index.claude_duplicate_request_witness_overflowed);
        for pending in fixture.index.claude_usage_family_pending.values() {
            assert_eq!(pending.census_window_end, CARRY_FAILED);
            assert!(pending.member_occurrences.is_empty());
            assert!(pending
                .member_request_id_hashes
                .values()
                .all(BTreeSet::is_empty));
        }
        let previous = fixture.index.clone();
        let partial =
            fixture
                .index
                .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert!(partial.claude_request_identity_contract_changed);
        let exclusions = fixture.index.claude_reemission_exclusions.clone();
        fixture.index = carry_reload(fixture.index);
        fixture.index.claude_reemission_exclusions = exclusions;
        fixture.index.active_effective_upload_body_witness_revision = 3;
        carry_red(&mut fixture.index, CARRY_RETRY, 1);
        carry_start(&mut fixture.index, CARRY_SECOND_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(
            scoped_retry_full_reads(&fixture.index, &fixture.candidates),
            0
        );
        assert!(fixture.index.claude_request_identity_contract_changed);
    }
}

#[test]
fn contract_debt_refuses_every_other_obligation_on_all_carry_routes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "missing_ack",
        "partial_ack",
        "account_hold",
        "authority_retry",
        "identity_hold",
        "owed_revision",
        "money_rule",
        "unsettled",
        "held_scope",
        "withheld",
        "listed",
    ] {
        let mut fixture = contract_debt_fixture(1);
        let root = fixture.roots[0].clone();
        let key = local_index_key(&fixture.candidates[0].path);
        match case {
            "missing_ack" => fixture.index.accepted_snapshot_fingerprints.clear(),
            "partial_ack" => {
                fixture
                    .index
                    .file_snapshot_fingerprints
                    .get_mut(&key)
                    .unwrap()
                    .insert("9".repeat(64));
                scoped_retry_accept_member(&mut fixture.index, &key);
            }
            "account_hold" => {
                fixture
                    .index
                    .claude_account_deferred_holds
                    .insert(key.clone(), "held".into());
            }
            "authority_retry" => fixture.index.bind_retry_pending_claude_authority_for_test(
                &root,
                BTreeMap::from([(
                    root.clone(),
                    fixture.index.files[&key].source_file_fingerprint.clone(),
                )]),
            ),
            "identity_hold" => {
                fixture
                    .index
                    .claude_usage_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .invalid = true
            }
            "owed_revision" => {
                fixture
                    .index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .effective_upload_body_witness_revision = 2
            }
            "money_rule" => {
                assert!(fixture
                    .index
                    .re_owe_effective_upload_body_witness_revision(&key, 2));
            }
            "unsettled" => fixture
                .index
                .mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds),
            "held_scope" => fixture
                .index
                .mark_bounded_sweep_held_by_families(Some(&BTreeSet::from([root.clone()]))),
            "withheld" => fixture
                .index
                .claude_request_census
                .invalidate_keeping_birth(&key),
            "listed" => {
                fixture.index.claude_reemission_exclusions = ReemissionExclusions::parse(
                    format!("{:x}\n", Sha256::digest(root.as_bytes())).as_bytes(),
                )
            }
            _ => unreachable!(),
        }
        let stale = BTreeSet::from([root.clone()]);
        assert!(
            claude_fence_closed_retry_carry(&fixture.index, &stale, true, true, true)
                .roots
                .is_empty(),
            "ordinary: {case}"
        );
        assert!(
            claude_stream_accepted_retry_carry(&fixture.index, &stale)
                .unwrap()
                .roots
                .is_empty(),
            "streaming: {case}"
        );
        assert!(
            claude_retry_admit_batch(&fixture.index, &stale, None, CARRY_RETRY)
                .0
                .roots
                .is_empty(),
            "batch: {case}"
        );
        assert!(
            fixture.index.claude_request_identity_contract_changed,
            "{case}"
        );
    }
}

#[test]
fn contract_debt_keeps_context_and_ledger_vetoes_and_changed_member_selection() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for case in [
        "ledger",
        "upload_context",
        "content",
        "sidecar",
        "account",
        "scratch",
    ] {
        let mut fixture = contract_debt_fixture(2);
        let changed_member = matches!(case, "content" | "sidecar" | "account");
        if changed_member {
            // Cancellation replays siblings: use the existing two-member
            // accepted fixture, rather than a singleton with no sibling work.
            fixture.index = carry_index();
            fixture.index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
            fixture.index.claude_request_identity_contract_changed = true;
            fixture
                .index
                .claude_duplicate_fence_next_full_rearm_unix_seconds =
                rfc3339_unix_seconds(CARRY_FAILED).map(|now| now + 86_400);
            let [root_key, agent_key] = carry_family_keys();
            fixture.candidates = vec![scoped_retry_accept_member(&mut fixture.index, &root_key)];
            scoped_retry_accept_member(&mut fixture.index, &agent_key);
        }
        let before = fixture.index.accepted_snapshot_fingerprints.clone();
        let _scratch = (case == "scratch").then(RefuseClaudeStaleFamilyCarryBudgetForTest::new);
        match case {
            "ledger" => fixture.index.accepted_snapshot_fingerprint_ledger_version = 0,
            "upload_context" => {
                fixture.index.active_upload_context_fingerprint = Some("changed".into())
            }
            _ => (),
        }
        carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        if changed_member {
            assert!(
                fixture.index.claude_stale_family_carry.contains(CARRY_ROOT),
                "{case}: the family is carried before its member changes"
            );
            let traversal = fixture.index.traversal.as_mut().unwrap();
            traversal.scan_roots = vec![PathBuf::from(CARRY_SCAN_ROOT)];
            traversal.observed_index_keys.extend(carry_family_keys());
            carry_fill_queue(&mut fixture.index);
        }
        let candidate = &mut fixture.candidates[0];
        match case {
            "content" => candidate.size_bytes += 1,
            "sidecar" | "account" => candidate.source_file_fingerprint = "e".repeat(64),
            _ => assert!(
                fixture.index.claude_stale_family_carry.roots.is_empty(),
                "{case}"
            ),
        }
        assert_eq!(
            fixture.index.candidate_decision_at(candidate, 1),
            CandidateDecision::Parse,
            "{case}"
        );
        if matches!(case, "content" | "sidecar" | "account") {
            let root = claude_index_path_member_ref(&candidate.path)
                .unwrap()
                .root
                .to_owned();
            cancel_claude_family_carry_for_member_parse(
                &mut fixture.index,
                CARRY_RETRY,
                &candidate.path,
                &[],
                &VecDeque::new(),
            );
            assert!(!fixture.index.claude_stale_family_carry.contains(&root));
            let agent_key = carry_key(CARRY_ROOT, Some(CARRY_AGENT));
            assert!(fixture.index.files[&agent_key]
                .source_file_fingerprint
                .is_empty());
            assert_eq!(
                fixture.index.claude_stale_family_carry.replay,
                vec![carry_replayed(&agent_key)]
            );
        }
        assert_eq!(fixture.index.accepted_snapshot_fingerprints, before);
        assert!(fixture.index.claude_request_identity_contract_changed);
        assert!(fixture.index.claude_duplicate_request_witness_overflowed);
    }
}

#[test]
fn contract_start_status_preserves_resume_placeholder_and_reowes_only_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }

    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::E2_GROUPING,
        || {
            let mut fixture = contract_debt_fixture(1);
            fixture.index.claude_request_identity_contract_changed = false;
            let key = local_index_key(&fixture.candidates[0].path);
            fixture
                .index
                .traversal
                .as_mut()
                .unwrap()
                .pending_directories
                .push_back(ScanTraversalPath {
                    path: PathBuf::from("/synthetic"),
                    scan_root: PathBuf::from("/synthetic"),
                    census_member: true,
                    watcher_hint: false,
                });
            fixture.index.observe_claude_request_identity_contract(true);
            // #825 (card G (b)): a late permit re-owes nothing (was 2).
            assert_eq!(
                fixture.index.files[&key].effective_upload_body_witness_revision,
                3
            );
            fixture
                .index
                .files
                .get_mut(&key)
                .unwrap()
                .effective_upload_body_witness_revision = 3;
            fixture.index.observe_claude_request_identity_contract(true);
            assert_eq!(
                fixture.index.files[&key].effective_upload_body_witness_revision, 3,
                "adoption re-owes only once"
            );
            let placeholder = fixture.index.claude_request_identity_contract.clone();
            assert_eq!(
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    &[],
                    &mut fixture.index,
                    CARRY_RETRY,
                    BACKFILL_WINDOW_DAYS
                ),
                TraversalProgress::Resumed
            );
            assert_eq!(fixture.index.claude_request_identity_contract, placeholder);
            carry_red(&mut fixture.index, CARRY_FAILED, 1);
            assert_eq!(
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    &[],
                    &mut fixture.index,
                    CARRY_RETRY,
                    BACKFILL_WINDOW_DAYS
                ),
                TraversalProgress::Started
            );
            fixture
                .index
                .record_started_claude_request_identity_contract(true);
            assert_eq!(
                fixture.index.claude_request_identity_contract.as_deref(),
                Some(claude_request_identity::E2_GROUPING)
            );
            assert!(fixture.index.claude_request_identity_contract_changed);
            assert_eq!(
                fixture.index.files[&key].effective_upload_body_witness_revision,
                3
            );
            fixture
                .index
                .observe_claude_request_identity_contract(false);
            assert_eq!(
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    &[PathBuf::from("/new-context")],
                    &mut fixture.index,
                    CARRY_SECOND_RETRY,
                    BACKFILL_WINDOW_DAYS
                ),
                TraversalProgress::Started
            );
            fixture
                .index
                .record_started_claude_request_identity_contract(false);
            assert_eq!(
                fixture.index.claude_request_identity_contract.as_deref(),
                Some("")
            );
            assert!(
                fixture.index.claude_request_identity_contract_changed,
                "denial with incomplete census cannot clear"
            );
        },
    );
    let counts = scope.finish().contract;
    assert_eq!(counts.identity_contract_latch.set, 1);
    assert_eq!(counts.identity_contract_latch.cleared, 0);
    assert_eq!(counts.identity_contract_transition.collector_e2_grouping, 1);
    assert_eq!(counts.identity_contract_transition.to_empty, 1);
    assert_eq!(
        counts
            .identity_contract_transition
            .mid_traversal_placeholder,
        4
    );
}

#[test]
fn contract_debt_scoped_hold_carries_only_settled_siblings() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = contract_debt_fixture(3);
    let held = fixture.roots[0].clone();
    fixture
        .index
        .mark_bounded_sweep_held_by_families(Some(&BTreeSet::from([held.clone()])));
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 2);
    assert!(!fixture.index.claude_stale_family_carry.contains(&held));
    assert!(fixture.roots[1..]
        .iter()
        .all(|root| fixture.index.claude_stale_family_carry.contains(root)));
    assert!(fixture.index.claude_request_identity_contract_changed);
}

#[test]
fn contract_debt_scratch_deferred_start_keeps_placeholder_and_old_window() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = contract_debt_fixture(2);
    fixture.index.claude_request_identity_contract =
        Some(CLAUDE_E2_IDENTITY_ADOPTION_PENDING.to_owned());
    fixture
        .index
        .claude_usage_family_pending
        .values_mut()
        .next()
        .unwrap()
        .member_request_id_hashes
        .values_mut()
        .next()
        .unwrap()
        .extend((0..12000).map(|n| format!("{n:064x}")));
    let before = serde_json::to_value(&fixture.index.files).unwrap();
    let _budget = ClaudeStaleFamilyCarryFundingBudgetForTest::new(0);
    assert_eq!(
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[],
            &mut fixture.index,
            CARRY_RETRY,
            BACKFILL_WINDOW_DAYS
        ),
        TraversalProgress::Resumed
    );
    assert_eq!(
        fixture.index.claude_request_identity_contract.as_deref(),
        Some(CLAUDE_E2_IDENTITY_ADOPTION_PENDING)
    );
    assert_eq!(
        fixture.index.traversal.as_ref().unwrap().census_window_end,
        CARRY_FAILED
    );
    assert_eq!(serde_json::to_value(&fixture.index.files).unwrap(), before);
    assert!(fixture.index.claude_request_identity_contract_changed);
}

#[test]
fn contract_debt_storage_recheck_cannot_forget_prior_scoped_hold() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for debt in [false, true] {
        let mut fixture = contract_debt_fixture(1);
        fixture.index.claude_request_identity_contract_changed = debt;
        let root = fixture.roots[0].clone();
        fixture
            .index
            .mark_bounded_sweep_held_by_families(Some(&BTreeSet::from([root.clone()])));
        let prior = claude_contract_debt_scope(&fixture.index);
        assert_eq!(
            claude_retry_singleton_storage_only_scoped(&fixture.index, &root, prior),
            !debt
        );
        let (_, _, mut state) = claude_retry_admit_batch(
            &fixture.index,
            &BTreeSet::from([root.clone()]),
            None,
            CARRY_RETRY,
        );
        // Seed the already admitted Structure-refused read obligation. This
        // regression concerns its later recheck, not the existing byte price.
        state.oversized_root = Some(root.clone());
        state.oversized_after_path = None;
        state.storage_deferred = false;
        state.complete = false;
        fixture.index.claude_stale_family_carry = ClaudeStaleFamilyCarry {
            origin: Some(ClaudeStaleFamilyCarryOrigin {
                context_fingerprint: fixture
                    .index
                    .traversal
                    .as_ref()
                    .unwrap()
                    .context_fingerprint
                    .clone(),
                process: claude_full_rearm_process(),
                full_rearm_window: false,
                admission: Some(state),
            }),
            ..Default::default()
        };
        fixture.index.traversal.as_mut().unwrap().scan_roots = vec![fixture._scratch.to_path_buf()];
        fixture.index.claude_full_rearm_progress.held_family_roots = None;
        fixture.index.bounded_sweep_had_unsettled_upload = false;
        fixture.index.bounded_sweep_unsettled_causes = 0;
        claude_retry_queue_due_families(&mut fixture.index, CARRY_RETRY);
        let state = fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap();
        assert_eq!(state.oversized_root.as_ref(), debt.then_some(&root));
        assert_eq!(state.storage_deferred, !debt);
        assert_eq!(
            fixture
                .index
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .len(),
            usize::from(debt),
            "debt keeps the held read obligation runnable"
        );
    }
}

#[test]
fn scanner_records_actual_contract_only_when_its_traversal_starts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut fixture = contract_debt_fixture(1);
    fixture.index.claude_request_identity_contract =
        Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL.to_owned());
    let scan = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &[],
        fixture.index,
        CARRY_RETRY,
        BACKFILL_WINDOW_DAYS,
        1,
        false,
        None,
        &[],
        false,
        true,
    );
    assert_eq!(
        scan.index.claude_request_identity_contract.as_deref(),
        Some(claude_request_identity::cycle_contract(true))
    );
    assert!(
        scan.index.claude_request_identity_contract_changed,
        "a real red-retry start records without clearing"
    );
    let mut index = scan.index;
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .push_back(ScanTraversalPath {
            path: fixture._scratch.join("missing"),
            scan_root: fixture._scratch.to_path_buf(),
            census_member: true,
            watcher_hint: false,
        });
    let scan = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &[],
        index,
        CARRY_SECOND_RETRY,
        BACKFILL_WINDOW_DAYS,
        1,
        false,
        None,
        &[],
        false,
        false,
    );
    assert_eq!(
        scan.index.claude_request_identity_contract.as_deref(),
        Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL)
    );
    assert!(
        scan.index.claude_request_identity_contract_changed,
        "a real resumed page retains the placeholder"
    );
}

/// [regress] A resumed Codex page erased outstanding Claude full_cause tags.
#[test]
fn resumed_codex_page_preserves_claude_full_cause() {
    use crate::transcript_acquisition::{FullReason, ReadMode};
    let key = carry_key(CARRY_ROOT, None);
    let mut entry = manifest_index_entry(Some("accepted"));
    entry.source_file_fingerprint = "proven".into();
    rearm_cause::clear(&key, &mut entry, rearm_cause::Cause::ContextChanged);

    let mut codex = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[],
        &mut codex,
        CARRY_FAILED,
        BACKFILL_WINDOW_DAYS,
    );
    assert_eq!(
        ensure_bounded_traversal(
            SnapshotSource::Codex,
            &[],
            &mut codex,
            CARRY_FAILED,
            BACKFILL_WINDOW_DAYS,
        ),
        TraversalProgress::Resumed,
    );
    let mode = ReadMode::Full(FullReason::StateMissing);
    let probe = crate::local_resource_diagnostics::Probe::start();
    probe.rearm_full_selected(&key, mode);
    probe.rearm_full_completed(&key, mode, 123);
    assert_eq!(
        serde_json::to_value(probe.rearm_fulls()).unwrap(),
        json!({"rearm_cleared{context_changed}": {"count": 1, "completed_native_bytes": 123}}),
    );
}

/// Evidence-owed fixture: the scoped-retry families, each member's census record bound
/// to the request ids its stored pending holds, after one whole-set re-arm
/// (BASE start: nothing carried) under `on`.
fn owed_rearmed(healthy: usize, on: bool) -> (ScopedRetryFixture, String) {
    let mut fixture = scoped_retry_fixture(0, healthy, false);
    for candidate in &fixture.candidates {
        let key = local_index_key(&candidate.path);
        let (root, member) = claude_index_path_family_member(&candidate.path).unwrap();
        let hashes =
            &fixture.index.claude_usage_family_pending[&root].member_request_id_hashes[&member];
        let record = scoped_retry_record(
            &key,
            serde_json::json!({
                "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
                "fp": fixture.index.files[&key].source_file_fingerprint,
                "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
                "s": "exact",
                "h": hashes.iter().map(|hash| &hash[..16]).collect::<String>(),
                "bi": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
                "bd": 1, "bn": 1,
            }),
        );
        fixture.index.claude_request_census.insert(key, record);
    }
    {
        let _base = KeepStaleClaudeFamilyRearmForTest::new();
        let _owed = on.then(evidence_owed::EvidenceOwedForTest::on);
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        assert_eq!(row["rearmed_index_files"], healthy);
    }
    let window = fixture
        .index
        .traversal
        .as_ref()
        .unwrap()
        .census_window_end
        .clone();
    (fixture, window)
}

/// The traversal's selection with the owed resolver: the members it parses.
fn owed_selected_parses(
    index: &mut ScanIndex,
    page: &mut evidence_owed::Page,
    candidates: &[CandidateFile],
    window: &str,
) -> usize {
    candidates
        .iter()
        .filter(|candidate| {
            let (mut decision, mut reason) = index.candidate_decision_with_reason_at(candidate, 0);
            evidence_owed::resolve(index, page, candidate, window, &mut decision, &mut reason);
            decision == CandidateDecision::Parse
        })
        .count()
}

/// [regress] Most Claude Full reads were `selection_cleared`: a whole-set
/// re-arm of unchanged ACKed families reads
/// every member on main; with evidence owed it reads none of them, and a
/// changed member is read once.
#[test]
fn owed_evidence_whole_set_rearm_reads_only_the_changed_member() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for on in [false, true] {
        let (mut fixture, window) = owed_rearmed(4, on);
        let _owed = on.then(evidence_owed::EvidenceOwedForTest::on);
        let mut candidates = fixture.candidates.clone();
        candidates[0].source_file_fingerprint = "f".repeat(64);
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let parsed = owed_selected_parses(
            &mut fixture.index,
            &mut evidence_owed::Page::default(),
            &candidates,
            &window,
        );
        assert_eq!(parsed, if on { 1 } else { 4 }, "on={on}");
        // Every owed visit is counted by outcome and evidence age.
        let counts = scope.finish().contract.evidence_owed;
        if on {
            assert_eq!((counts.restamped, counts.changed, counts.read), (3, 1, 0));
            let aged = counts.age_le_1h
                + counts.age_le_1d
                + counts.age_le_7d
                + counts.age_gt_7d
                + counts.age_unknown;
            assert_eq!(aged, 4);
        } else {
            assert_eq!(counts, Default::default());
        }
        let owed = fixture.index.files.values().filter(|e| e.evidence_owed);
        assert_eq!(
            owed.count(),
            usize::from(on),
            "only the changed member stays owed"
        );
    }
}

/// [money] A re-stamp's proof equals a fresh
/// Full's (the family pending a Full folds in this window: same ids, same
/// occurrences, observed for fence coverage), including a confirmed-empty
/// member with no pending re-stamped from its census record (a Full folds
/// nothing for it); both arms also against a real parse and fold of the same
/// bytes and from an identity-incomplete record of the same revision; an
/// owed cap-invalid family gets no read and no credit
/// unless its recorded requests fit the cap; and census completion retires
/// only proven families.
#[test]
fn owed_evidence_restamp_proof_equals_a_full_and_owed_families_get_no_credit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _owed = evidence_owed::EvidenceOwedForTest::on();
    owed_restamp_equals_a_real_fold_of_the_same_bytes();
    owed_identity_incomplete_restamp_equals_a_full();
    let (mut fixture, window) = owed_rearmed(2, true);
    let before = fixture.index.claude_usage_family_pending.clone();
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&fixture.index, &window),
        2,
        "owed members are not observed before their selection"
    );
    let parsed = owed_selected_parses(
        &mut fixture.index,
        &mut evidence_owed::Page::default(),
        &fixture.candidates,
        &window,
    );
    assert_eq!(parsed, 0);
    for (root, pending) in before.iter() {
        let full = ClaudeUsageFamilyPending {
            census_window_end: window.clone(),
            ..pending.clone()
        };
        assert_eq!(fixture.index.claude_usage_family_pending[root], full);
    }
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&fixture.index, &window),
        0
    );

    // A confirmed-empty member whose family has no pending (retired at a
    // completion): its record is current and holds no requests, so it
    // re-stamps from the record with no read. Pending stays exactly as a Full
    // leaves it (the empty parse yields no snapshot to fold) and the member
    // counts as observed. Under the latch, or with requests in the record, it
    // still reads.
    let (fixture, window) = owed_rearmed(2, true);
    let candidates = &fixture.candidates[1..];
    let key = local_index_key(&candidates[0].path);
    let (root, _) = claude_index_path_family_member(&candidates[0].path).unwrap();
    let record = |hashes: Option<&str>| {
        let mut value = serde_json::json!({
            "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
            "fp": fixture.index.files[&key].source_file_fingerprint,
            "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "s": if hashes.is_some() { "exact" } else { "empty" },
            "bi": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "bd": 1, "bn": 1,
        });
        if let Some(hashes) = hashes {
            value["h"] = hashes.into();
        }
        scoped_retry_record(&key, value)
    };
    let mut empty = fixture.index.clone();
    empty.claude_request_identity_contract =
        Some(claude_request_identity::cycle_contract(true).into());
    empty.claude_usage_family_pending.remove(&root);
    empty.confirmed_empty_files.insert(key.clone());
    empty
        .claude_request_census
        .insert(key.clone(), record(None));
    let full = empty.claude_usage_family_pending.clone();
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&empty, &window),
        2
    );
    let mut index = empty.clone();
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    let parsed = owed_selected_parses(
        &mut index,
        &mut evidence_owed::Page::default(),
        candidates,
        &window,
    );
    assert_eq!(parsed, 0);
    assert_eq!(
        scope.finish().contract.evidence_owed.restamped_from_record,
        1
    );
    assert_eq!(index.claude_usage_family_pending, full);
    assert!(!index.files[&key].evidence_owed);
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&index, &window),
        1
    );
    for (latched, requests) in [(true, false), (false, true)] {
        let mut index = empty.clone();
        index.claude_request_identity_contract_changed = latched;
        if requests {
            index
                .claude_request_census
                .insert(key.clone(), record(Some("0123456789abcdef")));
        }
        let parsed = owed_selected_parses(
            &mut index,
            &mut evidence_owed::Page::default(),
            candidates,
            &window,
        );
        assert_eq!(parsed, 1, "latched={latched} requests={requests}");
        assert!(index.files[&key].evidence_owed);
    }

    // Cap-invalid: invalid, evidence-free pending from the record's window.
    let (mut fixture, window) = owed_rearmed(1, true);
    let root = fixture.roots[0].clone();
    let pending = fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap();
    pending.member_occurrences.clear();
    pending.member_request_id_hashes.clear();
    pending.invalid = true;
    let invalid = pending.clone();
    // Under the identity-contract latch it is read, never kept waiting.
    for (cap, latched, parsed) in [
        (0, false, 0),
        (MAX_CLAUDE_PENDING_USAGE_OCCURRENCES, false, 1),
        (0, true, 1),
    ] {
        let mut index = fixture.index.clone();
        index.claude_request_identity_contract_changed = latched;
        let mut page = evidence_owed::Page {
            cap,
            ..Default::default()
        };
        assert_eq!(
            owed_selected_parses(&mut index, &mut page, &fixture.candidates, &window),
            parsed,
            "cap {cap} latched {latched}"
        );
        assert_eq!(index.claude_usage_family_pending[&root], invalid);
        assert!(index.files.values().all(|entry| entry.evidence_owed));
        assert_eq!(
            claude_duplicate_fence_coverage_missing_member_count(&index, &window),
            1
        );
    }

    // An indexed family this census did not prove stays owed.
    let indexed = BTreeSet::from([root.clone()]);
    assert!(evidence_owed::owed_at_completion(
        &root, &invalid, false, &indexed
    ));
    assert!(!evidence_owed::owed_at_completion(
        &root, &invalid, true, &indexed
    ));
    assert!(!evidence_owed::owed_at_completion(
        &root,
        &invalid,
        false,
        &BTreeSet::new()
    ));
}

/// Both re-stamp arms against a real parse and fold of the same bytes (the
/// account family fixture's root and child, plus two members whose transcripts
/// parse to no snapshot: one with no response, one whose only response is an
/// API error, an id with no usage, recorded identity incomplete): the pending
/// a Full folds in this window, with its ids and per-request usage, equals the
/// earlier window's real fold re-stamped from pending and from the census
/// records, with no read; each record stays as the Full rewrites it, and fence
/// coverage is the Full's. No body is re-emitted: the bodies the earlier fold
/// emitted equal a Full's (the emitted-money oracle, with placement), so the
/// accepted totals and placement stand.
fn owed_restamp_equals_a_real_fold_of_the_same_bytes() {
    let (dir, parent, items) = claude_account_family_fixture(false);
    let subagents = dir.join(&parent).join("subagents");
    let empty = subagents.join("agent-b4d1585d310070d0f.jsonl");
    fs::write(
        &empty,
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"user\",\"sessionId\":\"{parent}\",\"agentId\":\"b4d1585d310070d0f\",\"isSidechain\":true,\"message\":{{\"role\":\"user\",\"content\":\"x\"}}}}\n"
        ),
    )
    .unwrap();
    let api_error = subagents.join("agent-c4d1585d310070d0f.jsonl");
    fs::write(
        &api_error,
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:06Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"agentId\":\"c4d1585d310070d0f\",\"isSidechain\":true,\"requestId\":\"req_err\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":0,\"output_tokens\":0}}}}}}\n"
        ),
    )
    .unwrap();
    for path in [&empty, &api_error] {
        assert!(
            parse_claude_code_jsonl_file(path, CARRY_FAILED, "empty".to_string())
                .unwrap()
                .is_empty(),
            "a confirmed-empty parse"
        );
    }
    let paths = [
        dir.join(format!("{parent}.jsonl")),
        subagents.join("agent-a4d1585d310070d0f.jsonl"),
        empty,
        api_error.clone(),
    ];
    let (mut index, candidates) = real_family_index(&paths);
    index
        .confirmed_empty_files
        .insert(local_index_key(&paths[2]));
    index
        .confirmed_empty_files
        .insert(local_index_key(&paths[3]));
    let mut full = index.clone();
    let full_bodies = fold_real(&mut full, &items, CARRY_RETRY);
    let folded = &full.claude_usage_family_pending[&parent];
    assert!(
        !folded.invalid && folded.member_occurrences.len() == 2,
        "{folded:?}"
    );

    let mut owed = index;
    let earlier_bodies = fold_real(&mut owed, &items, CARRY_FAILED);
    assert_bodies_equal_a_full(&full_bodies, &earlier_bodies);
    let api_error = local_index_key(&api_error);
    for path in &paths {
        let key = local_index_key(path);
        let (_, member) = claude_index_path_family_member(path).unwrap();
        let fingerprint = owed.files[&key].source_file_fingerprint.clone();
        let hashes = owed.claude_usage_family_pending[&parent]
            .member_request_id_hashes
            .get(&member)
            .map(|hashes| hashes.iter().map(|hash| &hash[..16]).collect::<String>());
        let mut record = serde_json::json!({
            "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
            "fp": fingerprint,
            "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "s": if hashes.is_some() { "exact" } else { "empty" },
            "bi": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "bd": 1, "bn": 1,
        });
        if let Some(hashes) = hashes {
            record["h"] = hashes.into();
        }
        if key == api_error {
            record["s"] = "identity_incomplete".into();
            record["h"] = format!("{:x}", Sha256::digest(b"req_err"))[..16].into();
        }
        let record = scoped_retry_record(&key, record);
        owed.claude_request_census
            .insert(key.clone(), record.clone());
        full.claude_request_census.insert(key.clone(), record);
        evidence_owed::clear(owed.files.get_mut(&key).unwrap());
    }
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    for candidate in &candidates {
        let (mut decision, mut reason) = (CandidateDecision::Skip, None);
        evidence_owed::resolve(
            &mut owed,
            &mut evidence_owed::Page::default(),
            candidate,
            CARRY_RETRY,
            &mut decision,
            &mut reason,
        );
        assert_eq!(decision, CandidateDecision::Skip, "no read");
    }
    let counts = scope.finish().contract.evidence_owed;
    assert_eq!(
        (counts.restamped, counts.restamped_from_record, counts.read),
        (2, 2, 0),
        "{counts:?}"
    );
    assert!(owed.files.values().all(|entry| !entry.evidence_owed));
    assert_eq!(
        owed.claude_usage_family_pending,
        full.claude_usage_family_pending
    );
    assert_eq!(owed.claude_request_census, full.claude_request_census);
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&owed, CARRY_RETRY),
        claude_duplicate_fence_coverage_missing_member_count(&full, CARRY_RETRY),
    );
    fs::remove_dir_all(dir).unwrap();
}

/// Index entries and unchanged candidates for real transcripts, under the
/// recorded cycle contract.
fn real_family_index(paths: &[PathBuf]) -> (ScanIndex, Vec<CandidateFile>) {
    let mut index = ScanIndex {
        claude_request_identity_contract: Some(
            claude_request_identity::cycle_contract(true).to_string(),
        ),
        ..ScanIndex::default()
    };
    let mut candidates = Vec::new();
    for path in paths {
        let key = local_index_key(path);
        let mut entry = manifest_index_entry(None);
        entry.source_file_fingerprint = format!("{:x}", Sha256::digest(key.as_bytes()));
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
        let mut candidate = test_candidate(path.clone());
        candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
        candidate.legacy_source_file_fingerprint = entry.source_file_fingerprint.clone();
        candidate.size_bytes = entry.size_bytes;
        candidate.modified_unix_seconds = entry.modified_unix_seconds;
        candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap();
        index.files.insert(key, entry);
        candidates.push(candidate);
    }
    (index, candidates)
}

/// A real fold of `page` in `window`; returns the folded bodies a Full emits.
fn fold_real(index: &mut ScanIndex, page: &[SnapshotItem], window: &str) -> Vec<SnapshotItem> {
    let mut page = page.to_vec();
    apply_claude_reported_usage_with_index_and_limits(
        &mut page,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::new(),
            health: Default::default(),
        },
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        index,
        false,
        window,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    );
    page
}

/// A census record of this revision, read in the earlier window.
fn real_record(
    index: &ScanIndex,
    key: &str,
    shape: &str,
    hashes: impl IntoIterator<Item = String>,
) -> claude_request_census::ClaudeRequestCensusRecord {
    let prefixes = hashes
        .into_iter()
        .map(|hash| hash[..16].to_string())
        .collect::<BTreeSet<_>>();
    let mut record = serde_json::json!({
        "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
        "fp": index.files[key].source_file_fingerprint,
        "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
        "s": shape,
        "bi": rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
        "bd": 1, "bn": 1,
    });
    if !prefixes.is_empty() {
        record["h"] = prefixes.into_iter().collect::<String>().into();
    }
    scoped_retry_record(key, record)
}

/// Resolve each owed candidate in `window`, then record the ones it reads as
/// the scan does after their parse; returns them.
fn owed_reads(index: &mut ScanIndex, candidates: &[CandidateFile], window: &str) -> Vec<PathBuf> {
    let mut reads = Vec::new();
    for candidate in candidates {
        let (mut decision, mut reason) = (CandidateDecision::Skip, None);
        evidence_owed::resolve(
            index,
            &mut evidence_owed::Page::default(),
            candidate,
            window,
            &mut decision,
            &mut reason,
        );
        if decision == CandidateDecision::Parse {
            reads.push(candidate.path.clone());
        }
    }
    for candidate in candidates.iter().filter(|candidate| reads.contains(&candidate.path)) {
        index.record(candidate.clone(), None, ScanParseOutcome::Snapshot);
    }
    reads
}

/// An owed member re-stamps from this revision's identity-incomplete census
/// record (an id-less response or a repeated id; the incompleteness is a
/// function of the file's own bytes) when its stored ids are exactly the
/// record's, one per stored request: pending and records equal a Full's, fence
/// coverage is the Full's and the earlier fold's bodies equal a Full's. A
/// record that also holds an id the pending lacks (an API error's) refuses and
/// reads. Real id-less and repeated-id transcripts, through the real fold and
/// census record generation, get an identity-incomplete record and invalid
/// pending (fewer ids than requests), so they never re-stamp: each is read and
/// ends equal to a Full (pending, records, fence coverage, emitted money).
fn owed_identity_incomplete_restamp_equals_a_full() {
    let (dir, parent, items) = claude_account_family_fixture(false);
    let paths = [
        dir.join(format!("{parent}.jsonl")),
        dir.join(&parent)
            .join("subagents")
            .join("agent-a4d1585d310070d0f.jsonl"),
    ];
    for api_error in [false, true] {
        let (index, candidates) = real_family_index(&paths);
        let mut owed = index.clone();
        let earlier = fold_real(&mut owed, &items, CARRY_FAILED);
        let mut full = index;
        assert_bodies_equal_a_full(&fold_real(&mut full, &items, CARRY_RETRY), &earlier);
        for path in &paths {
            let key = local_index_key(path);
            let (_, member) = claude_index_path_family_member(path).unwrap();
            let mut hashes =
                owed.claude_usage_family_pending[&parent].member_request_id_hashes[&member].clone();
            if api_error && member == parent {
                hashes.insert(format!("{:x}", Sha256::digest(b"req_err")));
            }
            let record = real_record(&owed, &key, "identity_incomplete", hashes);
            owed.claude_request_census
                .insert(key.clone(), record.clone());
            full.claude_request_census.insert(key.clone(), record);
            evidence_owed::clear(owed.files.get_mut(&key).unwrap());
        }
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let reads = owed_reads(&mut owed, &candidates, CARRY_RETRY);
        let counts = scope.finish().contract.evidence_owed;
        assert_eq!(
            (counts.restamped, counts.refused_record, reads.len()),
            if api_error { (1, 1, 1) } else { (2, 0, 0) },
            "api_error={api_error}"
        );
        let read = items
            .iter()
            .filter(|item| {
                reads.iter().any(|path| {
                    claude_index_path_family_member(path)
                        .is_some_and(|(_, member)| member == item.source_session_id)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        fold_real(&mut owed, &read, CARRY_RETRY);
        assert_eq!(
            owed.claude_usage_family_pending, full.claude_usage_family_pending,
            "api_error={api_error}"
        );
        assert_eq!(owed.claude_request_census, full.claude_request_census);
        assert_eq!(
            claude_duplicate_fence_coverage_missing_member_count(&owed, CARRY_RETRY),
            claude_duplicate_fence_coverage_missing_member_count(&full, CARRY_RETRY),
        );
    }
    fs::remove_dir_all(dir).unwrap();

    let response = |session: &str, request: Option<&str>, message: &str, second: u32| {
        let mut value = serde_json::json!({
            "timestamp": format!("2026-08-02T07:00:{second:02}Z"),
            "type": "assistant",
            "sessionId": session,
            "message": {
                "id": message,
                "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 10},
            },
        });
        if let Some(request) = request {
            value["requestId"] = request.into();
        }
        format!("{value}\n")
    };
    for (session, lines) in [
        (
            "2338a80a-f36e-4cbc-a5bb-50fc66430ba5",
            [(Some("req_a"), "msg_a"), (None, "msg_b")],
        ),
        (
            "3338a80a-f36e-4cbc-a5bb-50fc66430ba5",
            [(Some("req_r"), "msg_r1"), (Some("req_r"), "msg_r2")],
        ),
    ] {
        let dir = crate::test_scratch::private_dir("claude-owed-identity-incomplete");
        let path = dir.join(format!("{session}.jsonl"));
        let body = lines
            .iter()
            .enumerate()
            .map(|(second, (request, message))| response(session, *request, message, second as u32))
            .collect::<String>();
        fs::write(&path, body).unwrap();
        let items =
            parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "fp".to_string()).unwrap();
        assert!(
            items.len() == 1 && !items[0].claude_context_curve_identity_complete,
            "{session}"
        );
        let (index, candidates) = real_family_index(std::slice::from_ref(&path));
        let key = local_index_key(&path);
        let fingerprint = index.files[&key].source_file_fingerprint.clone();
        let census = |index: &mut ScanIndex, window: &str| {
            claude_request_census::record_claude_request_census(
                index,
                claude_request_census::ClaudeRequestCensusParse {
                    path: &path,
                    index_key: &key,
                    source_file_fingerprint: &fingerprint,
                    census_window_end: window,
                    complete: true,
                    lossy: false,
                    source_verified: true,
                    unchanged_source: false,
                    itemless_request_hashes: Vec::new(),
                    opened_birth: None,
                    modified_unix_seconds: 0,
                },
                &items,
            )
        };
        let mut owed = index.clone();
        fold_real(&mut owed, &items, CARRY_FAILED);
        census(&mut owed, CARRY_FAILED);
        let mut full = index;
        let full_bodies = fold_real(&mut full, &items, CARRY_RETRY);
        census(&mut full, CARRY_RETRY);
        assert!(
            owed.claude_request_census
                .get(&key)
                .is_some_and(|record| record.idless_native_for(&fingerprint)),
            "{session}: identity incomplete"
        );
        assert!(
            owed.claude_usage_family_pending[session].invalid,
            "{session}"
        );
        evidence_owed::clear(owed.files.get_mut(&key).unwrap());
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let reads = owed_reads(&mut owed, &candidates, CARRY_RETRY);
        let counts = scope.finish().contract.evidence_owed;
        assert_eq!(
            (
                counts.refused_pending_invalid,
                counts.restamped,
                reads.len()
            ),
            (1, 0, 1),
            "{session}: read"
        );
        let bodies = fold_real(&mut owed, &items, CARRY_RETRY);
        census(&mut owed, CARRY_RETRY);
        assert_bodies_equal_a_full(&full_bodies, &bodies);
        assert_eq!(
            owed.claude_request_census, full.claude_request_census,
            "{session}"
        );
        assert_eq!(
            claude_duplicate_fence_coverage_missing_member_count(&owed, CARRY_RETRY),
            claude_duplicate_fence_coverage_missing_member_count(&full, CARRY_RETRY),
        );
        assert_eq!(
            owed.claude_usage_family_pending, full.claude_usage_family_pending,
            "{session}"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

/// The emitted-money oracle (`assert_equivalent`, placement included) over
/// folded pages: `full` is what a Full of these bytes emits, `kept` the bodies
/// a route leaves accepted without re-emitting them.
pub(super) fn assert_bodies_equal_a_full(full: &[SnapshotItem], kept: &[SnapshotItem]) {
    let route = |items: &[SnapshotItem]| {
        let mut scan = SourceScanResult::empty(SnapshotSource::ClaudeCode);
        scan.snapshots = items.to_vec();
        sampled_scan::transition_fixture::scan_money(
            SnapshotSource::ClaudeCode,
            &ScanIndex::default(),
            &scan,
        )
    };
    sampled_scan::transition_fixture::money_oracle::assert_equivalent(&route(full), &route(kept));
}

/// [money] With the identity-contract latch SET, a family whose pending is
/// stamped with the recorded, real contract re-stamps with no read and its
/// pending equals a Full's fold, but every member stays owed so fence
/// coverage, family proof and retirement stay vetoed. A legacy (None), mixed
/// (other contract or body-witness revision) or placeholder-recorded family
/// reads. A contract-unproven family proves its contract only through its own
/// stamp.
#[test]
fn owed_evidence_contract_stamp_restamps_under_the_latch_and_keeps_the_vetoes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _owed = evidence_owed::EvidenceOwedForTest::on();
    let (mut fixture, window) = owed_rearmed(2, true);
    fixture.index.claude_request_identity_contract =
        Some(claude_request_identity::cycle_contract(true).into());
    fixture.index.claude_request_identity_contract_changed = true;
    let current = evidence_owed::EvidenceContract::current(&fixture.index);
    assert!(current.is_some());
    let mut mixed = fixture.index.clone();
    mixed.active_effective_upload_body_witness_revision += 1;
    let mixed = evidence_owed::EvidenceContract::current(&mixed);
    let stamp = |index: &mut ScanIndex, stamp| {
        for pending in index.claude_usage_family_pending.values_mut() {
            pending.identity_contract = stamp;
        }
    };
    let visit = |index: &mut ScanIndex| {
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let parsed = owed_selected_parses(
            index,
            &mut evidence_owed::Page::default(),
            &fixture.candidates,
            &window,
        );
        (parsed, scope.finish().contract.evidence_owed)
    };

    let mut index = fixture.index.clone();
    stamp(&mut index, current);
    let before = index.claude_usage_family_pending.clone();
    let (parsed, counts) = visit(&mut index);
    assert_eq!(parsed, 0);
    assert_eq!((counts.restamped_under_latch, counts.restamped), (2, 0));
    for (root, pending) in before.iter() {
        let full = ClaudeUsageFamilyPending {
            census_window_end: window.clone(),
            ..pending.clone()
        };
        assert_eq!(index.claude_usage_family_pending[root], full);
    }
    assert!(
        index.claude_request_identity_contract_changed,
        "latch untouched"
    );
    assert!(index.files.values().all(|entry| entry.evidence_owed));
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&index, &window),
        2,
        "no fence coverage under the latch"
    );
    assert_eq!(
        evidence_owed::owed_roots(&index),
        fixture.roots.iter().cloned().collect(),
        "family proof skips owed roots"
    );

    let mut placeholder = fixture.index.clone();
    stamp(&mut placeholder, current);
    placeholder.claude_request_identity_contract =
        Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL.into());
    for (name, mut index) in [
        ("legacy", fixture.index.clone()),
        ("mixed", {
            let mut index = fixture.index.clone();
            stamp(&mut index, mixed);
            index
        }),
        ("placeholder", placeholder),
    ] {
        let (parsed, counts) = visit(&mut index);
        assert_eq!(parsed, 2, "{name}");
        assert_eq!(
            (counts.refused_contract_latch, counts.restamped_under_latch),
            (2, 0),
            "{name}"
        );
    }

    // After an exempt latch clear and the quarantine lifting, the family
    // proves its contract only through its own stamp: without it every owed
    // member takes the Full path, never a re-stamp through the cleared latch.
    for (stamped, parsed, restamped, refused) in [(false, 2, 0, 2), (true, 0, 2, 0)] {
        let mut index = fixture.index.clone();
        index.claude_request_identity_contract_changed = false;
        stamp(&mut index, stamped.then_some(current).flatten());
        for pending in index.claude_usage_family_pending.values_mut() {
            pending.contract_unproven = true;
        }
        let (got, counts) = visit(&mut index);
        assert_eq!(
            (got, counts.restamped, counts.refused_contract_unproven),
            (parsed, restamped, refused),
            "stamped={stamped}"
        );
    }
}

/// [behaviour] Owed Fulls share ONE per-page allowance
/// (the paced history-upgrade re-read budget). Past it an owed read is
/// deferred, counted, and requeued as a non-member re-read, still owed.
#[test]
fn owed_evidence_reads_are_capped_per_page() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _owed = evidence_owed::EvidenceOwedForTest::on();
    let (mut fixture, window) = owed_rearmed(3, true);
    // No pending to re-stamp from and requests in the record: each must read.
    fixture.index.claude_usage_family_pending.clear();
    let mut index = fixture.index.clone();
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    let parsed = owed_selected_parses(
        &mut index,
        &mut evidence_owed::Page::default(),
        &fixture.candidates,
        &window,
    );
    let counts = scope.finish().contract.evidence_owed;
    assert_eq!(
        (
            parsed,
            counts.read,
            counts.refused_no_pending,
            counts.restamped
        ),
        (3, 3, 3, 0)
    );

    let queued = fixture
        .index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .len();
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    let mut page = evidence_owed::Page {
        read_cap: 1,
        ..Default::default()
    };
    let parsed = owed_selected_parses(&mut fixture.index, &mut page, &fixture.candidates, &window);
    let counts = scope.finish().contract.evidence_owed;
    assert_eq!((parsed, counts.deferred_page_cap), (1, 2));
    let traversal = fixture.index.traversal.as_ref().unwrap();
    assert_eq!(traversal.pending_candidates.len(), queued + 2);
    assert!(traversal
        .pending_candidates
        .iter()
        .skip(queued)
        .all(|path| !path.census_member));
    assert!(fixture
        .index
        .files
        .values()
        .all(|entry| entry.evidence_owed));
}

/// [regress] A persisted unfinished admission vetoed traversal health for
/// good (a deadlock). Main keeps the admission;
/// evidence owed ON drops the unfinished one at the next start, creates no
/// batch admission, counts the drop, and its stale members keep their
/// fingerprints (owed, never credited by the dropped carry).
#[test]
fn owed_evidence_start_drops_an_unfinished_admission() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let start = |on: bool| {
        let _owed = on.then(evidence_owed::EvidenceOwedForTest::on);
        let mut fixture = contract_debt_fixture(3);
        let invalid = fixture.roots[2].clone();
        let pending = fixture
            .index
            .claude_usage_family_pending
            .get_mut(&invalid)
            .unwrap();
        pending.member_request_id_hashes.clear();
        pending.member_occurrences.clear();
        pending.invalid = true;
        let stale = fixture.roots.iter().cloned().collect();
        let admission = claude_retry_admission_start(&fixture.index, &stale, CARRY_RETRY, None);
        assert!(!admission.complete);
        fixture.index.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
            context_fingerprint: fixture
                .index
                .traversal
                .as_ref()
                .unwrap()
                .context_fingerprint
                .clone(),
            process: claude_full_rearm_process(),
            full_rearm_window: false,
            admission: Some(admission),
        });
        let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        (row, fixture)
    };
    let admission = |fixture: &ScopedRetryFixture| {
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .and_then(|origin| origin.admission.clone())
    };
    let (off, off_fixture) = start(false);
    assert!(admission(&off_fixture).is_some(), "main keeps an admission");
    assert!(off.get("admissions_dropped").is_none());

    let (on, on_fixture) = start(true);
    assert!(admission(&on_fixture).is_none(), "ON leaves no admission");
    assert_eq!(on["admissions_dropped"], 1);
    assert!(on.get("due_retained").is_none());
    let cleared = on_fixture
        .candidates
        .iter()
        .filter(|candidate| {
            on_fixture.index.files[&local_index_key(&candidate.path)]
                .source_file_fingerprint
                .is_empty()
        })
        .count();
    assert_eq!(
        cleared, 0,
        "re-armed members stay owed with their fingerprint"
    );

    // A healthy start is not completion: while members stay owed they give no
    // fence coverage, no family proof, no retirement and no latch clear.
    let _owed = evidence_owed::EvidenceOwedForTest::on();
    let index = &on_fixture.index;
    let window = index.traversal.as_ref().unwrap().census_window_end.clone();
    let indexed = on_fixture.roots.iter().cloned().collect::<BTreeSet<_>>();
    let owed = evidence_owed::owed_roots(index);
    assert!(!owed.is_empty() && owed.is_subset(&indexed));
    assert!(claude_duplicate_fence_coverage_missing_member_count(index, &window) > 0);
    let pending = index
        .claude_usage_family_pending
        .iter()
        .filter(|(root, _)| owed.contains(*root))
        .collect::<Vec<_>>();
    assert!(!pending.is_empty());
    for (root, pending) in pending {
        assert!(evidence_owed::owed_at_completion(
            root, pending, false, &indexed
        ));
    }
    assert_eq!(
        evidence_owed::latch_clearable(index, &window, &indexed),
        None
    );
}

/// [behaviour] An unfinished admission dropped at an evidence-owed start keeps
/// only its due cursor while due service is unoffered: every due path is then
/// offered through that cursor exactly once, none is orphaned, and the
/// finished cursor owes nothing.
#[test]
fn owed_evidence_drop_keeps_unserved_due_service_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _owed = evidence_owed::EvidenceOwedForTest::on();
    let mut fixture = retry_durable_fixture(2, 1);
    fixture.index.bounded_sweep_had_unsettled_upload = false;
    fixture.index.bounded_sweep_unsettled_causes = 0;
    fixture.index.claude_request_identity_contract_changed = true;
    for family in fixture.roots.iter().take(2) {
        let record = fixture
            .index
            .claude_usage_authority_quarantine
            .get_mut(family)
            .unwrap();
        record.contract = CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_string();
        record.disposition = ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
        record.failed_reconstruction_count = MAX_CLAUDE_USAGE_AUTHORITY_FAILURES;
        record.retry_after_unix_seconds = 0;
        record.proof_correction = Some(ClaudeAuthorityProofCorrection {
            proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
            owed_member_ids: BTreeSet::from([family.clone()]),
        });
    }
    let now = rfc3339_unix_seconds(CARRY_RETRY).unwrap();
    let stale = fixture.roots.iter().cloned().collect();
    let admission = claude_retry_admission_start(&fixture.index, &stale, CARRY_RETRY, None);
    let due = fixture
        .index
        .files
        .keys()
        .filter(|key| {
            claude_retry_path_due(
                &admission,
                &fixture.index.claude_usage_authority_quarantine,
                key,
                now,
            )
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(due.len(), 2);
    fixture.index.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
        context_fingerprint: fixture
            .index
            .traversal
            .as_ref()
            .unwrap()
            .context_fingerprint
            .clone(),
        process: claude_full_rearm_process(),
        full_rearm_window: false,
        admission: Some(admission),
    });
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["due_retained"], 1);
    assert!(row.get("admissions_dropped").is_none());
    let retained = |index: &ScanIndex| {
        index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .and_then(|origin| origin.admission.clone())
            .expect("the due cursor is retained")
    };
    let state = retained(&fixture.index);
    assert!(state.roots_complete && !state.complete);

    let root = fixture._scratch.to_path_buf();
    let path = root.join("due-state.json");
    retry_test_context(&mut fixture.index, &root);
    let mut offered = Vec::new();
    for _ in 0..4 {
        fixture.index = retry_test_reload(&mut fixture.index, &path);
        claude_retry_queue_due_families(&mut fixture.index, CARRY_RETRY);
        let state = retained(&fixture.index);
        let mut selected = Vec::new();
        let traversal = fixture.index.traversal.as_mut().unwrap();
        claude_retry_select_due_paths(
            &state,
            &fixture.index.claude_usage_authority_quarantine,
            &mut traversal.pending_candidates,
            &mut selected,
            now,
            1,
        );
        claude_retry_note_offered(&mut fixture.index, &selected, CARRY_RETRY);
        offered.extend(selected.iter().map(|path| local_index_key(&path.path)));
    }
    assert_eq!(offered.len(), due.len(), "none served twice");
    assert_eq!(
        offered.into_iter().collect::<BTreeSet<_>>(),
        due,
        "none orphaned"
    );
    let state = retained(&fixture.index);
    assert!(state.due_complete && state.complete);
    assert!(!evidence_owed::due_unoffered(
        &fixture.index,
        &state,
        CARRY_RETRY
    ));
}

const CARRY_SHARER: &str = "d4444444-4444-4444-8444-444444444444";

/// Add `hash` to one member's pending requests and occurrences; a witnessed
/// family's witness follows, so the family still matches it.
fn carry_add_request(index: &mut ScanIndex, root: &str, member: &str, hash: &str) {
    let pending = index.claude_usage_family_pending.get_mut(root).unwrap();
    let hashes = pending.member_request_id_hashes.get_mut(member).unwrap();
    hashes.insert(hash.to_string());
    let hashes = hashes.clone();
    let occurrences = pending.member_occurrences.get_mut(member).unwrap();
    occurrences.insert(hash.to_string(), carry_occurrence(9, 10));
    let occurrences = occurrences.clone();
    if let Some(witness) = index.claude_usage_family_witnesses.get_mut(root) {
        witness.member_request_id_fingerprints.insert(
            member.to_string(),
            claude_request_id_set_fingerprint(&hashes),
        );
        witness.member_occurrence_fingerprints.insert(
            member.to_string(),
            claude_occurrence_map_fingerprint(&occurrences),
        );
    }
}

/// The failed window plus a second witnessed family, rooted after the first
/// in root order. `shared`: the root's first request is also read in the
/// second family, and another request is read by both of the root's own
/// members.
fn carry_shared_index(shared: bool) -> ScanIndex {
    let mut index = carry_index();
    carry_family(&mut index, CARRY_SHARER, &[None], true);
    if shared {
        let root = carry_member(CARRY_ROOT, None);
        let agent = carry_member(CARRY_ROOT, Some(CARRY_AGENT));
        let first = index.claude_usage_family_pending[CARRY_ROOT].member_request_id_hashes[&root]
            .first()
            .unwrap()
            .clone();
        carry_add_request(&mut index, CARRY_SHARER, CARRY_SHARER, &first);
        let own = "e".repeat(64);
        carry_add_request(&mut index, CARRY_ROOT, &root, &own);
        carry_add_request(&mut index, CARRY_ROOT, &agent, &own);
    }
    index
}

/// The carry fixture with each `body-…` snapshot fingerprint spelled as a
/// real one (64 lowercase hex): a store load drops any other accepted
/// identity, which would leave every family body unaccepted.
fn carry_hex_bodies(index: &mut ScanIndex) {
    use sha2::Digest;
    let hex = |body: &str| format!("{:x}", sha2::Sha256::digest(body.as_bytes()));
    for (_, entry) in &mut index.files {
        if let Some(body) = entry.last_snapshot_fingerprint.as_mut() {
            *body = hex(body);
        }
    }
    for (_, bodies) in &mut index.file_snapshot_fingerprints {
        *bodies = bodies.iter().map(|body| hex(body)).collect();
    }
    let accepted: BTreeSet<String> = index
        .accepted_snapshot_fingerprints
        .iter()
        .map(|body| hex(body))
        .collect();
    index.accepted_snapshot_fingerprints = accepted.into();
}

/// [money] The shared-owner tie-breaks as on main: a request read in two
/// carried families is owned by the later root in root order, so only that
/// owner keeps its re-arm; a request read twice inside one family names no
/// other owner. Control: without them both witnessed families are carried.
#[test]
fn stale_carry_shared_request_is_owned_by_the_later_carried_root() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let carried = |shared: bool| {
        let mut index = carry_shared_index(shared);
        carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        index.claude_stale_family_carry.roots
    };
    assert_eq!(
        carried(false),
        BTreeSet::from([CARRY_ROOT.to_string(), CARRY_SHARER.to_string()])
    );
    assert_eq!(carried(true), BTreeSet::from([CARRY_ROOT.to_string()]));
}

/// [money] Under state v2, on the same failed window published cold: the
/// streamed two-pass join carries and compacts exactly what the resident
/// graph and a whole-kind load do, whether the pass
/// holds no family or the sharer first, and keeps no family it does not
/// carry. A row gone from the store defers the start, counted: nothing
/// carried, no fingerprint cleared, no family compacted.
#[test]
fn cold_stale_carry_streams_the_join_like_a_whole_kind_load() {
    use state_v2::money_test_support as v2;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = crate::test_scratch::canonical_private_dir("stale-carry-cold");
    let mut fixture = carry_shared_index(true);
    carry_hex_bodies(&mut fixture);
    let (custody, cold) = v2::ColdSession::publish(&fixture, &dir);
    assert_eq!(
        cold.accepted_snapshot_fingerprints, fixture.accepted_snapshot_fingerprints,
        "the load keeps every accepted body"
    );
    assert!(cold
        .claude_usage_family_pending
        .family(CARRY_SHARER)
        .is_err());
    let start = |mut index: ScanIndex| {
        carry_start(&mut index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
        index
    };
    let outcome = |index: &ScanIndex| {
        let view = v2::resident(index);
        (
            format!("{:?}", view.claude_stale_family_carry),
            serde_json::to_value(&view.files).unwrap(),
            serde_json::to_value(&view.claude_usage_family_pending).unwrap(),
        )
    };
    let resident = start(v2::resident(&cold));
    assert_eq!(
        resident.claude_stale_family_carry.roots,
        BTreeSet::from([CARRY_ROOT.to_string()])
    );
    let expected = outcome(&resident);
    let mut whole = cold.clone();
    state_v2::load_usage(&mut whole, None).unwrap();
    assert_eq!(outcome(&start(whole)), expected, "whole-kind load");
    let streamed = start(cold.clone());
    assert_eq!(outcome(&streamed), expected, "streamed");
    assert!(v2::usage_head_only(&streamed, CARRY_SHARER));
    assert!(v2::usage_loaded(&streamed, CARRY_ROOT), "compacted");
    let mut held = cold.clone();
    state_v2::load_usage(&mut held, Some(&BTreeSet::from([CARRY_SHARER.to_string()]))).unwrap();
    assert_eq!(outcome(&start(held)), expected, "sharer held first");

    let mut gone = cold.clone();
    v2::delete_usage_row_in_session(&gone, CARRY_SHARER);
    let before = v2::usage_unknown_count();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut gone,
        CARRY_RETRY,
        BACKFILL_WINDOW_DAYS,
    );
    assert!(v2::usage_unknown_count() > before, "counted");
    assert!(gone.claude_stale_family_carry.roots.is_empty());
    for key in carry_family_keys() {
        assert_eq!(
            gone.files[&key].source_file_fingerprint,
            cold.files[&key].source_file_fingerprint
        );
    }
    assert!(v2::usage_head_only(&gone, CARRY_ROOT), "nothing compacted");
    drop(custody);
    let _ = std::fs::remove_dir_all(dir);
}
