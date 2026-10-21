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
