// E7-8a: the count-only per-family Claude census shadow. Every fixture is
// synthetic and content-free, evaluates with transcript I/O denied, and checks
// that the shadow leaves the index (including every `census_complete` bit)
// byte-identical.
use super::claude_family_census_shadow::*;
use super::*;

const WINDOW: &str = "2026-10-30T00:00:00Z";
const OLD_WINDOW: &str = "2026-10-29T00:00:00Z";
const NOW: u64 = 1_793_318_400;
const SCAN_ROOT: &str = "/synthetic/projects";

fn root_id(n: usize) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}

fn root_key(dir: &str, root: &str) -> String {
    format!("{SCAN_ROOT}/{dir}/{root}.jsonl")
}

fn subagent_key(dir: &str, root: &str, agent: usize) -> String {
    format!("{SCAN_ROOT}/{dir}/{root}/subagents/agent-{agent}.jsonl")
}

fn traversal() -> ScanTraversalCheckpoint {
    ScanTraversalCheckpoint {
        context_fingerprint: "context".to_string(),
        census_window_end: WINDOW.to_string(),
        scan_roots: vec![PathBuf::from(SCAN_ROOT)],
        pending_directories: VecDeque::new(),
        pending_candidates: VecDeque::new(),
        observed_index_keys: BTreeSet::new(),
        codex_rollout_paths: BTreeSet::new(),
        codex_join_directory_census: None,
        reconciliation_upper_bound: None,
        reconciliation_after: None,
        reconciliation_started: false,
        watcher_hint_seen: false,
        codex_freshness_yield: false,
        codex_parent_resolution_retry_required: false,
        unhealthy_retry_attempt: 0,
        unhealthy_retry_not_before_unix_seconds: None,
        oversized_discovery: BTreeMap::new(),
        counts: ScanTraversalCounts::default(),
        residue: ScanTraversalResidue::default(),
    }
}

fn index() -> ScanIndex {
    ScanIndex {
        traversal: Some(traversal()),
        ..ScanIndex::default()
    }
}

fn request_hash(seed: usize) -> String {
    format!("{seed:016x}{}", "0".repeat(48))
}

/// Account proof for exactly `members`, one distinct request each.
fn pending(members: &[String], window: &str, seed: usize) -> ClaudeAccountFamilyPending {
    let member_requests = members
        .iter()
        .enumerate()
        .map(|(offset, member)| {
            let hashes = BTreeSet::from([request_hash(seed * 64 + offset)]);
            (
                member.clone(),
                ClaudeAccountRequestSet::from_full_hashes(&hashes).expect("distinct prefixes"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    ClaudeAccountFamilyPending {
        current: ClaudeAccountFamilyPendingWindow {
            version: CLAUDE_ACCOUNT_REQUEST_SET_VERSION.into(),
            census_window_end: window.into(),
            account_identifier_hash: "a".repeat(64),
            evidence_request_count: members.len() as u128,
            census_complete: false,
            members: members.iter().map(|member| (member.clone(), 1)).collect(),
            member_requests,
            invalid: false,
        },
        previous_windows: Vec::new(),
        confirmed_absent_members: BTreeSet::new(),
    }
}

fn member_name(root: &str, agent: Option<usize>) -> String {
    match agent {
        Some(agent) => format!("{root}_agent-{agent}"),
        None => root.to_string(),
    }
}

/// Index a family observed this generation at its current revision, with a
/// current-window account proof. Returns its member keys, root first.
fn add_family(index: &mut ScanIndex, dir: &str, n: usize, subagents: usize) -> Vec<String> {
    let root = root_id(n);
    let mut keys = vec![root_key(dir, &root)];
    let mut names = vec![member_name(&root, None)];
    for agent in 0..subagents {
        keys.push(subagent_key(dir, &root, agent));
        names.push(member_name(&root, Some(agent)));
    }
    for key in &keys {
        index
            .files
            .insert(key.clone(), tests::manifest_index_entry(None));
        index
            .traversal
            .as_mut()
            .unwrap()
            .observed_index_keys
            .insert(key.clone());
    }
    index
        .claude_account_family_pending
        .insert(root, pending(&names, WINDOW, n));
    keys
}

fn family(key: &str) -> FamilyRef {
    FamilyRef::of_key(key).expect("family member key")
}

fn queue(index: &mut ScanIndex, key: &str) {
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .push_back(ScanTraversalPath {
            scan_root: PathBuf::from(SCAN_ROOT),
            path: PathBuf::from(key),
            census_member: true,
            watcher_hint: false,
        });
}

/// Attest every indexed member at its current revision, as this
/// generation's parses or equality Skips would.
fn attest_all(index: &ScanIndex) -> Attestations {
    let generation = generation_tag(index.traversal.as_ref().unwrap());
    let mut attested = Attestations::default();
    for (key, entry) in &index.files {
        attested.record(generation, key, &entry.source_file_fingerprint);
    }
    attested.flush();
    attested
}

/// Each indexed key with its current revision, as a page's parses report it.
fn revisions(index: &ScanIndex) -> Vec<(String, String)> {
    index
        .files
        .iter()
        .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
        .collect()
}

fn as_parsed(parsed: &[(String, String)]) -> impl Iterator<Item = (&str, &str)> {
    parsed
        .iter()
        .map(|(key, revision)| (key.as_str(), revision.as_str()))
}

/// Evaluate `families` with every member attested.
fn evaluate(index: &ScanIndex, families: &[FamilyRef]) -> FamilyCounts {
    evaluate_attested(index, families, &attest_all(index))
}

/// Evaluate `families` with transcript I/O denied, and check the shadow left
/// the index byte-identical and the counts partition `evaluated`.
fn evaluate_attested(
    index: &ScanIndex,
    families: &[FamilyRef],
    attested: &Attestations,
) -> FamilyCounts {
    let before = serde_json::to_vec(index).unwrap();
    let traversal = index.traversal.as_ref().unwrap();
    let roots = RootCounts::build(index, traversal);
    let vetoes = Vetoes::current(index, traversal);
    let counts = with_transcript_io_denied(|| {
        View::new(index, traversal, &roots, attested, vetoes).evaluate(families)
    });
    assert_eq!(
        serde_json::to_vec(index).unwrap(),
        before,
        "acts on nothing"
    );
    assert_partition(&counts);
    counts
}

fn assert_partition(counts: &FamilyCounts) {
    assert_eq!(
        counts.complete + counts.deferred.quantum + counts.incomplete_total(),
        counts.evaluated
    );
}

fn no_census_bits(index: &ScanIndex) -> bool {
    index
        .claude_account_family_pending
        .values()
        .all(|pending| !pending.census_complete)
}

type Mutation = Box<dyn Fn(&mut ScanIndex)>;

fn case(
    reason: Incomplete,
    affected: u64,
    mutate: impl Fn(&mut ScanIndex) + 'static,
) -> (Incomplete, u64, Mutation) {
    (reason, affected, Box::new(mutate))
}

fn only(reason: Incomplete, count: u64) -> BTreeMap<Incomplete, u64> {
    BTreeMap::from([(reason, count)])
}

#[test]
fn current_families_complete_and_singletons_are_counted() {
    let mut index = index();
    let family_keys = add_family(&mut index, "dir-a", 1, 2);
    let singleton = add_family(&mut index, "dir-a", 2, 0);
    let counts = evaluate(&index, &[family(&family_keys[1]), family(&singleton[0])]);
    assert_eq!(counts.complete, 2);
    assert_eq!(counts.evaluated, 2);
    assert_eq!(counts.singletons, 1);
    assert!(counts.incomplete.is_empty());
    assert!(no_census_bits(&index));
    // A subagent key and its root key name the same family.
    assert_eq!(family(&family_keys[0]), family(&family_keys[2]));
}

#[test]
fn each_reason_in_isolation_partitions_the_incomplete_count() {
    let mut base = index();
    let families = (0..5)
        .map(|n| add_family(&mut base, "dir-a", n, 1))
        .collect::<Vec<_>>();
    let refs = families
        .iter()
        .map(|keys| family(&keys[0]))
        .collect::<Vec<_>>();
    let target = &families[2];
    let target_root = root_id(2);
    let quarantine = ClaudeUsageAuthorityQuarantineRecord {
        contract: String::new(),
        proven_witness_fingerprint: "b".repeat(64),
        member_source_file_fingerprints: BTreeMap::new(),
        failed_reconstruction_count: 1,
        disposition: Default::default(),
        retry_after_unix_seconds: 0,
        proof_correction: None,
    };
    let cases = vec![
        case(Incomplete::MembershipUnknown, 1, {
            let key = target[1].clone();
            move |index| {
                index
                    .traversal
                    .as_mut()
                    .unwrap()
                    .observed_index_keys
                    .remove(&key);
            }
        }),
        case(Incomplete::Queued, 1, {
            let key = target[1].clone();
            move |index| queue(index, &key)
        }),
        case(Incomplete::RefusedRead, 1, {
            let key = target[1].clone();
            move |index| {
                index
                    .traversal
                    .as_mut()
                    .unwrap()
                    .oversized_discovery
                    .insert(
                        oversized_discovery::path_hash(Path::new(&key)),
                        serde_json::from_value(json!({"content_hash": "c", "observations": 1}))
                            .unwrap(),
                    );
            }
        }),
        // Unattributed refusals cannot name a file: every family.
        case(Incomplete::RefusedReadUnattributed, 5, |index| {
            index
                .traversal
                .as_mut()
                .unwrap()
                .counts
                .disappeared_file_count = 1;
        }),
        case(Incomplete::RefusedReadUnattributed, 5, |index| {
            index
                .traversal
                .as_mut()
                .unwrap()
                .counts
                .record_unreadable(UnreadableCause::OpenRead, 1);
        }),
        case(Incomplete::Held, 1, {
            let key = target[0].clone();
            move |index| {
                index
                    .claude_account_deferred_holds
                    .insert(key.clone(), "held".into());
            }
        }),
        case(Incomplete::Quarantine, 1, {
            let root = target_root.clone();
            move |index| {
                index
                    .claude_usage_authority_quarantine
                    .insert(root.clone(), quarantine.clone());
            }
        }),
        case(Incomplete::Residue, 1, {
            let key = target[1].clone();
            move |index| {
                index
                    .traversal
                    .as_mut()
                    .unwrap()
                    .residue
                    .index_keys
                    .insert(key.clone());
            }
        }),
        case(Incomplete::Evidence, 1, {
            let root = target_root.clone();
            move |index| {
                index
                    .claude_account_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .invalid = true;
            }
        }),
        case(Incomplete::NotCurrentWindow, 1, {
            let root = target_root.clone();
            move |index| {
                index
                    .claude_account_family_pending
                    .get_mut(&root)
                    .unwrap()
                    .census_window_end = OLD_WINDOW.into();
            }
        }),
        // The same root also has a path in another directory.
        case(Incomplete::PathNotUnique, 1, {
            let duplicate = root_key("dir-b", &target_root);
            move |index| {
                index
                    .files
                    .insert(duplicate.clone(), tests::manifest_index_entry(None));
                index
                    .traversal
                    .as_mut()
                    .unwrap()
                    .observed_index_keys
                    .insert(duplicate.clone());
            }
        }),
    ];
    assert_eq!(evaluate(&base, &refs).complete, 5);
    for (reason, affected, mutate) in cases {
        let mut index = base.clone();
        mutate(&mut index);
        let counts = evaluate(&index, &refs);
        assert_eq!(counts.incomplete, only(reason, affected), "{reason:?}");
        assert_eq!(counts.complete, 5 - affected, "{reason:?}");
        assert_eq!(counts.evaluated, 5);
        assert!(no_census_bits(&index));
    }
}

#[test]
fn unknown_enumeration_keeps_every_family_incomplete() {
    let mut base = index();
    let refs = (0..3)
        .map(|n| family(&add_family(&mut base, "dir-a", n, 1)[0]))
        .collect::<Vec<_>>();
    let mut undrained = base.clone();
    undrained
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .push_back(ScanTraversalPath {
            scan_root: PathBuf::from(SCAN_ROOT),
            path: PathBuf::from(format!("{SCAN_ROOT}/dir-c")),
            census_member: true,
            watcher_hint: false,
        });
    let mut overflowed = base.clone();
    overflowed.traversal.as_mut().unwrap().watcher_hint_seen = true;
    // The walk pops a directory before it records that it could not list it
    // in full, so a drained queue alone does not prove enumeration.
    let mut too_wide = base.clone();
    too_wide
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .directory_entry_cap_exceeded_count = 1;
    let mut symlinked = base.clone();
    symlinked
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .symlink_rejected_count = 1;
    // Namespace loss: an unlistable path or directory, an unreadable
    // remainder no cause attributes, or an unresolved root.
    let unlisted = |cause| {
        let mut index = base.clone();
        index
            .traversal
            .as_mut()
            .unwrap()
            .counts
            .record_unreadable(cause, 1);
        index
    };
    let mut unattributed = base.clone();
    unattributed
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .unreadable_path_count = 1;
    let mut unresolved = base.clone();
    unresolved
        .legacy_unresolved_root_file_witnesses
        .insert(SCAN_ROOT.into());
    for index in [
        undrained,
        overflowed,
        too_wide,
        symlinked,
        unlisted(UnreadableCause::Metadata),
        unlisted(UnreadableCause::Directory),
        unattributed,
        unresolved,
    ] {
        let counts = evaluate(&index, &refs);
        assert_eq!(counts.incomplete, only(Incomplete::MembershipUnknown, 3));
    }
}

#[test]
fn coverage_needs_an_attestation_of_the_current_revision() {
    let mut base = index();
    let keys = add_family(&mut base, "dir-a", 4, 1);
    let refs = [family(&keys[0])];
    let presence_only = only(Incomplete::EvidencePresenceOnly, 1);
    // Observed and indexed at a non-empty revision, with an exact proof, but
    // nothing this generation attested it: presence only.
    let none = Attestations::default();
    assert_eq!(
        evaluate_attested(&base, &refs, &none).incomplete,
        presence_only
    );
    // One attested member is not the family.
    let generation = generation_tag(base.traversal.as_ref().unwrap());
    let mut partial = Attestations::default();
    partial.record(generation, &keys[0], "source");
    partial.flush();
    assert_eq!(
        evaluate_attested(&base, &refs, &partial).incomplete,
        presence_only
    );
    let attested = attest_all(&base);
    assert_eq!(evaluate_attested(&base, &refs, &attested).complete, 1);

    // A later revision the attestation does not name.
    let mut grown = base.clone();
    grown
        .files
        .get_mut(&keys[1])
        .unwrap()
        .source_file_fingerprint = "source-2".into();
    assert_eq!(
        evaluate_attested(&grown, &refs, &attested).incomplete,
        presence_only
    );
    // A growth hint after the attestation re-queues a current member
    // (Q-E1-4).
    let mut hinted = base.clone();
    hinted
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .push_back(ScanTraversalPath {
            scan_root: PathBuf::from(SCAN_ROOT),
            path: PathBuf::from(&keys[1]),
            census_member: false,
            watcher_hint: true,
        });
    assert_eq!(
        evaluate_attested(&hinted, &refs, &attested).incomplete,
        only(Incomplete::Queued, 1)
    );
    // Another generation's attestations cover nothing.
    let mut next = base.clone();
    next.traversal.as_mut().unwrap().context_fingerprint = "context-2".into();
    assert_eq!(
        evaluate_attested(&next, &refs, &attested).incomplete,
        presence_only
    );
}

#[test]
fn only_the_ordinary_equality_skip_attests() {
    let mut index = index();
    let key = root_key("dir-e", &root_id(1));
    let mut entry = tests::manifest_index_entry(Some("entity"));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    index.files.insert(key.clone(), entry.clone());
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["entity".to_string()]));
    index
        .snapshot_activity_at
        .insert("entity".into(), Some("2026-10-14T10:00:00Z".into()));
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from(SCAN_ROOT),
        path: PathBuf::from(&key),
        size_bytes: entry.size_bytes,
        modified_unix_seconds: entry.modified_unix_seconds,
        modified_unix_nanos: entry.modified_unix_nanos.unwrap(),
        source_file_fingerprint: entry.source_file_fingerprint.clone(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    };
    assert!(equality_skip(&index, &candidate, 0));
    // A changed revision is a parse, not an attestation.
    let mut changed = candidate.clone();
    changed.source_file_fingerprint = "source-2".into();
    assert!(!equality_skip(&index, &changed, 0));
    // A held Skip (here the family's authority quarantine) attests nothing.
    let mut quarantined = index.clone();
    quarantined.claude_usage_authority_quarantine.insert(
        root_id(1),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: String::new(),
            proven_witness_fingerprint: "b".repeat(64),
            member_source_file_fingerprints: BTreeMap::new(),
            failed_reconstruction_count: 1,
            disposition: Default::default(),
            retry_after_unix_seconds: 0,
            proof_correction: None,
        },
    );
    assert!(!equality_skip(&quarantined, &candidate, 0));
    // Witness-less upload-context debt (#899 R23) is presence, even when its
    // backoff lets the file skip.
    let mut debt = index.clone();
    debt.active_upload_context_fingerprint = Some("context-new".into());
    assert!(!equality_skip(&debt, &candidate, 0));
}

#[test]
fn loss_vetoes_stay_up_for_the_generation() {
    let mut index = index();
    let refs = (0..2)
        .map(|n| family(&add_family(&mut index, "dir-a", n, 1)[0]))
        .collect::<Vec<_>>();
    let keys = refs
        .iter()
        .flat_map(|family| {
            index
                .files
                .keys()
                .filter(|key| FamilyRef::of_key(key).as_ref() == Some(family))
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let touched = Touched::from_paths(keys.iter().map(Path::new));
    let parsed = revisions(&index);
    let mut runtime = Runtime::default();
    let mut page = |index: &ScanIndex, parsed: &[(String, String)], now| {
        with_transcript_io_denied(|| {
            evaluate_page(
                &mut runtime,
                index,
                &touched,
                as_parsed(parsed),
                "scope",
                now,
            )
            .unwrap()
        })
    };
    let complete = page(&index, &parsed, NOW);
    assert_eq!(complete.families.complete, 2);

    let mut lost = index.clone();
    lost.traversal
        .as_mut()
        .unwrap()
        .counts
        .disappeared_file_count = 1;
    let first = page(&lost, &[], NOW + 60);
    assert_eq!(
        first.families.incomplete,
        only(Incomplete::RefusedReadUnattributed, 2)
    );
    // The counter reads zero again in the same generation: still vetoed.
    let healed = page(&index, &[], NOW + 120);
    assert_eq!(
        healed.families.incomplete,
        only(Incomplete::RefusedReadUnattributed, 2)
    );
    assert_eq!(healed.sticky_vetoes.unattributed_age_s, Some(60));
    let mut walk_lost = index.clone();
    walk_lost
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .record_unreadable(UnreadableCause::Directory, 1);
    page(&walk_lost, &[], NOW + 180);
    let after = page(&index, &[], NOW + 240);
    assert_eq!(
        after.families.incomplete,
        only(Incomplete::MembershipUnknown, 2)
    );
    assert_eq!(after.sticky_vetoes.namespace_loss_age_s, Some(60));

    // A new generation clears the vetoes and the attestations alike.
    let mut next = index.clone();
    next.traversal.as_mut().unwrap().context_fingerprint = "context-2".into();
    let fresh = page(&next, &[], NOW + 300);
    assert_eq!(fresh.sticky_vetoes, StickyAges::default());
    assert_eq!(
        fresh.families.incomplete,
        only(Incomplete::EvidencePresenceOnly, 2)
    );
    let reattested = page(&next, &parsed, NOW + 360);
    assert_eq!(reattested.families.complete, 2);
}

#[test]
fn the_skipped_view_is_queue_plus_replay() {
    let mut index = index();
    let keys = add_family(&mut index, "dir-q", 1, 1);
    queue(&mut index, &keys[0]);
    index
        .claude_stale_family_carry
        .replay
        .push(ScanTraversalPath {
            scan_root: PathBuf::from(SCAN_ROOT),
            path: PathBuf::from(&keys[1]),
            census_member: false,
            watcher_hint: false,
        });
    // A re-read hint is no census member, so it is not in the view.
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .push_back(ScanTraversalPath {
            scan_root: PathBuf::from(SCAN_ROOT),
            path: PathBuf::from(&keys[1]),
            census_member: false,
            watcher_hint: true,
        });
    let view = skipped_view(&index).collect::<Vec<_>>();
    assert_eq!(view.len(), 2);
    assert_eq!(view.iter().filter(|skipped| skipped.replay).count(), 1);
    assert_eq!(skipped_census_members(&index).count(), 2);
    let mut first_pending = FirstPending::default();
    let (first, _) = first_pending.observe(skipped_view(&index), |_| false, NOW);
    assert_eq!((first.count, first.replay, first.replay_repeat), (2, 1, 0));
    // Still replayed a page later: repeated, and its age a lower bound.
    let (again, _) = first_pending.observe(skipped_view(&index), |_| false, NOW + 60);
    assert_eq!((again.replay, again.replay_repeat), (1, 1));
    assert_eq!(again.oldest_age_s, 60);
}

#[test]
fn no_consumer_reads_a_verdict_in_8a() {
    for completion in [
        Completion::Complete,
        Completion::Incomplete(Incomplete::Evidence),
    ] {
        for consumer in [
            FamilyConsumer::AccountWindowMark,
            FamilyConsumer::CensusRecordAging,
            FamilyConsumer::ScopedEvidenceLoad,
            FamilyConsumer::FamilyRetrySchedule,
        ] {
            assert!(!completion.permits(consumer));
        }
    }
}

#[test]
fn changed_new_and_deleted_members_never_count_as_covered() {
    let mut base = index();
    let keys = add_family(&mut base, "dir-a", 7, 1);
    let root = root_id(7);
    let refs = [family(&keys[0])];
    let reason = |index: &ScanIndex| evaluate(index, &refs).incomplete;

    // Changed: a growth hint re-queues the member, or a re-arm clears its
    // revision.
    let mut hinted = base.clone();
    queue(&mut hinted, &keys[1]);
    assert_eq!(reason(&hinted), only(Incomplete::Queued, 1));
    let mut cleared = base.clone();
    cleared
        .files
        .get_mut(&keys[1])
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert_eq!(reason(&cleared), only(Incomplete::Evidence, 1));

    // New: an indexed subagent the account proof does not name, or one
    // observed this generation with no index entry yet.
    let new_member = subagent_key("dir-a", &root, 9);
    let mut unproven = base.clone();
    unproven
        .files
        .insert(new_member.clone(), tests::manifest_index_entry(None));
    unproven
        .traversal
        .as_mut()
        .unwrap()
        .observed_index_keys
        .insert(new_member.clone());
    assert_eq!(reason(&unproven), only(Incomplete::Evidence, 1));
    let mut unindexed = base.clone();
    unindexed
        .traversal
        .as_mut()
        .unwrap()
        .observed_index_keys
        .insert(new_member);
    assert_eq!(reason(&unindexed), only(Incomplete::Evidence, 1));

    // Deleted: indexed but not enumerated this generation, or gone from the
    // index while the proof still names it.
    let mut unlisted = base.clone();
    unlisted
        .traversal
        .as_mut()
        .unwrap()
        .observed_index_keys
        .remove(&keys[1]);
    assert_eq!(reason(&unlisted), only(Incomplete::MembershipUnknown, 1));
    let mut removed = base.clone();
    removed.files.remove(&keys[1]);
    removed
        .traversal
        .as_mut()
        .unwrap()
        .observed_index_keys
        .remove(&keys[1]);
    assert_eq!(reason(&removed), only(Incomplete::Evidence, 1));
    assert!(base.claude_account_family_pending.contains_key(&root));
}

#[test]
fn old_window_carry_alone_stays_incomplete() {
    let mut index = index();
    let keys = add_family(&mut index, "dir-a", 3, 2);
    // Every member observed this generation at a non-empty revision, and an
    // otherwise exact proof, but from the previous window.
    index
        .claude_account_family_pending
        .get_mut(&root_id(3))
        .unwrap()
        .census_window_end = OLD_WINDOW.into();
    let counts = evaluate(&index, &[family(&keys[0])]);
    assert_eq!(counts.incomplete, only(Incomplete::NotCurrentWindow, 1));
    assert_eq!(counts.complete, 0);
}

#[test]
fn quantum_admits_64_complete_families_and_defers_the_rest() {
    let mut index = index();
    let refs = (0..65)
        .map(|n| family(&add_family(&mut index, "dir-a", n, 1)[0]))
        .collect::<Vec<_>>();
    let counts = evaluate(&index, &refs);
    assert_eq!(counts.evaluated, 65);
    assert_eq!(counts.complete, 64);
    assert_eq!(counts.deferred.quantum, 1);
    assert!(counts.incomplete.is_empty());
}

/// M4 shape: 1,000 three-member families, all 3,000 members queued, 100
/// served per page in FIFO order, so many families span a served (uncapped)
/// and a still-queued (capped) member at a page boundary.
#[test]
fn m4_shape_drains_3000_queued_members_at_100_per_page() {
    const FAMILIES: usize = 1_000;
    const PER_PAGE: usize = 100;
    let mut index = index();
    let mut order = Vec::new();
    for n in 0..FAMILIES {
        order.extend(add_family(&mut index, "dir-m4", n, 2));
    }
    for key in &order {
        queue(&mut index, key);
    }
    assert_eq!(skipped_census_members(&index).count(), 3_000);
    let mut runtime = Runtime::default();
    let mut completed = BTreeSet::new();
    for page in 0..order.len() / PER_PAGE {
        let served = index
            .traversal
            .as_mut()
            .unwrap()
            .pending_candidates
            .drain(..PER_PAGE)
            .map(|candidate| candidate.path)
            .collect::<Vec<_>>();
        let touched = Touched::from_paths(served.iter().map(PathBuf::as_path));
        let remaining = index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .filter_map(|candidate| FamilyRef::of_key(&local_index_key(&candidate.path)))
            .collect::<BTreeSet<_>>();
        let touched_refs = served
            .iter()
            .map(|path| family(&local_index_key(path)))
            .collect::<BTreeSet<_>>();
        let expected_complete = touched_refs.difference(&remaining).count() as u64;
        let counts = evaluate(&index, &touched_refs.iter().cloned().collect::<Vec<_>>());
        assert_eq!(counts.complete, expected_complete, "page {page}");
        assert_eq!(
            counts.incomplete_total(),
            touched_refs.intersection(&remaining).count() as u64
        );
        assert!(counts
            .incomplete
            .keys()
            .all(|reason| *reason == Incomplete::Queued));
        // FIFO: a family completes on the page that serves its last member.
        for complete in touched_refs.difference(&remaining) {
            assert!(completed.insert(complete.clone()), "completes once");
        }

        let now = NOW + page as u64 * 60;
        // The served members' parses attest their revisions.
        let parsed = served
            .iter()
            .map(|path| (local_index_key(path), "source".to_string()))
            .collect::<Vec<_>>();
        let before = serde_json::to_vec(&index).unwrap();
        let shadow = with_transcript_io_denied(|| {
            evaluate_page(
                &mut runtime,
                &index,
                &touched,
                as_parsed(&parsed),
                "scope",
                now,
            )
            .unwrap()
        });
        assert_eq!(serde_json::to_vec(&index).unwrap(), before);
        assert_partition(&shadow.families);
        assert_eq!(shadow.touched_families, touched_refs.len() as u64);
        assert!(shadow.rotation_families <= FAMILY_QUANTUM as u64);
        let left = (order.len() - (page + 1) * PER_PAGE) as u64;
        assert_eq!(shadow.pending_census_members.count, left);
        assert_eq!(skipped_census_members(&index).count() as u64, left);
        if left > 0 {
            // Every still-queued member was first stamped on page 0.
            assert_eq!(shadow.pending_census_members.oldest_age_s, page as u64 * 60);
            assert_eq!(
                shadow.skipped_set.retained,
                if page == 0 { 0 } else { left }
            );
        }
        assert_eq!(shadow.pending_census_members.over_24h, 0);
        // Served members are attested, so no stamp outlives the queue, and
        // every family the page sees was attested or is still queued.
        assert_eq!(shadow.pending_census_members.unqueued_unresolved, 0);
        assert!(!shadow
            .families
            .incomplete
            .contains_key(&Incomplete::EvidencePresenceOnly));
        assert!(no_census_bits(&index));
    }
    assert_eq!(completed.len(), FAMILIES);
}

#[test]
fn a_restart_between_pages_rederives_identical_counts_with_zero_reads() {
    let mut index = index();
    let mut touched_keys = Vec::new();
    for n in 0..40 {
        let keys = add_family(&mut index, "dir-a", n, n % 3);
        if n % 2 == 0 {
            touched_keys.push(PathBuf::from(&keys[0]));
        }
        match n % 5 {
            1 => queue(&mut index, &keys[0]),
            2 => {
                index
                    .claude_account_family_pending
                    .get_mut(&root_id(n))
                    .unwrap()
                    .census_window_end = OLD_WINDOW.into();
            }
            3 => {
                index
                    .traversal
                    .as_mut()
                    .unwrap()
                    .residue
                    .index_keys
                    .insert(keys[0].clone());
            }
            _ => {}
        }
    }
    let touched = Touched::from_paths(touched_keys.iter().map(PathBuf::as_path));
    let parsed = revisions(&index);
    let mut runtime = Runtime::default();
    let first = with_transcript_io_denied(|| {
        evaluate_page(
            &mut runtime,
            &index,
            &touched,
            as_parsed(&parsed),
            "scope",
            NOW,
        )
        .unwrap()
    });
    // Restart: reload the persisted index and lose all runtime state,
    // attestations included.
    let reloaded =
        serde_json::from_slice::<ScanIndex>(&serde_json::to_vec(&index).unwrap()).unwrap();
    let restart = || {
        let mut restarted = Runtime::default();
        with_transcript_io_denied(|| {
            evaluate_page(
                &mut restarted,
                &reloaded,
                &touched,
                std::iter::empty(),
                "scope",
                NOW,
            )
            .unwrap()
        })
    };
    let second = restart();
    let again = restart();
    assert_eq!(again.families, second.families, "deterministic");
    assert_eq!(again.pending_census_members, second.pending_census_members);
    assert!(first.families.complete > 0);
    assert!(first.families.incomplete_total() > 0);
    // What was covered only by attestation is presence again; nothing is
    // inferred from the persisted index. Earlier reasons are unchanged.
    let reason = |counts: &FamilyCounts, reason: Incomplete| {
        counts.incomplete.get(&reason).copied().unwrap_or_default()
    };
    assert_eq!(second.families.complete, 0);
    assert_eq!(
        reason(&second.families, Incomplete::EvidencePresenceOnly),
        first.families.complete
            + first.families.deferred.quantum
            + reason(&first.families, Incomplete::NotCurrentWindow)
    );
    for kept in [Incomplete::Queued, Incomplete::Residue] {
        assert_eq!(
            reason(&second.families, kept),
            reason(&first.families, kept)
        );
    }
    assert_eq!(second.families.evaluated, first.families.evaluated);
    assert_eq!(
        second.pending_census_members.count,
        first.pending_census_members.count
    );
    assert_eq!(second.skipped_set.digest, first.skipped_set.digest);
    assert!(no_census_bits(&reloaded));
}

#[test]
fn first_pending_at_is_bounded_and_counts_pace_evictions() {
    let path = |n: usize| ScanTraversalPath {
        scan_root: PathBuf::from(SCAN_ROOT),
        path: PathBuf::from(root_key("dir-p", &root_id(n))),
        census_member: true,
        watcher_hint: false,
    };
    fn queued(paths: &[ScanTraversalPath]) -> impl Iterator<Item = Skipped<'_>> + '_ {
        paths.iter().map(|path| Skipped {
            path,
            replay: false,
        })
    }
    let mut first_pending = FirstPending::default();
    let early = (0..100).map(path).collect::<Vec<_>>();
    first_pending.observe(queued(&early), |_| false, NOW);
    let all = (0..MAX_FIRST_PENDING + 10).map(path).collect::<Vec<_>>();
    let (pending, skipped) = first_pending.observe(queued(&all), |_| false, NOW + 2 * OVER_DAY);
    assert_eq!(pending.count, (MAX_FIRST_PENDING + 10) as u64);
    assert_eq!(pending.tracked, MAX_FIRST_PENDING as u64);
    // The ten oldest stamps go; the remaining 90 early ones still age.
    assert_eq!(pending.pace_evicted, 10);
    assert_eq!(pending.over_24h, 90);
    assert_eq!(pending.oldest_age_s, 2 * OVER_DAY);
    assert_eq!(skipped.retained, 100);
    // Members that leave the queue unresolved keep their stamps; resolved
    // ones drop out.
    let (pending, _) = first_pending.observe(std::iter::empty(), |_| false, NOW + 3 * OVER_DAY);
    assert_eq!(
        (pending.count, pending.tracked),
        (0, MAX_FIRST_PENDING as u64)
    );
    assert_eq!(pending.unqueued_unresolved, MAX_FIRST_PENDING as u64);
    let (pending, _) = first_pending.observe(std::iter::empty(), |_| true, NOW + 3 * OVER_DAY);
    assert_eq!((pending.count, pending.tracked), (0, 0));
}

const OVER_DAY: u64 = 24 * 60 * 60;

#[test]
fn rotation_visits_other_families_and_wraps() {
    let mut index = index();
    let refs = (0..100)
        .map(|n| family(&add_family(&mut index, "dir-r", n, 1)[0]))
        .collect::<Vec<_>>();
    let excluded = vec![refs[0].clone()];
    let mut cursor = None;
    let first = rotation(&index, &mut cursor, &excluded);
    assert_eq!(first.len(), FAMILY_QUANTUM);
    assert!(!first.contains(&refs[0]));
    let second = rotation(&index, &mut cursor, &excluded);
    assert_eq!(second.len(), FAMILY_QUANTUM);
    // The second turn finishes the 99 others and wraps to the first again.
    let seen = first.iter().chain(&second).collect::<BTreeSet<_>>();
    assert_eq!(seen.len(), 99);
}

#[test]
fn a_real_claude_page_emits_shadow_counts_and_keeps_the_census_bits() {
    let root = crate::test_scratch::private_dir("e7-8a-family-shadow");
    let parent = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    fs::write(
        root.join(format!("{parent}.jsonl")),
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"requestId\":\"req_1\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
        ),
    )
    .unwrap();
    let child_dir = root.join(parent).join("subagents");
    fs::create_dir_all(&child_dir).unwrap();
    fs::write(
        child_dir.join("agent-a4d1585d310070d0f.jsonl"),
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:04Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"agentId\":\"a4d1585d310070d0f\",\"isSidechain\":true,\"requestId\":\"req_5\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":1}}}}}}\n"
        ),
    )
    .unwrap();
    let mut index = ScanIndex::default();
    let (scan, records) = crate::local_resource_diagnostics::capture(|| {
        scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-08-02T07:10:00Z",
            7,
            1,
            false,
        )
        .unwrap()
    });
    let shadows = records
        .iter()
        .filter(|record| record["stage"] == "claude_family_census_shadow")
        .collect::<Vec<_>>();
    assert!(!shadows.is_empty(), "a Claude page emits the shadow");
    for shadow in &shadows {
        assert_eq!(shadow["source"], "claude_code");
        let counts = &shadow["counts"];
        let incomplete = counts["family_census_incomplete"]
            .as_object()
            .unwrap()
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(
            counts["family_census_complete"].as_u64().unwrap()
                + counts["family_complete_deferred"]["quantum"]
                    .as_u64()
                    .unwrap()
                + incomplete,
            counts["families_evaluated"].as_u64().unwrap()
        );
    }
    let last = &shadows.last().unwrap()["counts"];
    assert_eq!(
        last["pending_census_members"]["count"].as_u64().unwrap(),
        scan.skipped_file_count_due_to_limit as u64
    );
    if scan.skipped_file_count_due_to_limit > 0 {
        // One member was served and its sibling is still queued: the source
        // census stays open and the shadow sets no bit.
        assert!(!scan.census_complete);
        assert!(no_census_bits(&index));
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn the_root_index_rebuilds_when_membership_changes_at_equal_size() {
    let mut index = index();
    let keys = add_family(&mut index, "dir-a", 5, 0);
    let elsewhere = root_key("dir-b", &root_id(5));
    let unrelated = format!("{SCAN_ROOT}/dir-z/notes.txt");
    index
        .files
        .insert(elsewhere.clone(), tests::manifest_index_entry(None));
    index
        .traversal
        .as_mut()
        .unwrap()
        .observed_index_keys
        .insert(elsewhere.clone());
    // The other directory's path holds nothing yet: not a member anywhere.
    index.confirmed_empty_files.insert(elsewhere.clone());
    let touched = Touched::from_paths([Path::new(&keys[0])]);
    let parsed = revisions(&index);
    let mut runtime = Runtime::default();
    let first = evaluate_page(
        &mut runtime,
        &index,
        &touched,
        as_parsed(&parsed),
        "scope",
        NOW,
    )
    .unwrap();
    assert_eq!(first.families.complete, 1);
    // One page later it holds requests while an unrelated file turns empty:
    // every set keeps its size, and the root is no longer unique.
    index.confirmed_empty_files.remove(&elsewhere);
    index.confirmed_empty_files.insert(unrelated);
    let second = evaluate_page(
        &mut runtime,
        &index,
        &touched,
        as_parsed(&parsed),
        "scope",
        NOW + 60,
    )
    .unwrap();
    assert!(second.cost.root_index_rebuilt);
    assert_eq!(second.families.complete, 0);
    assert!(second
        .families
        .incomplete
        .contains_key(&Incomplete::PathNotUnique));
}

#[test]
fn only_an_attestation_after_leaving_the_queue_resolves_a_stamp() {
    let mut index = index();
    let keys = add_family(&mut index, "dir-a", 6, 0);
    let served = vec![(keys[0].clone(), "source".to_string())];
    let mut runtime = Runtime::default();
    let mut page = |index: &ScanIndex, parsed: &[(String, String)], now| {
        evaluate_page(
            &mut runtime,
            index,
            &Touched::default(),
            as_parsed(parsed),
            "scope",
            now,
        )
        .unwrap()
        .pending_census_members
    };
    let mut queued = index.clone();
    queue(&mut queued, &keys[0]);
    assert_eq!(page(&queued, &[], NOW).tracked, 1);
    // Served and parsed: resolved.
    assert_eq!(page(&index, &served, NOW + 60).tracked, 0);
    // Queued again, then leaves the queue unserved (refused): the earlier
    // attestation does not resolve the new stamp.
    assert_eq!(page(&queued, &[], NOW + 120).tracked, 1);
    let left = page(&index, &[], NOW + 180);
    assert_eq!((left.tracked, left.unqueued_unresolved), (1, 1));
    assert_eq!(page(&queued, &[], NOW + 240).oldest_age_s, 120);
}
