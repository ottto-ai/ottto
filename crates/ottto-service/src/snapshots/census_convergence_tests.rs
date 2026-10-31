// Census convergence: non-progressing local holds, exact family pending
// re-observation, duplicate-fence coverage and backoff, and count-only parse
// reasons. All fixtures are synthetic and content-free.
use super::*;

const WINDOW: &str = "2026-08-02T07:10:00Z";
const OLDER_WINDOW: &str = "2026-08-01T00:00:00Z";
const CENSUS_CLOCK: u64 = 1_785_654_600;

fn hex64(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn occurrence(sequence: u64, output_tokens: u64) -> ClaudeTranscriptUsageOccurrenceWitness {
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

fn occurrences(
    entries: &[(&str, ClaudeTranscriptUsageOccurrenceWitness)],
) -> BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness> {
    entries
        .iter()
        .map(|(request, occurrence)| (request.to_string(), occurrence.clone()))
        .collect()
}

fn current_pending(member: &str, request: &str) -> ClaudeUsageFamilyPending {
    ClaudeUsageFamilyPending {
        census_window_end: WINDOW.to_string(),
        member_request_id_hashes: BTreeMap::from([(
            member.to_string(),
            BTreeSet::from([request.to_string()]),
        )]),
        member_occurrences: BTreeMap::from([(
            member.to_string(),
            occurrences(&[(request, occurrence(0, 1))]),
        )]),
        invalid: false,
        idless_revision: None,
        identity_contract: None,
    }
}

/// A well-formed family quarantine bound to its retained witness, recording
/// `revision` for `member`.
fn bind_authority_quarantine(
    index: &mut ScanIndex,
    root_session_id: &str,
    member: &str,
    revision: &str,
    disposition: ClaudeUsageAuthorityQuarantineDisposition,
) {
    let witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: hex64('e'),
        member_request_id_fingerprints: BTreeMap::new(),
        member_occurrence_fingerprints: BTreeMap::new(),
        assigned_request_id_fingerprints: BTreeMap::new(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let failed_reconstruction_count = match disposition {
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending => 1,
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => {
            MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
        }
    };
    let record = ClaudeUsageAuthorityQuarantineRecord {
        proof_correction: None,
        contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
        proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
        member_source_file_fingerprints: BTreeMap::from([(
            member.to_string(),
            revision.to_string(),
        )]),
        failed_reconstruction_count,
        disposition,
        retry_after_unix_seconds: now + CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS,
    };
    assert!(claude_usage_authority_preserves_pending(&record, &witness));
    index
        .claude_usage_family_witnesses
        .insert(root_session_id.to_string(), witness);
    index
        .claude_usage_authority_quarantine
        .insert(root_session_id.to_string(), record);
}

fn committed_entry(source: &str, fingerprint: &str) -> ScanIndexEntry {
    let mut entry = manifest_index_entry(Some(fingerprint));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    entry.source_file_fingerprint = source.to_string();
    entry
}

fn index_file(index: &mut ScanIndex, key: &str, source: &str, fingerprint: &str, activity: &str) {
    index
        .files
        .insert(key.to_string(), committed_entry(source, fingerprint));
    index
        .file_snapshot_fingerprints
        .insert(key.to_string(), BTreeSet::from([fingerprint.to_string()]));
    index
        .snapshot_activity_at
        .insert(fingerprint.to_string(), Some(activity.to_string()));
}

fn matching_candidate(index: &ScanIndex, key: &str) -> CandidateFile {
    let entry = &index.files[key];
    let mut candidate = test_candidate(PathBuf::from(key));
    candidate.size_bytes = entry.size_bytes;
    candidate.modified_unix_seconds = entry.modified_unix_seconds;
    candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap_or_default();
    candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
    candidate
}

fn decision(
    index: &ScanIndex,
    candidate: &CandidateFile,
) -> (CandidateDecision, Option<CandidateParseReason>) {
    let decided = index.candidate_decision_with_reason_at(candidate, 0);
    // The reason is diagnostic only: it names a parse and never changes it.
    assert_eq!(decided.0, index.candidate_decision_at(candidate, 0));
    assert_eq!(decided.1.is_some(), decided.0 == CandidateDecision::Parse);
    decided
}

// A member re-observed in one census window must match exactly, across
// pages as well as within one page. Even an appended transcript invalidates
// the family: its request evidence cannot be tied to one physical member
// without immutable member provenance, so the fence stays closed and only the
// re-arm backoff bounds the repeated work.
#[test]
fn claude_family_pending_reobservation_stays_exact_within_a_window() {
    let (root, _, items) = claude_account_family_fixture(false);
    let full = items[0].clone();
    let mut prefix = full.clone();
    let last_request = prefix
        .claude_usage_request_ids
        .pop_last()
        .expect("parent request id");
    prefix.claude_usage_occurrences.remove(&last_request);
    prefix.request_count -= 1;
    let family_root = claude_snapshot_family_root(&full);

    // An identical later page keeps the family valid.
    let mut pending = BTreeMap::new();
    for _ in 0..2 {
        accumulate_claude_usage_family_pending_with_limit(
            std::slice::from_ref(&full),
            &mut pending,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
    }
    assert!(!pending[&family_root].invalid);

    // Growth or shrinkage on a later page of the same window invalidates.
    for pages in [[&prefix, &full], [&full, &prefix]] {
        let mut pending = BTreeMap::new();
        accumulate_claude_usage_family_pending_with_limit(
            std::slice::from_ref(pages[0]),
            &mut pending,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
        let counts = accumulate_claude_usage_family_pending_with_limit(
            std::slice::from_ref(pages[1]),
            &mut pending,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
        assert!(pending[&family_root].invalid);
        assert_eq!(
            counts,
            ClaudeDuplicateCensusCounts {
                page_invalidated_member_changed_count: 1,
                ..Default::default()
            }
        );
    }

    // A new census window starts over.
    let mut pending = BTreeMap::new();
    accumulate_claude_usage_family_pending_with_limit(
        std::slice::from_ref(&prefix),
        &mut pending,
        OLDER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    let counts = accumulate_claude_usage_family_pending_with_limit(
        std::slice::from_ref(&full),
        &mut pending,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    assert!(!pending[&family_root].invalid);
    assert_eq!(counts.page_invalidated_member_changed_count, 0);
    assert_eq!(pending[&family_root].census_window_end, WINDOW);

    let _ = fs::remove_dir_all(root);
}

// Coverage counts every indexed family member this window did not observe.
#[test]
fn claude_duplicate_fence_coverage_counts_unobserved_indexed_members() {
    let mut index = ScanIndex::default();
    for key in [
        "/opaque/root-a.jsonl",
        "/opaque/root-b.jsonl",
        "/opaque/root-c.jsonl",
    ] {
        index
            .files
            .insert(key.to_string(), manifest_index_entry(None));
    }
    index
        .confirmed_empty_files
        .insert("/opaque/root-c.jsonl".to_string());
    index
        .claude_usage_family_pending
        .insert("root-a".to_string(), current_pending("root-a", "req-a"));
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&index, WINDOW),
        1
    );

    // Pending that is invalid, from another window, or missing occurrences
    // proves nothing about the current window.
    let mut invalid = current_pending("root-b", "req-b");
    invalid.invalid = true;
    let mut older = current_pending("root-b", "req-b");
    older.census_window_end = OLDER_WINDOW.to_string();
    let mut without_occurrences = current_pending("root-b", "req-b");
    without_occurrences.member_occurrences.clear();
    for unproven in [invalid, older, without_occurrences] {
        let mut index = index.clone();
        index
            .claude_usage_family_pending
            .insert("root-b".to_string(), unproven);
        assert_eq!(
            claude_duplicate_fence_coverage_missing_member_count(&index, WINDOW),
            1
        );
    }

    let mut covered = index.clone();
    covered
        .claude_usage_family_pending
        .insert("root-b".to_string(), current_pending("root-b", "req-b"));
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&covered, WINDOW),
        0
    );

    // A root held by a bound quarantine is excluded, as the census excludes
    // its retained pending.
    let mut quarantined = index.clone();
    bind_authority_quarantine(
        &mut quarantined,
        "root-b",
        "root-b",
        &hex64('b'),
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
    );
    assert_eq!(
        claude_duplicate_fence_coverage_missing_member_count(&quarantined, WINDOW),
        0
    );
}

// The full re-arm backs off while the fence stays closed, and missing
// scheduling state only costs a replay.
#[test]
fn claude_duplicate_fence_full_rearm_backs_off_and_fails_closed() {
    let now = Some(CENSUS_CLOCK);
    let mut index = ScanIndex::default();
    // Staying open never replays; opening re-emits posture once.
    assert!(!claude_duplicate_fence_full_rearm_due(
        &index, false, false, now
    ));
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, true, false, now
    ));
    // Closing replays at once.
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, false, true, now
    ));
    // A closed fence without a deadline (legacy or lost) replays.
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, true, true, now
    ));
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK + 1);
    assert!(!claude_duplicate_fence_full_rearm_due(
        &index, true, true, now
    ));
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, true, true, None
    ));
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK);
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, true, true, now
    ));
    index.claude_duplicate_fence_next_full_rearm_unix_seconds =
        Some(CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_MAX_SECONDS + 1);
    assert!(claude_duplicate_fence_full_rearm_due(
        &index, true, true, now
    ));

    assert_eq!(
        claude_duplicate_fence_rearm_delay_seconds(0),
        CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS
    );
    assert_eq!(
        claude_duplicate_fence_rearm_delay_seconds(1),
        2 * CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS
    );
    for attempt in [5, CLAUDE_DUPLICATE_FENCE_REARM_MAX_ATTEMPT, u8::MAX] {
        assert_eq!(
            claude_duplicate_fence_rearm_delay_seconds(attempt),
            CLAUDE_DUPLICATE_FENCE_REARM_MAX_SECONDS
        );
    }
}

// A closed fence stays closed while any indexed member is unobserved,
// even when every observed family is valid; its full replay is deferred by
// backoff and the fence opens once coverage completes.
#[test]
fn claude_duplicate_fence_reopens_only_after_full_coverage() {
    let (root, _, items) = claude_account_family_fixture(false);
    let unobserved = "/opaque/unobserved-root.jsonl";
    let mut closed = ScanIndex {
        claude_duplicate_request_witness_overflowed: true,
        ..ScanIndex::default()
    };
    closed.files.insert(
        unobserved.to_string(),
        manifest_index_entry(Some("unobserved")),
    );

    let (_, after, counts) = claude_census_counts_run_twice(
        &items,
        &closed,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(after.claude_duplicate_request_witness_overflowed);
    assert_eq!(
        counts,
        ClaudeDuplicateCensusCounts {
            census_complete: true,
            fence_before: true,
            fence_after: true,
            pending_occurrence_count: 5,
            coverage_missing_member_count: 1,
            full_rearm: true,
            rearm_attempt: 1,
            full_rearm_deferred_until: Some(
                CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS
            ),
            ..Default::default()
        }
    );
    assert!(after.files[unobserved].source_file_fingerprint.is_empty());

    // Inside the backoff the same closed census does not replay again.
    let mut deferred = after.clone();
    deferred
        .files
        .get_mut(unobserved)
        .expect("unobserved entry")
        .source_file_fingerprint = "source".to_string();
    let (_, deferred_after, counts) = claude_census_counts_run_twice(
        &items,
        &deferred,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(deferred_after.claude_duplicate_request_witness_overflowed);
    assert!(!counts.full_rearm);
    assert_eq!(counts.rearm_attempt, 1);
    assert_eq!(
        counts.full_rearm_deferred_until,
        Some(CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS)
    );
    assert_eq!(
        deferred_after.files[unobserved].source_file_fingerprint,
        "source"
    );

    // Losing the scheduling fields replays rather than opening.
    let mut lost: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&deferred).expect("encode index"))
            .expect("decode index");
    lost.claude_duplicate_fence_rearm_attempt = 0;
    lost.claude_duplicate_fence_next_full_rearm_unix_seconds = None;
    let (_, lost_after, counts) = claude_census_counts_run_twice(
        &items,
        &lost,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(lost_after.claude_duplicate_request_witness_overflowed);
    assert!(counts.full_rearm);

    // An open fence is not closed by coverage alone.
    let mut open = closed.clone();
    open.claude_duplicate_request_witness_overflowed = false;
    let (_, open_after, counts) = claude_census_counts_run_twice(
        &items,
        &open,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(!open_after.claude_duplicate_request_witness_overflowed);
    assert!(!counts.coverage_complete);
    assert!(!counts.full_rearm);

    // Once the unobserved member is gone, the fence opens and posture is
    // re-emitted once.
    let mut covered = deferred.clone();
    covered.files.remove(unobserved);
    let (_, covered_after, counts) = claude_census_counts_run_twice(
        &items,
        &covered,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(!covered_after.claude_duplicate_request_witness_overflowed);
    assert!(counts.coverage_complete);
    assert!(counts.full_rearm);
    assert_eq!(covered_after.claude_duplicate_fence_rearm_attempt, 0);
    assert_eq!(
        covered_after.claude_duplicate_fence_next_full_rearm_unix_seconds,
        None
    );

    let _ = fs::remove_dir_all(root);
}

// Only a bound authority demotion of this exact revision (terminal, or, since
// the path-(a) bridge, RetryPending without a correction grant), or a durably
// disclosed account deferral, stops blocking traversal progress.
#[test]
fn claude_progress_blocking_holds_exclude_only_non_progressing_revisions() {
    let (root, _, items) = claude_account_family_fixture(false);
    let mut held = items[0].clone();
    let revision = hex64('a');
    held.source_file_fingerprint = Some(revision.clone());
    let family_root = claude_snapshot_family_root(&held);
    let snapshots = vec![held.clone()];

    let mut terminal = ScanIndex::default();
    bind_authority_quarantine(
        &mut terminal,
        &family_root,
        &held.source_session_id,
        &revision,
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(claude_authority_hold_is_bound(&held, &terminal));

    let mut retry = ScanIndex::default();
    bind_authority_quarantine(
        &mut retry,
        &family_root,
        &held.source_session_id,
        &revision,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
    );
    // FLIPS on the pre-bridge head: RetryPending was always progress-blocking.
    assert!(claude_authority_hold_is_bound(&held, &retry));

    // A correction grant keeps a RetryPending hold blocking.
    let mut retry_correction = retry.clone();
    {
        let record = retry_correction
            .claude_usage_authority_quarantine
            .get_mut(&family_root)
            .expect("RetryPending record");
        record.contract = CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_string();
        record.proof_correction = Some(ClaudeAuthorityProofCorrection {
            proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
            owed_member_ids: BTreeSet::from([held.source_session_id.clone()]),
        });
    }
    assert!(!claude_authority_hold_is_bound(&held, &retry_correction));

    let mut other_revision = ScanIndex::default();
    bind_authority_quarantine(
        &mut other_revision,
        &family_root,
        &held.source_session_id,
        &hex64('b'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(!claude_authority_hold_is_bound(&held, &other_revision));

    let mut unbound_witness = terminal.clone();
    unbound_witness
        .claude_usage_family_witnesses
        .get_mut(&family_root)
        .expect("retained witness")
        .evidence_fingerprint = hex64('f');
    assert!(!claude_authority_hold_is_bound(&held, &unbound_witness));

    let mut unknown_revision = held.clone();
    unknown_revision.source_file_fingerprint = None;
    assert!(!claude_authority_hold_is_bound(
        &unknown_revision,
        &terminal
    ));

    let mut demoted = ClaudeUsageAuthorityDisposition::default();
    demoted
        .quarantined_source_session_ids
        .insert(held.source_session_id.clone());
    use crate::local_resource_diagnostics::claude_reread::Scope;
    for settled in [&terminal, &retry] {
        let scope = Scope::begin(true);
        assert!(demoted
            .progress_blocking_held_fingerprints(&snapshots, settled, true)
            .is_empty());
        assert_eq!(
            serde_json::to_value(scope.finish()).unwrap(),
            serde_json::json!({})
        );
    }
    for (blocking, reason) in [
        (&retry_correction, "authority_correction_pending"),
        (&other_revision, "authority_unbound_revision"),
        (&unbound_witness, "authority_unbound_revision"),
        (&ScanIndex::default(), "authority_unbound_revision"),
    ] {
        let scope = Scope::begin(true);
        assert_eq!(
            demoted.progress_blocking_held_fingerprints(&snapshots, blocking, true),
            BTreeSet::from([held.snapshot_fingerprint.clone()])
        );
        assert_eq!(
            serde_json::to_value(scope.finish()).unwrap()["claude_reread"]["held_reason"],
            serde_json::json!({reason: 1})
        );
    }
    assert!(demoted.account_deferred_fingerprints(&snapshots).is_empty());

    let mut deferred = ClaudeUsageAuthorityDisposition::default();
    deferred.defer_sessions(BTreeSet::from([held.source_session_id.clone()]));
    assert_eq!(
        deferred.quarantined_fingerprints(&snapshots),
        BTreeSet::from([held.snapshot_fingerprint.clone()])
    );
    assert_eq!(
        deferred.account_deferred_fingerprints(&snapshots),
        BTreeSet::from([held.snapshot_fingerprint.clone()])
    );
    assert!(deferred
        .progress_blocking_held_fingerprints(&snapshots, &ScanIndex::default(), true)
        .is_empty());
    // Without a durable disclosure an account deferral keeps blocking.
    let scope = Scope::begin(true);
    assert_eq!(
        deferred.progress_blocking_held_fingerprints(&snapshots, &ScanIndex::default(), false),
        BTreeSet::from([held.snapshot_fingerprint.clone()])
    );
    assert_eq!(
        serde_json::to_value(scope.finish()).unwrap()["claude_reread"]["held_reason"],
        serde_json::json!({"account_hold_unrecorded": 1})
    );
    let mut retained = snapshots.clone();
    deferred.retain_uploadable(&mut retained);
    assert!(retained.is_empty());

    let _ = fs::remove_dir_all(root);
}

// SI P3 (path-(a) bridge): authority debt no longer marks the sweep, so the
// unchanged-proof skip may run while a family is held. A root that still
// carries a RetryPending record bound to its witness is never an
// unchanged-proof root; the same family without the record is one.
#[test]
fn retry_pending_root_is_never_an_unchanged_proof_root() {
    let root = "root-session".to_string();
    let mut held = ScanIndex::default();
    bind_authority_quarantine(
        &mut held,
        &root,
        &root,
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
    );
    held.claude_usage_family_pending.insert(
        root.clone(),
        ClaudeUsageFamilyPending {
            census_window_end: WINDOW.to_string(),
            member_request_id_hashes: BTreeMap::from([(
                root.clone(),
                BTreeSet::from([hex64('c')]),
            )]),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
            identity_contract: None,
        },
    );
    let witness = held.claude_usage_family_witnesses[&root].clone();
    let before = BTreeMap::from([(
        root.clone(),
        claude_usage_family_witness_fingerprint(&witness),
    )]);
    let proven = BTreeMap::from([(
        root.clone(),
        ProvenClaudeUsageFamily {
            witness,
            rows_by_member: BTreeMap::new(),
        },
    )]);
    let complete = BTreeMap::from([(root.clone(), BTreeSet::from([root.clone()]))]);
    let no_owners = BTreeSet::new();
    let no_hashes = BTreeSet::new();
    let unchanged = |index: &ScanIndex| {
        claude_unchanged_proof_roots(
            index,
            &proven,
            &complete,
            &before,
            &BTreeMap::new(),
            &BTreeSet::new(),
            WINDOW,
            &BTreeSet::new(),
            (&no_owners, &no_hashes, &no_hashes),
            None,
        )
        .map(|roots| roots.get(root.as_str()).copied())
    };
    let mut control = held.clone();
    control.claude_usage_authority_quarantine.remove(&root);
    let Some(control_root) = unchanged(&control) else {
        // The scratch budget is not admitted on this layout.
        return;
    };
    assert_eq!(control_root, Some(true), "control: an unchanged proof root");
    assert_eq!(
        unchanged(&held),
        Some(Some(false)),
        "the held root is excluded"
    );
}

// A held key keeps its committed revision, its activity and accepted
// ledger, and reparse debt; every other key commits as scanned. A held key
// with no committed revision in a family with retained authority evidence is
// not restorable.
#[test]
fn locally_held_keys_revert_to_committed_revision_and_keep_manifest() {
    let activity = "2026-08-02T07:00:00Z";
    let held_key = "/opaque/held.jsonl";
    let sibling_key = "/opaque/sibling.jsonl";
    let fresh_held_key = "/opaque/fresh-held.jsonl";
    let fresh_key = "/opaque/fresh.jsonl";
    let mut previous = ScanIndex::default();
    index_file(
        &mut previous,
        held_key,
        "held-old-source",
        "held-old",
        activity,
    );
    index_file(
        &mut previous,
        sibling_key,
        "sibling-old-source",
        "sibling-old",
        activity,
    );
    previous
        .accepted_snapshot_fingerprints
        .extend(["held-old".to_string(), "sibling-old".to_string()]);

    let mut scanned = previous.clone();
    index_file(
        &mut scanned,
        held_key,
        "held-new-source",
        "held-new",
        activity,
    );
    index_file(
        &mut scanned,
        sibling_key,
        "sibling-new-source",
        "sibling-new",
        activity,
    );
    index_file(
        &mut scanned,
        fresh_held_key,
        "fresh-held-source",
        "fresh-held",
        activity,
    );
    index_file(&mut scanned, fresh_key, "fresh-source", "fresh", activity);
    for replaced in ["held-old", "sibling-old"] {
        scanned.snapshot_activity_at.remove(replaced);
    }
    scanned
        .accepted_snapshot_fingerprints
        .extend(["sibling-new".to_string(), "fresh".to_string()]);
    let held = BTreeSet::from(["held-new".to_string(), "fresh-held".to_string()]);

    let reverted = scanned.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    let saved: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&reverted).expect("encode index"))
            .expect("decode index");
    assert_eq!(
        saved.files[held_key].source_file_fingerprint,
        "held-old-source"
    );
    assert_eq!(
        saved.files[held_key].last_snapshot_fingerprint.as_deref(),
        Some("held-old")
    );
    assert_eq!(
        saved.file_snapshot_fingerprints[held_key],
        BTreeSet::from(["held-old".to_string()])
    );
    assert!(saved.snapshot_activity_at.contains_key("held-old"));
    assert!(!saved.snapshot_activity_at.contains_key("held-new"));
    assert!(saved.accepted_snapshot_fingerprints.contains("held-old"));
    assert!(!saved.accepted_snapshot_fingerprints.contains("held-new"));
    // A held key that was never committed stays absent.
    assert!(!saved.files.contains_key(fresh_held_key));
    assert!(!saved
        .file_snapshot_fingerprints
        .contains_key(fresh_held_key));
    assert!(!saved.snapshot_activity_at.contains_key("fresh-held"));
    // Every other key commits exactly as scanned.
    assert_eq!(
        saved.files[sibling_key].source_file_fingerprint,
        "sibling-new-source"
    );
    assert_eq!(
        saved.file_snapshot_fingerprints[sibling_key],
        BTreeSet::from(["sibling-new".to_string()])
    );
    assert!(saved.files.contains_key(fresh_key));

    // The manifest is the fold of the committed held revision with every
    // other scanned key.
    let mut expected = scanned.clone();
    index_file(
        &mut expected,
        held_key,
        "held-old-source",
        "held-old",
        activity,
    );
    expected.files.remove(fresh_held_key);
    expected.file_snapshot_fingerprints.remove(fresh_held_key);
    expected.snapshot_activity_at.remove("held-new");
    expected.snapshot_activity_at.remove("fresh-held");
    let window_start = "2026-08-01T00:00:00Z";
    let window_end = "2026-08-03T00:00:00Z";
    let manifest = saved
        .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
        .expect("held revert keeps a complete activity witness");
    assert_eq!(manifest.entity_count, 3);
    assert_eq!(
        manifest,
        expected
            .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
            .expect("expected manifest")
    );

    // An unchanged held key is still skipped; reparse debt re-arms it.
    let candidate = matching_candidate(&previous, held_key);
    assert_eq!(
        decision(&saved, &candidate),
        (CandidateDecision::Skip, None)
    );
    let reparse = scanned.with_locally_held_keys_reverted(&previous, &held, &held);
    assert!(reparse.files[held_key].source_file_fingerprint.is_empty());
    assert_eq!(
        decision(&reparse, &candidate),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::Rearmed)
        )
    );

    // An explicitly cleared source fingerprint on the scanned held key
    // (a terminal full re-arm or prior reparse debt) survives the revert.
    let mut rearmed = scanned.clone();
    rearmed
        .files
        .get_mut(held_key)
        .expect("held entry")
        .source_file_fingerprint
        .clear();
    let rearmed = rearmed.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    assert!(rearmed.files[held_key].source_file_fingerprint.is_empty());
    assert_eq!(
        rearmed.files[held_key].last_snapshot_fingerprint.as_deref(),
        Some("held-old")
    );

    // Dropping a never-committed held key is settleable only while its family
    // carries no retained authority evidence; a committed held key restores.
    assert!(scanned.locally_held_keys_restorable(&previous, &held, &BTreeSet::new()));
    let mut fresh_family_evidence = scanned.clone();
    bind_authority_quarantine(
        &mut fresh_family_evidence,
        "fresh-held",
        "fresh-held",
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(!fresh_family_evidence.locally_held_keys_restorable(
        &previous,
        &held,
        &BTreeSet::new()
    ));
    let mut previous_family_evidence = previous.clone();
    bind_authority_quarantine(
        &mut previous_family_evidence,
        "fresh-held",
        "fresh-held",
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(!scanned.locally_held_keys_restorable(
        &previous_family_evidence,
        &held,
        &BTreeSet::new()
    ));
    let mut committed_family_evidence = scanned.clone();
    bind_authority_quarantine(
        &mut committed_family_evidence,
        "held",
        "held",
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(committed_family_evidence.locally_held_keys_restorable(
        &previous,
        &held,
        &BTreeSet::new()
    ));
}

// A never-committed subagent of a committed family, held by that family's
// bound terminal quarantine at exactly its scanned revision, settles with a
// delivery-free membership entry: no entity, activity, acceptance, or
// manifest member, and the unchanged file is skipped at the quarantine gate.
// The family census then sees every present member. Every other shape keeps
// the conservative block or drop.
#[test]
fn bound_terminal_member_of_committed_family_keeps_delivery_free_membership() {
    let activity = "2026-08-02T07:00:00Z";
    let root_key = "/opaque/family-root.jsonl";
    let member_key = "/opaque/family-root/subagents/agent-member.jsonl";
    let member = "family-root_agent-member";
    let member_revision = hex64('b');
    let mut previous = ScanIndex::default();
    index_file(&mut previous, root_key, &hex64('a'), "root-old", activity);
    previous
        .accepted_snapshot_fingerprints
        .insert("root-old".to_string());
    let mut scanned = previous.clone();
    index_file(
        &mut scanned,
        member_key,
        &member_revision,
        "member-held",
        activity,
    );
    {
        let entry = scanned.files.get_mut(member_key).expect("member entry");
        entry.last_upload_body_witness = Some("member-witness".to_string());
        entry.effective_upload_body_witness_revision = 1;
    }
    bind_authority_quarantine(
        &mut scanned,
        "family-root",
        member,
        &member_revision,
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    let held = BTreeSet::from(["member-held".to_string()]);
    let no_account_holds = BTreeSet::new();

    assert!(scanned.locally_held_keys_restorable(&previous, &held, &no_account_holds));
    let reverted = scanned.with_locally_held_keys_reverted(&previous, &held, &no_account_holds);
    let saved: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&reverted).expect("encode index"))
            .expect("decode index");
    let placeholder = &saved.files[member_key];
    assert_eq!(placeholder.source_file_fingerprint, member_revision);
    assert_eq!(placeholder.last_snapshot_fingerprint, None);
    assert_eq!(placeholder.last_upload_body_witness, None);
    assert_eq!(placeholder.effective_upload_body_witness_revision, 0);
    assert!(!saved.file_snapshot_fingerprints.contains_key(member_key));
    assert!(!saved.confirmed_empty_files.contains(member_key));
    assert!(!saved.snapshot_activity_at.contains_key("member-held"));
    assert!(!saved.accepted_snapshot_fingerprints.contains("member-held"));
    assert!(!saved
        .current_snapshot_fingerprints()
        .contains("member-held"));
    let window_start = "2026-08-01T00:00:00Z";
    let window_end = "2026-08-03T00:00:00Z";
    assert_eq!(
        saved
            .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
            .expect("placeholder adds no activity witness"),
        previous
            .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
            .expect("committed manifest")
    );
    assert_eq!(
        complete_claude_usage_family_members(&saved).get("family-root"),
        Some(&BTreeSet::from([
            "family-root".to_string(),
            member.to_string()
        ]))
    );
    let candidate = matching_candidate(&saved, member_key);
    assert_eq!(
        decision(&saved, &candidate),
        (CandidateDecision::Skip, None)
    );
    let mut replaced = candidate.clone();
    replaced.source_file_fingerprint = hex64('d');
    assert_eq!(
        decision(&saved, &replaced),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
    // Once the quarantine is gone the delivery-free entry is reparsed.
    let mut resolved = saved.clone();
    resolved.claude_usage_authority_quarantine.clear();
    assert_eq!(
        decision(&resolved, &candidate),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::UnknownOutcome)
        )
    );

    // An account deferral on the same key keeps the replay-reset block.
    assert!(!scanned.locally_held_keys_restorable(&previous, &held, &held));
    assert!(!scanned
        .with_locally_held_keys_reverted(&previous, &held, &held)
        .files
        .contains_key(member_key));
    // A family whose root entry is not committed (a replay reset) blocks.
    let mut rootless = previous.clone();
    rootless.files.remove(root_key);
    assert!(!scanned.locally_held_keys_restorable(&rootless, &held, &no_account_holds));
    // A record bound to another revision, or a RetryPending record, blocks.
    for (revision, disposition) in [
        (
            hex64('c'),
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
        ),
        (
            member_revision.clone(),
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
        ),
    ] {
        let mut unbound = scanned.clone();
        bind_authority_quarantine(&mut unbound, "family-root", member, &revision, disposition);
        assert!(!unbound.locally_held_keys_restorable(&previous, &held, &no_account_holds));
    }
    // The root member itself never gets a placeholder.
    let mut root_held = ScanIndex::default();
    index_file(&mut root_held, root_key, &hex64('a'), "root-held", activity);
    bind_authority_quarantine(
        &mut root_held,
        "family-root",
        "family-root",
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    let root_hold = BTreeSet::from(["root-held".to_string()]);
    assert!(!root_held.locally_held_keys_restorable(
        &ScanIndex::default(),
        &root_hold,
        &no_account_holds
    ));
}

// A bound terminal hold keeps its revision and is skipped even under a
// changed upload context; a due retry or changed revision reparses.
#[test]
fn bound_terminal_hold_skips_until_family_changes() {
    let key = "/opaque/terminal-root.jsonl";
    let revision = hex64('c');
    let mut index = ScanIndex::default();
    index_file(
        &mut index,
        key,
        &revision,
        "terminal-old",
        "2026-08-02T07:00:00Z",
    );
    bind_authority_quarantine(
        &mut index,
        "terminal-root",
        "terminal-root",
        &revision,
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    let candidate = matching_candidate(&index, key);
    assert_eq!(
        decision(&index, &candidate),
        (CandidateDecision::Skip, None)
    );
    let mut context_changed = index.clone();
    context_changed.upload_context_fingerprint = Some("previous-context".to_string());
    assert_eq!(
        decision(&context_changed, &candidate),
        (CandidateDecision::Skip, None)
    );

    let mut changed = candidate.clone();
    changed.source_file_fingerprint = hex64('d');
    assert_eq!(
        decision(&index, &changed),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
    let mut retry_due = index.clone();
    let record = retry_due
        .claude_usage_authority_quarantine
        .get_mut("terminal-root")
        .expect("quarantine");
    record.disposition = ClaudeUsageAuthorityQuarantineDisposition::RetryPending;
    record.retry_after_unix_seconds = 0;
    assert_eq!(
        decision(&retry_due, &candidate),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
}

/// [format] Account holds are durable, bounded, and pruned only by a resolving
/// parse or two stable-parent absence observations.
#[test]
fn claude_account_deferred_holds_are_durable_bounded_and_pruned_by_proof() {
    let dir = crate::test_scratch::ScratchDir::new("account-hold-rooted-proof");
    let scan_root = fs::canonicalize(&dir).unwrap();
    let held_path = scan_root.join("deferred.jsonl");
    let other_path = scan_root.join("other.jsonl");
    fs::write(&held_path, b"owed\n").unwrap();
    let held_key = held_path.to_str().unwrap();
    let other_key = other_path.to_str().unwrap();
    let mut index = ScanIndex::default();
    index.file_snapshot_fingerprints.insert(
        held_key.to_string(),
        BTreeSet::from(["deferred".to_string()]),
    );
    index
        .file_snapshot_fingerprints
        .insert(other_key.to_string(), BTreeSet::from(["other".to_string()]));
    let deferred = BTreeMap::from([("deferred".to_string(), 7)]);

    assert!(index.record_claude_account_deferred_holds(
        [(held_key, "deferred-source"), (other_key, "other-source")],
        &deferred,
    ));
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    assert_eq!(
        index
            .claude_account_deferred_holds
            .get(held_key)
            .map(String::as_str),
        Some("deferred-source")
    );

    // Persisted across saves and later pages that do not parse the key.
    let mut index: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&index).expect("encode index"))
            .expect("decode index");
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    assert!(index.record_claude_account_deferred_holds([(other_key, "other-source")], &deferred));
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    // The committable subset of a later page keeps the disclosure.
    let subset = index.committable_subset(&index.clone(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(subset.claude_account_deferred_hold_count(), 1);

    // A parse that resolves the deferral clears it.
    let mut resolved = index.clone();
    assert!(resolved
        .record_claude_account_deferred_holds([(held_key, "deferred-source")], &BTreeMap::new(),));
    assert_eq!(resolved.claude_account_deferred_hold_count(), 0);
    // W4: a release on resolution is counted apart from a deletion.
    let [released, _, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
    assert_eq!(released, BTreeMap::from([("resolved", 1)]));

    // Census absence prompts a rooted proof; absence of index/observation
    // membership alone is never enough to release owed usage.
    let mut observed = index.clone();
    observed.probe_absent_claude_account_deferred_holds();
    assert_eq!(observed.claude_account_deferred_hold_count(), 1);
    let mut indexed = index.clone();
    indexed
        .files
        .insert(held_key.to_string(), manifest_index_entry(Some("deferred")));
    indexed.probe_absent_claude_account_deferred_holds();
    assert_eq!(indexed.claude_account_deferred_hold_count(), 1);
    let mut absent = index.clone();
    absent.probe_absent_claude_account_deferred_holds();
    assert_eq!(
        absent.claude_account_deferred_hold_count(),
        1,
        "no configured proof root"
    );
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&scan_root),
        &mut absent,
        "2026-10-07T12:00:00Z",
        7,
    );
    assert!(!sampled_audit::proven_absent(
        &held_path,
        std::slice::from_ref(&scan_root)
    ));
    absent.probe_absent_claude_account_deferred_holds();
    assert_eq!(
        absent.claude_account_deferred_hold_count(),
        1,
        "still present"
    );
    crate::snapshots::line_delivery_tests::walk_all(&mut absent, 7);
    fs::remove_file(&held_path).unwrap();
    assert!(sampled_audit::proven_absent(
        &held_path,
        std::slice::from_ref(&scan_root)
    ));
    withheld_account::support::clock(&absent.withheld_memo);
    sampled_scan::set_test_now(Some(1_000));
    absent.probe_absent_claude_account_deferred_holds();
    assert_eq!(absent.claude_account_deferred_hold_count(), 1);
    crate::snapshots::line_delivery_tests::next_walk(
        &mut absent,
        std::slice::from_ref(&scan_root),
        "2026-10-07T12:00:00Z",
        7,
    );
    sampled_scan::set_test_now(Some(1_600));
    absent.probe_absent_claude_account_deferred_holds();
    sampled_scan::set_test_now(None);
    assert_eq!(absent.claude_account_deferred_hold_count(), 0);

    // At the bound a new hold cannot be recorded and the caller must keep
    // account deferrals blocking; an existing hold still updates.
    let mut full = index.clone();
    for slot in 1..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
        full.claude_account_deferred_holds
            .insert(format!("/opaque/bound-{slot}.jsonl"), "source".to_string());
    }
    assert_eq!(
        full.claude_account_deferred_hold_count(),
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
    );
    full.file_snapshot_fingerprints.insert(
        other_key.to_string(),
        BTreeSet::from(["deferred".to_string()]),
    );
    assert!(!full.record_claude_account_deferred_holds([(other_key, "other-source")], &deferred));
    assert!(!full.claude_account_deferred_holds.contains_key(other_key));
    // W3: the unrecorded key's withheld tokens are disclosed on the page line.
    let [_, _, unrecorded] = crate::local_resource_diagnostics::withheld_support::take_withheld();
    assert_eq!(unrecorded, BTreeMap::from([("events", 1), ("tokens", 7)]));
    assert!(full.record_claude_account_deferred_holds([(held_key, "next-source")], &deferred));
    assert_eq!(
        full.claude_account_deferred_holds
            .get(held_key)
            .map(String::as_str),
        Some("next-source")
    );
}

// Each parse is attributed to the first selecting gate, by stable name.
#[test]
fn candidate_parse_reasons_name_the_selecting_gate() {
    let names = CANDIDATE_PARSE_REASON_NAMES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), CANDIDATE_PARSE_REASON_COUNT);
    assert!(names.iter().all(|name| name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')));
    assert_eq!(
        CANDIDATE_PARSE_REASON_NAMES[CandidateParseReason::UploadContext as usize],
        "upload_context"
    );
    assert_eq!(
        CANDIDATE_PARSE_REASON_NAMES[CandidateParseReason::ForcedFamily as usize],
        "forced_family"
    );
    assert_eq!(
        CandidateParseReason::ForcedFamily as usize,
        CANDIDATE_PARSE_REASON_COUNT - 1
    );

    let key = "/opaque/reason.jsonl";
    let mut index = ScanIndex::default();
    index_file(&mut index, key, "source", "reason", "2026-08-02T07:00:00Z");
    let candidate = matching_candidate(&index, key);
    assert_eq!(
        decision(&index, &candidate),
        (CandidateDecision::Skip, None)
    );

    let parse = |reason| (CandidateDecision::Parse, Some(reason));
    assert_eq!(
        decision(&ScanIndex::default(), &candidate),
        parse(CandidateParseReason::NewFile)
    );
    let mut context = index.clone();
    context.upload_context_fingerprint = Some("previous-context".to_string());
    assert_eq!(
        decision(&context, &candidate),
        parse(CandidateParseReason::UploadContext)
    );
    let mut activity = index.clone();
    activity.snapshot_activity_at.clear();
    assert_eq!(
        decision(&activity, &candidate),
        parse(CandidateParseReason::ActivityOrQuarantineRetry)
    );
    let mut grown = candidate.clone();
    grown.size_bytes += 1;
    assert_eq!(
        decision(&index, &grown),
        parse(CandidateParseReason::TranscriptChanged)
    );
    let mut unknown = index.clone();
    unknown
        .files
        .get_mut(key)
        .expect("entry")
        .last_snapshot_fingerprint = None;
    unknown.file_snapshot_fingerprints.clear();
    assert_eq!(
        decision(&unknown, &candidate),
        parse(CandidateParseReason::UnknownOutcome)
    );
    let mut rearmed = index.clone();
    rearmed
        .files
        .get_mut(key)
        .expect("entry")
        .source_file_fingerprint
        .clear();
    assert_eq!(
        decision(&rearmed, &candidate),
        parse(CandidateParseReason::Rearmed)
    );
    let mut changed = candidate.clone();
    changed.source_file_fingerprint = "changed-source".to_string();
    assert_eq!(
        decision(&index, &changed),
        parse(CandidateParseReason::SourceChanged)
    );
}

// Contract 5 withdraws transcript markers even when the census is complete.
// A quarantine can excuse fence coverage without comparing an original, but
// neither that excusal nor the fully compared control authorizes copied tags.
fn transcript_ownership<'i>(
    index: &'i ScanIndex,
    disposition: &ClaudeUsageAuthorityDisposition,
) -> crate::snapshots::claude_request_identity::TranscriptOwnership<'i> {
    crate::snapshots::claude_request_identity::TranscriptOwnership::after_census(index, disposition)
}

#[test]
fn transcript_ownership_needs_quarantined_originals_observed() {
    use crate::snapshots::claude_request_identity as identity;
    const ORIGINAL: &str = "4669db3d-c69f-4f0f-98ee-83cf99763ed8";
    const COPY: &str = "577aec4e-d7a0-4a10-a9ff-940da0874fe9";
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    let dir = temp_dir("c5-quarantined-original");
    let path = dir.join(format!("{COPY}.jsonl"));
    std::fs::write(
        &path,
        [
            json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment", "sessionId": COPY,
                "attachment": {"type": "credential_org", "organizationUuid": ORG}}),
            json!({"timestamp": "2026-08-02T07:00:01Z", "type": "assistant", "sessionId": COPY,
                "requestId": "req_copied", "message": {"id": "m1", "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ]
        .iter()
        .map(|line| line.to_string() + "\n")
        .collect::<String>(),
    )
    .expect("write copy transcript");
    let parse = || {
        parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "fp".into())
            .expect("parse copy")
    };
    let (api, trace) = (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
    );
    let evidence = identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    // One terminal pass over `index`, then contract 5 under its ownership.
    let run = |mut index: ScanIndex| {
        let mut items = parse();
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        identity::apply_scan_with_ownership(
            &mut items,
            &evidence,
            BTreeMap::new(),
            &transcript_ownership(&index, &disposition),
        );
        (disposition.duplicate_census, index, items.remove(0))
    };
    let bases = |item: &SnapshotItem| {
        item.request_evidence
            .iter()
            .map(|evidence| evidence.identity_basis.clone())
            .collect::<Vec<_>>()
    };
    let before = parse().remove(0);
    let conserved = |item: &SnapshotItem| {
        assert_eq!(
            (item.request_count, item.input_tokens, item.output_tokens),
            (
                before.request_count,
                before.input_tokens,
                before.output_tokens
            )
        );
        assert_eq!(item.usage_buckets.len(), before.usage_buckets.len());
        assert_eq!(item.cost, before.cost);
    };

    // Control: every indexed member was compared; marker tags still withdraw.
    let (counts, _, copy) = run(ScanIndex::default());
    assert!(
        counts.census_complete && counts.coverage_complete,
        "{counts:?}"
    );
    assert!(bases(&copy).is_empty());
    conserved(&copy);

    // The original is indexed, held by a bound terminal quarantine, and its
    // retained pending (which names the copied request) is from an older
    // window, so this census never compared it.
    let mut held = ScanIndex::default();
    held.files.insert(
        format!("/opaque/{ORIGINAL}.jsonl"),
        manifest_index_entry(Some("original")),
    );
    bind_authority_quarantine(
        &mut held,
        ORIGINAL,
        ORIGINAL,
        &hex64('a'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    let mut retained = current_pending(ORIGINAL, &format!("{:x}", Sha256::digest(b"req_copied")));
    retained.census_window_end = OLDER_WINDOW.to_string();
    held.claude_usage_family_pending
        .insert(ORIGINAL.to_string(), retained);
    let (counts, after, copy) = run(held);
    // Every fence flag passes: the quarantine excuses the original.
    assert!(
        counts.census_complete
            && counts.coverage_complete
            && !counts.census_invalid
            && !counts.fence_after,
        "{counts:?}"
    );
    assert!(after.claude_duplicate_request_owners.is_empty());
    // The census pruned this window's pending before contract 5 ran; only the
    // quarantined family's retained pending remains.
    assert!(after.claude_usage_family_pending.contains_key(ORIGINAL));
    assert!(!after.claude_usage_family_pending.contains_key(COPY));
    // The copied marker never tags the original's request: withdrawn to
    // missing, not refused, usage unchanged.
    assert!(bases(&copy).is_empty(), "{:?}", bases(&copy));
    assert_eq!(copy.request_identity_refusals, 0);
    conserved(&copy);

    let _ = std::fs::remove_dir_all(dir);
}

mod provider_envelope_experiment_tests {
    include!("provider_envelope_experiment_tests.rs");
}

mod witness_reconstruct_scope {
    include!("witness_reconstruct_scope_tests.rs");
}

// Re-review r3 (path-(a) bridge): with the absent-family scratch refused for
// the whole test, more RetryPending roots than one fallback window all get
// checked through the runtime cursor. Absent roots retire with their pending
// entries, at most one window per raw-complete census; roots whose member is
// observed (root transcript or subagent) or residue stay held.
#[test]
fn bounded_absence_fallback_checks_every_retry_pending_root_through_its_cursor() {
    let _refuse = RefuseClaudeAbsentFamilyScratchForTest::new();
    let window = MAX_CLAUDE_ABSENT_FAMILY_FALLBACK_ROOTS;
    assert_eq!(window, 16);
    let roots = (0..40).map(|n| format!("root-{n:02}")).collect::<Vec<_>>();
    let mut index = ScanIndex::default();
    for root in &roots {
        index.insert_retry_pending_claude_authority_for_test(root);
        index.insert_claude_usage_family_pending_for_test(root, OLDER_WINDOW);
    }
    // An unrelated terminal record is neither counted nor touched.
    index.insert_claude_authority_for_test(
        "terminal-root",
        &hex64('9'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert_eq!(index.claude_usage_authority_pending_count(), roots.len());
    let observed = BTreeSet::from([
        "/synthetic/projects/p/root-05.jsonl".to_string(),
        "/synthetic/projects/p/root-38/subagents/agent-a1.jsonl".to_string(),
    ]);
    let residue = BTreeSet::from(["/synthetic/projects/q/root-20.jsonl".to_string()]);
    let present = ["root-05", "root-20", "root-38"];
    // Windows: roots 00-15 (05 present), then 16-31 after the kept 05 (20
    // present), then the ten left, wrapping (38 present).
    let mut retired_per_census = Vec::new();
    for _ in 0..4 {
        retired_per_census
            .push(index.retire_absent_retry_pending_claude_families(&observed, &residue, ""));
    }
    assert_eq!(retired_per_census, vec![15, 15, 7, 0]);
    assert!(retired_per_census.iter().all(|retired| *retired <= window));
    assert_eq!(index.claude_usage_authority_pending_count(), present.len());
    for root in &roots {
        let held = present.contains(&root.as_str());
        assert_eq!(
            index.claude_authority_record_for_test(root).is_some(),
            held,
            "{root}"
        );
        assert_eq!(
            index.claude_usage_family_pending_retained_for_test(root),
            held,
            "{root}"
        );
    }
    assert!(index
        .claude_authority_record_for_test("terminal-root")
        .is_some_and(|record| record.terminal));
}

/// `count` RetryPending roots named `{prefix}-NN`, each with pending, and the
/// observed paths of those whose number `present` accepts.
fn retry_pending_roots_index(
    prefix: &str,
    count: usize,
    present: impl Fn(usize) -> bool,
) -> (ScanIndex, BTreeSet<String>) {
    let mut index = ScanIndex::default();
    let mut observed = BTreeSet::new();
    for number in 0..count {
        let root = format!("{prefix}-{number:02}");
        index.insert_retry_pending_claude_authority_for_test(&root);
        index.insert_claude_usage_family_pending_for_test(&root, OLDER_WINDOW);
        if present(number) {
            observed.insert(format!("/synthetic/projects/{prefix}/{root}.jsonl"));
        }
    }
    (index, observed)
}

// Re-review r4 (path-(a) bridge): fallback cursors are scoped per index. Two
// stable indexes, each with 32 RetryPending roots, alternate under a
// persistent scratch refusal. With one shared cursor, A would always check
// its roots 00-15 and B its roots 16-31, so A's absent root 31 would never
// be examined. Scoped, A's root 31 retires on A's second census, and B (all
// present) is untouched.
#[test]
fn bounded_absence_fallback_cursor_is_scoped_per_index() {
    let _refuse = RefuseClaudeAbsentFamilyScratchForTest::new();
    let (mut a, a_observed) = retry_pending_roots_index("a", 32, |number| number != 31);
    let (mut b, b_observed) = retry_pending_roots_index("b", 32, |_| true);
    let residue = BTreeSet::new();
    let mut a_retired = Vec::new();
    let mut b_retired = Vec::new();
    for _ in 0..2 {
        a_retired.push(a.retire_absent_retry_pending_claude_families(
            &a_observed,
            &residue,
            "index-a",
        ));
        b_retired.push(b.retire_absent_retry_pending_claude_families(
            &b_observed,
            &residue,
            "index-b",
        ));
    }
    assert_eq!(
        a_retired,
        vec![0, 1],
        "A's absent root retires on A's second census"
    );
    assert!(a.claude_authority_record_for_test("a-31").is_none());
    assert!(!a.claude_usage_family_pending_retained_for_test("a-31"));
    assert_eq!(a.claude_usage_authority_pending_count(), 31);
    assert_eq!(b_retired, vec![0, 0]);
    assert_eq!(b.claude_usage_authority_pending_count(), 32);
    for number in 0..32 {
        let root = format!("b-{number:02}");
        assert!(
            b.claude_authority_record_for_test(&root).is_some(),
            "{root}"
        );
        assert!(
            b.claude_usage_family_pending_retained_for_test(&root),
            "{root}"
        );
    }
}

/// A synthetic traversal problem, applied to a clean terminal traversal.
type TraversalProblem = fn(&mut ScanTraversalCheckpoint);

/// A clean terminal traversal that observed `observed`.
fn clean_terminal_traversal(observed: BTreeSet<String>) -> ScanTraversalCheckpoint {
    ScanTraversalCheckpoint {
        observed_index_keys: observed,
        unhealthy_retry_attempt: 0,
        unhealthy_retry_not_before_unix_seconds: None,
        counts: ScanTraversalCounts::default(),
        ..terminal_unhealthy_traversal(String::new())
    }
}

/// SOURCE Round 15: the tombstone uncertainty fence comes down only at a
/// complete healthy terminal. This one observed `observed` on disk.
fn drain_fence_at_clean_terminal(
    index: &mut ScanIndex,
    observed: BTreeSet<String>,
) -> ClaudeTombstoneFenceRepair {
    index.drain_claude_retired_family_tombstone_fence(&clean_terminal_traversal(observed))
}

// SOURCE Round 11 guard (c): traversal counts carry no per-directory
// attribution, so any read, permission or symlink error, entry cap, or
// unfinished directory or candidate page anywhere in the traversal keeps
// every absent family. The clean control retires and tombstones it.
#[test]
fn absence_retirement_keeps_every_family_after_any_traversal_problem() {
    restart_claude_reemission_stop_for_test();
    let pending_path = || ScanTraversalPath {
        scan_root: PathBuf::from("/synthetic/projects"),
        path: PathBuf::from("/synthetic/projects/elsewhere"),
        census_member: true,
        watcher_hint: false,
    };
    let problems: [(&str, TraversalProblem); 7] = [
        ("symlink", |traversal| {
            traversal.counts.symlink_rejected_count = 1
        }),
        ("unreadable", |traversal| {
            traversal
                .counts
                .record_unreadable(UnreadableCause::OpenRead, 1)
        }),
        ("entry cap", |traversal| {
            traversal.counts.directory_entry_cap_exceeded_count = 1
        }),
        ("disappeared", |traversal| {
            traversal.counts.disappeared_file_count = 1
        }),
        ("unsettled residue", |traversal| {
            traversal.counts.ownership_incomplete_file_count = 1
        }),
        ("partial directory page", |_| {}),
        ("partial candidate page", |_| {}),
    ];
    for (shape, problem) in problems {
        let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
        let mut traversal = clean_terminal_traversal(observed);
        problem(&mut traversal);
        match shape {
            "partial directory page" => traversal.pending_directories.push_back(pending_path()),
            "partial candidate page" => traversal.pending_candidates.push_back(pending_path()),
            _ => {}
        }
        let before = claude_absence_counters_for_test();
        assert_eq!(
            index.retire_positively_absent_claude_families(&traversal, ""),
            Err(ClaudeAbsenceRetirementRefusal::TraversalProblem),
            "{shape}"
        );
        assert!(
            index.claude_authority_record_for_test("gone-00").is_some(),
            "{shape}: the family is kept"
        );
        assert!(
            index.claude_usage_family_pending_retained_for_test("gone-00"),
            "{shape}"
        );
        assert!(
            !index.claude_family_tombstoned_for_test("gone-00"),
            "{shape}"
        );
        let after = claude_absence_counters_for_test();
        assert_eq!(
            after.retirements_refused,
            before.retirements_refused + 1,
            "{shape}"
        );
        assert_eq!(
            after.absent_families_retired, before.absent_families_retired,
            "{shape}"
        );
    }
    let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
    let before = claude_absence_counters_for_test();
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(1)
    );
    assert!(index.claude_authority_record_for_test("gone-00").is_none());
    assert!(!index.claude_usage_family_pending_retained_for_test("gone-00"));
    assert!(index.claude_family_tombstoned_for_test("gone-00"));
    assert_eq!(
        claude_absence_counters_for_test().absent_families_retired,
        before.absent_families_retired + 1
    );
}

// SOURCE Round 11 guards (a) and (b) at the unit seam: the latch and an
// unverified-history index each refuse with their own reason.
#[test]
fn absence_retirement_names_the_latch_and_unverified_history_refusals() {
    restart_claude_reemission_stop_for_test();
    let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
    let traversal = clean_terminal_traversal(observed);
    index.claude_history_unverified_in_process = true;
    assert_eq!(
        index.retire_positively_absent_claude_families(&traversal, ""),
        Err(ClaudeAbsenceRetirementRefusal::UnverifiedHistory)
    );
    index.claude_history_unverified_in_process = false;
    latch_claude_reemission_stop_for_test();
    assert_eq!(
        index.retire_positively_absent_claude_families(&traversal, ""),
        Err(ClaudeAbsenceRetirementRefusal::ReemissionStopLatched)
    );
    assert!(index.claude_authority_record_for_test("gone-00").is_some());
    restart_claude_reemission_stop_for_test();
    assert_eq!(
        index.retire_positively_absent_claude_families(&traversal, ""),
        Ok(1)
    );
}

/// Saves `index` at a new `path` through ordinary compare-and-swap saves
/// until the saved index carries `generation`; it never loads the path.
fn save_through_generation(index: &mut ScanIndex, path: &std::path::Path, generation: u64) {
    while index.generation < generation {
        index.save(path).unwrap();
    }
}

// SOURCE Round 11 guard (b) at load: a missing, quarantined or empty
// generation-0 load marks its path unverified for the rest of the process;
// a load with history does not, until a restart forgets the fresh load.
#[test]
fn fresh_index_loads_leave_their_path_unverified_until_a_restart() {
    forget_claude_unverified_history_indexes_for_test();
    let dir = temp_dir("patha-unverified-history-load");
    let fresh = dir.join("fresh-index.json");
    assert!(
        ScanIndex::load(&fresh)
            .unwrap()
            .claude_history_unverified_in_process
    );
    save_through_generation(&mut ScanIndex::default(), &fresh, 3);
    assert!(
        ScanIndex::load(&fresh)
            .unwrap()
            .claude_history_unverified_in_process,
        "a fresh load stays unverified for the process"
    );
    let corrupt = dir.join("corrupt-index.json");
    fs::write(&corrupt, b"{ not json").unwrap();
    assert!(
        ScanIndex::load(&corrupt)
            .unwrap()
            .claude_history_unverified_in_process
    );
    let historic = dir.join("historic-index.json");
    save_through_generation(&mut ScanIndex::default(), &historic, 3);
    assert!(
        !ScanIndex::load(&historic)
            .unwrap()
            .claude_history_unverified_in_process
    );
    forget_claude_unverified_history_indexes_for_test();
    assert!(
        !ScanIndex::load(&fresh)
            .unwrap()
            .claude_history_unverified_in_process,
        "after a restart only the history on disk counts"
    );
    let _ = fs::remove_dir_all(&dir);
}

// #705/#712 composition: both daemon and general loads share freshness,
// retain guard (b) after the index fills, and repair a lost tombstone set.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn source_aware_loads_share_history_freshness_and_repair_tombstones() {
    forget_claude_unverified_history_indexes_for_test();
    let dir = temp_dir("patha-history-origin-composition");
    let support = dir.join("support");
    for (name, origin) in [
        ("missing", ScanIndexLoadOrigin::Missing),
        ("quarantined", ScanIndexLoadOrigin::Quarantined),
        ("generation-zero", ScanIndexLoadOrigin::Loaded),
    ] {
        let path = dir.join(format!("{name}.json"));
        match origin {
            ScanIndexLoadOrigin::Missing => {}
            ScanIndexLoadOrigin::Quarantined => fs::write(&path, b"{ not json").unwrap(),
            ScanIndexLoadOrigin::Loaded => {
                fs::write(&path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
            }
        }
        let (mut index, actual_origin) = ScanIndex::load_for_snapshot_source_with_origin(
            &path,
            SnapshotSource::ClaudeCode,
            &support,
        )
        .unwrap();
        assert_eq!(actual_origin, origin, "{name}");
        assert!(actual_origin.is_fresh(&index), "{name}");
        assert!(index.claude_history_unverified_in_process, "{name}");
        assert!(index.claude_retired_family_tombstones_initialized, "{name}");
        save_through_generation(&mut index, &path, 3);
        let (filled, filled_origin) = ScanIndex::load_for_snapshot_source_with_origin(
            &path,
            SnapshotSource::ClaudeCode,
            &support,
        )
        .unwrap();
        assert_eq!(filled_origin, ScanIndexLoadOrigin::Loaded, "{name}");
        assert!(!filled_origin.is_fresh(&filled), "{name}");
        assert!(
            filled.claude_history_unverified_in_process,
            "{name}: guard b stays"
        );
        assert!(
            ScanIndex::load(&path)
                .unwrap()
                .claude_history_unverified_in_process
        );
    }

    let path = dir.join("lost-tombstones.json");
    let (mut historic, _) = retry_pending_roots_index("gone", 1, |_| false);
    historic.generation = 7;
    let mut raw = serde_json::to_value(&historic).unwrap();
    raw["claude_retired_family_tombstones_initialized"] = true.into();
    raw.as_object_mut()
        .unwrap()
        .remove("claude_retired_family_tombstones");
    fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    let (mut repaired, origin) = ScanIndex::load_for_snapshot_source_with_origin(
        &path,
        SnapshotSource::ClaudeCode,
        &support,
    )
    .unwrap();
    assert_eq!(origin, ScanIndexLoadOrigin::Loaded);
    assert!(!origin.is_fresh(&repaired));
    assert!(!repaired.claude_history_unverified_in_process);
    // Round 15: the source-aware load raises the fence; only a complete
    // healthy terminal lowers it.
    assert!(repaired.claude_retired_family_tombstones_uncertain);
    assert!(!repaired.claude_family_tombstoned_for_test("gone-00"));
    drain_fence_at_clean_terminal(&mut repaired, BTreeSet::new());
    assert!(repaired.claude_family_tombstoned_for_test("gone-00"));
    assert!(!repaired.claude_retired_family_tombstones_uncertain);
    assert!(repaired
        .claude_authority_record_for_test("gone-00")
        .is_some());
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 11 tombstone decode: malformed entries drop one by one, a
// wrong container type decodes as empty, each counted; the index and all its
// other state still load, never quarantined.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn malformed_tombstones_never_fail_the_index_decode() {
    let dir = temp_dir("patha-malformed-tombstones");
    let path = dir.join("scan-index.json");
    let kept = claude_retired_family_digest("kept-root");
    // Round 13: damage raises the uncertainty fence, and the next complete
    // terminal (Round 15; never the load) replaces it with a tombstone for
    // every witnessed root it did not see on disk: here the held root.
    let held = claude_retired_family_digest("held-root");
    let mut index = ScanIndex::default();
    index.insert_retry_pending_claude_authority_for_test("held-root");
    save_through_generation(&mut index, &path, 7);
    let saved = || serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
    let write_tombstones = |tombstones: serde_json::Value| {
        let mut value = saved();
        value["claude_retired_family_tombstones"] = tombstones;
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    };
    let assert_rest_kept = |loaded: &ScanIndex, shape: &str| {
        assert_eq!(loaded.generation, 7, "{shape}: not quarantined");
        assert!(
            loaded
                .claude_authority_record_for_test("held-root")
                .is_some(),
            "{shape}: other state kept"
        );
        assert_eq!(loaded.claude_usage_authority_pending_count(), 1, "{shape}");
    };
    write_tombstones(serde_json::Value::Object(
        [
            (kept.clone(), json!(1_700_000_000_u64)),
            ("not-a-digest".to_string(), json!(1_700_000_001_u64)),
            (hex64('a'), json!("yesterday")),
            (hex64('b'), json!(-5)),
            (hex64('c'), json!([1, 2])),
            (hex64('d'), serde_json::Value::Null),
        ]
        .into_iter()
        .collect(),
    ));
    let before = claude_absence_counters_for_test();
    let mut loaded = ScanIndex::load(&path).expect("malformed entries still load");
    assert_rest_kept(&loaded, "malformed entries");
    assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
    drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
    let tombstones = loaded.claude_retired_family_tombstones_for_test();
    assert_eq!(tombstones.get(&kept), Some(&1_700_000_000_u64));
    assert_eq!(
        tombstones.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([kept.clone(), held.clone()]),
        "the well-formed entry is kept and the fence tombstoned the witnessed root"
    );
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(
        claude_absence_counters_for_test().tombstone_decode_drops,
        before.tombstone_decode_drops + 5
    );
    for (shape, container) in [
        ("array", json!([kept.clone(), 1])),
        ("string", json!("tombstones")),
        ("number", json!(12)),
        ("bool", json!(true)),
        ("null", serde_json::Value::Null),
    ] {
        write_tombstones(container);
        let before = claude_absence_counters_for_test();
        let mut loaded = ScanIndex::load(&path).expect("a wrong container still loads");
        assert_rest_kept(&loaded, shape);
        assert!(
            loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "{shape}: the load raises the fence and never lowers it"
        );
        drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
        assert_eq!(
            loaded
                .claude_retired_family_tombstones_for_test()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([held.clone()]),
            "{shape}: nothing decoded; the fence tombstoned the witnessed root"
        );
        assert!(
            !loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "{shape}"
        );
        assert_eq!(
            claude_absence_counters_for_test().tombstone_decode_drops,
            before.tombstone_decode_drops + 1,
            "{shape}"
        );
    }
    // A well-formed set round-trips through save and load.
    let mut index = ScanIndex::load(&path).unwrap();
    tombstone_retired_claude_family(&mut index.claude_retired_family_tombstones, "kept-root", 9);
    index.save(&path).unwrap();
    assert!(ScanIndex::load(&path)
        .unwrap()
        .claude_family_tombstoned_for_test("kept-root"));
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 13 F2: a full tombstone set refuses the next retirement and
// never evicts. The refused family keeps its RetryPending record, pending
// and witness, and the refusal is counted; the oldest tombstone stays. Both
// the priced fast path and the bounded fallback reserve before removing, and
// the state survives a save and reload. On return the oldest family's member
// is read through the authority path; the kept family's record still holds
// its member.
#[test]
fn full_tombstone_set_refuses_retirement_and_keeps_the_family() {
    let cap = MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES;
    assert_eq!(cap, 1024);
    for refuse_scratch in [false, true] {
        let shape = if refuse_scratch { "fallback" } else { "fast" };
        let _refuse = refuse_scratch.then(RefuseClaudeAbsentFamilyScratchForTest::new);
        restart_claude_reemission_stop_for_test();
        let dir = temp_dir(&format!("patha-tombstone-capacity-{shape}"));
        let path = dir.join("scan-index.json");
        let (mut index, excess_present) = retry_pending_roots_index("gone", 2, |n| n == 1);
        assert_eq!(
            index.retire_positively_absent_claude_families(
                &clean_terminal_traversal(excess_present),
                ""
            ),
            Ok(1),
            "{shape}: the oldest family retires first"
        );
        assert!(
            index.claude_family_tombstoned_for_test("gone-00"),
            "{shape}"
        );
        // Every later slot holds a newer retirement.
        index.fill_claude_retired_family_tombstones_for_test(cap, u64::from(u32::MAX));
        assert_eq!(index.claude_retired_family_tombstones_for_test().len(), cap);
        let before = claude_absence_counters_for_test();
        assert_eq!(
            index.retire_positively_absent_claude_families(
                &clean_terminal_traversal(BTreeSet::new()),
                ""
            ),
            Ok(0),
            "{shape}: a full set retires nothing"
        );
        let after = claude_absence_counters_for_test();
        assert_eq!(
            after.tombstone_capacity_refusals,
            before.tombstone_capacity_refusals + 1,
            "{shape}"
        );
        assert_eq!(
            after.absent_families_retired, before.absent_families_retired,
            "{shape}"
        );
        save_through_generation(&mut index, &path, 2);
        let reloaded = ScanIndex::load(&path).unwrap();
        for (label, index) in [("before reload", &index), ("after reload", &reloaded)] {
            let record = index
                .claude_authority_record_for_test("gone-01")
                .unwrap_or_else(|| panic!("{shape} {label}: the excess family is kept"));
            assert!(!record.terminal && record.bound_to_retained_witness);
            assert!(
                index.claude_usage_family_pending_retained_for_test("gone-01"),
                "{shape} {label}"
            );
            assert!(
                index
                    .claude_usage_family_witness_digest_for_test("gone-01")
                    .is_some(),
                "{shape} {label}"
            );
            assert!(
                !index.claude_family_tombstoned_for_test("gone-01"),
                "{shape} {label}"
            );
            assert_eq!(index.claude_usage_authority_pending_count(), 1);
            assert!(
                index.claude_family_tombstoned_for_test("gone-00"),
                "{shape} {label}: the oldest tombstone is never evicted"
            );
            assert!(
                index
                    .claude_usage_family_witness_digest_for_test("gone-00")
                    .is_some(),
                "{shape} {label}"
            );
            assert_eq!(index.claude_retired_family_tombstones_for_test().len(), cap);
            assert!(!index.claude_retired_family_tombstones_uncertain_for_test());
            // The oldest family's returning member is never a new file.
            let returning = test_candidate(PathBuf::from("/synthetic/projects/gone/gone-00.jsonl"));
            assert_eq!(
                decision(index, &returning),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::AuthorityQuarantine)
                ),
                "{shape} {label}"
            );
        }
        // Only a settled proof frees a slot; then the kept family retires.
        let mut index = reloaded;
        let filler = claude_retired_family_digest("filler-0000");
        assert!(index
            .claude_retired_family_tombstones
            .remove(&filler)
            .is_some());
        assert_eq!(
            index.retire_positively_absent_claude_families(
                &clean_terminal_traversal(BTreeSet::new()),
                ""
            ),
            Ok(1),
            "{shape}"
        );
        assert!(
            index.claude_family_tombstoned_for_test("gone-01"),
            "{shape}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// Edits a saved index's top-level JSON object.
type IndexJsonEdit<'a> = dyn Fn(&mut serde_json::Map<String, serde_json::Value>) + 'a;

// SOURCE Round 13 F1: the persisted marker separates an index from before
// the bridge (no marker: an empty set is safe, nothing ever retired) from a
// marked index whose tombstone set was omitted, wrongly typed or damaged.
// The latter raises the uncertainty fence; the next complete terminal
// (Round 15) tombstones every absent witnessed root, so the retired family's returning
// member is still read through the authority path, never as a new file, and
// that survives a save and reload. An unwitnessed new root stays new.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_lost_tombstone_set_never_restores_new_file_eligibility() {
    restart_claude_reemission_stop_for_test();
    let dir = temp_dir("patha-lost-tombstones");
    let path = dir.join("scan-index.json");
    let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(1)
    );
    assert!(index
        .claude_usage_family_witness_digest_for_test("gone-00")
        .is_some());
    save_through_generation(&mut index, &path, 3);
    let saved = serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        saved["claude_retired_family_tombstones_initialized"],
        json!(true)
    );
    let digest = claude_retired_family_digest("gone-00");
    assert!(saved["claude_retired_family_tombstones"][&digest].is_u64());
    let write = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
        let mut value = saved.clone();
        edit(value.as_object_mut().unwrap());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    };
    let returning = test_candidate(PathBuf::from("/synthetic/projects/gone/gone-00.jsonl"));
    let unwitnessed = test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"));
    let authority = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::AuthorityQuarantine),
    );
    let new_file = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::NewFile),
    );

    // Intact.
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(decision(&loaded, &returning), authority);
    assert_eq!(decision(&loaded, &unwitnessed), new_file);

    // An index from before the bridge carries neither field: empty is safe
    // while every witnessed root is accounted for, here by its RetryPending
    // record, as before any retirement.
    let pre_bridge = dir.join("pre-bridge-index.json");
    let (before, _) = retry_pending_roots_index("gone", 1, |_| false);
    let mut value = serde_json::to_value(&before).unwrap();
    for field in [
        "claude_retired_family_tombstones",
        "claude_retired_family_tombstones_initialized",
    ] {
        value.as_object_mut().unwrap().remove(field);
    }
    fs::write(&pre_bridge, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&pre_bridge).unwrap();
    assert!(loaded
        .claude_retired_family_tombstones_for_test()
        .is_empty());
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert!(loaded.claude_authority_record_for_test("gone-00").is_some());

    // The same omission after the retirement is what an older writer leaves
    // (SOURCE Round 14, downgrade): the retired root's witness has no record,
    // pending proof, indexed member or tombstone, so the load fails closed
    // and the next complete terminal re-tombstones it.
    write(&|object| {
        object.remove("claude_retired_family_tombstones");
        object.remove("claude_retired_family_tombstones_initialized");
    });
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(decision(&loaded, &returning), authority);
    assert_eq!(decision(&loaded, &unwitnessed), authority);
    drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
    assert!(loaded.claude_family_tombstoned_for_test("gone-00"));
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(decision(&loaded, &returning), authority);
    assert_eq!(decision(&loaded, &unwitnessed), new_file);

    let shapes: [(&str, &IndexJsonEdit<'_>); 4] = [
        ("omitted set", &|object| {
            object.remove("claude_retired_family_tombstones");
        }),
        ("null set", &|object| {
            object.insert("claude_retired_family_tombstones".into(), json!(null));
        }),
        ("array set", &|object| {
            object.insert("claude_retired_family_tombstones".into(), json!([1]));
        }),
        ("damaged entry", &|object| {
            object["claude_retired_family_tombstones"][&digest] = json!("yesterday");
        }),
    ];
    for (shape, edit) in shapes {
        write(edit);
        let mut loaded = ScanIndex::load(&path).expect("a lost set still loads");
        assert_eq!(loaded.generation, 3, "{shape}: never quarantined");
        assert!(
            loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "{shape}: the load raises the fence and never lowers it"
        );
        assert_eq!(decision(&loaded, &returning), authority, "{shape}");
        drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
        assert!(
            loaded.claude_family_tombstoned_for_test("gone-00"),
            "{shape}: the fence tombstoned the witnessed root"
        );
        assert!(
            !loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "{shape}: it fit, so the fence came down"
        );
        assert!(
            loaded
                .claude_usage_family_witness_digest_for_test("gone-00")
                .is_some(),
            "{shape}: the authority basis is kept"
        );
        assert_eq!(decision(&loaded, &returning), authority, "{shape}");
        assert_eq!(decision(&loaded, &unwitnessed), new_file, "{shape}");
        loaded.save(&path).unwrap();
        let reloaded = ScanIndex::load(&path).unwrap();
        assert!(
            reloaded.claude_family_tombstoned_for_test("gone-00"),
            "{shape}"
        );
        assert_eq!(decision(&reloaded, &returning), authority, "{shape}");
    }
    // A wrongly typed marker or fence decodes as set (fail closed).
    write(&|object| {
        object.insert(
            "claude_retired_family_tombstones_initialized".into(),
            json!("yes"),
        );
        object.remove("claude_retired_family_tombstones");
    });
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
    drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
    assert!(loaded.claude_family_tombstoned_for_test("gone-00"));
    assert_eq!(decision(&loaded, &returning), authority);
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 13 F1/F2: when the lost roots cannot all be tombstoned within
// the cap (here an over-cap persisted set, trimmed at decode, dropped the
// retired family's tombstone), the uncertainty fence stays up durably: every
// unindexed Claude member, even an unwitnessed new root, is read through the
// authority path, across saves, reloads and complete terminals. Once a
// settled proof frees enough slots, the next complete terminal (Round 15)
// tombstones the absent witnessed roots and lowers it.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn an_unplaceable_tombstone_loss_keeps_a_durable_fence() {
    restart_claude_reemission_stop_for_test();
    let cap = MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES;
    let dir = temp_dir("patha-durable-tombstone-fence");
    let path = dir.join("scan-index.json");
    let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(1)
    );
    index.fill_claude_retired_family_tombstones_for_test(cap, u64::from(u32::MAX));
    save_through_generation(&mut index, &path, 2);
    // The retired family's retirement is the oldest; one more persisted
    // entry puts the set over its cap, so the decode trims exactly it.
    let digest = claude_retired_family_digest("gone-00");
    let mut value = serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
    value["claude_retired_family_tombstones"][&digest] = json!(1_u64);
    value["claude_retired_family_tombstones"][hex64_number(7)] = json!(u64::MAX);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let returning = test_candidate(PathBuf::from("/synthetic/projects/gone/gone-00.jsonl"));
    let unwitnessed = test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"));
    let authority = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::AuthorityQuarantine),
    );
    let before = claude_absence_counters_for_test();
    let mut loaded = ScanIndex::load(&path).expect("an over-cap set still loads");
    assert_eq!(
        claude_absence_counters_for_test().tombstone_decode_drops,
        before.tombstone_decode_drops + 1
    );
    assert_eq!(loaded.generation, 2, "never quarantined");
    assert_eq!(
        loaded.claude_retired_family_tombstones_for_test().len(),
        cap
    );
    assert!(!loaded.claude_family_tombstoned_for_test("gone-00"));
    for round in 0..2 {
        assert!(
            matches!(
                drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new()),
                ClaudeTombstoneFenceRepair::Kept { .. }
            ),
            "round {round}: no free slot for the absent root"
        );
        assert!(
            loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "round {round}: the fence stays up"
        );
        assert!(loaded
            .claude_usage_family_witness_digest_for_test("gone-00")
            .is_some());
        assert_eq!(decision(&loaded, &returning), authority, "round {round}");
        assert_eq!(
            decision(&loaded, &unwitnessed),
            authority,
            "round {round}: no new-file eligibility under the fence"
        );
        loaded.save(&path).unwrap();
        loaded = ScanIndex::load(&path).unwrap();
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap()
            ["claude_retired_family_tombstones_uncertain"],
        json!(true),
        "the fence is durable"
    );
    // A settled proof frees a slot; the next complete terminal lowers the
    // fence (the load alone never does).
    let freed = loaded
        .claude_retired_family_tombstones_for_test()
        .keys()
        .next()
        .cloned()
        .unwrap();
    assert!(loaded
        .claude_retired_family_tombstones
        .remove(&freed)
        .is_some());
    loaded.save(&path).unwrap();
    let mut lowered = ScanIndex::load(&path).unwrap();
    assert!(lowered.claude_retired_family_tombstones_uncertain_for_test());
    drain_fence_at_clean_terminal(&mut lowered, BTreeSet::new());
    assert!(!lowered.claude_retired_family_tombstones_uncertain_for_test());
    assert!(lowered.claude_family_tombstoned_for_test("gone-00"));
    assert_eq!(decision(&lowered, &returning), authority);
    assert_eq!(
        decision(&lowered, &unwitnessed),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::NewFile)
        )
    );
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 14 H729-1 control: a member that returns and parses empty is
// indexed (confirmed empty) while its family's proof is unsettled, so its
// tombstone stays. If the set is then lost, that indexed member must not
// waive the root's slot: the next complete terminal (Round 15), which does
// not see its file, re-tombstones the witnessed root, and once
// the member is gone again its return is still read through the authority
// path.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn an_indexed_member_never_waives_a_lost_tombstone() {
    restart_claude_reemission_stop_for_test();
    let dir = temp_dir("patha-indexed-member-lost-tombstone");
    let path = dir.join("scan-index.json");
    let (mut index, observed) = retry_pending_roots_index("gone", 1, |_| false);
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(1)
    );
    let key = "/synthetic/projects/gone/gone-00.jsonl".to_string();
    let mut entry = manifest_index_entry(None);
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    index.files.insert(key.clone(), entry);
    index.confirmed_empty_files.insert(key.clone());
    assert!(index.claude_family_tombstoned_for_test("gone-00"));
    assert!(index.claude_authority_record_for_test("gone-00").is_none());
    let witness = index
        .claude_usage_family_witness_digest_for_test("gone-00")
        .expect("the retired family keeps its witness");
    save_through_generation(&mut index, &path, 3);
    let mut value = serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        value["claude_retired_family_tombstones_initialized"],
        json!(true)
    );
    value
        .as_object_mut()
        .unwrap()
        .remove("claude_retired_family_tombstones");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).expect("a lost set still loads");
    assert!(
        loaded.files.contains_key(&key),
        "the member is still indexed"
    );
    assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
    // The walk does not see the indexed member's file: it counts as absent,
    // and as aged out (SOURCE h733-2).
    let aged_out = claude_absence_counters_for_test().absent_family_tombstone_aged_out;
    drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
    assert!(
        loaded.claude_family_tombstoned_for_test("gone-00"),
        "indexed presence never waives the root's slot"
    );
    assert_eq!(
        claude_absence_counters_for_test().absent_family_tombstone_aged_out,
        aged_out + 1
    );
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(
        loaded.claude_usage_family_witness_digest_for_test("gone-00"),
        Some(witness)
    );
    loaded.files.remove(&key);
    loaded.confirmed_empty_files.remove(&key);
    assert_eq!(
        decision(&loaded, &test_candidate(PathBuf::from(&key))),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        )
    );
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 14 H729-2: the fence drain is bounded whatever the witness
// count. It counts untombstoned witnessed roots only until one more than it
// may tombstone, keeps nothing but the entries it inserts, and those are
// priced first. Over capacity the fence stays up and nothing is inserted.
// A refused scratch never lowers the fence (SOURCE h733-1), whatever it
// counts: zero, one, exactly the fixed-size fallback, or every witness
// already tombstoned. It inserts nothing, counts the skip and raises the
// kept-fence alarm; after save and reload the next admitted complete
// terminal lowers it. Since Round 15 the drain runs at a complete terminal,
// never at load; here every witnessed root is absent (the walk observed
// nothing).
#[test]
fn tombstone_fence_repair_is_bounded_and_a_refusal_keeps_the_fence() {
    let cap = MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES;
    let fallback = MAX_CLAUDE_TOMBSTONE_FENCE_FALLBACK_ROOTS;
    assert_eq!(fallback, 16);
    let admitted = crate::heap_layout_bound::layout_supported();
    let nothing = BTreeSet::new();
    let witnessed = |count: usize| {
        let mut index = ScanIndex::default();
        for number in 0..count {
            index.insert_retry_pending_claude_authority_for_test(&format!("w-{number:05}"));
        }
        index.claude_retired_family_tombstones_uncertain = true;
        index
    };
    // Three times the cap of witnessed roots and an empty set: the count
    // stops one past the free slots.
    let mut index = witnessed(3 * cap);
    assert_eq!(
        index.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
        ClaudeTombstoneFenceRepair::Kept {
            scratch_admitted: admitted,
            visited: if admitted { cap + 1 } else { fallback + 1 },
        }
    );
    assert!(index.claude_retired_family_tombstones_uncertain_for_test());
    assert!(index.claude_retired_family_tombstones_for_test().is_empty());
    // One free slot: two visits decide, whatever the witness count.
    index.fill_claude_retired_family_tombstones_for_test(cap - 1, 0);
    assert_eq!(
        index.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
        ClaudeTombstoneFenceRepair::Kept {
            scratch_admitted: admitted,
            visited: 2,
        }
    );
    assert_eq!(
        index.claude_retired_family_tombstones_for_test().len(),
        cap - 1
    );
    assert!(index.claude_retired_family_tombstones_uncertain_for_test());
    // An unfenced index does no work.
    let mut index = witnessed(4);
    index.claude_retired_family_tombstones_uncertain = false;
    assert_eq!(
        index.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
        ClaudeTombstoneFenceRepair::NotFenced
    );
    assert!(index.claude_retired_family_tombstones_for_test().is_empty());

    // A refused scratch never lowers (SOURCE h733-1; this replaces the
    // Round 15 oracle that a refused pass lowered exactly `fallback` roots,
    // which that ruling makes wrong). Exactly the fallback size: Kept,
    // nothing inserted, the skip counted and the kept-fence alarm raised.
    let refuse = RefuseClaudeTombstoneRepairScratchForTest::new();
    let dir = temp_dir("patha-refused-tombstone-repair");
    let skipped = || claude_absence_counters_for_test().fence_lowering_skipped_scratch_fallback;
    let mut small = witnessed(fallback);
    let before = skipped();
    let (outcome, alarms) = crate::local_resource_diagnostics::capture(|| {
        drain_fence_at_clean_terminal(&mut small, BTreeSet::new())
    });
    assert_eq!(
        outcome,
        ClaudeTombstoneFenceRepair::Kept {
            scratch_admitted: false,
            visited: fallback,
        }
    );
    assert_eq!(skipped(), before + 1);
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["stage"],
        "claude_absent_family_tombstone_uncertain"
    );
    assert_eq!(alarms[0]["counts"]["scratch_admitted"], json!(false));
    assert_eq!(
        alarms[0]["counts"]["cause"],
        if admitted {
            "scratch_refused"
        } else {
            "unsupported_layout"
        }
    );
    assert_eq!(
        alarms[0]["counts"]["absent_family_tombstone_uncertain"],
        json!(true)
    );
    assert!(small.claude_retired_family_tombstones_uncertain_for_test());
    assert!(small.claude_retired_family_tombstones_for_test().is_empty());
    // Zero and one root, and every witness already tombstoned: still Kept.
    for (count, tombstoned) in [(0, 0), (1, 0), (fallback, fallback)] {
        let mut index = witnessed(count);
        for number in 0..tombstoned {
            index
                .claude_retired_family_tombstones
                .entries
                .insert(claude_retired_family_digest(&format!("w-{number:05}")), 0);
        }
        let before = skipped();
        assert_eq!(
            index.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
            ClaudeTombstoneFenceRepair::Kept {
                scratch_admitted: false,
                visited: count,
            },
            "{count} witnessed, {tombstoned} tombstoned"
        );
        assert_eq!(skipped(), before + 1);
        assert!(index.claude_retired_family_tombstones_uncertain_for_test());
        assert_eq!(
            index.claude_retired_family_tombstones_for_test().len(),
            tombstoned
        );
    }
    // An unfenced index does no work and counts no skip.
    let mut index = witnessed(1);
    index.claude_retired_family_tombstones_uncertain = false;
    let before = skipped();
    assert_eq!(
        index.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
        ClaudeTombstoneFenceRepair::NotFenced
    );
    assert_eq!(skipped(), before);
    // The refusal is durable: saved and reloaded, it still keeps the fence.
    let small_path = dir.join("small-index.json");
    save_through_generation(&mut small, &small_path, 2);
    let mut reloaded = ScanIndex::load(&small_path).unwrap();
    assert!(matches!(
        drain_fence_at_clean_terminal(&mut reloaded, BTreeSet::new()),
        ClaudeTombstoneFenceRepair::Kept {
            scratch_admitted: false,
            ..
        }
    ));
    assert!(reloaded.claude_retired_family_tombstones_uncertain_for_test());
    reloaded.save(&small_path).unwrap();
    let path = dir.join("scan-index.json");
    let mut large = witnessed(fallback + 1);
    assert_eq!(
        large.lower_claude_retired_family_tombstone_fence(&nothing, &nothing),
        ClaudeTombstoneFenceRepair::Kept {
            scratch_admitted: false,
            visited: fallback + 1,
        }
    );
    save_through_generation(&mut large, &path, 2);
    let unwitnessed = test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"));
    let authority = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::AuthorityQuarantine),
    );
    for round in 0..2 {
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new()),
            ClaudeTombstoneFenceRepair::Kept {
                scratch_admitted: false,
                visited: fallback + 1,
            },
            "round {round}"
        );
        assert!(
            loaded.claude_retired_family_tombstones_uncertain_for_test(),
            "round {round}: a refusal keeps the fence"
        );
        assert!(loaded
            .claude_retired_family_tombstones_for_test()
            .is_empty());
        assert_eq!(loaded.claude_usage_authority_pending_count(), fallback + 1);
        assert_eq!(decision(&loaded, &unwitnessed), authority, "round {round}");
        loaded.save(&path).unwrap();
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap()
            ["claude_retired_family_tombstones_uncertain"],
        json!(true),
        "the fence is durable"
    );
    drop(refuse);
    // The later admitted complete terminal lowers both: the small loss
    // refused above, and the larger one.
    let mut small = ScanIndex::load(&small_path).unwrap();
    assert!(small.claude_retired_family_tombstones_uncertain_for_test());
    let before = skipped();
    let outcome = drain_fence_at_clean_terminal(&mut small, BTreeSet::new());
    if admitted {
        assert_eq!(
            outcome,
            ClaudeTombstoneFenceRepair::Lowered {
                tombstoned: fallback,
                visited: 2 * fallback,
            }
        );
        assert_eq!(skipped(), before, "an admitted pass skips nothing");
        assert!(!small.claude_retired_family_tombstones_uncertain_for_test());
        assert_eq!(
            small.claude_retired_family_tombstones_for_test().len(),
            fallback
        );
        assert_eq!(
            decision(&small, &unwitnessed),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::NewFile)
            )
        );
    } else {
        assert!(small.claude_retired_family_tombstones_uncertain_for_test());
    }
    let mut lowered = ScanIndex::load(&path).unwrap();
    assert!(lowered.claude_retired_family_tombstones_uncertain_for_test());
    let aged_out = claude_absence_counters_for_test().absent_family_tombstone_aged_out;
    drain_fence_at_clean_terminal(&mut lowered, BTreeSet::new());
    // None of these roots has an indexed member: none aged out.
    assert_eq!(
        claude_absence_counters_for_test().absent_family_tombstone_aged_out,
        aged_out
    );
    if admitted {
        assert!(!lowered.claude_retired_family_tombstones_uncertain_for_test());
        assert_eq!(
            lowered.claude_retired_family_tombstones_for_test().len(),
            fallback + 1
        );
        assert_eq!(
            decision(&lowered, &unwitnessed),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::NewFile)
            )
        );
    } else {
        assert!(lowered.claude_retired_family_tombstones_uncertain_for_test());
    }
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 14 (d): an older writer drops the marker, the set and the
// fence. A load that then finds a witnessed root with no record, pending
// proof, indexed member or tombstone fails closed: the fence goes up, and
// the next complete terminal (Round 15) re-tombstones the absent witnessed
// roots, or the fence stays durably when they cannot all be. The intermediate binary that kept the set but not the
// marker (and could evict at its cap) is caught the same way. A healthy
// unmarked index (the witnessed root is indexed) still starts empty.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_downgrade_that_drops_the_marker_and_set_fails_closed() {
    restart_claude_reemission_stop_for_test();
    let fallback = MAX_CLAUDE_TOMBSTONE_FENCE_FALLBACK_ROOTS;
    let admitted = crate::heap_layout_bound::layout_supported();
    let dir = temp_dir("patha-downgrade-tombstones");
    let path = dir.join("scan-index.json");
    let (mut index, observed) = retry_pending_roots_index("gone", fallback + 1, |_| false);
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(fallback + 1)
    );
    save_through_generation(&mut index, &path, 3);
    let saved = serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
    let write = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
        let mut value = saved.clone();
        edit(value.as_object_mut().unwrap());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    };
    let downgrade = |object: &mut serde_json::Map<String, serde_json::Value>| {
        for field in [
            "claude_retired_family_tombstones",
            "claude_retired_family_tombstones_initialized",
            "claude_retired_family_tombstones_uncertain",
        ] {
            object.remove(field);
        }
    };
    let returning = test_candidate(PathBuf::from("/synthetic/projects/gone/gone-00.jsonl"));
    let unwitnessed = test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"));
    let authority = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::AuthorityQuarantine),
    );
    let new_file = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::NewFile),
    );

    // Refused repair scratch: the check fails closed and a refused drain
    // never lowers (SOURCE h733-1), so the fence stays up across saves.
    write(&downgrade);
    {
        let _refuse = RefuseClaudeTombstoneRepairScratchForTest::new();
        for round in 0..2 {
            let mut loaded = ScanIndex::load(&path).expect("a downgraded index loads");
            assert_eq!(loaded.generation, 3 + round, "never quarantined");
            assert!(
                matches!(
                    drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new()),
                    ClaudeTombstoneFenceRepair::Kept {
                        scratch_admitted: false,
                        ..
                    }
                ),
                "round {round}: the fallback cannot place every root"
            );
            assert!(
                loaded.claude_retired_family_tombstones_uncertain_for_test(),
                "round {round}: fenced"
            );
            assert_eq!(decision(&loaded, &returning), authority, "round {round}");
            assert_eq!(decision(&loaded, &unwitnessed), authority, "round {round}");
            assert!(loaded
                .claude_usage_family_witness_digest_for_test("gone-00")
                .is_some());
            loaded.save(&path).unwrap();
        }
    }
    let mut lowered = ScanIndex::load(&path).unwrap();
    assert!(lowered.claude_retired_family_tombstones_uncertain_for_test());
    drain_fence_at_clean_terminal(&mut lowered, BTreeSet::new());
    if admitted {
        assert!(!lowered.claude_retired_family_tombstones_uncertain_for_test());
        for number in 0..=fallback {
            assert!(lowered.claude_family_tombstoned_for_test(&format!("gone-{number:02}")));
        }
        assert_eq!(decision(&lowered, &returning), authority);
        assert_eq!(decision(&lowered, &unwitnessed), new_file);
    }

    // Admitted from the start: the check sees the unaccounted root and the
    // repair re-tombstones every witnessed root at once.
    if admitted {
        write(&downgrade);
        let before = claude_absence_counters_for_test();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            claude_absence_counters_for_test().tombstone_fence_raised_on_upgrade,
            before.tombstone_fence_raised_on_upgrade + 1
        );
        assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
        drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
        assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
        assert!(loaded.claude_family_tombstoned_for_test("gone-00"));
        assert_eq!(decision(&loaded, &returning), authority);
        assert_eq!(decision(&loaded, &unwitnessed), new_file);

        // The intermediate binary: its set survives without the marker, but
        // one retired root's entry is gone (evicted at its cap).
        let digest = claude_retired_family_digest("gone-00");
        write(&|object| {
            object.remove("claude_retired_family_tombstones_initialized");
            object["claude_retired_family_tombstones"]
                .as_object_mut()
                .unwrap()
                .remove(&digest);
        });
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
        drain_fence_at_clean_terminal(&mut loaded, BTreeSet::new());
        assert!(loaded.claude_family_tombstoned_for_test("gone-00"));
        assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
        assert_eq!(decision(&loaded, &returning), authority);
    }

    // A healthy unmarked index: every witnessed root without a record is
    // indexed, so nothing was lost and the set starts empty.
    let healthy = dir.join("healthy-index.json");
    let (mut index, observed) = retry_pending_roots_index("live", 1, |_| false);
    assert_eq!(
        index.retire_positively_absent_claude_families(&clean_terminal_traversal(observed), ""),
        Ok(1)
    );
    let mut entry = manifest_index_entry(None);
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    index
        .files
        .insert("/synthetic/projects/live/live-00.jsonl".to_string(), entry);
    let mut value = serde_json::to_value(&index).unwrap();
    downgrade(value.as_object_mut().unwrap());
    fs::write(&healthy, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = claude_absence_counters_for_test();
    let loaded = ScanIndex::load(&healthy).unwrap();
    assert_eq!(
        claude_absence_counters_for_test().tombstone_fence_raised_on_upgrade,
        before.tombstone_fence_raised_on_upgrade,
        "nothing was raised"
    );
    assert!(loaded
        .claude_usage_family_witness_digest_for_test("live-00")
        .is_some());
    assert!(loaded
        .claude_retired_family_tombstones_for_test()
        .is_empty());
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    let _ = fs::remove_dir_all(&dir);
}

// SOURCE Round 15 bounded drain: the fence comes down at a complete healthy
// terminal once every witnessed root the walk did not see present is
// tombstoned under the cap. Present roots (observed, every observed member
// indexed) take no slot, so more of them than the cap never block it; they
// stay indexed files, never new ones. An indexed entry whose file the walk
// did not see is absent (H729-1), and a root the walk saw only through an
// unindexed or confirmed-empty member needs a tombstone too (the normal
// retirement would not cover its later disappearance). More absent roots
// than free slots keep the fence up, publish it and alarm at most hourly.
#[test]
fn the_fence_drain_skips_present_roots_and_only_absent_roots_block_it() {
    let cap = MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES;
    if !crate::heap_layout_bound::layout_supported() {
        // The refused-scratch fallback is covered by
        // `tombstone_fence_repair_is_bounded_and_a_refusal_keeps_the_fence`.
        return;
    }
    let key = |root: &str| format!("/synthetic/projects/drain/{root}.jsonl");
    let present_roots = (0..cap + 8)
        .map(|number| format!("present-{number:05}"))
        .collect::<Vec<_>>();
    // Witnessed roots with no record, as settled families leave them.
    let witness_only = |index: &mut ScanIndex, root: &str| {
        index.insert_retry_pending_claude_authority_for_test(root);
        index.claude_usage_authority_quarantine.remove(root);
    };
    let fenced = |absent: usize| {
        let mut index = ScanIndex::default();
        let mut observed = BTreeSet::new();
        for root in &present_roots {
            witness_only(&mut index, root);
            let mut entry = manifest_index_entry(None);
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
            index.files.insert(key(root), entry);
            observed.insert(key(root));
        }
        // H729-1: indexed, but the walk does not see its file.
        witness_only(&mut index, "absent-stale");
        let mut entry = manifest_index_entry(None);
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
        index.files.insert(key("absent-stale"), entry);
        // Seen by the walk, but never indexed.
        witness_only(&mut index, "absent-unindexed");
        observed.insert(key("absent-unindexed"));
        // Seen and indexed, but confirmed empty: its proof may be unsettled.
        witness_only(&mut index, "absent-empty");
        let mut entry = manifest_index_entry(None);
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
        index.files.insert(key("absent-empty"), entry);
        index.confirmed_empty_files.insert(key("absent-empty"));
        observed.insert(key("absent-empty"));
        for number in 0..absent {
            witness_only(&mut index, &format!("absent-{number:02}"));
        }
        index.fill_claude_retired_family_tombstones_for_test(cap - 5, 0);
        index.claude_retired_family_tombstones_uncertain = true;
        (index, observed)
    };

    // Five free slots, five roots needing one, more than the cap present.
    // Of the five, only `absent-stale` is unobserved with an indexed member:
    // it aged out of the walk (SOURCE h733-2) and is counted, still absent.
    let aged_out = || claude_absence_counters_for_test().absent_family_tombstone_aged_out;
    let before = aged_out();
    let (mut index, observed) = fenced(2);
    assert!(index.claude_usage_family_witnesses.len() > cap + 5);
    assert!(matches!(
        drain_fence_at_clean_terminal(&mut index, observed.clone()),
        ClaudeTombstoneFenceRepair::Lowered { tombstoned: 5, .. }
    ));
    assert_eq!(aged_out(), before + 1);
    assert!(!index.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(index.claude_retired_family_tombstones_for_test().len(), cap);
    for root in [
        "absent-stale",
        "absent-unindexed",
        "absent-empty",
        "absent-00",
        "absent-01",
    ] {
        assert!(index.claude_family_tombstoned_for_test(root), "{root}");
    }
    for root in &present_roots {
        assert!(!index.claude_family_tombstoned_for_test(root), "{root}");
        assert_ne!(
            decision(&index, &test_candidate(PathBuf::from(key(root)))).1,
            Some(CandidateParseReason::NewFile),
            "{root}: a present root is read as an indexed file"
        );
    }
    // Their unindexed returns are read through the authority path.
    for root in ["absent-unindexed", "absent-00"] {
        assert_eq!(
            decision(&index, &test_candidate(PathBuf::from(key(root)))),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::AuthorityQuarantine)
            ),
            "{root}"
        );
    }
    // Lowered: an unwitnessed root is new again.
    assert_eq!(
        decision(
            &index,
            &test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"))
        ),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::NewFile)
        )
    );

    // One more absent root than free slots: the fence stays, nothing is
    // inserted, the row publishes it and the alarm fires at most hourly.
    let (mut index, observed) = fenced(3);
    let (outcomes, alarms) = crate::local_resource_diagnostics::capture(|| {
        [
            drain_fence_at_clean_terminal(&mut index, observed.clone()),
            drain_fence_at_clean_terminal(&mut index, observed.clone()),
        ]
    });
    for outcome in outcomes {
        assert!(matches!(
            outcome,
            ClaudeTombstoneFenceRepair::Kept {
                scratch_admitted: true,
                ..
            }
        ));
    }
    assert_eq!(
        aged_out(),
        before + 1,
        "a kept fence inserts and counts nothing"
    );
    assert!(index.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(
        index.claude_retired_family_tombstones_for_test().len(),
        cap - 5
    );
    assert_eq!(alarms.len(), 1, "rate limited");
    assert_eq!(
        alarms[0]["stage"],
        "claude_absent_family_tombstone_uncertain"
    );
    assert_eq!(
        alarms[0]["counts"]["absent_family_tombstone_uncertain"],
        json!(true)
    );
    assert_eq!(alarms[0]["counts"]["free_tombstone_slots"], json!(5));
    assert_eq!(
        decision(
            &index,
            &test_candidate(PathBuf::from("/synthetic/projects/new/new-00.jsonl"))
        ),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        ),
        "still fenced"
    );
    // Present roots alone, however many, never block it.
    for number in 0..3 {
        let root = format!("absent-{number:02}");
        index.claude_usage_family_witnesses.remove(&root);
    }
    assert!(matches!(
        drain_fence_at_clean_terminal(&mut index, observed),
        ClaudeTombstoneFenceRepair::Lowered { tombstoned: 3, .. }
    ));
    assert!(!index.claude_retired_family_tombstones_uncertain_for_test());
    assert!(index.claude_family_tombstoned_for_test("absent-stale"));
    assert_eq!(aged_out(), before + 2);
}

// SOURCE Round 15, checkpoint selection: the drain exempts a present root by
// the working index. When a partial checkpoint then drops that root's new
// entry (its body is not held by the server yet), the root would be
// unindexed and untombstoned, so the checkpoint keeps the fence up. A
// checkpoint that keeps the entry keeps the lowered fence.
#[test]
fn a_partial_checkpoint_that_drops_an_exempted_entry_keeps_the_fence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let key = "/synthetic/projects/fresh/fresh-00.jsonl".to_string();
    let fenced = || {
        let mut index = ScanIndex::default();
        index.insert_retry_pending_claude_authority_for_test("fresh-00");
        index.claude_usage_authority_quarantine.remove("fresh-00");
        index.claude_retired_family_tombstones_uncertain = true;
        index
    };
    let committed = fenced();
    let mut working = fenced();
    let mut entry = manifest_index_entry(Some("unheld-body"));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    working.files.insert(key.clone(), entry);
    assert!(matches!(
        drain_fence_at_clean_terminal(&mut working, BTreeSet::from([key.clone()])),
        ClaudeTombstoneFenceRepair::Lowered { tombstoned: 0, .. }
    ));
    assert!(!working.claude_retired_family_tombstones_uncertain_for_test());

    let dropped = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    assert!(!dropped.files.contains_key(&key));
    assert!(!dropped.claude_family_tombstoned_for_test("fresh-00"));
    assert!(dropped.claude_retired_family_tombstones_uncertain_for_test());
    assert_eq!(
        decision(&dropped, &test_candidate(PathBuf::from(&key))),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::AuthorityQuarantine)
        ),
        "never a new file"
    );

    let kept = working.committable_subset(
        &committed,
        &BTreeSet::from(["unheld-body".to_string()]),
        &BTreeMap::new(),
    );
    assert!(kept.files.contains_key(&key));
    assert!(!kept.claude_retired_family_tombstones_uncertain_for_test());
}

// SOURCE Round 15: the accepted upgrade false positive. A pre-bridge index
// whose removed family's witness outlived its entry looks like a downgrade,
// so the load raises the fence and counts it, with no carve-out. The next
// complete terminal bounds the cost: only the absent witnessed root takes a
// tombstone; the present one stays an indexed file.
#[test]
fn an_upgrade_false_positive_is_counted_and_bounded_by_the_drain() {
    restart_claude_reemission_stop_for_test();
    let dir = temp_dir("patha-upgrade-false-positive");
    let path = dir.join("scan-index.json");
    let mut index = ScanIndex::default();
    for root in ["removed-00", "live-00"] {
        index.insert_retry_pending_claude_authority_for_test(root);
        index.claude_usage_authority_quarantine.remove(root);
    }
    let live_key = "/synthetic/projects/live/live-00.jsonl".to_string();
    let mut entry = manifest_index_entry(None);
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    index.files.insert(live_key.clone(), entry);
    index.generation = 4;
    let mut value = serde_json::to_value(&index).unwrap();
    for field in [
        "claude_retired_family_tombstones",
        "claude_retired_family_tombstones_initialized",
        "claude_retired_family_tombstones_uncertain",
    ] {
        value.as_object_mut().unwrap().remove(field);
    }
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = claude_absence_counters_for_test();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        claude_absence_counters_for_test().tombstone_fence_raised_on_upgrade,
        before.tombstone_fence_raised_on_upgrade + 1
    );
    assert!(loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert!(loaded
        .claude_retired_family_tombstones_for_test()
        .is_empty());
    if !crate::heap_layout_bound::layout_supported() {
        // Without the presence scratch the fallback keeps the fence.
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let aged_out = claude_absence_counters_for_test().absent_family_tombstone_aged_out;
    assert!(matches!(
        drain_fence_at_clean_terminal(&mut loaded, BTreeSet::from([live_key.clone()])),
        ClaudeTombstoneFenceRepair::Lowered { tombstoned: 1, .. }
    ));
    // `removed-00` has no indexed member: absent, not aged out.
    assert_eq!(
        claude_absence_counters_for_test().absent_family_tombstone_aged_out,
        aged_out
    );
    assert!(!loaded.claude_retired_family_tombstones_uncertain_for_test());
    assert!(loaded.claude_family_tombstoned_for_test("removed-00"));
    assert!(!loaded.claude_family_tombstoned_for_test("live-00"));
    assert_ne!(
        decision(&loaded, &test_candidate(PathBuf::from(&live_key))).1,
        Some(CandidateParseReason::NewFile)
    );
    // Marked from now on: the next load is not an upgrade.
    loaded.save(&path).unwrap();
    let before = claude_absence_counters_for_test();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        claude_absence_counters_for_test().tombstone_fence_raised_on_upgrade,
        before.tombstone_fence_raised_on_upgrade
    );
    assert!(!reloaded.claude_retired_family_tombstones_uncertain_for_test());
    assert!(reloaded.claude_family_tombstoned_for_test("removed-00"));
    let _ = fs::remove_dir_all(&dir);
}

fn hex64_number(number: usize) -> String {
    format!("{number:064x}")
}

/// Returning RetryPending roots must be visible separately from ordinary
/// RetryPending causes, terminal records, and recordless retirement markers.
#[test]
fn returning_family_grown_held_counts_only_tombstoned_retry_pending_roots() {
    let mut index = ScanIndex::default();
    assert_eq!(index.claude_returning_family_grown_held_count(), 0);
    for root in ["ordinary", "returning-a", "returning-b", "terminal"] {
        index.insert_retry_pending_claude_authority_for_test(root);
    }
    assert_eq!(index.claude_returning_family_grown_held_count(), 0);
    for root in ["returning-a", "returning-b", "terminal", "recordless"] {
        index.tombstone_claude_family_for_test(root);
    }
    index
        .claude_usage_authority_quarantine
        .get_mut("terminal")
        .unwrap()
        .disposition = ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
    assert_eq!(index.claude_usage_authority_pending_count(), 3);
    assert_eq!(index.claude_returning_family_grown_held_count(), 2);
    index
        .claude_usage_authority_quarantine
        .remove("returning-a");
    assert_eq!(index.claude_returning_family_grown_held_count(), 1);
    index
        .claude_retired_family_tombstones
        .entries
        .remove(&claude_retired_family_digest("returning-b"));
    assert_eq!(index.claude_usage_authority_pending_count(), 2);
    assert_eq!(index.claude_returning_family_grown_held_count(), 0);
}
