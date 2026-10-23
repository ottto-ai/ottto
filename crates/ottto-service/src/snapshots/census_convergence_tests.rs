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
    diagnostic_invalid_causes: 0,
    ClaudeUsageFamilyPending {
        diagnostic_invalid_causes: 0,
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
    let (root, _, items) = claude_account_family_fixture();
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
    let (root, _, items) = claude_account_family_fixture();
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

// Only a bound terminal demotion of this exact revision, or a durably
// disclosed account deferral, stops blocking traversal progress.
#[test]
fn claude_progress_blocking_holds_exclude_only_non_progressing_revisions() {
    let (root, _, items) = claude_account_family_fixture();
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
    assert!(claude_terminal_authority_hold_is_bound(&held, &terminal));

    let mut retry = ScanIndex::default();
    bind_authority_quarantine(
        &mut retry,
        &family_root,
        &held.source_session_id,
        &revision,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
    );
    assert!(!claude_terminal_authority_hold_is_bound(&held, &retry));

    let mut other_revision = ScanIndex::default();
    bind_authority_quarantine(
        &mut other_revision,
        &family_root,
        &held.source_session_id,
        &hex64('b'),
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    );
    assert!(!claude_terminal_authority_hold_is_bound(
        &held,
        &other_revision
    ));

    let mut unbound_witness = terminal.clone();
    unbound_witness
        .claude_usage_family_witnesses
        .get_mut(&family_root)
        .expect("retained witness")
        .evidence_fingerprint = hex64('f');
    assert!(!claude_terminal_authority_hold_is_bound(
        &held,
        &unbound_witness
    ));

    let mut unknown_revision = held.clone();
    unknown_revision.source_file_fingerprint = None;
    assert!(!claude_terminal_authority_hold_is_bound(
        &unknown_revision,
        &terminal
    ));

    let mut demoted = ClaudeUsageAuthorityDisposition::default();
    demoted
        .quarantined_source_session_ids
        .insert(held.source_session_id.clone());
    assert!(demoted
        .progress_blocking_held_fingerprints(&snapshots, &terminal, true)
        .is_empty());
    for blocking in [
        &retry,
        &other_revision,
        &unbound_witness,
        &ScanIndex::default(),
    ] {
        assert_eq!(
            demoted.progress_blocking_held_fingerprints(&snapshots, blocking, true),
            BTreeSet::from([held.snapshot_fingerprint.clone()])
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
    assert_eq!(
        deferred.progress_blocking_held_fingerprints(&snapshots, &ScanIndex::default(), false),
        BTreeSet::from([held.snapshot_fingerprint.clone()])
    );
    let mut retained = snapshots.clone();
    deferred.retain_uploadable(&mut retained);
    assert!(retained.is_empty());

    let _ = fs::remove_dir_all(root);
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

// Account holds are durable, bounded, and pruned only by a resolving
// parse or proved absence.
#[test]
fn claude_account_deferred_holds_are_durable_bounded_and_pruned_by_proof() {
    let held_key = "/opaque/deferred.jsonl";
    let other_key = "/opaque/other.jsonl";
    let mut index = ScanIndex::default();
    index.file_snapshot_fingerprints.insert(
        held_key.to_string(),
        BTreeSet::from(["deferred".to_string()]),
    );
    index
        .file_snapshot_fingerprints
        .insert(other_key.to_string(), BTreeSet::from(["other".to_string()]));
    let deferred = BTreeSet::from(["deferred".to_string()]);

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
        .record_claude_account_deferred_holds([(held_key, "deferred-source")], &BTreeSet::new(),));
    assert_eq!(resolved.claude_account_deferred_hold_count(), 0);

    // A complete traversal proves absence only for keys neither indexed nor
    // observed.
    let mut observed = index.clone();
    observed.retain_observed_claude_account_deferred_holds(&BTreeSet::from([held_key.to_string()]));
    assert_eq!(observed.claude_account_deferred_hold_count(), 1);
    let mut indexed = index.clone();
    indexed
        .files
        .insert(held_key.to_string(), manifest_index_entry(Some("deferred")));
    indexed.retain_observed_claude_account_deferred_holds(&BTreeSet::new());
    assert_eq!(indexed.claude_account_deferred_hold_count(), 1);
    let mut absent = index.clone();
    absent.retain_observed_claude_account_deferred_holds(&BTreeSet::new());
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

mod owned_held_index_allocation {
    include!("owned_held_index_allocation_tests.rs");
}

mod authority_binding_prototype {
    include!("authority_binding_prototype_tests.rs");
}

mod provider_envelope_experiment_tests {
    include!("provider_envelope_experiment_tests.rs");
}

mod witness_reconstruct_scope {
    include!("witness_reconstruct_scope_tests.rs");
}

#[test]
fn p12_experimental_base_exit_duplicate_fence_full_coverage_oracle() {
    let scope = envelope_selection_experiment::Scope::restart();
    claude_duplicate_fence_reopens_only_after_full_coverage();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_duplicate_fence_reopens_only_after_full_coverage mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}
