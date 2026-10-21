// StateMissing characterization baselines through the production
// reported-usage fold. Each defect test asserts TODAY's behavior, so it passes
// on main; the assertions a fix flips are marked `FLIPS`. Every other
// assertion is a precondition, a control or an invariant. Fixtures are the
// terminal family-proof fixture of this module and the shared family fixture,
// unchanged; transcripts are parsed from disk and content-free.
use super::*;

/// The fixture census clock: `claude_census_counts_run` folds at
/// 2026-08-02T07:10:00Z.
const STATEMISSING_CENSUS_CLOCK: u64 = 1_785_654_600;
/// A root transcript whose second response has usage but no `requestId`.
const STATEMISSING_INVALID_ROOT: &str = "d4444444-4444-4444-8444-444444444444";

/// Positive control for the proof-candidate baseline
/// (`statemissing_baseline_unchanged_proof_rearms_family_at_every_healthy_
/// terminal` in `snapshot_sync/statemissing_baseline_pipeline_tests.rs`): a
/// CHANGED family witness must keep re-arming an earlier-page member after the
/// fix. The child gains one reported request; one census window observes the
/// root on an earlier page and the grown child on the terminal page, proves the
/// changed witness, and clears the root's revision. This holds today and after
/// the fix. The unchanged-witness fold counterpart is
/// `p12_member_change_base_control_reveals_unmet_original_prelude`.
#[test]
fn statemissing_baseline_changed_witness_still_rearms_earlier_page_member() {
    let mut family = Family::new();
    let first = family.proven_and_corrected();
    let parent_key = family.parent_key.clone();
    assert!(
        family.armed(&parent_key),
        "precondition: the corrected root is settled at its revision"
    );
    let root_session_id = family.root_session_id.clone();
    let appended = format!(
        "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"{root_session_id}\",\"agentId\":\"{CHILD_AGENT}\",\"isSidechain\":true,\"requestId\":\"req_6\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":1}}}}}}\n"
    );
    let mut transcript = fs::read_to_string(&family.child_path).expect("read child transcript");
    transcript.push_str(&appended);
    fs::write(&family.child_path, transcript).expect("append child transcript");
    family
        .api_rows
        .push(complete_api_row(&root_session_id, "req_6", 6, 10, 1, 0));
    family
        .trace_rows
        .push(complete_trace_row(&root_session_id, "req_6", CHILD_AGENT));

    let window = "2026-08-02T07:30:00Z";
    let mut parent = family.parent(window);
    family.page(&mut parent, false, window);
    let mut grown = family.child(window, 3);
    assert_eq!(grown[0].request_count, 2, "precondition: the child grew");
    family.page(&mut grown, true, window);
    assert_ne!(
        family.witness(),
        first,
        "the window proves a changed family witness"
    );
    // Kept by every fix: the changed proof re-arms the earlier-page root.
    assert!(!family.armed(&parent_key));
    eprintln!(
        "STATEMISSING_BASELINE test=T1_changed_witness_control witness_changed=true earlier_page_root_rearmed=true"
    );
}

/// The shared two-member family plus, optionally, one root transcript parsed
/// from disk whose second response has usage but no `requestId`, and a closed
/// duplicate fence over an index holding every member's committed revision.
struct StatemissingFenceFixture {
    root: PathBuf,
    items: Vec<SnapshotItem>,
    revisions: BTreeMap<String, String>,
    closed: ScanIndex,
}

impl StatemissingFenceFixture {
    fn new(identity_invalid_member: bool) -> Self {
        assert_eq!(
            rfc3339_unix_seconds("2026-08-02T07:10:00Z"),
            Some(STATEMISSING_CENSUS_CLOCK)
        );
        let (root, parent, mut items) = claude_account_family_fixture();
        let mut paths = vec![
            root.join(format!("{parent}.jsonl")),
            root.join(&parent)
                .join("subagents")
                .join(format!("agent-{CHILD_AGENT}.jsonl")),
        ];
        if identity_invalid_member {
            let path = root.join(format!("{STATEMISSING_INVALID_ROOT}.jsonl"));
            fs::write(
                &path,
                concat!(
                    "{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"d4444444-4444-4444-8444-444444444444\",\"requestId\":\"req_invalid_1\",\"message\":{\"id\":\"msg_invalid_1\",\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":10}}}\n",
                    "{\"timestamp\":\"2026-08-02T07:00:06Z\",\"type\":\"assistant\",\"sessionId\":\"d4444444-4444-4444-8444-444444444444\",\"message\":{\"id\":\"msg_invalid_2\",\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":10}}}\n"
                ),
            )
            .expect("write identity-invalid transcript");
            let mut parsed =
                parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "invalid-fp".into())
                    .expect("parse identity-invalid transcript");
            assert_eq!(parsed.len(), 1);
            let invalid = parsed.remove(0);
            // Preconditions: the file content alone makes this member
            // identity-invalid, and it is its own single-member family.
            assert_eq!(invalid.source_session_id, STATEMISSING_INVALID_ROOT);
            assert_eq!(
                claude_snapshot_family_root(&invalid),
                STATEMISSING_INVALID_ROOT
            );
            assert_eq!(invalid.request_count, 2);
            assert_eq!(
                invalid.claude_usage_request_ids,
                BTreeSet::from(["req_invalid_1".to_string()])
            );
            assert!(claude_snapshot_request_id_hashes(&invalid).is_none());
            items.push(invalid);
            paths.push(path);
        }
        let revisions = paths
            .iter()
            .zip(1..)
            .map(|(path, seed)| (local_index_key(path), revision(seed)))
            .collect::<BTreeMap<_, _>>();
        let mut closed = ScanIndex {
            claude_duplicate_request_witness_overflowed: true,
            ..ScanIndex::default()
        };
        for (key, source) in &revisions {
            let mut entry = manifest_index_entry(None);
            entry.source_file_fingerprint = source.clone();
            closed.files.insert(key.clone(), entry);
        }
        Self {
            root,
            items,
            revisions,
            closed,
        }
    }

    /// Every indexed member's revision cleared by a full re-arm.
    fn all_cleared(&self, index: &ScanIndex) -> bool {
        self.revisions
            .keys()
            .all(|key| index.files[key].source_file_fingerprint.is_empty())
    }

    /// The full replay reparsed every unchanged member and settled it again.
    fn replayed(&self, index: &ScanIndex) -> ScanIndex {
        let mut index = index.clone();
        for (key, source) in &self.revisions {
            index
                .files
                .get_mut(key)
                .expect("indexed member")
                .source_file_fingerprint = source.clone();
        }
        index
    }
}

impl Drop for StatemissingFenceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Control for both fence baselines: a complete census that observes every
/// indexed member of a valid family in one window reopens a closed fence.
/// This holds today and after any fix; it shows the member keys and the
/// window are what the coverage census expects.
#[test]
fn statemissing_baseline_valid_full_coverage_window_reopens_fence_control() {
    let fixture = StatemissingFenceFixture::new(false);
    let (_, opened, counts) = claude_census_counts_run_twice(
        &fixture.items,
        &fixture.closed,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(counts.census_complete);
    assert!(counts.fence_before);
    assert!(!counts.census_invalid);
    assert_eq!(counts.pending_occurrence_count, 5);
    assert!(counts.coverage_complete);
    assert_eq!(counts.coverage_missing_member_count, 0);
    assert!(!counts.fence_after);
    assert!(!opened.claude_duplicate_request_witness_overflowed);
    assert_eq!(opened.claude_duplicate_fence_rearm_attempt, 0);
    eprintln!("STATEMISSING_BASELINE test=T4_fence control_counts={counts:?}");
}

/// Defect: one transcript whose response has usage but no `requestId` makes
/// its family identity-invalid on content alone. A complete census that
/// observes every indexed member in one window is therefore still not a valid
/// family census: the closed duplicate fence stays closed, every member is
/// re-armed by the full re-arm, and once its backoff elapses the replay of the
/// UNCHANGED corpus reproduces the same invalidity and schedules the next full
/// replay. Complete traversal is not valid coverage, and nothing here forces a
/// valid census.
///
/// Expected after the fix (OWNER-PLAN C1c, then slice D): the fence still
/// stays closed (fail closed), but a full replay whose structural cause could
/// not have changed (the invalid member's revision is unchanged) is deferred
/// instead of re-armed, so the second window's `full_rearm` is false and no
/// member is cleared.
#[test]
fn statemissing_baseline_identity_invalid_transcript_keeps_fence_closed_and_replaying() {
    let fixture = StatemissingFenceFixture::new(true);
    let (_, after, counts) = claude_census_counts_run_twice(
        &fixture.items,
        &fixture.closed,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    // A complete traversal that observed every indexed member this window.
    assert!(counts.census_complete);
    assert!(counts.fence_before);
    assert_eq!(fixture.revisions.len(), 3);
    // Not a valid family census: the transcript content invalidates its family.
    assert_eq!(counts.page_invalidated_identity_count, 1);
    assert_eq!(counts.invalid_current_window_family_count, 1);
    assert!(counts.census_invalid);
    assert_eq!(counts.pending_occurrence_count, 5);
    assert_eq!(counts.coverage_missing_member_count, 1);
    assert!(!counts.coverage_complete);
    // Fail closed, kept by every fix.
    assert!(counts.fence_after);
    assert!(after.claude_duplicate_request_witness_overflowed);
    // The closed fence re-arms the whole corpus once.
    assert!(counts.full_rearm);
    assert_eq!(counts.rearm_attempt, 1);
    assert_eq!(
        counts.full_rearm_deferred_until,
        Some(STATEMISSING_CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS)
    );
    assert!(fixture.all_cleared(&after));

    // The replay reparses every unchanged member; its backoff has elapsed.
    let mut replayed = fixture.replayed(&after);
    replayed.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(STATEMISSING_CENSUS_CLOCK);
    let (_, again, second) = claude_census_counts_run_twice(
        &fixture.items,
        &replayed,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(second.census_complete);
    assert_eq!(second.page_invalidated_identity_count, 1);
    assert!(second.census_invalid);
    assert!(second.fence_after);
    assert!(again.claude_duplicate_request_witness_overflowed);
    // FLIPS: the unchanged invalid content schedules another whole replay.
    assert!(second.full_rearm);
    assert_eq!(second.rearm_attempt, 2);
    assert_eq!(
        second.full_rearm_deferred_until,
        Some(STATEMISSING_CENSUS_CLOCK + claude_duplicate_fence_rearm_delay_seconds(1))
    );
    assert!(fixture.all_cleared(&again));
    eprintln!(
        "STATEMISSING_BASELINE test=T4_fence arm=identity_invalid first={counts:?} second={second:?}"
    );
}

/// Defect, cap variant: the same valid family whose window carries more
/// request occurrences than the pending-occurrence bound is cap-invalidated.
/// The complete, fully observed window again keeps the fence closed and
/// re-arms the whole corpus, although a replay of unchanged content cannot
/// fall under the bound. Production's bound is 250,000 occurrences, which the
/// saved M4 census meets at 249,987 of 250,000; here it is the fixture total
/// minus one.
///
/// Expected after the fix: as for the identity variant, the fence stays
/// closed and the full replay is deferred until the corpus could fit the
/// bound, so `full_rearm` is false and no member is cleared.
#[test]
fn statemissing_baseline_pending_occurrence_cap_keeps_fence_closed_and_replaying() {
    let fixture = StatemissingFenceFixture::new(false);
    let total = fixture
        .items
        .iter()
        .map(|item| item.claude_usage_occurrences.len())
        .sum::<usize>();
    assert_eq!(total, 5);
    let (_, after, counts) = claude_census_counts_run_twice(
        &fixture.items,
        &fixture.closed,
        true,
        total - 1,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
    );
    assert!(counts.census_complete);
    assert!(counts.fence_before);
    assert_eq!(counts.page_invalidated_cap_count, 1);
    assert_eq!(counts.page_invalidated_identity_count, 0);
    assert_eq!(counts.invalid_current_window_family_count, 1);
    assert!(counts.census_invalid);
    assert_eq!(counts.coverage_missing_member_count, 2);
    assert!(counts.fence_after);
    assert!(after.claude_duplicate_request_witness_overflowed);
    // FLIPS: the cap-invalid window re-arms the whole corpus.
    assert!(counts.full_rearm);
    assert_eq!(counts.rearm_attempt, 1);
    assert_eq!(
        counts.full_rearm_deferred_until,
        Some(STATEMISSING_CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS)
    );
    assert!(fixture.all_cleared(&after));
    eprintln!("STATEMISSING_BASELINE test=T4_fence arm=occurrence_cap counts={counts:?}");
}
