// Claude posture member waiver: while the global duplicate-census fence is
// closed, a member whose own Claude Code telemetry assigns it every counted
// request keeps first/peak/last context and owned compactions. Copies, legacy
// prefixes, own-family gaps, visible duplicates and incomplete identity stay
// withheld. All fixtures are synthetic and content-free.
use super::*;

const WINDOW: &str = "2026-08-02T07:10:00Z";
const LATER_WINDOW: &str = "2026-08-02T08:10:00Z";
const OWNED: &str = "a0000000-0000-4000-8000-00000000000a";
const UNRELATED: &str = "e0000000-0000-4000-8000-00000000000e";
const PEER: &str = "b0000000-0000-4000-8000-00000000000b";
const OTHER_ROOT: &str = "c0000000-0000-4000-8000-00000000000c";

fn assistant(session: &str, request: &str, second: u32, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn id_less_assistant(session: &str, second: u32, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"message\":{{\"id\":\"msg_id_less\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn boundary(
    session: &str,
    second: u32,
    pre: u64,
    post: u64,
    dropped: u64,
    duration: u64,
) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}.500Z\",\"sessionId\":\"{session}\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{{\"trigger\":\"auto\",\"preTokens\":{pre},\"postTokens\":{post},\"cumulativeDroppedTokens\":{dropped},\"durationMs\":{duration}}}}}\n"
    )
}

/// Write one top-level transcript and parse its single snapshot.
fn session(dir: &Path, session_id: &str, lines: &[String]) -> (PathBuf, SnapshotItem) {
    let path = dir.join(format!("{session_id}.jsonl"));
    fs::write(&path, lines.concat()).expect("write transcript fixture");
    let item =
        parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", format!("{session_id}-fp"))
            .expect("parse transcript fixture")
            .remove(0);
    (path, item)
}

/// Complete API and trace rows, each request owned by its root (no agent).
fn reports(
    rows: &[(&str, &str, u64, u64)],
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let mut api = BTreeMap::<String, Vec<_>>::new();
    let mut trace = BTreeMap::<String, Vec<_>>::new();
    for (root, request, sequence, input_tokens) in rows {
        api.entry(root.to_string())
            .or_default()
            .push(complete_api_row(
                root,
                request,
                *sequence,
                *input_tokens,
                1,
                0,
            ));
        trace
            .entry(root.to_string())
            .or_default()
            .push(complete_trace_row(root, request, ""));
    }
    (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: api,
            health: Default::default(),
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: trace,
            ..Default::default()
        },
    )
}

fn indexed(paths: &[&Path]) -> ScanIndex {
    let mut index = ScanIndex::default();
    for path in paths {
        index
            .files
            .insert(local_index_key(path), manifest_index_entry(None));
    }
    index
}

/// One fold with the Mac-wide pending cap set to `max_pending_occurrences`.
fn fold(
    items: &mut [SnapshotItem],
    reports: &(
        crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ),
    index: &mut ScanIndex,
    census_complete: bool,
    window: &str,
    max_pending_occurrences: usize,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_index_and_limits(
        items,
        &reports.0,
        &reports.1,
        index,
        census_complete,
        window,
        max_pending_occurrences,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    )
}

fn posture(item: &SnapshotItem) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    (
        item.first_turn_context_tokens,
        item.peak_context_fill_tokens,
        item.last_turn_context_tokens,
        item.compaction_count,
    )
}

fn assert_cleared(item: &SnapshotItem) {
    assert_eq!(posture(item), (None, None, None, None));
    assert!(item.compaction_timestamps.is_empty());
    assert_eq!(item.compaction_total_pre_tokens, None);
    assert_eq!(item.compaction_total_post_tokens, None);
    assert_eq!(item.compaction_total_cumulative_dropped_tokens, None);
    assert_eq!(item.compaction_total_duration_ms, None);
}

fn assert_curve_withheld(item: &SnapshotItem) {
    assert!(item
        .context_curve
        .as_ref()
        .map_or(true, |curve| curve.coverage == "ownership_unresolved"));
}

const V1: Option<&str> = Some("session_exclusive_reported_usage:v1");

/// The owned three-request session plus an unrelated id-bearing session whose
/// family the pending cap invalidates, which closes the global fence.
fn owned_and_cap_invalid(dir: &Path) -> (Vec<PathBuf>, Vec<SnapshotItem>) {
    let (owned_path, owned) = session(
        dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            assistant(OWNED, "req_a2", 2, 300),
            assistant(OWNED, "req_a3", 3, 200),
        ],
    );
    let (unrelated_path, unrelated) =
        session(dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    (vec![owned_path, unrelated_path], vec![owned, unrelated])
}

fn owned_rows() -> Vec<(&'static str, &'static str, u64, u64)> {
    vec![
        (OWNED, "req_a1", 1, 100),
        (OWNED, "req_a2", 2, 300),
        (OWNED, "req_a3", 3, 200),
    ]
}

#[test]
fn unrelated_cap_invalid_family_keeps_member_owned_scalars() {
    let dir = temp_dir("claude-waiver-unrelated-cap");
    let (paths, mut items) = owned_and_cap_invalid(&dir);
    let expected_start = items[0]
        .session_start
        .clone()
        .and_then(|start| (*start).inherited());
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());

    let disposition = fold(
        &mut items,
        &reports(&owned_rows()),
        &mut index,
        true,
        WINDOW,
        3,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert!(index.claude_duplicate_request_witness_overflowed);
    let owned = &items[0];
    assert_eq!(owned.usage_accounting_contract.as_deref(), V1);
    assert_eq!(disposition.posture_admission(OWNED), Some("member_waiver"));
    assert_eq!(posture(owned), (Some(100), Some(300), Some(200), Some(0)));
    assert_eq!(owned.session_start.as_deref(), expected_start.as_ref());
    assert!(owned.cache_observations.is_none(), "cache stays strict");
    assert_curve_withheld(owned);
    assert_eq!(
        disposition.posture_admission(UNRELATED),
        Some("withheld_no_contract")
    );
    assert_cleared(&items[1]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn own_invalid_family_withholds_even_with_reconstructed_witness() {
    let dir = temp_dir("claude-waiver-own-invalid");
    let (owned_path, owned) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            assistant(OWNED, "req_a2", 2, 300),
            assistant(OWNED, "req_a3", 3, 200),
        ],
    );
    let evidence = reports(&owned_rows());
    let mut index = indexed(&[&owned_path]);
    let mut first = vec![owned.clone()];
    let disposition = fold(&mut first, &evidence, &mut index, true, WINDOW, 1_000);
    assert_eq!(disposition.posture_admission(OWNED), Some("strict"));
    assert!(index.claude_usage_family_witnesses.contains_key(OWNED));

    // A member changed earlier in the later window, so the accumulator left
    // the own family invalid with its evidence erased.
    index.claude_usage_family_pending.insert(
        OWNED.to_string(),
        ClaudeUsageFamilyPending {
            census_window_end: LATER_WINDOW.to_string(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: true,
        },
    );
    let mut later = vec![owned];
    let disposition = fold(
        &mut later,
        &evidence,
        &mut index,
        false,
        LATER_WINDOW,
        1_000,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(later[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_own_family")
    );
    assert_cleared(&later[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn stale_unrelated_family_keeps_current_valid_reconstructed_member() {
    let dir = temp_dir("claude-waiver-stale-unrelated");
    let (owned_path, owned) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            assistant(OWNED, "req_a2", 2, 300),
            assistant(OWNED, "req_a3", 3, 200),
        ],
    );
    let (unrelated_path, _) = session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let evidence = reports(&owned_rows());
    let mut index = indexed(&[&owned_path, &unrelated_path]);
    let mut first = vec![owned.clone()];
    fold(&mut first, &evidence, &mut index, true, WINDOW, 1_000);
    assert!(index.claude_usage_family_witnesses.contains_key(OWNED));

    // An unrelated family's pending from the earlier window, with its file
    // still indexed and no quarantine, fences posture on an incomplete pass.
    index.claude_usage_family_pending.insert(
        UNRELATED.to_string(),
        ClaudeUsageFamilyPending {
            census_window_end: WINDOW.to_string(),
            member_request_id_hashes: BTreeMap::from([(
                UNRELATED.to_string(),
                BTreeSet::from([format!("{:x}", Sha256::digest(b"req_u1"))]),
            )]),
            member_occurrences: BTreeMap::new(),
            invalid: false,
        },
    );
    let mut later = vec![owned];
    let disposition = fold(
        &mut later,
        &evidence,
        &mut index,
        false,
        LATER_WINDOW,
        1_000,
    );

    assert!(!disposition.duplicate_census.census_complete);
    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(later[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(disposition.posture_admission(OWNED), Some("member_waiver"));
    assert_eq!(
        posture(&later[0]),
        (Some(100), Some(300), Some(200), Some(0))
    );
    assert_curve_withheld(&later[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copied_prefix_successor_without_contract_stays_cleared() {
    let dir = temp_dir("claude-waiver-copied-prefix");
    // The predecessor transcript is gone; its copied near-1M response looks
    // unique, but this session's telemetry never assigned it that request.
    let (successor_path, successor) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_predecessor", 1, 900_000),
            assistant(OWNED, "req_a2", 2, 300),
            assistant(OWNED, "req_a3", 3, 200),
        ],
    );
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let mut items = vec![successor, unrelated];
    let mut index = indexed(&[&successor_path, &unrelated_path]);
    let evidence = reports(&[(OWNED, "req_a2", 2, 300), (OWNED, "req_a3", 3, 200)]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 3);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract, None);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_no_contract")
    );
    assert_cleared(&items[0]);
    assert_ne!(items[0].peak_context_fill_tokens, Some(900_000));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn legacy_excluded_successor_stays_on_the_global_fence() {
    let dir = temp_dir("claude-waiver-legacy-prefix");
    let parent = PEER;
    let child = OWNED;
    let (parent_path, parent_item) = session(
        &dir,
        parent,
        &[
            assistant(parent, "req_shared", 1, 10),
            assistant(parent, "req_parent", 2, 11),
        ],
    );
    let (child_path, child_item) = session(
        &dir,
        child,
        &[
            assistant(child, "req_shared", 1, 10),
            assistant(child, "req_child", 3, 12),
            assistant(child, "req_child_2", 4, 14),
        ],
    );
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 5, 50)]);
    let mut items = vec![parent_item, child_item, unrelated];
    let mut index = indexed(&[&parent_path, &child_path, &unrelated_path]);
    let evidence = reports(&[
        (parent, "req_shared", 1, 10),
        (parent, "req_parent", 2, 11),
        (child, "req_child", 3, 12),
        (child, "req_child_2", 4, 14),
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 5);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[1].usage_accounting_contract.as_deref(), V1);
    assert!(index
        .claude_usage_family_witnesses
        .get(child)
        .is_some_and(|witness| !witness.legacy_excluded_request_id_hashes.is_empty()));
    assert_eq!(
        disposition.posture_admission(child),
        Some("withheld_global_census")
    );
    assert_cleared(&items[1]);
    // The maker still shares that request with a visible peer: fail closed.
    assert_eq!(
        disposition.posture_admission(parent),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn visible_duplicate_in_valid_peer_family_withholds() {
    let dir = temp_dir("claude-waiver-visible-duplicate");
    let (owned_path, owned) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            assistant(OWNED, "req_a2", 2, 300),
        ],
    );
    // The copy is not a leading prefix, so no legacy exclusion applies.
    let (peer_path, peer) = session(
        &dir,
        PEER,
        &[
            assistant(PEER, "req_b1", 1, 40),
            assistant(PEER, "req_a1", 3, 100),
        ],
    );
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let mut items = vec![owned, peer, unrelated];
    let mut index = indexed(&[&owned_path, &peer_path, &unrelated_path]);
    let evidence = reports(&[
        (OWNED, "req_a1", 1, 100),
        (OWNED, "req_a2", 2, 300),
        (PEER, "req_b1", 1, 40),
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 4);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    assert_eq!(
        disposition.posture_admission(PEER),
        Some("withheld_no_contract")
    );
    assert_cleared(&items[1]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn request_reported_under_another_root_withholds() {
    let dir = temp_dir("claude-waiver-foreign-report");
    let (paths, mut items) = owned_and_cap_invalid(&dir);
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
    let mut evidence = reports(&owned_rows());
    evidence.0.evidence.insert(
        OTHER_ROOT.to_string(),
        vec![complete_api_row(OTHER_ROOT, "req_a2", 9, 300, 1, 0)],
    );

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 3);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn request_traced_under_another_root_withholds() {
    let dir = temp_dir("claude-waiver-foreign-trace");
    let (paths, mut items) = owned_and_cap_invalid(&dir);
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
    let mut evidence = reports(&owned_rows());
    evidence.1.evidence.insert(
        OTHER_ROOT.to_string(),
        vec![complete_trace_row(OTHER_ROOT, "req_a3", "")],
    );

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 3);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn stale_valid_peer_holding_the_request_withholds() {
    let dir = temp_dir("claude-waiver-stale-peer");
    let (paths, mut items) = owned_and_cap_invalid(&dir);
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
    // Valid pending retained from an earlier window still shows the copy.
    index.claude_usage_family_pending.insert(
        PEER.to_string(),
        ClaudeUsageFamilyPending {
            census_window_end: "2026-08-01T00:00:00Z".to_string(),
            member_request_id_hashes: BTreeMap::from([(
                PEER.to_string(),
                BTreeSet::from([format!("{:x}", Sha256::digest(b"req_a1"))]),
            )]),
            member_occurrences: BTreeMap::new(),
            invalid: false,
        },
    );

    let disposition = fold(
        &mut items,
        &reports(&owned_rows()),
        &mut index,
        true,
        WINDOW,
        3,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn persisted_duplicate_owner_withholds_under_the_closed_fence() {
    let dir = temp_dir("claude-waiver-persisted-duplicate");
    let (paths, mut items) = owned_and_cap_invalid(&dir);
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
    index.claude_duplicate_request_owners.insert(
        format!("{:x}", Sha256::digest(b"req_a2")),
        BTreeSet::from([
            claude_duplicate_request_owner(OWNED, OWNED),
            claude_duplicate_request_owner(PEER, PEER),
        ]),
    );

    let disposition = fold(
        &mut items,
        &reports(&owned_rows()),
        &mut index,
        true,
        WINDOW,
        3,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_duplicate")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn incomplete_request_identity_withholds() {
    let dir = temp_dir("claude-waiver-identity");
    // Natural shape: an id-less response leaves the family identity-invalid,
    // so it is unknown, never unique, and no contract is proven.
    let (id_less_path, id_less) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            id_less_assistant(OWNED, 2, 300),
        ],
    );
    let mut items = vec![id_less];
    let mut index = indexed(&[&id_less_path]);
    let disposition = fold(
        &mut items,
        &reports(&[(OWNED, "req_a1", 1, 100)]),
        &mut index,
        true,
        WINDOW,
        1_000,
    );
    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract, None);
    assert_ne!(disposition.posture_admission(OWNED), Some("member_waiver"));
    assert_cleared(&items[0]);

    // A proven ledger never overrides a curve identity defect.
    let dir_2 = temp_dir("claude-waiver-identity-flag");
    let (paths, mut items) = owned_and_cap_invalid(&dir_2);
    items[0].claude_context_curve_identity_complete = false;
    let mut index = indexed(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
    let disposition = fold(
        &mut items,
        &reports(&owned_rows()),
        &mut index,
        true,
        WINDOW,
        3,
    );
    assert_eq!(items[0].usage_accounting_contract.as_deref(), V1);
    assert_eq!(
        disposition.posture_admission(OWNED),
        Some("withheld_identity")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(dir_2);
}

fn compacted_owned(dir: &Path) -> (PathBuf, SnapshotItem) {
    session(
        dir,
        OWNED,
        &[
            // Copied at the head: no owned response precedes it.
            boundary(OWNED, 0, 900_000, 100_000, 5, 7),
            assistant(OWNED, "req_a1", 1, 100),
            boundary(OWNED, 1, 120, 40, 3, 9),
            assistant(OWNED, "req_a2", 2, 150),
        ],
    )
}

fn compacted_rows() -> Vec<(&'static str, &'static str, u64, u64)> {
    vec![(OWNED, "req_a1", 1, 100), (OWNED, "req_a2", 2, 150)]
}

#[test]
fn waiver_counts_only_compactions_after_the_first_owned_response() {
    let dir = temp_dir("claude-waiver-compaction");
    let (owned_path, owned) = compacted_owned(&dir);
    assert_eq!(owned.compaction_count, Some(2));
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let mut items = vec![owned, unrelated];
    let mut index = indexed(&[&owned_path, &unrelated_path]);

    let disposition = fold(
        &mut items,
        &reports(&compacted_rows()),
        &mut index,
        true,
        WINDOW,
        2,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(disposition.posture_admission(OWNED), Some("member_waiver"));
    let owned = &items[0];
    assert_eq!(posture(owned), (Some(100), Some(150), Some(150), Some(1)));
    assert_eq!(
        owned.compaction_timestamps,
        vec!["2026-08-02T07:00:01.500Z".to_string()]
    );
    assert_eq!(owned.compaction_total_pre_tokens, Some(120));
    assert_eq!(owned.compaction_total_post_tokens, Some(40));
    assert_eq!(owned.compaction_total_cumulative_dropped_tokens, Some(3));
    assert_eq!(owned.compaction_total_duration_ms, Some(9));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn open_fence_keeps_the_strict_rule_unchanged() {
    let dir = temp_dir("claude-waiver-open-fence");
    let (owned_path, owned) = compacted_owned(&dir);
    let mut items = vec![owned];
    let mut index = indexed(&[&owned_path]);

    let disposition = fold(
        &mut items,
        &reports(&compacted_rows()),
        &mut index,
        true,
        WINDOW,
        1_000,
    );

    assert!(!disposition.duplicate_census.census_invalid);
    assert!(!index.claude_duplicate_request_witness_overflowed);
    assert_eq!(disposition.posture_admission(OWNED), Some("strict"));
    assert!(disposition
        .posture_admissions
        .values()
        .all(|admission| *admission != ClaudePostureAdmission::MemberWaiver));
    let owned = &items[0];
    // The strict exclusive-root rule still owns every observed boundary.
    assert_eq!(posture(owned), (Some(100), Some(150), Some(150), Some(2)));
    assert_eq!(owned.compaction_total_pre_tokens, Some(900_120));
    assert!(owned.context_curve.as_ref().map_or(true, |curve| matches!(
        curve.coverage.as_str(),
        "complete" | "sampled"
    )));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn family_level_only_attribution_has_no_member_waiver() {
    let (root, parent, mut items) = claude_account_family_fixture();
    let child_agent = "a4d1585d310070d0f";
    let unrelated_path = root.join(format!("{UNRELATED}.jsonl"));
    fs::write(&unrelated_path, assistant(UNRELATED, "req_u1", 9, 50)).expect("write unrelated");
    items.extend(
        parse_claude_code_jsonl_file(&unrelated_path, "2026-08-02T07:01:00Z", "u-fp".to_string())
            .expect("parse unrelated"),
    );
    // The family's telemetry assigns the root's own req_1 to the sibling
    // subagent, so no member holds an exact per-member proof.
    let api_rows = (1..=5_u64)
        .map(|index| {
            let output_tokens = if index == 5 { 1 } else { 10 };
            complete_api_row(
                &parent,
                &format!("req_{index}"),
                index,
                10,
                output_tokens,
                0,
            )
        })
        .collect::<Vec<_>>();
    let trace_rows = (1..=5_u64)
        .map(|index| {
            let agent = if matches!(index, 1 | 5) {
                child_agent
            } else {
                ""
            };
            complete_trace_row(&parent, &format!("req_{index}"), agent)
        })
        .collect::<Vec<_>>();
    let evidence = (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(parent.clone(), api_rows)]),
            health: Default::default(),
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(parent.clone(), trace_rows)]),
            ..Default::default()
        },
    );
    let mut index = indexed(&[
        &root.join(format!("{parent}.jsonl")),
        &root
            .join(&parent)
            .join("subagents")
            .join(format!("agent-{child_agent}.jsonl")),
        &unrelated_path,
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 5);

    assert!(disposition.duplicate_census.census_invalid);
    for item in &items[..2] {
        assert_eq!(item.usage_accounting_contract, None);
        assert_eq!(
            disposition.posture_admission(&item.source_session_id),
            Some("withheld_no_contract")
        );
        assert_cleared(item);
    }
    let _ = fs::remove_dir_all(root);
}

const CHILD: &str = "d0000000-0000-4000-8000-00000000000d";

/// A provider-stamped copied record, written by branch/fork/rewind writers.
fn copied_assistant(session: &str, request: &str, second: u32, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"uuid\":\"copied-{request}\",\"sessionId\":\"{session}\",\"forkedFrom\":{{\"sessionId\":\"{OTHER_ROOT}\",\"messageUuid\":\"original-{request}\"}},\"type\":\"assistant\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn copied_boundary(session: &str, second: u32, pre: u64) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}.250Z\",\"uuid\":\"copied-compact-{second}\",\"sessionId\":\"{session}\",\"forkedFrom\":{{\"sessionId\":\"{OTHER_ROOT}\",\"messageUuid\":\"original-compact-{second}\"}},\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{{\"trigger\":\"auto\",\"preTokens\":{pre},\"postTokens\":1,\"cumulativeDroppedTokens\":1,\"durationMs\":1}}}}\n"
    )
}

#[test]
fn waiver_compactions_follow_a_non_zero_non_contiguous_first_owned_sequence() {
    let dir = temp_dir("claude-waiver-sparse-sequence");
    let (owned_path, mut owned) = session(
        &dir,
        OWNED,
        &[
            boundary(OWNED, 0, 1_000, 1, 1, 1),
            assistant(OWNED, "req_a1", 1, 100),
            boundary(OWNED, 1, 2_000, 1, 1, 1),
            assistant(OWNED, "req_a2", 2, 300),
            boundary(OWNED, 2, 30, 3, 3, 3),
            assistant(OWNED, "req_a3", 3, 200),
            boundary(OWNED, 3, 40, 4, 4, 4),
            boundary(OWNED, 4, 50, 5, 5, 5),
        ],
    );
    // The parser numbers responses consecutively from zero. Pin the rule to
    // ordinals, not positions: the counted responses sit at 2, 5 and 9, and
    // the other ordinals are responses this member does not count. Request
    // order (a1, a2, a3) deliberately differs from ordinal order.
    for (request_id, sequence) in [("req_a1", 9), ("req_a2", 2), ("req_a3", 5)] {
        owned
            .claude_usage_occurrences
            .get_mut(request_id)
            .expect("parsed occurrence")
            .sequence = sequence;
    }
    assert_eq!(owned.claude_context_curve_boundaries.len(), 5);
    // Before the inherited ordinals, at the first owned response, after it,
    // after the second owned response, and after the last one.
    for (observation, response_count_before) in owned
        .claude_context_curve_boundaries
        .iter_mut()
        .zip([0, 2, 3, 6, 10])
    {
        observation.response_count_before = response_count_before;
    }
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 5, 50)]);
    let mut items = vec![owned, unrelated];
    let mut index = indexed(&[&owned_path, &unrelated_path]);

    let disposition = fold(
        &mut items,
        &reports(&owned_rows()),
        &mut index,
        true,
        WINDOW,
        3,
    );

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(disposition.posture_admission(OWNED), Some("member_waiver"));
    let owned = &items[0];
    // First and last follow ordinals 2 and 9; the boundaries at 0 and at the
    // first owned ordinal (2) have no owned response before them.
    assert_eq!(posture(owned), (Some(300), Some(300), Some(100), Some(3)));
    assert_eq!(owned.compaction_total_pre_tokens, Some(30 + 40 + 50));
    assert_eq!(
        owned.compaction_timestamps,
        vec![
            "2026-08-02T07:00:02.500Z".to_string(),
            "2026-08-02T07:00:03.500Z".to_string(),
            "2026-08-02T07:00:04.500Z".to_string(),
        ]
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copied_markers_and_responses_never_borrow_ownership() {
    let dir = temp_dir("claude-waiver-copied-markers");
    let (child_path, child) = session(
        &dir,
        CHILD,
        &[
            // Inherited history and its compaction, then an own boundary
            // before any owned response.
            copied_assistant(CHILD, "req_p1", 0, 800_000),
            copied_boundary(CHILD, 0, 700_000),
            boundary(CHILD, 1, 900_000, 1, 1, 1),
            assistant(CHILD, "req_c1", 2, 100),
            // Copied records between and after owned responses.
            copied_assistant(CHILD, "req_p2", 2, 850_000),
            copied_boundary(CHILD, 3, 600_000),
            boundary(CHILD, 3, 30, 3, 3, 3),
            assistant(CHILD, "req_c2", 4, 400),
            copied_boundary(CHILD, 5, 500_000),
        ],
    );
    assert!(child.claude_context_curve_owned_start_proven);
    assert_eq!(child.claude_context_curve_boundaries.len(), 2);
    let expected_start = child
        .session_start
        .clone()
        .and_then(|start| (*start).inherited());
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 6, 50)]);
    let mut items = vec![child, unrelated];
    let mut index = indexed(&[&child_path, &unrelated_path]);
    // The maker's telemetry reports the copied requests under its own root.
    let evidence = reports(&[
        (CHILD, "req_c1", 2, 100),
        (CHILD, "req_c2", 4, 400),
        (OTHER_ROOT, "req_p1", 0, 800_000),
        (OTHER_ROOT, "req_p2", 1, 850_000),
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 2);

    assert!(disposition.duplicate_census.census_invalid);
    let child = &items[0];
    assert_eq!(child.usage_accounting_contract.as_deref(), V1);
    assert_eq!(disposition.posture_admission(CHILD), Some("member_waiver"));
    assert_eq!(posture(child), (Some(100), Some(400), Some(400), Some(1)));
    assert_eq!(child.compaction_total_pre_tokens, Some(30));
    assert_eq!(
        child.compaction_timestamps,
        vec!["2026-08-02T07:00:03.500Z".to_string()]
    );
    assert_eq!(child.session_start.as_deref(), expected_start.as_ref());
    assert!(child.cache_observations.is_none(), "cache stays strict");
    assert_curve_withheld(child);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn own_boundary_without_an_owned_response_stays_null() {
    let dir = temp_dir("claude-waiver-no-owned-response");
    let (child_path, child) = session(
        &dir,
        CHILD,
        &[
            copied_assistant(CHILD, "req_p1", 0, 800_000),
            boundary(CHILD, 1, 900_000, 1, 1, 1),
        ],
    );
    assert_eq!(child.compaction_count, Some(1));
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 2, 50)]);
    let mut items = vec![child, unrelated];
    let mut index = indexed(&[&child_path, &unrelated_path]);
    let evidence = reports(&[
        (OTHER_ROOT, "req_p1", 0, 800_000),
        (UNRELATED, "req_u1", 2, 50),
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 0);

    assert!(disposition.duplicate_census.census_invalid);
    assert_eq!(items[0].usage_accounting_contract, None);
    assert_eq!(
        disposition.posture_admission(CHILD),
        Some("withheld_global_census")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn waived_body_differs_from_the_withheld_control_only_in_context_scalars() {
    let dir = temp_dir("claude-waiver-body-diff");
    let (owned_path, owned) = compacted_owned(&dir);
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let mut items = vec![owned, unrelated];
    let mut index = indexed(&[&owned_path, &unrelated_path]);

    let disposition = fold(
        &mut items,
        &reports(&compacted_rows()),
        &mut index,
        true,
        WINDOW,
        2,
    );

    assert_eq!(disposition.posture_admission(OWNED), Some("member_waiver"));
    let waived = items[0].clone();
    // Without the waiver this fold's only other branch for the item clears
    // the posture; every later step is shared and re-derives the semantic
    // fingerprint from the item.
    let mut control = waived.clone();
    clear_claude_context_posture(&mut control);
    control.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &control);
    let waived_body = serde_json::to_value(&waived).expect("serialize waived body");
    let control_body = serde_json::to_value(&control).expect("serialize control body");
    let (waived_body, control_body) = (
        waived_body.as_object().expect("body object"),
        control_body.as_object().expect("body object"),
    );
    let differing = waived_body
        .keys()
        .chain(control_body.keys())
        .filter(|key| waived_body.get(*key) != control_body.get(*key))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        differing,
        BTreeSet::from([
            "compaction_count",
            "compaction_timestamps",
            "compaction_total_cumulative_dropped_tokens",
            "compaction_total_duration_ms",
            "compaction_total_post_tokens",
            "compaction_total_pre_tokens",
            "first_turn_context_tokens",
            "last_turn_context_tokens",
            "peak_context_fill_tokens",
            // Derived: context posture participates in semantic identity.
            "snapshot_fingerprint",
        ])
    );
    for identity_field in [
        "source_session_id",
        "session_account_evidence",
        "attribution_facts",
        "request_evidence",
        "usage_accounting_contract",
        "session_display_name",
        "session_start",
        "provenance",
        "origin",
    ] {
        assert_eq!(
            waived_body.get(identity_field),
            control_body.get(identity_field),
            "{identity_field} must not depend on the waiver"
        );
    }
    assert_eq!(
        waived.claude_account_withheld_reason,
        control.claude_account_withheld_reason
    );
    assert_eq!(
        waived.request_identity_refusals,
        control.request_identity_refusals
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copier_with_requests_reported_under_another_root_stays_cleared() {
    let dir = temp_dir("claude-waiver-copier");
    // An unmarked copy of another root's request: its maker's telemetry
    // reports it under that root, never under the copier.
    let (copier_path, copier) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_copied", 1, 900_000),
            assistant(OWNED, "req_a2", 2, 300),
        ],
    );
    let (unrelated_path, unrelated) =
        session(&dir, UNRELATED, &[assistant(UNRELATED, "req_u1", 4, 50)]);
    let mut items = vec![copier, unrelated];
    let mut index = indexed(&[&copier_path, &unrelated_path]);
    let evidence = reports(&[
        (OTHER_ROOT, "req_copied", 1, 900_000),
        (OWNED, "req_a2", 2, 300),
    ]);

    let disposition = fold(&mut items, &evidence, &mut index, true, WINDOW, 2);

    assert!(disposition.duplicate_census.census_invalid);
    assert_ne!(disposition.posture_admission(OWNED), Some("member_waiver"));
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn waiver_evidence_refuses_before_allocating_past_its_bound() {
    let dir = temp_dir("claude-waiver-evidence-bound");
    let (_, owned) = session(
        &dir,
        OWNED,
        &[
            assistant(OWNED, "req_a1", 1, 100),
            assistant(OWNED, "req_a2", 2, 300),
        ],
    );
    let candidates = [owned];
    let index = ScanIndex::default();
    let evidence = reports(&[(OWNED, "req_a1", 1, 100), (OWNED, "req_a2", 2, 300)]);

    assert!(
        claude_posture_waiver_evidence(candidates.iter(), 1, &index, &evidence.0, &evidence.1)
            .is_none()
    );
    let bounded =
        claude_posture_waiver_evidence(candidates.iter(), 2, &index, &evidence.0, &evidence.1)
            .expect("candidates within the bound");
    assert!(bounded.visible_dupes.is_empty());
    assert_eq!(bounded.foreign_otel.len(), 2);
    assert!(bounded.foreign_otel.values().all(
        |reported| matches!(reported, ClaudeReportedRequestRoot::One(root) if *root == OWNED)
    ));
    let _ = fs::remove_dir_all(dir);
}
