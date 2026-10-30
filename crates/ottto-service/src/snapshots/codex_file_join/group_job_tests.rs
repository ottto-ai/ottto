//! P2 group StreamProof, ordinal domain and census fencing tests (§n P2).
//! Every fixture is synthetic; no provider account content. Scaled budgets
//! come from `codex_cursor::with_test_limits` only.
use super::super::tests::{
    counting_v2_unbound_fixture, fixture, legacy_index, member, replay_group, scan, usage,
};
use super::*;
use crate::transcript_acquisition::Scope;
use sampled_scan::codex_cursor::{with_test_limits, with_test_state_budget, Counters};
use sampled_scan::SharedCache;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER: &str = "ffffffff-1111-4111-8111-ffffffffffff";
const UNKNOWN: &str = "99999999-9999-4999-8999-999999999999";
static NEXT: AtomicU64 = AtomicU64::new(0);

fn write_rows(path: &Path, rows: &[Value]) {
    fs::write(
        path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}

/// A fresh `<root>/sessions` directory.
fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ottto-codex-group-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, AtomicOrdering::Relaxed)
    ));
    fs::create_dir_all(root.join("sessions")).unwrap();
    root
}

/// The owner's group from a complete header inventory of `root/sessions`.
fn group_of(root: &Path) -> Group {
    let sessions = root.join("sessions");
    let paths = fs::read_dir(&sessions)
        .unwrap()
        .map(|entry| local_index_key(&entry.unwrap().path()))
        .collect::<BTreeSet<_>>();
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    assert!(inventory.complete);
    inventory
        .groups()
        .into_values()
        .find(|group| group.owner == OWNER)
        .expect("the owner's group")
}

fn meta(owner: &str, created: &str, extra: Value) -> Value {
    let mut payload = json!({"id": owner, "timestamp": created});
    if let (Some(payload), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
        payload.extend(extra.clone());
    }
    json!({"type": "session_meta", "timestamp": created, "payload": payload})
}

fn native(owner: &str, response: &str, input: u64, after: u64) -> Value {
    json!({"type": "token_usage_record", "timestamp": "2026-10-01T10:01:00Z", "payload": {
        "thread_id": owner, "response_id": response, "usage": usage(input),
        "thread_token_usage": usage(after)}})
}

fn ui(input: u64, total: u64, at: &str) -> Value {
    json!({"type": "event_msg", "timestamp": at, "payload": {"type": "token_count",
        "info": {"last_token_usage": usage(input), "total_token_usage": usage(total)}}})
}

fn turn(id: &str) -> Value {
    json!({"type": "turn_context", "payload": {"turn_id": id, "model": "gpt-5.2"}})
}

/// Number `rows` from `first` (the ordinal domain).
fn ordinals(rows: Vec<Value>, first: u64) -> Vec<Value> {
    rows.into_iter()
        .zip(first..)
        .map(|(mut row, ordinal)| {
            row["ordinal"] = json!(ordinal);
            row
        })
        .collect()
}

fn rollout(uuid: &str) -> String {
    format!("rollout-2026-10-01T10-00-00-{uuid}.jsonl")
}

fn candidate(name: &str, size: u64) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/fixture/sessions"),
        path: PathBuf::from(format!("/fixture/sessions/{name}")),
        size_bytes: size,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    }
}

/// `plan_group` over header rows and file names (distinct sizes).
fn plan(members: &[(Value, String)]) -> std::result::Result<GroupPlan, JoinRefusal> {
    plan_sized(members, 100u64..)
}

/// `plan_group` over header rows, file names and member sizes.
fn plan_sized(
    members: &[(Value, String)],
    sizes: impl IntoIterator<Item = u64>,
) -> std::result::Result<GroupPlan, JoinRefusal> {
    let headers = members
        .iter()
        .zip(sizes)
        .map(|((row, name), size)| {
            MemberHeader::parse(
                serde_json::to_string(row).unwrap().as_bytes(),
                &candidate(name, size),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let keys = members
        .iter()
        .map(|(_, name)| format!("/fixture/sessions/{name}"))
        .collect::<Vec<_>>();
    plan_group(&headers, &keys)
}

/// R1-L2: byte-identical line 0 at an equal size is one copied candidate
/// (`CandidateCopy`), never a chain; the same line 0 at another size is not.
#[test]
fn plan_refuses_an_equal_header_and_size_as_a_candidate_copy() {
    let header = meta(OWNER, "2026-10-01T10:00:00Z", json!({}));
    let members = [
        (
            header.clone(),
            rollout("11111111-cccc-4ccc-8ccc-111111111111"),
        ),
        (header, rollout("22222222-cccc-4ccc-8ccc-222222222222")),
    ];
    assert_eq!(
        plan_sized(&members, [100, 100]).err(),
        Some(JoinRefusal::CandidateCopy)
    );
    assert_ne!(
        plan_sized(&members, [100, 101]).err(),
        Some(JoinRefusal::CandidateCopy)
    );
}

/// Feed rows to `proof` with the parser's S10 tap after every UI record.
fn feed(proof: &mut StreamProof, rows: &[Value], starts: impl IntoIterator<Item = u64>) {
    for (row, start) in rows.iter().zip(starts) {
        proof.set_record_start(start);
        proof.observe(row);
        if codex_last_usage(row).is_some() {
            proof.admitted_usage(row, true, codex_usage_event_identity(row).as_deref(), None);
        }
    }
}

fn refused(
    result: std::result::Result<Box<OwnedActiveFile>, GroupEnd>,
) -> Option<(JoinRefusal, usize)> {
    match result {
        Err(GroupEnd::Refused {
            reason, position, ..
        }) => Some((reason, position)),
        _ => None,
    }
}

/// One sampled page: a scan object with the shared cache, stepped to
/// completion, then the collector's post-policy finalization.
fn sampled(
    root: &Path,
    index: ScanIndex,
    limit: usize,
    cache: &Arc<SharedCache>,
) -> (ScanIndex, SourceScanResult) {
    sampled_at(root, index, limit, cache, "2026-10-06T23:00:00Z")
}

/// `sampled` at `collected_at`: a new traversal's census window ends there,
/// so a later `collected_at` is a new generation (K7 fence token).
fn sampled_at(
    root: &Path,
    index: ScanIndex,
    limit: usize,
    cache: &Arc<SharedCache>,
    collected_at: &str,
) -> (ScanIndex, SourceScanResult) {
    sampled_in(root, index, limit, cache, collected_at, "group-fixture")
}

/// `sampled_at` in scan namespace `scope`.
fn sampled_in(
    root: &Path,
    index: ScanIndex,
    limit: usize,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    scope: &str,
) -> (ScanIndex, SourceScanResult) {
    sampled_hinted(root, index, limit, cache, collected_at, scope, &[])
}

/// `sampled_in` with watcher `hints`.
fn sampled_hinted(
    root: &Path,
    index: ScanIndex,
    limit: usize,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    scope: &str,
    hints: &[PathBuf],
) -> (ScanIndex, SourceScanResult) {
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        collected_at,
        7,
        limit,
        false,
        None,
        hints,
        false,
        false,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope(scope.into()));
    for _ in 0..100_000 {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
    panic!("bounded sampled scan did not finish");
}

fn counters(cache: &SharedCache) -> Counters {
    cache.counters_for_test()
}

/// Two members of `OWNER`, the second refused at its first native (`Overlap`).
fn refused_fixture() -> PathBuf {
    let (root, _) = fixture();
    write_rows(
        &root.join("sessions/b.jsonl"),
        &member(OWNER, "bad-overlap", 200, 250),
    );
    root
}

#[test]
fn terminal_join_debt_settles_census_without_alias_parser() {
    let root = refused_fixture();
    let (index, result) = scan(&root, ScanIndex::default(), 2);
    assert!(result.snapshots.is_empty());
    assert_eq!(
        result.unreadable_path_count, 0,
        "terminal proof debt is not an unreadable file"
    );
    assert!(
        result.census_complete,
        "outcome R: settleable residue lets the census complete: {result:?}"
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fence_filters_watcher_hint_after_attempt() {
    let root = refused_fixture();
    write_rows(
        &root.join("sessions/c.jsonl"),
        &member(OTHER, "healthy", 100, 100),
    );
    let cache = Arc::new(SharedCache::default());
    let (mut index, first) = sampled(&root, ScanIndex::default(), 2, &cache);
    assert!(first.snapshots.is_empty());
    let overlap = JoinRefusal::Overlap.slot();
    assert_eq!(counters(&cache).join_terminal_debt[overlap], 1);
    // A watcher hint for a member of the attempted group, same generation.
    let traversal = index.traversal.as_mut().expect("the generation continues");
    let scan_root = traversal.scan_roots[0].clone();
    traversal.pending_candidates.push_back(ScanTraversalPath {
        path: scan_root.join("b.jsonl"),
        scan_root,
        census_member: false,
        watcher_hint: true,
    });
    let (_, next) = sampled(&root, index, 2, &cache);
    let after = counters(&cache);
    assert_eq!(
        after.join_terminal_debt[overlap], 1,
        "no second attempt in the generation: {after:?}"
    );
    assert_eq!(after.groups_fenced, 1, "{after:?}");
    assert!(next
        .snapshots
        .iter()
        .all(|snapshot| snapshot.source_session_id == OTHER));
    fs::remove_dir_all(root).unwrap();
}

/// G1 (review of #751, P1): a processed group re-hinted through one member
/// is a re-read group. On every page it would take the whole file allowance
/// (two files) and evict the waiting census-member singleton `c`, so the
/// census never closed. It now waits for a page without a waiting member,
/// and a group fenced by its attempt this generation is decided at admission
/// without taking allowance: `c` is read on the first hinted page and the
/// census closes. Covered for an ordinary group, a fenced group and an
/// own-page group (more members than the page's file limit).
#[test]
fn reread_group_never_starves_a_waiting_census_singleton() {
    let ordinary = || fixture().0;
    let own_page = || {
        let (root, _) = fixture();
        write_rows(
            &root.join("sessions/d.jsonl"),
            &member(OWNER, "r-d", 300, 600),
        );
        root
    };
    let cases: [(&str, &dyn Fn() -> PathBuf); 3] = [
        ("ordinary", &ordinary),
        ("fenced", &refused_fixture),
        ("own-page", &own_page),
    ];
    for (case, make) in cases {
        let root = make();
        write_rows(
            &root.join("sessions/c.jsonl"),
            &member(OTHER, "healthy", 100, 100),
        );
        let cache = Arc::new(SharedCache::default());
        let at = |page: u64| format!("2026-10-06T23:{page:02}:00Z");
        // Page 0, two files: the group (a, b) is attempted; `c` waits.
        let (mut index, first) = sampled_hinted(
            &root,
            ScanIndex::default(),
            2,
            &cache,
            &at(0),
            "group-fixture",
            &[],
        );
        assert!(
            first
                .snapshots
                .iter()
                .all(|snapshot| snapshot.source_session_id != OTHER),
            "{case}"
        );
        let traversal = index.traversal.as_ref().expect("the generation continues");
        assert!(
            traversal
                .pending_candidates
                .iter()
                .any(|pending| pending.path.ends_with("c.jsonl") && pending.census_member),
            "{case}: c waits as a census member"
        );
        let hinted = traversal.scan_roots[0].join("b.jsonl");
        let mut published = 0;
        let mut closed = None;
        for page in 1..=3_u64 {
            let (next, scan) = sampled_hinted(
                &root,
                index,
                2,
                &cache,
                &at(page),
                "group-fixture",
                std::slice::from_ref(&hinted),
            );
            index = next;
            published += scan
                .snapshots
                .iter()
                .filter(|snapshot| snapshot.source_session_id == OTHER)
                .count();
            if scan.census_complete {
                closed = Some(page);
                break;
            }
        }
        assert_eq!(
            published,
            1,
            "{case}: c is read once: {:?}",
            counters(&cache)
        );
        assert_eq!(closed, Some(1), "{case}: {:?}", counters(&cache));
        if case == "fenced" {
            // Decided at admission: fenced, and no allowance taken from `c`.
            assert_eq!(counters(&cache).groups_fenced, 1, "{:?}", counters(&cache));
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// `count` native/UI pairs continuing the counter from `start`.
fn chain_rows(owner: &str, prefix: &str, created: &str, start: u64, count: u64) -> Vec<Value> {
    let mut rows = vec![meta(owner, created, json!({}))];
    for i in 0..count {
        let after = start + 10 * (i + 1);
        rows.push(native(owner, &format!("{prefix}-{i}"), 10, after));
        rows.push(ui(
            10,
            after,
            &format!(
                "2026-10-01T{:02}:{:02}:{:02}Z",
                10 + after / 3600,
                after / 60 % 60,
                after % 60
            ),
        ));
    }
    rows
}

#[test]
fn selection_skips_job_owned_entries() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("paged");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &chain_rows(OWNER, "a", "2026-10-01T10:00:00Z", 0, 30),
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 300, 30),
    );
    let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
    assert_eq!(unpaged.snapshots.len(), 2, "one alias per member");
    let cache = Arc::new(SharedCache::default());
    let paged = with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..128 {
            let (next, result) = sampled(&root, index, 10, &cache);
            index = next;
            let done = counters(&cache);
            if done.jobs_certified + done.jobs_uncertified > 0 {
                return result;
            }
            assert!(
                result.snapshots.is_empty(),
                "a paused group publishes nothing"
            );
        }
        panic!("group job did not complete: {:?}", counters(&cache));
    });
    let after = counters(&cache);
    eprintln!("CODEX_GROUP_PAGED counters={after:?}");
    assert_eq!(after.groups_started, 1, "one job, never restarted");
    assert!(after.jobs_paused > 0 && after.jobs_resumed > 0);
    // #603: with the cutover inactive the group view is the inactive view
    // and `counting_reusable` lets every unchanged pause resume.
    assert_eq!(after.jobs_invalidated, 0, "{after:?}");
    assert!(
        after.join_in_progress_members > 0,
        "selected members of the paused job are skipped, not read again"
    );
    let fingerprints = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
    assert!(cache.cursor_slot_free());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn blocked_owner_released_when_all_members_vanish_on_clean_walk() {
    let root = refused_fixture();
    write_rows(
        &root.join("sessions/c.jsonl"),
        &member(OTHER, "healthy", 100, 100),
    );
    let cache = Arc::new(SharedCache::default());
    let (mut index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
    fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
    // A later generation walks the corpus again.
    index.traversal = None;
    for _ in 0..8 {
        let (next, _) = sampled(&root, index, 10, &cache);
        index = next;
        if !index.codex_state_only_blocked_session_ids.contains(OWNER) {
            break;
        }
    }
    assert!(
        !index.codex_state_only_blocked_session_ids.contains(OWNER),
        "B releases the owner it blocked once every member left the census"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn v2_group_with_ui_only_turn_held_until_turn_hook() {
    let root = temp_root("v2");
    let first = "11111111-aaaa-4aaa-8aaa-111111111111";
    let second = "22222222-aaaa-4aaa-8aaa-222222222222";
    write_rows(
        &root.join("sessions/a.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
            turn(first),
            native(OWNER, "r-a", 100, 100),
            ui(100, 100, "2026-10-01T10:00:30Z"),
        ],
    );
    let bound = [
        meta(OWNER, "2026-10-01T10:01:00Z", json!({})),
        turn(first),
        native(OWNER, "r-b", 200, 300),
        ui(200, 300, "2026-10-01T10:01:30Z"),
    ];
    let mut ui_only = bound.to_vec();
    ui_only.extend([turn(second), ui(50, 350, "2026-10-01T10:02:30Z")]);
    write_rows(&root.join("sessions/b.jsonl"), &ui_only);
    // Legacy counting: the extra admission has no native in its member.
    assert_eq!(
        refused(replay_group(group_of(&root), None, &ScanIndex::default())),
        Some((JoinRefusal::UiUnmatched, 1))
    );
    // §k.3 interim: under V2 the UI side is not money; a UI-only turn holds
    // the group at its end until the counting writer's turn hook lands.
    let held = with_test_v2(|| replay_group(group_of(&root), None, &ScanIndex::default()));
    assert_eq!(refused(held), Some((JoinRefusal::V2UiOnlyTurn, 1)));
    write_rows(&root.join("sessions/b.jsonl"), &bound);
    assert!(
        with_test_v2(|| replay_group(group_of(&root), None, &ScanIndex::default())).is_ok(),
        "every admitted turn has a native: the V2 group replays"
    );
    fs::remove_dir_all(root).unwrap();
}

/// R(t), E(t), zero Z, then `repeat` in member b.
fn eze(repeat: Value) -> Option<(JoinRefusal, usize)> {
    let root = temp_root("eze");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &member(OWNER, "r-a", 100, 100),
    );
    let mut rows = vec![
        meta(OWNER, "2026-10-01T10:01:00Z", json!({})),
        native(OWNER, "r-b", 200, 300),
        ui(200, 300, "2026-10-01T10:01:30Z"),
        ui(0, 300, "2026-10-01T10:01:40Z"),
    ];
    rows.push(repeat);
    write_rows(&root.join("sessions/b.jsonl"), &rows);
    let result = refused(replay_group(group_of(&root), None, &ScanIndex::default()));
    fs::remove_dir_all(root).unwrap();
    result
}

#[test]
fn eze_identical_repeat_is_overlap() {
    // The repeated E has the same identity (the whole record): the parser
    // admits it again after Z, and the tap's identity set refuses it.
    assert_eq!(
        eze(ui(200, 300, "2026-10-01T10:01:30Z")),
        Some((JoinRefusal::Overlap, 1))
    );
}

#[test]
fn eze_distinct_identity_repeat_is_ui_repeat_unproven() {
    // A distinct record of the same tuple, with no native between the two
    // admissions: held, never counted twice.
    assert_eq!(
        eze(ui(200, 300, "2026-10-01T10:01:50Z")),
        Some((JoinRefusal::UiRepeatUnproven, 1))
    );
}

#[test]
fn duplicate_origin_stub_replayed_first_does_not_change_live_context() {
    let root = temp_root("stub");
    write_rows(
        &root.join("sessions/stub.jsonl"),
        &ordinals(
            vec![
                meta(OWNER, "2026-10-01T09:00:00Z", json!({})),
                json!({"type": "turn_context", "payload": {
                    "turn_id": "33333333-aaaa-4aaa-8aaa-333333333333", "model": "stub-model"}}),
            ],
            0,
        ),
    );
    let main = ordinals(
        vec![
            meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
            native(OWNER, "r-main", 100, 100),
            ui(100, 100, "2026-10-01T10:00:30Z"),
        ],
        0,
    );
    write_rows(&root.join("sessions/main.jsonl"), &main);
    let job = replay_group(group_of(&root), None, &ScanIndex::default())
        .expect("a neutral duplicate origin joins as a stub");
    let OwnedActiveFile {
        parser,
        candidate,
        aliases,
        ..
    } = *job;
    assert_eq!(aliases.len(), 2);
    assert!(
        candidate.path.ends_with("main.jsonl"),
        "the last origin is the main (live) member"
    );
    let parsed = parser
        .finish(
            &candidate.opened_object_identity,
            &candidate.path,
            "2026-10-06T23:00:00Z",
            candidate.source_file_fingerprint.clone(),
            Some(&CodexTitleMetadata::default()),
            None,
            None,
        )
        .unwrap();
    assert!(parsed.complete());
    assert_eq!(parsed.snapshots.len(), 1);
    assert_eq!(parsed.snapshots[0].input_tokens, 100);
    assert!(
        parsed.snapshots[0]
            .model_usage
            .iter()
            .all(|row| row.model != "stub-model"),
        "the stub's context never prices the live member"
    );
    // A duplicate origin that carries usage is a restart, not a stub.
    write_rows(
        &root.join("sessions/stub.jsonl"),
        &ordinals(
            vec![
                meta(OWNER, "2026-10-01T09:00:00Z", json!({})),
                native(OWNER, "r-stub", 100, 100),
                ui(100, 100, "2026-10-01T09:00:30Z"),
            ],
            0,
        ),
    );
    assert_eq!(
        refused(replay_group(group_of(&root), None, &ScanIndex::default())),
        Some((JoinRefusal::OrdinalRestart, 0))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ui_shape_unreadable_is_proof_domain() {
    let start = |proof: &mut StreamProof| {
        proof.begin_member(0);
        proof.observe(&meta(OWNER, "2026-10-01T10:00:00Z", json!({})));
        proof.observe(&native(OWNER, "r", 100, 100));
    };
    let mut proof = StreamProof::new(OWNER.into(), false, vec![MemberPlan::default()]);
    start(&mut proof);
    let mut row = ui(100, 100, "2026-10-01T10:00:30Z");
    row["payload"]["info"]["last_token_usage"]
        .as_object_mut()
        .unwrap()
        .remove("reasoning_output_tokens");
    proof.admitted_usage(&row, true, Some("identity"), None);
    assert_eq!(proof.refusal(), Some((JoinRefusal::UiShape, 0)));
    // No identity is the same named shape debt, never skipped.
    let mut proof = StreamProof::new(OWNER.into(), false, vec![MemberPlan::default()]);
    start(&mut proof);
    proof.admitted_usage(&ui(100, 100, "2026-10-01T10:00:30Z"), true, None, None);
    assert_eq!(proof.refusal(), Some((JoinRefusal::UiShape, 0)));
    // An admission the parser derived from cumulative counters.
    let mut proof = StreamProof::new(OWNER.into(), false, vec![MemberPlan::default()]);
    start(&mut proof);
    proof.admitted_usage(
        &ui(100, 100, "2026-10-01T10:00:30Z"),
        false,
        Some("x"),
        None,
    );
    assert_eq!(proof.refusal(), Some((JoinRefusal::CumulativeOnly, 0)));
}

#[test]
fn ui_root_shared_with_parser() {
    let last = usage(70);
    for row in [
        json!({"type": "event_msg", "payload": {"type": "token_count",
            "info": {"last_token_usage": last}}}),
        json!({"type": "event_msg", "payload": {"type": "token_count",
            "last_token_usage": last}}),
        json!({"token_count": {"info": {"last_token_usage": last}}}),
        json!({"last_token_usage": last}),
    ] {
        assert_eq!(codex_last_usage_root(&row), Some(&last), "{row}");
        assert_eq!(
            codex_last_usage(&row).map(|usage| usage.input_tokens),
            Some(70)
        );
    }
    let cumulative = json!({"payload": {"info": {"total_token_usage": last}}});
    assert!(codex_last_usage_root(&cumulative).is_none());
    assert!(codex_last_usage(&cumulative).is_none());
}

#[test]
fn binding_requires_unique_logical_uuid_offset_and_chain() {
    let origin = (
        ordinals(vec![meta(OWNER, "2026-10-01T10:00:00Z", json!({}))], 0).remove(0),
        rollout(OWNER),
    );
    let base_row = |thread: &str, end: u64, ordinal: u64| {
        let mut row = meta(
            OWNER,
            "2026-10-01T11:00:00Z",
            json!({"history_base": {"thread_id": thread,
                "end_ordinal_exclusive": end, "end_byte_offset": 500}}),
        );
        row["ordinal"] = json!(ordinal);
        row
    };
    let base =
        |thread: &str, end: u64, ordinal: u64| (base_row(thread, end, ordinal), rollout(OTHER));
    // Bound by the predecessor's file UUID, first ordinal E and offset.
    let planned = plan(&[origin.clone(), base(OWNER, 3, 3)]).unwrap();
    assert!(planned.ordinal);
    assert_eq!(planned.order, vec![0, 1]);
    assert_eq!(planned.plans[1].binding, Some((0, 3, 500)));
    assert_eq!(planned.plans[0].watch, vec![3]);
    // A first ordinal other than E.
    assert_eq!(
        plan(&[origin.clone(), base(OWNER, 3, 4)]),
        Err(JoinRefusal::HistoryBase)
    );
    // A thread id no member's file carries (a predecessor outside the
    // inventory, e.g. an unscanned `.zst`), or two members carry.
    assert_eq!(
        plan(&[origin.clone(), base(UNKNOWN, 3, 3)]),
        Err(JoinRefusal::MissingPredecessor)
    );
    let twin = (
        ordinals(vec![meta(OWNER, "2026-10-01T10:30:00Z", json!({}))], 0).remove(0),
        format!("archived/{}", rollout(OWNER)),
    );
    assert_eq!(
        plan(&[origin.clone(), twin, base(OWNER, 3, 3)]),
        Err(JoinRefusal::AmbiguousPredecessor)
    );
    // The offset and the native chain are proven in the replay.
    let plans = planned.plans;
    let run = |offset: u64, before: u64| {
        let mut proof = StreamProof::new(OWNER.into(), false, plans.clone());
        proof.begin_member(0);
        let rows = ordinals(
            vec![
                meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
                native(OWNER, "r-0", 100, 100),
                ui(100, 100, "2026-10-01T10:00:30Z"),
            ],
            0,
        );
        feed(&mut proof, &rows, (0..).step_by(100));
        // Ordinals 0..=2 end at byte 500: E = 3 binds there.
        proof.end_member(offset);
        proof.begin_member(1);
        let mut rows = vec![base_row(OWNER, 3, 3)];
        rows.extend(ordinals(
            vec![
                native(OWNER, "r-1", 50, before + 50),
                ui(50, before + 50, "2026-10-01T11:00:30Z"),
            ],
            4,
        ));
        feed(&mut proof, &rows, (0..).step_by(100));
        proof.end_member(300);
        proof.finish_group();
        proof.refusal()
    };
    assert_eq!(run(500, 100), None);
    assert_eq!(run(400, 100), Some((JoinRefusal::HistoryBase, 1)));
    assert_eq!(run(500, 150), Some((JoinRefusal::Gap, 1)));
    assert_eq!(run(500, 50), Some((JoinRefusal::Overlap, 1)));
}

#[test]
fn fork_first_member_held_from_headers() {
    let forked = meta(
        OWNER,
        "2026-10-01T10:00:00Z",
        json!({"forked_from_id": OTHER}),
    );
    let later = meta(OWNER, "2026-10-01T10:30:00Z", json!({}));
    assert_eq!(
        plan(&[
            (forked.clone(), "a.jsonl".into()),
            (later.clone(), "b.jsonl".into())
        ]),
        Err(JoinRefusal::ForkedFromOtherSession)
    );
    // From headers alone: the boot refuses before any replay byte.
    let root = temp_root("fork");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &[
            forked,
            native(OWNER, "r-a", 100, 100),
            ui(100, 100, "2026-10-01T10:00:30Z"),
        ],
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &[
            later,
            native(OWNER, "r-b", 200, 300),
            ui(200, 300, "2026-10-01T10:30:30Z"),
        ],
    );
    let mut boot = GroupBoot::new(group_of(&root), &ScanIndex::default());
    let reason = loop {
        match boot.step(None, &ScanIndex::default()) {
            Boot::Pending => {}
            Boot::Refused(reason) => break reason,
            _ => panic!("a forked first member is held from its header"),
        }
    };
    assert_eq!(reason, JoinRefusal::ForkedFromOtherSession);
    fs::remove_dir_all(root).unwrap();
    // A first member continuing a thread outside the inventory (typically a
    // compressed predecessor) is a missing predecessor, never a fork (R1-M3).
    let continued = meta(
        OWNER,
        "2026-10-01T10:00:00Z",
        json!({"history_base": {"thread_id": UNKNOWN,
            "end_ordinal_exclusive": 3, "end_byte_offset": 500}}),
    );
    assert_eq!(
        plan(&[
            (continued, "a.jsonl".into()),
            (
                meta(OWNER, "2026-10-01T10:30:00Z", json!({})),
                "b.jsonl".into()
            )
        ]),
        Err(JoinRefusal::MissingPredecessor)
    );
}

#[test]
fn equal_before_tie_held() {
    let root = temp_root("tie");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &member(OWNER, "r-a", 100, 100),
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &member(OWNER, "r-bb", 100, 100),
    );
    assert_eq!(
        refused(replay_group(group_of(&root), None, &ScanIndex::default())),
        Some((JoinRefusal::EqualBeforeTie, 0))
    );
    let tokens = probe_before(&member(OWNER, "r", 100, 100)[1]);
    assert_eq!(
        order_by_probes(&[0, 1], &[tokens, tokens]),
        Err(JoinRefusal::EqualBeforeTie)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn origins_with_different_ownership_classification_held() {
    let origin = |created: &str, source: &str| {
        ordinals(vec![meta(OWNER, created, json!({"source": source}))], 0).remove(0)
    };
    assert_eq!(
        plan(&[
            (origin("2026-10-01T10:00:00Z", "cli"), "a.jsonl".into()),
            (origin("2026-10-01T10:30:00Z", "vscode"), "b.jsonl".into()),
        ]),
        Err(JoinRefusal::OrdinalRestart)
    );
    assert!(plan(&[
        (origin("2026-10-01T10:00:00Z", "cli"), "a.jsonl".into()),
        (origin("2026-10-01T10:30:00Z", "cli"), "b.jsonl".into()),
    ])
    .is_ok());
}

fn append_rows(path: &Path, rows: &[Value]) {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    for row in rows {
        file.write_all((serde_json::to_string(row).unwrap() + "\n").as_bytes())
            .unwrap();
    }
}

fn completions(cache: &SharedCache) -> u64 {
    let counters = counters(cache);
    counters.jobs_certified + counters.jobs_uncertified
}

fn fingerprints(scan: &SourceScanResult) -> BTreeSet<String> {
    scan.snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect()
}

fn input_totals(scan: &SourceScanResult) -> BTreeSet<u64> {
    scan.snapshots
        .iter()
        .map(|snapshot| snapshot.input_tokens)
        .collect()
}

/// Two members of `OWNER`, each larger than the scaled singleton budget
/// (`with_test_limits(2048, 1024, 64)`): a paged group job.
fn paged_corpus(tag: &str) -> PathBuf {
    let root = temp_root(tag);
    write_rows(
        &root.join("sessions/a.jsonl"),
        &chain_rows(OWNER, "a", "2026-10-01T10:00:00Z", 0, 30),
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 300, 30),
    );
    root
}

/// The next generation (`n` minutes later): a new walk and fence token.
fn next_generation(
    root: &Path,
    mut index: ScanIndex,
    cache: &Arc<SharedCache>,
    n: u32,
) -> (ScanIndex, SourceScanResult) {
    index.traversal = None;
    sampled_at(root, index, 10, cache, &format!("2026-10-06T23:{n:02}:00Z"))
}

/// Sampled pages until `done`; returns the last page and every page before.
fn pages(
    root: &Path,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    done: impl FnMut() -> bool,
) -> (ScanIndex, SourceScanResult, Vec<SourceScanResult>) {
    pages_at(root, index, cache, "2026-10-06T23:00:00Z", done)
}

fn pages_at(
    root: &Path,
    mut index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    mut done: impl FnMut() -> bool,
) -> (ScanIndex, SourceScanResult, Vec<SourceScanResult>) {
    let mut earlier = Vec::new();
    for _ in 0..256 {
        let (next, result) = sampled_at(root, index, 10, cache, collected_at);
        index = next;
        if done() {
            return (index, result, earlier);
        }
        earlier.push(result);
    }
    panic!("pages did not reach the condition: {:?}", counters(cache));
}

#[test]
fn line_loss_before_refusal_is_strict_and_not_memoized() {
    let root = temp_root("loss");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &chain_rows(OWNER, "a", "2026-10-01T10:00:00Z", 0, 2),
    );
    // b's second native is missing: the chain gaps at its third.
    let mut rows = chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 20, 3);
    rows.remove(3);
    rows.remove(3);
    write_rows(&root.join("sessions/b.jsonl"), &rows);
    assert_eq!(
        refused(replay_group(group_of(&root), None, &ScanIndex::default())),
        Some((JoinRefusal::Gap, 1)),
        "without loss the gap is terminal proof debt"
    );
    // The same gap after a skipped (malformed) line may be the loss's own
    // effect: strict, never settleable or memoized (R1-B1).
    let body = rows
        .iter()
        .enumerate()
        .map(|(at, row)| {
            let line = serde_json::to_string(row).unwrap() + "\n";
            if at == 3 {
                "{\"type\": \"token_usage_record\", \"payload\": \n".to_owned() + &line
            } else {
                line
            }
        })
        .collect::<String>();
    fs::write(root.join("sessions/b.jsonl"), body).unwrap();
    assert!(matches!(
        replay_group(group_of(&root), None, &ScanIndex::default()),
        Err(GroupEnd::Strict)
    ));
    let cache = Arc::new(SharedCache::default());
    let (index, result) = sampled(&root, ScanIndex::default(), 10, &cache);
    let after = counters(&cache);
    assert_eq!(after.memo_records, 0, "{after:?}");
    assert!(
        after.join_terminal_debt.iter().all(|count| *count == 0),
        "{after:?}"
    );
    assert!(result.unreadable_path_count > 0, "strict AliasParser debt");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn refused_group_memo_hit_on_live_growth_rereads_nothing() {
    let root = refused_fixture();
    let cache = Arc::new(SharedCache::default());
    let overlap = JoinRefusal::Overlap.slot();
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let first = counters(&cache);
    assert_eq!(first.join_terminal_debt[overlap], 1, "{first:?}");
    assert_eq!(first.memo_records, 1, "{first:?}");
    // The live member grows; an append cannot cure an overlap before it.
    append_rows(
        &root.join("sessions/b.jsonl"),
        &[turn("44444444-aaaa-4aaa-8aaa-444444444444")],
    );
    let (index, again) = next_generation(&root, index, &cache, 1);
    let after = counters(&cache);
    assert_eq!(after.group_memo_hits, 1, "{after:?}");
    assert_eq!(
        after.join_terminal_debt[overlap], 1,
        "a memo hit replays no byte: {after:?}"
    );
    assert!(again.snapshots.is_empty());
    assert!(again.census_complete, "re-disclosed as settleable residue");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn append_curable_live_refusal_memo_matches_only_the_exact_stamp() {
    let root = temp_root("curable");
    let first = "11111111-aaaa-4aaa-8aaa-111111111111";
    let second = "22222222-aaaa-4aaa-8aaa-222222222222";
    write_rows(
        &root.join("sessions/a.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
            turn(first),
            native(OWNER, "r-a", 100, 100),
            ui(100, 100, "2026-10-01T10:00:30Z"),
        ],
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:01:00Z", json!({})),
            turn(first),
            native(OWNER, "r-b", 200, 300),
            ui(200, 300, "2026-10-01T10:01:30Z"),
            turn(second),
            ui(50, 350, "2026-10-01T10:02:30Z"),
        ],
    );
    let unmatched = JoinRefusal::UiUnmatched.slot();
    let cache = Arc::new(SharedCache::default());
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let refused = counters(&cache);
    assert_eq!(refused.join_terminal_debt[unmatched], 1, "{refused:?}");
    assert_eq!(refused.memo_records, 1, "recorded with an exact stamp");
    // Unchanged: the next generation does not re-read the group (R2-M1).
    let (index, _) = next_generation(&root, index, &cache, 1);
    let unchanged = counters(&cache);
    assert_eq!(unchanged.group_memo_hits, 1, "{unchanged:?}");
    assert_eq!(unchanged.join_terminal_debt[unmatched], 1, "{unchanged:?}");
    // Any growth of the live member may cure it: one attempt.
    append_rows(
        &root.join("sessions/b.jsonl"),
        &[turn("55555555-aaaa-4aaa-8aaa-555555555555")],
    );
    let _ = next_generation(&root, index, &cache, 2);
    let grown = counters(&cache);
    assert_eq!(grown.group_memo_hits, 1, "{grown:?}");
    assert_eq!(grown.join_terminal_debt[unmatched], 2, "{grown:?}");
    fs::remove_dir_all(root).unwrap();
}

/// Round-3 R1-M1: a live-member `Gap` raised mid-stream stops the reader
/// before the file's end; bytes after it cannot cure it, so the exact-stamp
/// entry is recorded and an unchanged group is not re-read.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn mid_stream_live_gap_is_memoized_and_skipped_while_unchanged() {
    let root = temp_root("midgap");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
            native(OWNER, "r-a", 100, 100),
            ui(100, 100, "2026-10-01T10:00:30Z"),
        ],
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:01:00Z", json!({})),
            native(OWNER, "r-b", 200, 300),
            ui(200, 300, "2026-10-01T10:01:30Z"),
            // A counter reset inside the live member: `before` 350 != 300.
            native(OWNER, "r-reset", 50, 400),
            ui(50, 400, "2026-10-01T10:02:30Z"),
            native(OWNER, "r-tail", 10, 410),
            ui(10, 410, "2026-10-01T10:03:30Z"),
        ],
    );
    let gap = JoinRefusal::Gap.slot();
    let cache = Arc::new(SharedCache::default());
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let refused = counters(&cache);
    assert_eq!(refused.join_terminal_debt[gap], 1, "{refused:?}");
    assert_eq!(
        refused.memo_records, 1,
        "recorded although the reader stopped mid-stream: {refused:?}"
    );
    let _ = next_generation(&root, index, &cache, 1);
    let unchanged = counters(&cache);
    assert_eq!(unchanged.group_memo_hits, 1, "{unchanged:?}");
    // One replay only: the unpaged group's attempt count is its refusals.
    assert_eq!(
        unchanged.join_terminal_debt[gap], 1,
        "not re-read: {unchanged:?}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn state_bound_group_parks_on_live_stamp_until_a_real_change() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("parked");
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        // The first pause (inside sealed member a) cannot fit the scaled
        // state budget: strict `JoinStateBound`, parked.
        let (index, first) =
            with_test_state_budget(1, || sampled(&root, ScanIndex::default(), 10, &cache));
        let bound = counters(&cache);
        assert_eq!(bound.jobs_state_bound, 1, "{bound:?}");
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(bound.groups_started, 1, "{bound:?}");
        assert!(first.snapshots.is_empty());
        assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
        // A new generation without a capacity or input change: no attempt.
        let (index, _) = next_generation(&root, index, &cache, 1);
        let parked = counters(&cache);
        assert_eq!(parked.parked_hits, 1, "{parked:?}");
        assert_eq!(
            parked.groups_started, 1,
            "never retried per generation (R2-H1)"
        );
        // Growth of the live member keeps it parked.
        append_rows(
            &root.join("sessions/b.jsonl"),
            &chain_rows(OWNER, "b2", "2026-10-01T10:30:00Z", 600, 2)[1..],
        );
        let (index, _) = next_generation(&root, index, &cache, 2);
        let grown = counters(&cache);
        assert_eq!(grown.parked_hits, 2, "{grown:?}");
        assert_eq!(grown.groups_started, 1, "{grown:?}");
        // A sealed member's change wakes it: one new attempt.
        append_rows(
            &root.join("sessions/a.jsonl"),
            &[turn("66666666-aaaa-4aaa-8aaa-666666666666")],
        );
        let _ = next_generation(&root, index, &cache, 3);
        let woken = counters(&cache);
        assert_eq!(woken.parked_hits, 2, "{woken:?}");
        assert_eq!(woken.groups_started, 2, "{woken:?}");
    });
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn new_continuation_during_job_invalidates_and_never_emits_as_singleton() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("rotation");
    let cache = Arc::new(SharedCache::default());
    let done = with_test_limits(2048, 1024, 64, || {
        let (mut index, first, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).jobs_paused > 0
        });
        assert!(
            first.snapshots.is_empty(),
            "a paused group publishes nothing"
        );
        // A continuation appears while the job is paused; the next walk's
        // complete inventory sees it.
        write_rows(
            &root.join("sessions/c.jsonl"),
            &chain_rows(OWNER, "c", "2026-10-01T11:00:00Z", 600, 30),
        );
        index.traversal = None;
        let (_, done, earlier) = pages(&root, index, &cache, || completions(&cache) > 0);
        assert!(
            earlier.iter().all(|page| page.snapshots.is_empty()),
            "no member (the new one included) is emitted before the group"
        );
        done
    });
    let after = counters(&cache);
    assert!(
        after.jobs_invalidated >= 1,
        "invalidated at resume: {after:?}"
    );
    assert_eq!(
        after.groups_started, 2,
        "one restart with N+1 members: {after:?}"
    );
    let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
    assert_eq!(unpaged.snapshots.len(), 3, "one alias per member");
    assert_eq!(fingerprints(&done), fingerprints(&unpaged));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn live_member_growth_mid_job_publishes_frozen_prefix_then_replaces_it() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("growth");
    let (_, prefix) = scan(&root, ScanIndex::default(), 10);
    let cache = Arc::new(SharedCache::default());
    let (first, second) = with_test_limits(2048, 1024, 64, || {
        // Page until the paused job reads the live (last) member.
        let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            cache.paused_group_position() == Some(1)
        });
        append_rows(
            &root.join("sessions/b.jsonl"),
            &chain_rows(OWNER, "b2", "2026-10-01T10:30:00Z", 600, 5)[1..],
        );
        let (mut index, first, earlier) = pages(&root, index, &cache, || completions(&cache) > 0);
        assert!(earlier.iter().all(|page| page.snapshots.is_empty()));
        // The appended tail stays pending; the next generation replaces
        // the body.
        index.traversal = None;
        let (_, second, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            completions(&cache) > 1
        });
        (first, second)
    });
    assert!(!first.snapshots.is_empty());
    assert_eq!(
        input_totals(&first),
        input_totals(&prefix),
        "the first body covers exactly the frozen prefix"
    );
    let (_, full) = scan(&root, ScanIndex::default(), 10);
    assert_ne!(input_totals(&full), input_totals(&prefix));
    assert_eq!(
        input_totals(&second),
        input_totals(&full),
        "the replacing body counts the prefix once"
    );
    assert_eq!(counters(&cache).groups_started, 2);
    fs::remove_dir_all(root).unwrap();
}

/// E1 S3: a metadata-only change of a member already read, while the job
/// is paused in its live member, is not a member change: the job resumes
/// without invalidation or a second group start and counts the unpaged
/// body. A moved mtime at the same length still invalidates it.
#[test]
fn paused_group_resumes_across_a_sealed_member_metadata_only_change() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    for change in ["chmod", "mtime"] {
        let root = paged_corpus(&format!("s3-sealed-{change}"));
        let sealed = root.join("sessions/a.jsonl");
        let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
        let cache = Arc::new(SharedCache::default());
        let done = with_test_limits(2048, 1024, 64, || {
            let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
                cache.paused_group_position() == Some(1)
            });
            let before = fs::metadata(&sealed).unwrap();
            if change == "chmod" {
                let ctime = |m: &fs::Metadata| (m.ctime(), m.ctime_nsec());
                let mut tries = 0;
                loop {
                    let mode = fs::metadata(&sealed).unwrap().permissions().mode();
                    fs::set_permissions(&sealed, fs::Permissions::from_mode(mode ^ 0o004)).unwrap();
                    let after = fs::metadata(&sealed).unwrap();
                    assert_eq!(
                        (after.len(), after.modified().unwrap(), after.ino()),
                        (before.len(), before.modified().unwrap(), before.ino())
                    );
                    if ctime(&after) != ctime(&before) {
                        break;
                    }
                    tries += 1;
                    assert!(tries < 2000, "chmod never moved ctime");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            } else {
                File::options()
                    .write(true)
                    .open(&sealed)
                    .unwrap()
                    .set_modified(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000),
                    )
                    .unwrap();
                assert_eq!(fs::metadata(&sealed).unwrap().len(), before.len());
            }
            let (_, done, _) = pages(&root, index, &cache, || completions(&cache) > 0);
            done
        });
        let after = counters(&cache);
        if change == "chmod" {
            assert_eq!(after.jobs_invalidated, 0, "{change}: {after:?}");
            assert_eq!(after.groups_started, 1, "{change}: {after:?}");
            assert_eq!(input_totals(&done), input_totals(&unpaged), "{change}");
        } else {
            assert!(after.jobs_invalidated >= 1, "{change}: {after:?}");
            assert_eq!(after.groups_started, 2, "{change}: {after:?}");
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn restart_mid_job_reboots_group_and_keeps_owner_blocked() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("restart");
    let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
    with_test_limits(2048, 1024, 64, || {
        let before = Arc::new(SharedCache::default());
        let (mut index, first, _) = pages(&root, ScanIndex::default(), &before, || {
            counters(&before).jobs_paused > 0
        });
        assert!(first.snapshots.is_empty());
        assert!(
            index.codex_state_only_blocked_session_ids.contains(OWNER),
            "F8: no state-only body for the owner of a paused group"
        );
        // Restart: the RAM cache and its paused job are gone; the index is
        // saved and loaded.
        drop(before);
        let path = root.join("index.json");
        index.save(&path).unwrap();
        let index = ScanIndex::load(&path).unwrap();
        assert!(
            index.codex_state_only_blocked_session_ids.contains(OWNER),
            "F8 across a restart"
        );
        let after = Arc::new(SharedCache::default());
        let (_, done, earlier) = pages(&root, index, &after, || completions(&after) > 0);
        assert!(
            earlier.iter().all(|page| page
                .snapshots
                .iter()
                .all(|snapshot| snapshot.source_session_id != OWNER)),
            "no body for the in-progress owner before its group completes"
        );
        let counted = counters(&after);
        assert_eq!(
            counted.groups_started, 1,
            "the group re-boots once: {counted:?}"
        );
        assert_eq!(completions(&after), 1);
        assert_eq!(
            fingerprints(&done),
            fingerprints(&unpaged),
            "exactly one body"
        );
    });
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn refused_group_debt_and_blocked_owner_survive_save_and_restart() {
    let root = refused_fixture();
    let overlap = JoinRefusal::Overlap.slot();
    let cache = Arc::new(SharedCache::default());
    let (mut index, first) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(first.census_complete, "{first:?}");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    let path = root.join("index.json");
    index.save(&path).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.codex_state_only_blocked_session_ids.contains(OWNER));
    assert_eq!(
        loaded
            .traversal
            .as_ref()
            .map(|traversal| &traversal.residue),
        index.traversal.as_ref().map(|traversal| &traversal.residue),
        "residue survives save and load"
    );
    // A new process: no memo, one bounded re-attempt, the same settleable
    // debt and the same blocked owner.
    loaded.traversal = None;
    let restarted = Arc::new(SharedCache::default());
    let (index, again) = sampled(&root, loaded, 10, &restarted);
    assert!(again.snapshots.is_empty());
    assert!(again.census_complete, "{again:?}");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    assert_eq!(counters(&restarted).join_terminal_debt[overlap], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn upload_context_change_invalidates_paused_group() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("scope");
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (mut index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).jobs_paused > 0
        });
        // §p (R1-M1): receipts must not mix upload scopes.
        index.active_upload_context_fingerprint = Some("other-upload-context".into());
        let (_, done, _) = pages(&root, index, &cache, || completions(&cache) > 0);
        assert!(!done.snapshots.is_empty());
    });
    let after = counters(&cache);
    assert!(after.jobs_invalidated >= 1, "{after:?}");
    assert_eq!(after.groups_started, 2, "{after:?}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unchanged_group_releases_persisted_blocked_owner() {
    let (root, _) = fixture();
    let previous = ScanIndex::default();
    let (mut index, mut result) = scan(&root, previous.clone(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    let mut settled = index.committable_subset(&previous, &accepted, &BTreeMap::new());
    let path = root.join("index.json");
    settled.save(&path).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    // A block a previous process persisted (F8) without its RAM provenance.
    loaded
        .codex_state_only_blocked_session_ids
        .insert(OWNER.to_owned());
    let (index, restarted) = scan(&root, loaded, 2);
    assert_eq!(
        restarted.semantic_noop_count, 2,
        "the group boots unchanged"
    );
    assert!(
        !index.codex_state_only_blocked_session_ids.contains(OWNER),
        "R1-L3: no job or debt holds the owner"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn group_with_legacy_tee_is_byte_charged() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (root, inventory) = fixture();
    let previous = legacy_index(&inventory, None);
    let mut boot = GroupBoot::new(inventory.groups().into_values().next().unwrap(), &previous);
    loop {
        match boot.step(None, &previous) {
            Boot::Pending => {}
            Boot::Ready => break,
            _ => panic!("the legacy group boots"),
        }
    }
    let metadata = CodexTitleMetadata::default();
    let mut job = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            ledgers: None,
            artifacts: false,
            context_curve: false,
            index: &previous,
        })
        .unwrap();
    assert!(job.group.as_ref().unwrap().tee.is_some());
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        artifacts: false,
        context_curve: false,
        live_scope: &no_scope,
    };
    assert!(matches!(
        step_group(&mut job, &inputs),
        GroupStep::Read(Ok(false))
    ));
    let cache = Arc::new(SharedCache::default());
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        previous,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_sampled_acquisition(Arc::clone(&cache), Scope("group-fixture".into()));
    *owned.active_file = Some(job);
    // R2-M2: the group read without the cursor is charged by bytes
    // (`completed_bound`, tee inputs taken out), never refused by the
    // per-line visit walk, so retained singleton copies survive.
    assert!(owned.sampled_copy_budget() > 0);
    let walked = owned
        .active_file
        .as_ref()
        .and_then(|active| active.group.as_ref())
        .and_then(|group| group.walked);
    assert!(
        walked.is_some_and(|(charge, _, _)| charge != usize::MAX),
        "{walked:?}"
    );
    assert!(owned.sampled_copy_budget() > 0, "the E3 estimate");
    // L-A1: a group active owns a proof and tee, so even a measured copy
    // refusal keeps the conservative release.
    let (_, measured) = owned.sampled_copy_parts();
    assert!(measured.is_some(), "precondition: residents measured");
    let (_, lifecycle) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        sampled_scan::release_cache_for_copy_refusal(
            owned.sampling.as_ref(),
            owned.active_file.as_deref(),
            measured,
        )
    });
    assert_eq!(lifecycle.clear_other_active, 1);
    assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
    // P1-RETAIN R0 (T-R0d): given a Tail acquisition and with every other
    // borrowed-state conjunct cleared, the group conjunct alone keeps the job
    // off shape F, so its refusal keeps ClearOtherActive and its completion
    // never reaches R0's release.
    let active = owned.active_file.as_deref_mut().unwrap();
    let mut file = fs::File::open(&active.candidate.path).unwrap();
    let plan = crate::transcript_acquisition::ReadPlan::prepare(
        &mut file,
        None,
        &Scope("group-fixture".into()),
        None,
        100,
    )
    .unwrap();
    let sampling = active.sampling.replace(sampled_scan::Active {
        no_record: false,
        key: String::new(),
        scope: Scope("group-fixture".into()),
        mode: crate::transcript_acquisition::ReadMode::Tail,
        audit_due: None,
        retained_hint: Some((0, 0)),
        retained_finalization_charge: 0,
        retained_usage: None,
        pi_restored_behind_accepted: false,
        reinsertion: Default::default(),
    });
    let acquisition = active.parser.reader.acquisition.replace(plan);
    let replay = active.parser.accumulator.codex_tier_replay.take();
    let aliases = std::mem::take(&mut active.aliases);
    let receipts = std::mem::take(&mut active.applied_receipts);
    let comparison_target = std::mem::replace(&mut active.comparison_target, false);
    let cursor = active.cursor.take();
    assert!(active.group.is_some());
    assert!(!sampled_scan::borrows_only_retained_reduction(active));
    let group = active.group.take();
    assert!(
        sampled_scan::borrows_only_retained_reduction(active),
        "precondition: only the group conjunct differs from shape F"
    );
    active.group = group;
    let (_, lifecycle) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        sampled_scan::release_cache_for_copy_refusal(
            owned.sampling.as_ref(),
            owned.active_file.as_deref(),
            measured,
        )
    });
    assert_eq!(lifecycle.clear_other_active, 1, "a Tail group job");
    assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
    let active = owned.active_file.as_deref_mut().unwrap();
    active.sampling = sampling;
    active.parser.reader.acquisition = acquisition;
    active.parser.accumulator.codex_tier_replay = replay;
    active.aliases = aliases;
    active.applied_receipts = receipts;
    active.comparison_target = comparison_target;
    active.cursor = cursor;
    fs::remove_dir_all(root).unwrap();
}

/// M1 review F2: a byte-charged group job whose real charge overflows the
/// state budget beside full residents is walked to the whole state budget,
/// so its refusal evicts to fit on that charge: one entry for an overflow
/// below one entry's charge, never a wipe-all clear. Its E3 record is that
/// walk, not `usize::MAX`, so the next step's estimate opens the budget and
/// nothing is released again.
///
/// Red at round 1 (66e5315c): the walk stopped at the remaining room,
/// recorded `usize::MAX` and cleared every filler (`ClearOtherActive`).
#[test]
fn group_overflow_evicts_at_most_overflow_plus_one_entry() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::cache_policy_tests as policy;
    let (root, inventory) = fixture();
    let previous = legacy_index(&inventory, None);
    let mut boot = GroupBoot::new(inventory.groups().into_values().next().unwrap(), &previous);
    loop {
        match boot.step(None, &previous) {
            Boot::Pending => {}
            Boot::Ready => break,
            _ => panic!("the legacy group boots"),
        }
    }
    let metadata = CodexTitleMetadata::default();
    let mut job = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            ledgers: None,
            artifacts: false,
            context_curve: false,
            index: &previous,
        })
        .unwrap();
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        artifacts: false,
        context_curve: false,
        live_scope: &no_scope,
    };
    assert!(matches!(
        step_group(&mut job, &inputs),
        GroupStep::Read(Ok(false))
    ));
    // The job's own state grows by bytes past the room the fillers leave.
    job.parser
        .accumulator
        .provider_skills
        .extend((0..4800).map(|n| format!("group-{n:05}-{}", "x".repeat(1000))));
    let (cache, filler_charge) = policy::filled_cache();
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        previous,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_sampled_acquisition(Arc::clone(&cache), Scope("group-fixture".into()));
    *owned.active_file = Some(job);
    let (budget, step) = owned.sampled_copy_step();
    let walked = owned
        .active_file
        .as_ref()
        .and_then(|active| active.group.as_ref())
        .and_then(|group| group.walked);
    let receipt =
        format!("budget={budget} step={step:?} walked={walked:?} filler_charge={filler_charge}");
    eprintln!("CACHE_POLICY test=M1_group_overflow {receipt}");
    assert_eq!(
        budget, 0,
        "precondition: the group overflows the room; {receipt}"
    );
    assert!(
        step.active.is_some() && walked.map(|(charge, _, _)| charge) == step.active,
        "F2: the real walk is the refusal's charge and the E3 record; {receipt}"
    );
    let overflow = step
        .resident
        .zip(step.active)
        .map(|(resident, active)| (resident + active).saturating_sub(policy::POLICY_STATE_BYTES));
    assert!(
        overflow.is_some_and(|overflow| overflow > 0 && overflow < filler_charge),
        "precondition: an overflow below one entry; {receipt}"
    );
    let (_, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        sampled_scan::release_cache_to_fit(
            owned.sampling.as_ref(),
            owned.active_file.as_deref(),
            step,
        )
    });
    assert_eq!(
        policy::wipe_clears(&counts),
        0,
        "F2: a wipe-all clear; {counts:?}"
    );
    assert_eq!(counts.copy_refusal_entries_evicted, 1, "{counts:?}");
    assert_eq!(policy::fillers_resident(&cache), policy::FILLERS - 1);
    assert!(
        owned.sampled_copy_budget() > 0,
        "F2: the next step's E3 estimate keeps the budget shut"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn proof_charge_uses_proven_btree_fill() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut proof = StreamProof::new(OWNER.into(), false, vec![MemberPlan::default()]);
    proof.responses.extend(0..100_000u64);
    proof.ui.extend(0..100_000u64);
    let charged = crate::heap_layout_bound::completed_bound(&proof, usize::MAX).unwrap();
    // R2-M4: every non-root std B-tree node holds at least 5 entries.
    let node = 256 + 12 * size_of::<usize>() + 11 * size_of::<u64>();
    let ceiling = 2 * (100_000 / 5 + 1) * node + 64 * 1024;
    assert!(charged <= ceiling, "{charged} > {ceiling}");
    assert!(charged >= 2 * 100_000 * size_of::<u64>(), "{charged}");
}

/// R1-H1 (round 2): an append-curable refusal at a paged group's frozen cut
/// is not memoized while the live member already holds bytes past the cut:
/// they may cure it, so the next generation reads them and accepts.
#[test]
fn curable_refusal_at_frozen_cut_with_unread_growth_is_not_memoized() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("frozen-cut");
    write_rows(
        &root.join("sessions/a.jsonl"),
        &chain_rows(OWNER, "a", "2026-10-01T10:00:00Z", 0, 30),
    );
    // The final turn's UI record is written before its native.
    let mut live = chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 300, 30);
    live.push(ui(20, 620, "2026-10-01T10:10:20Z"));
    write_rows(&root.join("sessions/b.jsonl"), &live);
    let unmatched = JoinRefusal::UiUnmatched.slot();
    let cache = Arc::new(SharedCache::default());
    let done = with_test_limits(2048, 1024, 64, || {
        let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            cache.paused_group_position() == Some(1)
        });
        // The native lands past the live member's frozen extent.
        append_rows(
            &root.join("sessions/b.jsonl"),
            &[native(OWNER, "b-30", 20, 620)],
        );
        let (mut index, _, _) = pages(&root, index, &cache, || {
            counters(&cache).join_terminal_debt[unmatched] > 0
        });
        let refused = counters(&cache);
        assert_eq!(refused.memo_records, 0, "{refused:?}");
        index.traversal = None;
        let (_, done, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            completions(&cache) > 0
        });
        done
    });
    let after = counters(&cache);
    assert_eq!(after.group_memo_hits, 0, "{after:?}");
    assert_eq!(after.groups_started, 2, "one new attempt: {after:?}");
    assert_eq!(after.join_terminal_debt[unmatched], 1, "{after:?}");
    let (_, full) = scan(&root, ScanIndex::default(), 10);
    assert_eq!(fingerprints(&done), fingerprints(&full), "a body accepted");
    fs::remove_dir_all(root).unwrap();
}

/// R2-N1: E1 for a paged group's live member. A quiescent live member
/// ending in a valid unterminated record has it applied at its genuine
/// unchanged EOF, like a singleton: counted once, verified, and the next
/// generation reads nothing (no hourly audit debt).
#[test]
fn quiescent_live_member_unterminated_record_applied_at_genuine_eof() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("eof");
    let live = root.join("sessions/b.jsonl");
    let mut body = fs::read(&live).unwrap();
    assert_eq!(body.pop(), Some(b'\n'));
    fs::write(&live, body).unwrap();
    let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
    let cache = Arc::new(SharedCache::default());
    let (index, done) = with_test_limits(2048, 1024, 64, || {
        let (index, done, _) = pages(&root, ScanIndex::default(), &cache, || {
            completions(&cache) > 0
        });
        (index, done)
    });
    let applied = counters(&cache);
    assert_eq!(applied.eof_record_applied, 1, "{applied:?}");
    assert_eq!(applied.sealed_fragment_withheld, 0, "{applied:?}");
    assert_eq!(
        fingerprints(&done),
        fingerprints(&unpaged),
        "counted once, like main's read"
    );
    assert!(!index
        .files
        .get(&local_index_key(&live))
        .is_some_and(|entry| entry.has_unverified_source()));
    with_test_limits(2048, 1024, 64, || {
        let (_, again) = next_generation(&root, index, &cache, 1);
        assert!(again.snapshots.is_empty());
    });
    assert_eq!(counters(&cache).groups_started, 1, "no re-read");
    fs::remove_dir_all(root).unwrap();
}

/// R1-M1 / R2-N2: probes are capped by the page's remaining singleton
/// budget. Past it the group keeps chronological order; a refusal in that
/// order is our own artifact: strict `ProbeBudgetOrder`, never settleable
/// or memoized. With the budget, the probes order the same group and it is
/// accepted.
#[test]
fn probe_budget_fallback_refusal_is_strict_and_not_memoized() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("probe-budget");
    // Legacy (non-ordinal) members whose header times disagree with their
    // counter order: only the probes order them.
    write_rows(
        &root.join("sessions/a.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:00:00Z", json!({})),
            native(OWNER, "r-a", 200, 300),
            ui(200, 300, "2026-10-01T10:05:01Z"),
        ],
    );
    write_rows(
        &root.join("sessions/b.jsonl"),
        &[
            meta(OWNER, "2026-10-01T10:05:00Z", json!({})),
            native(OWNER, "r-b", 100, 100),
            ui(100, 100, "2026-10-01T10:00:01Z"),
        ],
    );
    let (_, ordered) = scan(&root, ScanIndex::default(), 10);
    assert!(!ordered.snapshots.is_empty(), "probes order the group");
    let cache = Arc::new(SharedCache::default());
    let (index, result) = with_test_limits(2048, 1, 64, || {
        sampled(&root, ScanIndex::default(), 10, &cache)
    });
    let after = counters(&cache);
    assert!(after.probe_bound >= 1, "{after:?}");
    assert_eq!(
        after.join_terminal_debt[JoinRefusal::ProbeBudgetOrder.slot()],
        1,
        "{after:?}"
    );
    assert_eq!(after.memo_records, 0, "{after:?}");
    assert!(result.snapshots.is_empty());
    assert!(result.unreadable_path_count > 0, "strict AliasParser debt");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_dir_all(root).unwrap();
}

/// The `probe_budget_fallback…` fixture: legacy members whose header times
/// disagree with their counter order, so only the probes order them; the
/// chronological fallback order breaks the chain (a `Gap` at sealed `a`).
fn probe_order_corpus(tag: &str, padding: usize) -> PathBuf {
    let root = temp_root(tag);
    write_probe_order(&root, OWNER, ["a", "b"], padding, 0);
    root
}

/// The probe-order fixture of `owner` in `<first>.jsonl` and
/// `<second>.jsonl`: `first` is created first but continues `second`'s
/// counter. `extra` native/UI pairs after `first`'s make the group large.
fn write_probe_order(root: &Path, owner: &str, names: [&str; 2], padding: usize, extra: u64) {
    let [first, second] = names;
    let mut rows = vec![meta(owner, "2026-10-01T10:00:00Z", json!({}))];
    // Padding before the first native: past `PROBE_BYTES` when large.
    rows.extend((0..padding).map(|i| {
        json!({"type": "event_msg", "timestamp": "2026-10-01T10:00:01Z", "payload": {
            "type": "agent_message", "message": format!("{i}:{}", "p".repeat(4096))}})
    }));
    rows.push(native(owner, &format!("r-{first}"), 200, 300));
    rows.push(ui(200, 300, "2026-10-01T10:05:01Z"));
    for i in 0..extra {
        let after = 300 + 10 * (i + 1);
        rows.push(native(owner, &format!("r-{first}-{i}"), 10, after));
        rows.push(ui(
            10,
            after,
            &format!("2026-10-01T10:{:02}:{:02}Z", 6 + i / 60, i % 60),
        ));
    }
    write_rows(&root.join(format!("sessions/{first}.jsonl")), &rows);
    write_rows(
        &root.join(format!("sessions/{second}.jsonl")),
        &[
            meta(owner, "2026-10-01T10:05:00Z", json!({})),
            native(owner, &format!("r-{second}"), 100, 100),
            ui(100, 100, "2026-10-01T10:00:01Z"),
        ],
    );
}

/// Bytes of the first `lines` lines of `path`.
fn head_bytes(path: &Path, lines: usize) -> u64 {
    fs::read(path)
        .unwrap()
        .split_inclusive(|byte| *byte == b'\n')
        .take(lines)
        .map(|line| line.len() as u64)
        .sum()
}

/// The inventory's groups in page selection order.
fn inventory_groups(root: &Path) -> Vec<Group> {
    let sessions = root.join("sessions");
    let paths = fs::read_dir(&sessions)
        .unwrap()
        .map(|entry| local_index_key(&entry.unwrap().path()))
        .collect::<BTreeSet<_>>();
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    inventory.groups().into_values().collect()
}

/// The owner of the first group in inventory (page selection) order.
fn first_group_owner(root: &Path) -> String {
    inventory_groups(root)
        .into_iter()
        .next()
        .expect("a group")
        .owner
}

/// The job key of `owner`'s group (its rotation and fence key).
fn group_job_key(root: &Path, owner: &str) -> String {
    job_key(
        &inventory_groups(root)
            .into_iter()
            .find(|group| group.owner == owner)
            .expect("the owner's group"),
    )
}

/// Round 3 (R1-L1, R2-L2 (a)): a `ProbeBudgetOrder` the page's remaining
/// singleton budget forced takes a page of its own next; forced again there,
/// it is parked like `JoinStateBound`: strict debt disclosed each generation
/// with no attempt, until a member changes (growth of the live member does
/// not cure a sealed member's `Gap`).
#[test]
fn allowance_bound_probe_order_takes_an_own_page_then_parks() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = probe_order_corpus("probe-own-page", 0);
    let order = JoinRefusal::ProbeBudgetOrder.slot();
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1, 64, || {
        let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
        assert_eq!(counters(&cache).join_terminal_debt[order], 1);
        assert_eq!(counters(&cache).parked_hits, 0);
        // On its own page the allowance is still short: parked.
        let (index, _) = next_generation(&root, index, &cache, 1);
        assert_eq!(counters(&cache).join_terminal_debt[order], 2);
        let (index, parked) = next_generation(&root, index, &cache, 2);
        let after = counters(&cache);
        assert_eq!(
            after.join_terminal_debt[order], 2,
            "not replayed: {after:?}"
        );
        assert_eq!(after.parked_hits, 1, "{after:?}");
        assert_eq!(after.memo_records, 0, "{after:?}");
        assert!(parked.snapshots.is_empty());
        assert!(parked.unreadable_path_count > 0, "disclosed as strict debt");
        assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
        // Growth of the live member cannot cure the sealed member's `Gap`.
        append_rows(
            &root.join("sessions/b.jsonl"),
            &[ui(1, 101, "2026-10-01T10:06:00Z")],
        );
        let (index, _) = next_generation(&root, index, &cache, 3);
        let grown = counters(&cache);
        assert_eq!(grown.parked_hits, 2, "{grown:?}");
        assert_eq!(grown.join_terminal_debt[order], 2, "{grown:?}");
        // A sealed member's change wakes it: one more attempt.
        append_rows(
            &root.join("sessions/a.jsonl"),
            &[turn("66666666-aaaa-4aaa-8aaa-666666666666")],
        );
        let _ = next_generation(&root, index, &cache, 4);
        assert_eq!(counters(&cache).join_terminal_debt[order], 3);
    });
    fs::remove_dir_all(root).unwrap();
}

/// Round 3 (R1-L1, R2-L2 (b)): a probe cut by `PROBE_BYTES` itself gives
/// the same fallback order every generation: parked at once, not replayed.
#[test]
fn probe_limit_bound_order_parks_until_a_member_changes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = probe_order_corpus("probe-limit", PROBE_BYTES / 4096 + 16);
    let order = JoinRefusal::ProbeBudgetOrder.slot();
    let cache = Arc::new(SharedCache::default());
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let first = counters(&cache);
    assert!(first.probe_bound >= 1, "{first:?}");
    assert_eq!(first.join_terminal_debt[order], 1, "{first:?}");
    let (index, parked) = next_generation(&root, index, &cache, 1);
    let after = counters(&cache);
    assert_eq!(
        after.join_terminal_debt[order], 1,
        "not replayed: {after:?}"
    );
    assert_eq!(after.parked_hits, 1, "{after:?}");
    assert!(parked.snapshots.is_empty());
    assert!(parked.unreadable_path_count > 0, "disclosed as strict debt");
    assert!(index.codex_state_only_blocked_session_ids.contains(OWNER));
    fs::remove_dir_all(root).unwrap();
}

/// Round 4 (L4): the own-page cure. A group read first leaves the shared
/// page's singleton remainder short of this paged group's probes
/// (`ProbeBudgetOrder`); on its own page the remainder covers them, the
/// probes order it and the join is accepted once, equal to the unpaged scan.
#[test]
fn allowance_bound_probe_order_joins_on_its_own_page() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("probe-cure");
    write_probe_order(&root, OTHER, ["c", "d"], 0, 40);
    // Each header read takes at most one 1 KiB buffer; probes read line 0
    // and the first native.
    let probes = head_bytes(&root.join("sessions/c.jsonl"), 2)
        + head_bytes(&root.join("sessions/d.jsonl"), 2);
    let singleton = 2 * 1024 + probes + 1024;
    // A two-member group that sorts first and charges its headers and
    // probes to the shared page before `c`/`d` boot. Groups are read in key
    // order and a key hashes the home path, which differs every run, so the
    // owner is chosen by key: a fixed few candidates can all sort after.
    let home = inventory_groups(&root)
        .into_iter()
        .find(|group| group.owner == OTHER)
        .expect("the paged group")
        .home;
    let other_key = super::super::group_key(&home, OTHER);
    let filler = (0..u64::from(u32::MAX))
        .map(|i| format!("aaaaaaaa-bbbb-4ccc-8ddd-{i:012x}"))
        .find(|owner| super::super::group_key(&home, owner) < other_key)
        .expect("an owner whose group sorts first");
    write_rows(
        &root.join("sessions/f1.jsonl"),
        &member(&filler, "f-1", 100, 100),
    );
    write_rows(
        &root.join("sessions/f2.jsonl"),
        &member(&filler, "f-2", 200, 300),
    );
    assert_eq!(
        first_group_owner(&root),
        filler,
        "a filler group that sorts first"
    );
    // The group's physical aliases share one body fingerprint.
    let other = |scan: &SourceScanResult| {
        let snapshots = scan
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.source_session_id == OTHER)
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect::<Vec<_>>();
        (
            snapshots.len(),
            snapshots.into_iter().collect::<BTreeSet<_>>(),
        )
    };
    let (_, unpaged) = scan(&root, ScanIndex::default(), 10);
    let expected = other(&unpaged);
    assert_eq!(expected.0, 2, "one alias per member");
    let order = JoinRefusal::ProbeBudgetOrder.slot();
    let cache = Arc::new(SharedCache::default());
    with_test_limits(8192, singleton, 64, || {
        let (mut index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
        let shared = counters(&cache);
        assert_eq!(shared.join_terminal_debt[order], 1, "{shared:?}");
        index.traversal = None;
        let (_, joined, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            completions(&cache) == 1
        });
        let after = counters(&cache);
        assert_eq!(
            after.join_terminal_debt[order], 1,
            "no second refusal: {after:?}"
        );
        assert_eq!(after.parked_hits, 0, "{after:?}");
        assert_eq!(after.jobs_certified, 1, "{after:?}");
        assert_eq!(other(&joined), expected, "counted once, as unpaged");
    });
    fs::remove_dir_all(root).unwrap();
}

/// Round 4 (L1): a paged group that waited behind a P1 singleton and then
/// ends as `ProbeBudgetOrder` completes its rotation: it is fenced for the
/// generation (#630 delta L-a), no waiter remains and a later P1 singleton
/// takes the slot without a rotation deferral.
#[test]
fn probe_order_end_leaves_no_waiter_ahead_of_p1_singletons() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("probe-waiter");
    write_rows(
        &root.join("sessions/s.jsonl"),
        &chain_rows(OTHER, "s", "2026-10-01T11:00:00Z", 0, 30),
    );
    let order = JoinRefusal::ProbeBudgetOrder.slot();
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1, 64, || {
        // `s` takes the slot and pauses in it.
        let (mut index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).jobs_paused > 0
        });
        write_probe_order(&root, OWNER, ["a", "b"], 0, 0);
        index.traversal = None;
        let (index, _, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            counters(&cache).join_terminal_debt[order] == 1
        });
        let ended = counters(&cache);
        assert!(
            ended.deferred >= 1,
            "the group waited behind `s`: {ended:?}"
        );
        assert_eq!(completions(&cache), 1, "`s` completed first: {ended:?}");
        assert_eq!(cache.rotation_waiters_for_test(), 0, "{ended:?}");
        // The end completed the group's rotation: fenced for the generation
        // (a `release()` end leaves it unfenced).
        let fence = cursor::census_token(&index);
        assert!(fence.is_some(), "the generation continues");
        assert!(
            cache.group_fenced(
                &Scope("group-fixture".into()),
                &group_job_key(&root, OWNER),
                fence.as_deref(),
            ),
            "{ended:?}"
        );
        // A later large P1 singleton is not deferred behind the group.
        write_rows(
            &root.join("sessions/u.jsonl"),
            &chain_rows(UNKNOWN, "u", "2026-10-01T12:00:00Z", 0, 30),
        );
        let _ = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            completions(&cache) == 2
        });
        let after = counters(&cache);
        assert_eq!(
            after.deferred_rotation, ended.deferred_rotation,
            "{after:?}"
        );
        assert_eq!(after.join_terminal_debt[order], 1, "fenced: {after:?}");
        assert_eq!(cache.rotation_waiters_for_test(), 0, "{after:?}");
    });
    fs::remove_dir_all(root).unwrap();
}

/// Round 4 (L3): `MEMBER_SWAP_CHARGE` covers the fixed records a member swap
/// adds: the applied receipt's B-tree slot share (a non-root node holds at
/// least 5 of its 11 entries) and the baseline and `MemberSeen` Vec slots
/// (at most twice the element under doubling). The first swap also covers
/// the one-time first allocations: the root node and the Vec minimum
/// capacity of 4 (two elements past the doubling share).
#[test]
fn member_swap_charge_covers_the_fixed_per_member_records() {
    let entry = size_of::<String>() + size_of::<AppliedTierReceipt>();
    let node = 11 * entry + 12 * size_of::<usize>() + 2 * size_of::<usize>();
    let fixed = node / 5 + 2 * size_of::<LegacyBaseline>() + 2 * size_of::<MemberSeen>();
    assert!(cursor::MEMBER_SWAP_CHARGE as usize >= fixed, "{fixed}");
    let first = fixed + node + 2 * (size_of::<LegacyBaseline>() + size_of::<MemberSeen>());
    assert!(cursor::MEMBER_SWAP_CHARGE as usize >= first, "{first}");
    // An unbounded record walks at the next step.
    assert_eq!(
        cursor::swap_charge(&[Some(10), None]),
        cursor::swap_charge(&[Some(usize::MAX)])
    );
    assert_eq!(
        cursor::swap_charge(&[Some(10), Some(0), Some(0)]),
        cursor::MEMBER_SWAP_CHARGE + 10
    );
}

/// Round 3 (R2-M1): a memoized group larger than the singleton budget
/// reaches its memo hit without the cursor slot while a P1 singleton's job
/// holds it: no deferral, no rotation waiter, no group job; the singleton
/// completes.
#[test]
fn memoized_large_group_takes_no_slot_and_leaves_no_waiter() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("memo-slot");
    // An empty response id mid-way through live `b`: terminal `Corrupt`, a
    // per-member reason (the scaled singleton budget leaves the probes in
    // chronological order, under which a chain reason is `ProbeBudgetOrder`).
    let mut b = chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 300, 30);
    b[5]["payload"]["response_id"] = json!("");
    write_rows(&root.join("sessions/b.jsonl"), &b);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).memo_records == 1
        });
        let recorded = counters(&cache);
        assert_eq!(
            recorded.join_terminal_debt[JoinRefusal::Corrupt.slot()],
            1,
            "{recorded:?}"
        );
        assert_eq!(recorded.groups_started, 1, "{recorded:?}");
        // A large P1 singleton takes the slot and pauses in it.
        write_rows(
            &root.join("sessions/s.jsonl"),
            &chain_rows(OTHER, "s", "2026-10-01T11:00:00Z", 0, 30),
        );
        let (mut index, _, _) = pages(&root, index, &cache, || {
            counters(&cache).jobs_paused > recorded.jobs_paused
        });
        let paused = counters(&cache);
        assert_eq!(completions(&cache), 0, "{paused:?}");
        // The next generation: the group's lookup runs while `s` holds it.
        index.traversal = None;
        let _ = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            counters(&cache).group_memo_hits == 1 && completions(&cache) == 1
        });
        let after = counters(&cache);
        assert_eq!(after.deferred, paused.deferred, "{after:?}");
        assert_eq!(
            after.deferred_rotation, paused.deferred_rotation,
            "{after:?}"
        );
        assert_eq!(after.groups_started, 1, "no group job: {after:?}");
        assert_eq!(cache.rotation_waiters_for_test(), 0, "{after:?}");
    });
    fs::remove_dir_all(root).unwrap();
}

/// #603 integration: the group parser is configured once from every member's
/// evidence and the proof follows the accumulator's own V2 decision (made on
/// the first owned record, after the proof was built). The #603 fixture's UI
/// is unbound-span, which §k.3 rule 5 holds under V2; inactive, it replays.
#[test]
fn counting_v2_decision_reaches_the_group_proof() {
    let (root, _) = counting_v2_unbound_fixture();
    assert!(replay_group(group_of(&root), None, &ScanIndex::default()).is_ok());
    let _cutover = codex_counting_version::TestCutover::set(0);
    assert_eq!(
        refused(replay_group(group_of(&root), None, &ScanIndex::default())),
        Some((JoinRefusal::V2UnboundUi, 1))
    );
    fs::remove_dir_all(root).unwrap();
}

/// #603 integration (K8 for groups): with the cutover active, a paused V2
/// group resumes only while `configure_group_once` would still pick its
/// rule from every member's current entry. A Legacy ACK on any member, here
/// the sealed first one, takes precedence and invalidates the job; a V2 mark
/// there keeps it resuming.
#[test]
fn active_cutover_resume_follows_every_member_ack() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for legacy_ack in [false, true] {
        let root = paged_corpus(if legacy_ack { "ack-legacy" } else { "ack-v2" });
        let cache = Arc::new(SharedCache::default());
        let _cutover = codex_counting_version::TestCutover::set(0);
        let invalidated = with_test_limits(2048, 1024, 64, || {
            let (mut index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
                counters(&cache).jobs_paused > 0
            });
            let key = local_index_key(&root.join("sessions/a.jsonl"));
            let entry = index.files.entry(key).or_insert_with(|| {
                serde_json::from_value(json!({
                    "size_bytes": 1, "modified_unix_seconds": 1, "modified_unix_nanos": 1,
                    "source_file_fingerprint": "source",
                    "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
                }))
                .unwrap()
            });
            entry
                .last_snapshot_fingerprint
                .get_or_insert_with(|| "acknowledged".into());
            entry.codex_counting_v2 = !legacy_ack;
            let before = counters(&cache);
            pages(&root, index, &cache, || {
                counters(&cache).jobs_resumed > before.jobs_resumed
            });
            counters(&cache).jobs_invalidated - before.jobs_invalidated
        });
        assert_eq!(
            invalidated,
            u64::from(legacy_ack),
            "legacy_ack: {legacy_ack}"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

// #641 L-1 join release (H1-H9): J-T2..J-T6 and J-T12 beside J-T1 above.

/// `owner` is blocked: no state-only body publishes for it.
fn held_owner(index: &ScanIndex, owner: &str) -> bool {
    index.codex_state_only_blocked_session_ids.contains(owner)
}

fn session_key(root: &Path, name: &str) -> String {
    local_index_key(&root.join("sessions").join(name))
}

/// The owners whose block `key`'s latest disclosure holds.
fn claims(index: &ScanIndex, key: &str) -> Option<BTreeSet<String>> {
    index.codex_state_only_blocked_by_file.get(key).cloned()
}

/// J-T1's steps after its first page: members `a` and `b` leave, then later
/// generations walk the corpus until `done` (at most 8 pages).
fn walk_without_members(
    root: &Path,
    mut index: ScanIndex,
    cache: &Arc<SharedCache>,
    done: impl Fn(&ScanIndex) -> bool,
) -> ScanIndex {
    fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
    fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
    index.traversal = None;
    for _ in 0..8 {
        let (next, _) = sampled(root, index, 10, cache);
        index = next;
        if done(&index) {
            break;
        }
    }
    index
}

/// J-T1's fixture after its first page: `OWNER` blocked by its refused group.
fn refused_first_page(cache: &Arc<SharedCache>) -> (PathBuf, ScanIndex) {
    let root = refused_fixture();
    write_rows(
        &root.join("sessions/c.jsonl"),
        &member(OTHER, "healthy", 100, 100),
    );
    let (index, _) = sampled(&root, ScanIndex::default(), 10, cache);
    assert!(held_owner(&index, OWNER));
    (root, index)
}

/// J-T2: the release removes only the recorded members' claims on the
/// owner. A departed non-member key (never on disk, so never in the census)
/// keeps its claim, and with it the owner's block.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn join_release_keeps_a_non_member_claim_on_the_same_owner() {
    let cache = Arc::new(SharedCache::default());
    let (root, mut index) = refused_first_page(&cache);
    let [a, b, n] = ["a.jsonl", "b.jsonl", "n.jsonl"].map(|name| session_key(&root, name));
    index
        .codex_state_only_blocked_by_file
        .insert(n.clone(), BTreeSet::from([OWNER.to_owned()]));
    let index = walk_without_members(&root, index, &cache, |index| {
        !claims(index, &a).is_some_and(|owners| owners.contains(OWNER))
    });
    for key in [&a, &b] {
        assert!(
            !claims(&index, key).is_some_and(|owners| owners.contains(OWNER)),
            "the member's own claim is released"
        );
    }
    assert_eq!(claims(&index, &n), Some(BTreeSet::from([OWNER.to_owned()])));
    assert!(
        held_owner(&index, OWNER),
        "the non-member claim still holds it"
    );
    fs::remove_dir_all(root).unwrap();
}

thread_local! {
    /// J-T3: `(from, to)`: the posted compact key of `from` is `to`'s.
    static FORCE_COLLISION: std::cell::RefCell<Option<(String, String)>> =
        const { std::cell::RefCell::new(None) };
}

/// Main's `compact_key` body, test-local, with the forced collision.
fn posted_compact_key(key: &str) -> u64 {
    let key = FORCE_COLLISION.with(|forced| match &*forced.borrow() {
        Some((from, to)) if from == key => to.clone(),
        _ => key.to_owned(),
    });
    let digest = <sha2::Sha256 as sha2::Digest>::digest(key.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

/// A clean walk's traversal whose census is exactly `census`.
fn census_traversal(census: &[&str]) -> crate::snapshots::ScanTraversalCheckpoint {
    crate::snapshots::ScanTraversalCheckpoint {
        context_fingerprint: "join-release-fixture".to_string(),
        census_window_end: "2026-10-06T23:00:00Z".to_string(),
        scan_roots: Vec::new(),
        pending_directories: std::collections::VecDeque::new(),
        pending_candidates: std::collections::VecDeque::new(),
        observed_index_keys: BTreeSet::new(),
        oversized_discovery: Default::default(),
        codex_rollout_paths: census.iter().map(|key| (*key).to_owned()).collect(),
        codex_join_directory_census: None,
        reconciliation_upper_bound: None,
        reconciliation_after: None,
        reconciliation_started: false,
        watcher_hint_seen: false,
        codex_freshness_yield: false,
        codex_parent_resolution_retry_required: false,
        unhealthy_retry_attempt: 0,
        unhealthy_retry_not_before_unix_seconds: None,
        counts: crate::snapshots::ScanTraversalCounts::default(),
        residue: crate::snapshots::ScanTraversalResidue::default(),
    }
}

/// `OWNER` recorded for members `a` and `b` (both claiming it, blocked),
/// beside a departed non-member claim `n`.
fn recorded_release_fixture(cache: &SharedCache) -> (ScanIndex, [String; 3]) {
    let members = [candidate("a.jsonl", 100), candidate("b.jsonl", 200)];
    cache.record_join_owner(OWNER, &members);
    let keys = [
        local_index_key(&members[0].path),
        local_index_key(&members[1].path),
        local_index_key(Path::new("/fixture/sessions/n.jsonl")),
    ];
    let mut index = ScanIndex::default();
    for key in &keys {
        index
            .codex_state_only_blocked_by_file
            .insert(key.clone(), BTreeSet::from([OWNER.to_owned()]));
    }
    index
        .codex_state_only_blocked_session_ids
        .insert(OWNER.to_owned());
    (index, keys)
}

/// J-T3: a forced compact-key collision (`n` digests as member `a`) makes
/// the posted digest filter select the non-member `n`; the amended release
/// matches exact keys, so the collision has nothing to act on.
#[test]
fn forced_compact_key_collision_cannot_remove_a_non_member_claim() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let (mut index, [a, b, n]) = recorded_release_fixture(&cache);
    let census = "/fixture/sessions/c.jsonl";
    index.traversal = Some(census_traversal(&[census]));
    FORCE_COLLISION.with(|forced| *forced.borrow_mut() = Some((n.clone(), a.clone())));
    // The posted (B) filter, verbatim, on this state.
    let members = [&a, &b].map(|key| posted_compact_key(key.as_str()));
    let present = BTreeSet::from([posted_compact_key(census)]);
    let selected = index
        .codex_state_only_blocked_by_file
        .keys()
        .filter(|key| {
            members.contains(&posted_compact_key(key.as_str()))
                && !present.contains(&posted_compact_key(key.as_str()))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(selected.contains(&n), "the forced collision is real");
    crate::snapshots::release_departed_join_owners(&mut index, &cache, |_| false);
    FORCE_COLLISION.with(|forced| *forced.borrow_mut() = None);
    assert_eq!(claims(&index, &a), None);
    assert_eq!(claims(&index, &b), None);
    assert_eq!(claims(&index, &n), Some(BTreeSet::from([OWNER.to_owned()])));
    assert!(held_owner(&index, OWNER));
}

/// J-T4 (a): an unclean walk (a rejected symlink) releases nothing.
#[test]
fn join_release_waits_for_a_clean_census() {
    let cache = Arc::new(SharedCache::default());
    let (root, index) = refused_first_page(&cache);
    let before = [session_key(&root, "a.jsonl"), session_key(&root, "b.jsonl")]
        .map(|key| claims(&index, &key));
    assert!(before
        .iter()
        .all(|owners| owners.as_ref().is_some_and(|owners| owners.contains(OWNER))));
    std::os::unix::fs::symlink(
        root.join("sessions/c.jsonl"),
        root.join("sessions/link.jsonl"),
    )
    .unwrap();
    let index = walk_without_members(&root, index, &cache, |_| false);
    assert!(held_owner(&index, OWNER));
    let after = [session_key(&root, "a.jsonl"), session_key(&root, "b.jsonl")]
        .map(|key| claims(&index, &key));
    assert_eq!(after, before);
    fs::remove_dir_all(root).unwrap();
}

/// J-T4 (b): an inventoried header naming the owner keeps it (main's `keep`).
#[test]
fn join_release_keeps_an_owner_a_header_still_names() {
    let cache = Arc::new(SharedCache::default());
    let (root, index) = refused_first_page(&cache);
    let before = [session_key(&root, "a.jsonl"), session_key(&root, "b.jsonl")]
        .map(|key| claims(&index, &key));
    assert!(before
        .iter()
        .all(|owners| owners.as_ref().is_some_and(|owners| owners.contains(OWNER))));
    write_rows(
        &root.join("sessions/d.jsonl"),
        &member(OWNER, "single", 100, 100),
    );
    let index = walk_without_members(&root, index, &cache, |_| false);
    assert!(held_owner(&index, OWNER));
    let after = [session_key(&root, "a.jsonl"), session_key(&root, "b.jsonl")]
        .map(|key| claims(&index, &key));
    assert_eq!(after, before);
    fs::remove_dir_all(root).unwrap();
}

/// J-T5: releasing `OWNER` removes only its claims: `OTHER`'s claim on the
/// same member key and its block survive; an emptied key is removed.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn join_release_of_one_owner_never_deletes_another() {
    let cache = Arc::new(SharedCache::default());
    let (root, mut index) = refused_first_page(&cache);
    let [a, b] = ["a.jsonl", "b.jsonl"].map(|name| session_key(&root, name));
    index
        .codex_state_only_blocked_by_file
        .entry(a.clone())
        .or_default()
        .insert(OTHER.to_owned());
    index
        .codex_state_only_blocked_session_ids
        .insert(OTHER.to_owned());
    let index = walk_without_members(&root, index, &cache, |index| !held_owner(index, OWNER));
    assert!(!held_owner(&index, OWNER), "B's provenance releases it");
    assert_eq!(claims(&index, &a), Some(BTreeSet::from([OTHER.to_owned()])));
    assert!(held_owner(&index, OTHER));
    assert_eq!(claims(&index, &b), None);
    fs::remove_dir_all(root).unwrap();
}

/// J-T6: provenance refused at admission (no room) is never recorded, so
/// the owner stays blocked when its members leave (J-T1 is the control).
#[test]
fn join_provenance_refused_at_admission_keeps_the_owner_blocked() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let root = refused_fixture();
    write_rows(
        &root.join("sessions/c.jsonl"),
        &member(OTHER, "healthy", 100, 100),
    );
    let (index, _) = with_test_state_budget(1, || sampled(&root, ScanIndex::default(), 10, &cache));
    assert!(held_owner(&index, OWNER));
    let index = walk_without_members(&root, index, &cache, |_| false);
    assert!(held_owner(&index, OWNER));
    for name in ["a.jsonl", "b.jsonl"] {
        assert!(
            claims(&index, &session_key(&root, name)).is_some_and(|owners| owners.contains(OWNER))
        );
    }
    fs::remove_dir_all(root).unwrap();
}

/// R2-M1: J-T1's parity holds under one oversized job. A later group whose
/// pause can never fit (`JoinStateBound`, another root on the same cache)
/// forgets no provenance, so `OWNER` is still released when its members
/// leave. Before the fix the hopeless reserve evicted every entry first.
#[test]
fn hopeless_pause_keeps_join_provenance_for_the_release() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const BIG: &str = "33333333-cccc-4ccc-8ccc-333333333333";
    let cache = Arc::new(SharedCache::default());
    let (root, index) = refused_first_page(&cache);
    let big = temp_root("hopeless-pause");
    write_rows(
        &big.join("sessions/a.jsonl"),
        &chain_rows(BIG, "a", "2026-10-01T10:00:00Z", 0, 30),
    );
    write_rows(
        &big.join("sessions/b.jsonl"),
        &chain_rows(BIG, "b", "2026-10-01T10:30:00Z", 300, 30),
    );
    let _ = with_test_limits(2048, 1024, 64, || {
        with_test_state_budget(1, || sampled(&big, ScanIndex::default(), 10, &cache))
    });
    assert_eq!(counters(&cache).jobs_state_bound, 1);
    assert_eq!(cache.cursor_reserved(), 0);
    let index = walk_without_members(&root, index, &cache, |index| !held_owner(index, OWNER));
    assert!(
        !held_owner(&index, OWNER),
        "the hopeless pause left B's provenance in place"
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(big).unwrap();
}

/// R2-L4: the release's paused-job keep arm, at scan level. A live paused
/// group job of `OWNER` in another namespace (K10 leaves it in the slot)
/// keeps `OWNER` blocked although its recorded members left a clean walk
/// (J-T1 is the control: without the arm, the same walk releases it). The queued and active arms cannot be isolated
/// here: a queued or active group's members are in this walk, so their
/// headers hold the owner first.
#[test]
fn join_release_keeps_the_paused_group_owner() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let paged = paged_corpus("paused-keep");
    with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..256 {
            let (next, _) = sampled_in(
                &paged,
                index,
                10,
                &cache,
                "2026-10-06T23:00:00Z",
                "paused-keep",
            );
            index = next;
            if counters(&cache).jobs_paused > 0 {
                return;
            }
        }
        panic!("no pause: {:?}", counters(&cache));
    });
    assert_eq!(cache.cursor_group_owner().as_deref(), Some(OWNER));
    // Recorded last, so `OWNER`'s provenance names `root`'s members (the
    // paused group's queueing recorded its own members first).
    let (root, index) = refused_first_page(&cache);
    let index = walk_without_members(&root, index, &cache, |_| false);
    assert_eq!(
        cache.cursor_group_owner().as_deref(),
        Some(OWNER),
        "the foreign paused job is still live: {:?}",
        counters(&cache)
    );
    // F8 re-blocks a paused owner every page, so the arm shows in the
    // members' claims: the release would have removed them (J-T2).
    assert!(held_owner(&index, OWNER));
    for name in ["a.jsonl", "b.jsonl"] {
        assert!(
            claims(&index, &session_key(&root, name)).is_some_and(|owners| owners.contains(OWNER)),
            "the paused group kept {name}'s claim"
        );
    }
    // Tail control (delta L-a): once the foreign job goes stale (K10: 16
    // cursor pages) this namespace's resume evicts it, and the next clean
    // walk releases the same claims. So the provenance named `root`'s
    // members all along, and only the paused arm kept it.
    let owned = |index: &ScanIndex, name: &str| {
        claims(index, &session_key(&root, name)).is_some_and(|owners| owners.contains(OWNER))
    };
    let mut index = index;
    for _ in 0..24 {
        index.traversal = None;
        let (next, _) = sampled(&root, index, 10, &cache);
        index = next;
        if !owned(&index, "a.jsonl") {
            break;
        }
    }
    assert_eq!(cache.cursor_group_owner(), None, "{:?}", counters(&cache));
    for name in ["a.jsonl", "b.jsonl"] {
        assert!(!owned(&index, name), "released once the job left: {name}");
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(paged).unwrap();
}

/// J-T12: a missing traversal skips the release (never an empty census) and
/// keeps the provenance; with a census lacking the members the same call
/// releases the owner exactly once and puts the traversal back unchanged.
#[test]
fn join_release_skips_a_missing_traversal() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let (mut index, [a, b, n]) = recorded_release_fixture(&cache);
    index.codex_state_only_blocked_by_file.remove(&n);
    crate::snapshots::release_departed_join_owners(&mut index, &cache, |_| false);
    assert!(index.traversal.is_none());
    assert!(held_owner(&index, OWNER));
    for key in [&a, &b] {
        assert_eq!(
            claims(&index, key),
            Some(BTreeSet::from([OWNER.to_owned()]))
        );
    }
    // Control: the provenance survived the skip.
    index.traversal = Some(census_traversal(&["/fixture/sessions/c.jsonl"]));
    let traversal = serde_json::to_value(index.traversal.as_ref()).unwrap();
    crate::snapshots::release_departed_join_owners(&mut index, &cache, |_| false);
    assert_eq!(
        serde_json::to_value(index.traversal.as_ref()).unwrap(),
        traversal
    );
    assert!(!held_owner(&index, OWNER));
    assert_eq!(claims(&index, &a), None);
    assert_eq!(claims(&index, &b), None);
    // Released once: the provenance went with it.
    index
        .codex_state_only_blocked_by_file
        .insert(a.clone(), BTreeSet::from([OWNER.to_owned()]));
    index
        .codex_state_only_blocked_session_ids
        .insert(OWNER.to_owned());
    crate::snapshots::release_departed_join_owners(&mut index, &cache, |_| false);
    assert!(held_owner(&index, OWNER));
    assert_eq!(cache.cursor_reserved(), 0);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn retained_parked_group_and_sealed_dependencies_ignore_ctime_only_changes() {
    use std::os::unix::fs::PermissionsExt;
    for change in [
        "chmod_live",
        "chmod_sealed",
        "append_sealed",
        "replace_sealed",
        "poison_replace_sealed",
    ] {
        let root = paged_corpus("wake-content");
        let cache = Arc::new(SharedCache::default());
        with_test_limits(2048, 1024, 64, || {
            let (index, _) =
                with_test_state_budget(1, || sampled(&root, ScanIndex::default(), 10, &cache));
            assert_eq!(counters(&cache).jobs_state_bound, 1);
            let (index, _) = next_generation(&root, index, &cache, 1);
            assert_eq!(counters(&cache).parked_hits, 1);
            let path = root.join(if change == "chmod_live" {
                "sessions/b.jsonl"
            } else {
                "sessions/a.jsonl"
            });
            match change {
                "append_sealed" => {
                    append_rows(&path, &[turn("66666666-aaaa-4aaa-8aaa-666666666666")])
                }
                "replace_sealed" | "poison_replace_sealed" => {
                    let modified = fs::metadata(&path).unwrap().modified().unwrap();
                    let replacement = path.with_extension("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    File::options()
                        .write(true)
                        .open(&replacement)
                        .unwrap()
                        .set_modified(modified)
                        .unwrap();
                    if change == "poison_replace_sealed" {
                        cache.poison_retained();
                    }
                    assert_ne!(
                        fs::metadata(&path).unwrap().ino(),
                        fs::metadata(&replacement).unwrap().ino()
                    );
                    fs::rename(replacement, &path).unwrap();
                }
                _ => {
                    let before = fs::metadata(&path).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(before.permissions().mode() ^ 0o004),
                    )
                    .unwrap();
                    let after = fs::metadata(&path).unwrap();
                    assert_ne!(
                        (before.ctime(), before.ctime_nsec()),
                        (after.ctime(), after.ctime_nsec())
                    );
                    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
                }
            }
            let _ = next_generation(&root, index, &cache, 2);
            let after = counters(&cache);
            if change.starts_with("chmod") {
                assert_eq!(after.groups_started, 1, "{change}: zero wakes: {after:?}");
                assert_eq!(after.parked_hits, 2, "{change}: {after:?}");
            } else {
                assert_eq!(after.groups_started, 2, "{change}: must wake: {after:?}");
                assert_eq!(after.parked_hits, 1, "{change}: {after:?}");
            }
        });
        fs::remove_dir_all(root).unwrap();
    }
}

/// B1: a spent T14 member holds its whole joined acquisition through the
/// production exit WITHOUT making its source census unreadable. An unrelated
/// session still publishes; the held group's accepted witnesses stay intact.
#[cfg(unix)]
#[test]
fn spent_known_corrupt_group_keeps_census_healthy_and_peer_progresses() {
    use crate::durable_tail_store::{self as store, SingleWriter};
    use std::io::Read;
    let (root, _) = fixture();
    let source = SnapshotSource::Codex;
    let cache = Arc::new(SharedCache::default());
    let (index, seed) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(seed.census_complete);
    let key = local_index_key(&root.join("sessions/a.jsonl"));
    let accepted = index.files[&key].last_snapshot_fingerprint.clone();
    assert!(accepted.is_some());
    let index_path = root.join("index.json");
    let scope = Scope("group-fixture".into());
    let path = root.join("sessions/a.jsonl");
    let mut file = fs::File::open(&path).unwrap();
    let mut plan = crate::transcript_acquisition::ReadPlan::prepare(
        &mut file,
        None,
        &scope,
        None,
        1_800_000_000,
    )
    .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let checkpoint = plan
        .commit_after_native_completion(&file, &scope, 1_800_000_000)
        .unwrap();
    let certificate = checkpoint
        .durable_certificate(crate::transcript_acquisition::birth_unix_nanos(
            &file.metadata().unwrap(),
        ))
        .unwrap();
    struct Writer(PathBuf);
    impl SingleWriter for Writer {
        fn state_dir(&self) -> &Path {
            &self.0
        }
    }
    let writer = Writer(root.clone());
    let mut disk = store::DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        store::DurableSource::Codex,
    );
    let digest = store::key_digest(store::DurableSource::Codex, &key);
    disk.write_after_save(
        &writer,
        1,
        0,
        vec![store::PendingRecord {
            acquisition: None,
            binding: store::Binding {
                source: store::DurableSource::Codex,
                key: digest,
                context: [0; 32],
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate,
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist: sampled_jsonl::durable::allowlist_digest(source),
        }],
    )
    .unwrap();
    let record = disk.dir().join(format!(
        "{}.rec",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut corrupt = fs::read(&record).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&record, &corrupt).unwrap();
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &scope, false);
    assert_eq!(
        cache.durable_full_hold(source, &key, true).unwrap(),
        None,
        "initial group rebuild attempt"
    );
    assert_eq!(
        cache
            .durable_counters(source)
            .unwrap()
            .1
            .t14_rebuild_full_started,
        1
    );
    cache.durable_begin_pass(source, &index_path, &scope, false);
    // A healthy, unrelated singleton is selected in the same terminal pass.
    let peer_owner = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    write_rows(
        &root.join("sessions/peer.jsonl"),
        &member(peer_owner, "r-peer", 90, 90),
    );
    // A size change invalidates the joined witness (clearing only the
    // singleton fingerprint does not force a joined acquisition).
    use std::io::Write;
    writeln!(fs::OpenOptions::new().append(true).open(&path).unwrap()).unwrap();
    // A later timestamp alone retains the prior traversal; start a fresh walk
    // so both existing group members reach the production acquisition guard.
    let (index, result) = next_generation(&root, index, &cache, 1);
    assert!(
        result.census_complete,
        "a known_corrupt group must not make source census red"
    );
    assert_eq!(result.unreadable_path_count, 0);
    assert_eq!(index.files[&key].last_snapshot_fingerprint, accepted);
    assert!(!result
        .snapshots
        .iter()
        .any(|item| item.source_session_id == OWNER));
    assert!(result
        .snapshots
        .iter()
        .any(|item| item.source_session_id == peer_owner));
    let (counts, stats) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.durable_held, [0; 8]);
    assert_eq!(counts.not_persisted.get("known_corrupt_held"), Some(&1));
    assert_eq!(stats.t14_rebuild_full_started, 1);
    assert_eq!(fs::read(&record).unwrap(), corrupt);
    fs::remove_dir_all(root).unwrap();
}

/// L23/F1: grouped members never reach the per-candidate guard, so a held
/// member (here a newer binary's record) holds its whole joined group before
/// acquisition: no member read, no POST body, the record byte-identical.
#[cfg(unix)]
#[test]
fn durable_hold_on_one_member_holds_the_joined_group() {
    use crate::durable_tail_store as store;
    let mut scanned = Vec::new();
    for refused_members in 0..=2 {
        let held = refused_members > 0;
        let (root, _) = fixture();
        let _writer = crate::locked_state_dir::test_locks::hold(&root);
        let cache = Arc::new(SharedCache::default());
        let index_path = root.join("index.json");
        let namespace = Scope("group-fixture".into());
        cache.durable_begin_pass(SnapshotSource::Codex, &index_path, &namespace, false);
        let key = store::key_digest(
            store::DurableSource::Codex,
            &local_index_key(&root.join("sessions/a.jsonl")),
        );
        let dir = store::store_dir_for_index(&index_path);
        let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let record = dir.join(format!("{hex}.rec"));
        let bytes = [
            b"ottto-dt".as_slice(),
            &(crate::durable_tail_store::FORMAT_V3 + 1).to_le_bytes(),
            &[7_u8; 64],
        ]
        .concat();
        if held {
            fs::create_dir_all(&dir).unwrap();
            fs::write(&record, &bytes).unwrap();
            if refused_members == 2 {
                let peer = store::key_digest(
                    store::DurableSource::Codex,
                    &local_index_key(&root.join("sessions/b.jsonl")),
                );
                let peer = peer.iter().map(|b| format!("{b:02x}")).collect::<String>();
                fs::write(dir.join(format!("{peer}.rec")), &bytes).unwrap();
            }
        }
        let (_, result) = sampled(&root, ScanIndex::default(), 10, &cache);
        let (durable, _) = cache.durable_counters(SnapshotSource::Codex).unwrap();
        assert_eq!(durable.durable_held[6], 0, "no pending receipt");
        if held {
            assert!(result.snapshots.is_empty(), "held group emits nothing");
            assert_eq!(fs::read(&record).unwrap(), bytes);
            assert_eq!(
                durable.durable_held[store::Refusal::NewerFormat as usize],
                refused_members,
                "C9: every refused group member counted, not only the first"
            );
        } else {
            assert_eq!(durable.durable_held, [0; 8]);
        }
        scanned.push(result.scanned_file_count);
        fs::remove_dir_all(root).unwrap();
    }
    assert!(
        scanned[1] + 2 <= scanned[0] && scanned[2] + 2 <= scanned[0],
        "control acquires both members; the held group acquires neither: {scanned:?}"
    );
}

#[test]
fn compressed_group_probe_initial_swap_and_legacy_tee_never_read() {
    use codex_zst_refusal_tests::assert_refused;
    let (root, inventory) = fixture();
    let index = ScanIndex::default();
    let group = inventory.groups().into_values().next().unwrap();
    let mut boot = GroupBoot::new(group.clone(), &index);
    let plain = group.members[0].clone();
    let mut compressed = plain.clone();
    compressed.path.set_extension("jsonl.zst");
    fs::copy(&plain.path, &compressed.path).unwrap();
    boot.group.members[0] = compressed.clone();
    assert_refused(CodexZstCause::GroupProbeUnsupported, || {
        assert!(matches!(boot.probe(0), Boot::Strict));
        assert_eq!(boot.charge, 0);
    });
    let metadata = CodexTitleMetadata::default();
    assert_refused(CodexZstCause::GroupReadUnsupported, || {
        assert!(open_member_file(&mut compressed).is_err());
        assert!(new_group_parser(
            File::open(&compressed.path).unwrap(),
            &compressed,
            &metadata,
            None,
            None,
            false,
            false,
            codex_counting_version::AckEvidence::None
        )
        .is_err());
        let expected =
            BTreeMap::from([(local_index_key(&compressed.path), "accepted-body".into())]);
        assert!(legacy_tee(
            &expected,
            &compressed,
            &File::open(&compressed.path).unwrap(),
            &metadata,
            None,
            None,
            false,
            false
        )
        .is_err());
    });
    let mut boot = GroupBoot::new(group, &index);
    loop {
        match boot.step(None, &index) {
            Boot::Pending => {}
            Boot::Ready => break,
            _ => panic!("plain group boots"),
        }
    }
    let mut active = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            ledgers: None,
            artifacts: false,
            context_curve: false,
            index: &index,
        })
        .unwrap();
    let before = active.parser.reader.consumed_bytes();
    let group = active.group.as_deref_mut().unwrap();
    group.current = 1;
    group.members[1] = compressed;
    let join = active
        .parser
        .accumulator
        .codex_tier_replay
        .as_mut()
        .unwrap()
        .join
        .take()
        .unwrap();
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        artifacts: false,
        context_curve: false,
        live_scope: &no_scope,
    };
    assert_refused(CodexZstCause::GroupReadUnsupported, || {
        assert!(matches!(
            open_member(&mut active, join, &inputs),
            Err(GroupEnd::Strict)
        ));
        assert_eq!(
            active.parser.reader.consumed_bytes(),
            before,
            "swap never reset the reader"
        );
    });
    active.candidate.path.set_extension("jsonl.zst");
    let cache = Arc::new(SharedCache::default());
    assert_refused(CodexZstCause::PhysicalOffsetUnsupported, || {
        assert!(matches!(
            cache.cursor_start(&mut active, &Scope("zst".into()), None, None, true, &index),
            Err(cursor::StartRefusal::Unstartable)
        ));
    });
    fs::remove_dir_all(root).unwrap();
}

/// A valid debt-bearing v1 record per `(member, due, upload context)` and no
/// index membership: the reset state the grouped missing-carrier handoff
/// recovers. Returns each member path with its record path.
#[cfg(unix)]
fn seed_member_debts<W: crate::durable_tail_store::SingleWriter>(
    root: &Path,
    writer: &W,
    debts: &[(&str, u64, Option<&str>)],
) -> Vec<(PathBuf, PathBuf)> {
    use crate::durable_tail_store as store;
    use std::io::Read;
    let scope = Scope("group-fixture".into());
    let now = sampled_scan::now_seconds();
    let ds = store::DurableSource::Codex;
    let dir = store::store_dir_for_index(&root.join("index.json"));
    let mut seeded = Vec::new();
    let mut pending = Vec::new();
    for (name, due, context) in debts {
        let path = root.join(format!("sessions/{name}.jsonl"));
        let mut file = fs::File::open(&path).unwrap();
        let mut plan =
            crate::transcript_acquisition::ReadPlan::prepare(&mut file, None, &scope, None, now)
                .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let mut certificate = plan
            .commit_after_native_completion(&file, &scope, now)
            .unwrap()
            .durable_certificate(0)
            .unwrap();
        certificate.audit_debt_unix_seconds = Some(*due);
        let digest = store::key_digest(ds, &local_index_key(&path));
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        seeded.push((path, dir.join(format!("{hex}.rec"))));
        pending.push(store::PendingRecord {
            acquisition: None,
            binding: store::Binding {
                source: ds,
                key: digest,
                context: store::context_digest(&scope.0, *context),
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate,
            body: crate::snapshots::durable_store_fixture_body(SnapshotSource::Codex, 0, 0),
            allowlist: sampled_jsonl::durable::allowlist_digest(SnapshotSource::Codex),
        });
    }
    let mut disk = store::DurableTailStore::new(dir, ds);
    let written = disk
        .write_after_save(writer, 1, 0, pending)
        .unwrap()
        .written;
    assert_eq!(written, debts.len());
    seeded
}

/// One scan of `root` through its group's completion: a single unpaged page,
/// or cursor pages under the scaled singleton budget.
#[cfg(unix)]
fn group_pass(
    root: &Path,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    paged: bool,
) -> (ScanIndex, SourceScanResult) {
    if !paged {
        return sampled_at(root, index, 10, cache, collected_at);
    }
    let before = completions(cache);
    with_test_limits(2048, 1024, 64, || {
        let (index, result, _) = pages_at(root, index, cache, collected_at, || {
            completions(cache) > before
        });
        (index, result)
    })
}

/// #865 P1 / SOURCE Addendum 6: reset + debt-bearing joined members (the
/// non-live alias `a` and the live member `b`) + complete join inventory +
/// incomplete sidecar census. The group publishes unverified; each member's
/// own native entry carries its own deadline through save, post-save GC and
/// restart, is selected past W, and a later verified Full retires both with
/// the existing completion counter. Paged and unpaged reads share the one
/// job-start capture and the one settlement; both are exercised.
#[cfg(unix)]
fn grouped_missing_carriers_mark_each_member_until_verified(paged: bool) {
    let source = SnapshotSource::Codex;
    let root = if paged {
        paged_corpus("missing-carrier")
    } else {
        fixture().0
    };
    let lock = crate::locked_state_dir::test_locks::hold(&root);
    let index_path = root.join("index.json");
    let namespace = Scope("group-fixture".into());
    let now = sampled_scan::now_seconds();
    let dues = [now - 120, now - 60];
    let seeded = seed_member_debts(&root, lock, &[("a", dues[0], None), ("b", dues[1], None)]);
    let originals = seeded
        .iter()
        .map(|(_, record)| fs::read(record).unwrap())
        .collect::<Vec<_>>();
    fs::write(root.join("session_index.jsonl"), "{not valid json}\n").unwrap();
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let (mut index, result) = group_pass(
        &root,
        ScanIndex::default(),
        &cache,
        "2026-10-06T23:00:00Z",
        paged,
    );
    assert!(!result.sidecar_census_complete);
    assert!(
        result
            .snapshots
            .iter()
            .any(|item| item.source_session_id == OWNER),
        "the unverified group publishes"
    );
    for ((path, _), due) in seeded.iter().zip(dues) {
        let entry = &index.files[&local_index_key(path)];
        assert!(entry.has_unverified_source(), "{path:?}");
        assert_eq!(
            entry.unverified_deadline(),
            Some(due),
            "each member keeps its own recovered debt"
        );
    }
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(
        counts.ineligible.get("audit_carrier"),
        Some(&2),
        "counted once per recovered member"
    );
    assert_eq!(
        counts.ineligible.get("audit_carrier_staged_unverified"),
        Some(&2)
    );
    assert_eq!(counts.restored, 0);
    assert_eq!(counts.durable_held, [0; 8]);
    // Actual save and post-save GC keep both predecessors while debt is owed.
    index.save(&index_path).unwrap();
    crate::snapshots::durable_after_save(&cache, &root, source, &index);
    assert_eq!(
        cache.durable_counters(source).unwrap().1.gc_records_deleted,
        0
    );
    for ((_, record), original) in seeded.iter().zip(&originals) {
        assert_eq!(&fs::read(record).unwrap(), original);
    }
    drop(cache);
    let mut loaded = ScanIndex::load(&index_path).unwrap();
    for ((path, _), due) in seeded.iter().zip(dues) {
        assert_eq!(
            loaded.files[&local_index_key(path)].unverified_deadline(),
            Some(due)
        );
        assert!(crate::snapshots::sampled_audit::path_requires_verification(
            &loaded.files,
            path
        ));
    }
    // Later: the sidecar census is repaired; discovery runs past W on a
    // fresh cache, and only the markers select the idle members.
    fs::remove_file(root.join("session_index.jsonl")).unwrap();
    loaded.traversal = None;
    let aged = (::time::OffsetDateTime::now_utc() + ::time::Duration::days(8))
        .format(&::time::format_description::well_known::Rfc3339)
        .unwrap();
    let restart = Arc::new(SharedCache::default());
    restart.durable_begin_pass(source, &index_path, &namespace, false);
    let ((verified, clean), rows) = crate::local_resource_diagnostics::capture(|| {
        group_pass(&root, loaded, &restart, &aged, paged)
    });
    assert!(clean.sidecar_census_complete);
    assert!(clean
        .snapshots
        .iter()
        .any(|item| item.source_session_id == OWNER));
    for (path, _) in &seeded {
        let entry = &verified.files[&local_index_key(path)];
        assert!(!entry.has_unverified_source(), "{path:?}");
        assert_eq!(entry.unverified_deadline(), None);
    }
    assert_eq!(
        rows.iter()
            .filter(|row| row["stage"] == "native_collection_page")
            .map(|row| {
                row["counts"]["sampled_acquisition"]["page_events"]["audits_completed"]
                    .as_u64()
                    .expect("production page_events exposes the completion counter")
            })
            .sum::<u64>(),
        2,
        "the existing completion counter retires each member once"
    );
    let (counts, _) = restart.durable_counters(source).unwrap();
    assert_eq!(
        counts.ineligible.get("audit_carrier"),
        None,
        "verifying a marked member is not a new miss"
    );
    assert_eq!(
        counts.ineligible.get("audit_carrier_staged_unverified"),
        None
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn grouped_missing_carriers_mark_each_unpaged_member_until_verified() {
    grouped_missing_carriers_mark_each_member_until_verified(false);
}

#[cfg(unix)]
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn grouped_missing_carriers_mark_each_paged_member_until_verified() {
    assert!(crate::heap_layout_bound::layout_supported());
    grouped_missing_carriers_mark_each_member_until_verified(true);
}

/// Grouped controls: a valid foreign-context record on the alias contributes
/// no obligation or count; the live member's future envelope deadline clamps
/// once to the recovery boundary's now, and later offers cannot renew it.
#[cfg(unix)]
#[test]
fn grouped_missing_carrier_requires_live_context_and_clamps_future_debt() {
    let source = SnapshotSource::Codex;
    let (root, _) = fixture();
    let lock = crate::locked_state_dir::test_locks::hold(&root);
    let now = sampled_scan::now_seconds();
    let seeded = seed_member_debts(
        &root,
        lock,
        &[
            ("a", now - 60, Some("foreign-account")),
            ("b", now + 600, Some("live-account")),
        ],
    );
    fs::write(root.join("session_index.jsonl"), "{not valid json}\n").unwrap();
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("group-fixture".into()),
        false,
    );
    let live = ScanIndex {
        active_upload_context_fingerprint: Some("live-account".into()),
        ..ScanIndex::default()
    };
    let before = sampled_scan::now_seconds();
    let (mut index, result) = sampled(&root, live, 10, &cache);
    let after = sampled_scan::now_seconds();
    assert!(!result.sidecar_census_complete);
    assert!(result
        .snapshots
        .iter()
        .any(|item| item.source_session_id == OWNER));
    let alias = local_index_key(&seeded[0].0);
    let member = local_index_key(&seeded[1].0);
    assert!(
        !index.files[&alias].has_unverified_source(),
        "a foreign envelope contributes no obligation"
    );
    assert_eq!(index.files[&alias].unverified_deadline(), None);
    let due = index.files[&member].unverified_deadline().unwrap();
    assert!(
        (before..=after).contains(&due),
        "clamped at the recovery boundary"
    );
    assert!(due < now + 600, "the future envelope cannot postpone audit");
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.ineligible.get("audit_carrier"), Some(&1));
    assert_eq!(
        counts.ineligible.get("audit_carrier_staged_unverified"),
        Some(&1)
    );
    let fingerprint = index.files[&member].source_file_fingerprint.clone();
    assert!(index.stage_sampled_audit(
        &member,
        &fingerprint,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: now + 1200
        }
    ));
    assert_eq!(
        index.files[&member].unverified_deadline(),
        Some(due),
        "later offers cannot renew the clamped debt"
    );
    fs::remove_dir_all(root).unwrap();
}

/// R1: a paged group captures its dues while both members are indexed (none
/// owed), then parks; the per-pass index loses their entries (a fresh load).
/// On resume the job keeps its progress, and settlement re-probes each absent
/// member's record and stages its own marker, counted once. The singleton
/// paged re-probe is the same settlement block (`dues.1`, via the singleton
/// guard), so this group fixture covers the shared path.
#[cfg(unix)]
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn parked_group_across_fresh_index_reprobes_member_debt_on_resume() {
    assert!(crate::heap_layout_bound::layout_supported());
    let source = SnapshotSource::Codex;
    let root = paged_corpus("missing-carrier-r1");
    fs::write(root.join("session_index.jsonl"), "{not valid json}\n").unwrap();
    let (mut index, seed) = sampled(
        &root,
        ScanIndex::default(),
        10,
        &Arc::new(SharedCache::default()),
    );
    assert!(seed
        .snapshots
        .iter()
        .any(|item| item.source_session_id == OWNER));
    let lock = crate::locked_state_dir::test_locks::hold(&root);
    let now = sampled_scan::now_seconds();
    let dues = [now - 120, now - 60];
    let seeded = seed_member_debts(&root, lock, &[("a", dues[0], None), ("b", dues[1], None)]);
    append_rows(
        &root.join("sessions/b.jsonl"),
        &chain_rows(OWNER, "b2", "2026-10-01T10:30:00Z", 600, 5)[1..],
    );
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("group-fixture".into()),
        false,
    );
    index.traversal = None;
    let collected_at = "2026-10-06T23:01:00Z";
    let (fresh, done) = with_test_limits(2048, 1024, 64, || {
        let (mut index, _, _) = pages_at(&root, index, &cache, collected_at, || {
            cache.paused_group_position().is_some()
        });
        assert!(seeded
            .iter()
            .all(|(path, _)| index.files.contains_key(&local_index_key(path))));
        // The per-pass index loads without the members' entries.
        index.files.clear();
        let (index, result, _) = pages_at(&root, index, &cache, collected_at, || {
            completions(&cache) > 0
        });
        (index, result)
    });
    assert!(done
        .snapshots
        .iter()
        .any(|item| item.source_session_id == OWNER));
    let counted = counters(&cache);
    assert_eq!(
        counted.groups_started, 1,
        "resumed, not rebooted: {counted:?}"
    );
    assert_eq!(counted.jobs_invalidated, 0, "{counted:?}");
    for ((path, _), due) in seeded.iter().zip(dues) {
        assert_eq!(
            fresh.files[&local_index_key(path)].unverified_deadline(),
            Some(due),
            "{path:?}: staged from the record on resume"
        );
    }
    let (durable, _) = cache.durable_counters(source).unwrap();
    assert_eq!(durable.ineligible.get("audit_carrier"), Some(&2));
    assert_eq!(
        durable.ineligible.get("audit_carrier_staged_unverified"),
        Some(&2)
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn protected_group_peer_does_not_spend_corruption_rebuild_before_input() {
    let (root, _) = fixture();
    let writer = crate::locked_state_dir::test_locks::hold(&root);
    let records = seed_member_debts(&root, writer, &[("a", 1, None), ("b", 1, None)]);
    let newer = [
        b"ottto-dt".as_slice(),
        &(crate::durable_tail_store::FORMAT_V3 + 1).to_le_bytes(),
        &[7_u8; 64],
    ]
    .concat();
    fs::write(&records[0].1, &newer).unwrap();
    let mut corrupt = fs::read(&records[1].1).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&records[1].1, &corrupt).unwrap();
    let cache = Arc::new(SharedCache::default());
    let source = SnapshotSource::Codex;
    // The synthetic scanner helper does not install a durable store itself.
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("group-fixture".into()),
        false,
    );
    let (index, held) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(held.snapshots.is_empty());
    assert_eq!(
        cache
            .durable_counters(source)
            .unwrap()
            .1
            .t14_rebuild_full_started,
        0,
        "a held peer must leave the corrupt member's native attempt unspent"
    );
    assert_eq!(fs::read(&records[0].1).unwrap(), newer);
    assert_eq!(fs::read(&records[1].1).unwrap(), corrupt);
    fs::remove_file(&records[0].1).unwrap();
    let (_, recovered) = next_generation(&root, index, &cache, 1);
    assert!(!recovered.snapshots.is_empty());
    assert_eq!(
        cache
            .durable_counters(source)
            .unwrap()
            .1
            .t14_rebuild_full_started,
        1,
        "same-process recovery retains the one native rebuild attempt"
    );
    fs::remove_dir_all(root).unwrap();
}
