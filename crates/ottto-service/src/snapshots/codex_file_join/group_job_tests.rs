//! Group StreamProof, ordinal domain and census fencing tests.
//! Every fixture is synthetic; no provider account content. Scaled budgets
//! come from `codex_cursor::with_test_limits` only.
use super::super::tests::{
    bound_rows, counting_v2_unbound_fixture, fixture, member, replay_group, scan, usage,
};
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::observe_consumed;
use crate::snapshots::transcript_acquisition_tests::accept_after_policy;
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
        bound_rows(rows)
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}

/// A fresh `<root>/sessions` directory.
fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
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
    bound_rows(&rows)
        .into_iter()
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
        withheld_content_stamp: None,
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

/// Byte-identical line 0 at an equal size is one copied candidate
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

/// Feed rows to `proof` with the parser's `admitted_usage` tap after every UI record.
fn feed(proof: &mut StreamProof, rows: &[Value], starts: impl IntoIterator<Item = u64>) {
    let mut turn = None;
    for (row, start) in rows.iter().zip(starts) {
        if row["type"] == "token_usage_record" {
            turn = row["payload"]["response_id"].as_str();
            proof.turn = turn.map(|id| compact(b"t:", id));
        }
        proof.set_record_start(start);
        proof.observe(row);
        if codex_last_usage(row).is_some() {
            proof.admitted_usage(row, true, codex_usage_event_identity(row).as_deref(), turn);
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
        None,
        hints,
        false,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope(scope.into()));
    for _ in 0..100_000 {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                accept_after_policy(SnapshotSource::Codex, &scan, &mut index);
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

/// A processed group re-hinted through one member
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
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [regress] A joined group admitted through its first member, the only one
/// this one-file page selected, is first-read progress once its last
/// member's read completes the group.
#[test]
fn group_read_through_a_selected_non_final_member_is_first_read_progress() {
    let (root, _) = fixture();
    let cache = Arc::new(SharedCache::default());
    let (_, scan) = sampled(&root, ScanIndex::default(), 1, &cache);
    assert!(!scan.snapshots.is_empty(), "{:?}", counters(&cache));
    assert!(scan.first_read_progress, "{:?}", counters(&cache));
    fs::remove_dir_all(root).unwrap();
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
    bound_rows(&rows)
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
    // §k.3 interim: under V2 the UI side is not money; a UI-only turn holds
    // the group at its end until the counting writer's turn hook lands.
    let held = replay_group(group_of(&root), &ScanIndex::default());
    assert_eq!(refused(held), Some((JoinRefusal::V2UiOnlyTurn, 1)));
    write_rows(&root.join("sessions/b.jsonl"), &bound);
    assert!(
        replay_group(group_of(&root), &ScanIndex::default()).is_ok(),
        "every admitted turn has a native: the V2 group replays"
    );
    fs::remove_dir_all(root).unwrap();
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
    let job = replay_group(group_of(&root), &ScanIndex::default())
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
    assert!(parsed.progress_complete());
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
        refused(replay_group(group_of(&root), &ScanIndex::default())),
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
    let mut proof = StreamProof::new(OWNER.into(), vec![MemberPlan::default()]);
    start(&mut proof);
    let mut row = ui(100, 100, "2026-10-01T10:00:30Z");
    row["payload"]["info"]["last_token_usage"]
        .as_object_mut()
        .unwrap()
        .remove("reasoning_output_tokens");
    proof.admitted_usage(&row, true, Some("identity"), None);
    assert_eq!(proof.refusal(), Some((JoinRefusal::UiShape, 0)));
    // No identity is the same named shape debt, never skipped.
    let mut proof = StreamProof::new(OWNER.into(), vec![MemberPlan::default()]);
    start(&mut proof);
    proof.admitted_usage(&ui(100, 100, "2026-10-01T10:00:30Z"), true, None, None);
    assert_eq!(proof.refusal(), Some((JoinRefusal::UiShape, 0)));
    // An admission the parser derived from cumulative counters.
    let mut proof = StreamProof::new(OWNER.into(), vec![MemberPlan::default()]);
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
    let raw_ordinals = |rows: Vec<Value>, first: u64| {
        rows.into_iter()
            .zip(first..)
            .map(|(mut row, n)| {
                row["ordinal"] = json!(n);
                row
            })
            .collect::<Vec<_>>()
    };
    let run = |offset: u64, before: u64| {
        let mut proof = StreamProof::new(OWNER.into(), plans.clone());
        proof.begin_member(0);
        let rows = raw_ordinals(
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
        rows.extend(raw_ordinals(
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
    // compressed predecessor) is a missing predecessor, never a fork.
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
        refused(replay_group(group_of(&root), &ScanIndex::default())),
        Some((JoinRefusal::EqualBeforeTie, 0))
    );
    let tokens = probe_before(&member(OWNER, "r", 100, 100)[3]);
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

fn group_replays() -> (u64, u64) {
    use crate::snapshots::tail_source::counters::total;
    (
        total("tail_reconstruct", "group_replay"),
        total("tail_reconstruct_bytes", "group_replay"),
    )
}

fn corpus_bytes(root: &Path) -> u64 {
    fs::read_dir(root.join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum()
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
    rows.remove(4);
    rows.remove(4);
    write_rows(&root.join("sessions/b.jsonl"), &rows);
    assert_eq!(
        refused(replay_group(group_of(&root), &ScanIndex::default())),
        Some((JoinRefusal::Gap, 1)),
        "without loss the gap is terminal proof debt"
    );
    // The same gap after a skipped (malformed) line may be the loss's own
    // effect: strict, never settleable or memoized.
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
        replay_group(group_of(&root), &ScanIndex::default()),
        Err(GroupEnd::Strict)
    ));
    let cache = Arc::new(SharedCache::default());
    let (_, result) = sampled(&root, ScanIndex::default(), 10, &cache);
    let after = counters(&cache);
    assert_eq!(after.memo_records, 0, "{after:?}");
    assert!(result.unreadable_path_count > 0, "strict AliasParser debt");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn refused_group_memo_hit_on_live_growth_rereads_nothing() {
    let root = refused_fixture();
    let cache = Arc::new(SharedCache::default());
    let before = group_replays();
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let first = counters(&cache);
    assert_eq!(first.memo_records, 1, "{first:?}");
    let refused = group_replays();
    assert_eq!(refused.0, before.0 + 1, "one executed refusal");
    assert!(refused.1 > before.1, "the first attempt read bytes");
    // The live member grows; an append cannot cure an overlap before it.
    append_rows(
        &root.join("sessions/b.jsonl"),
        &[turn("44444444-aaaa-4aaa-8aaa-444444444444")],
    );
    let ((_, again), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
    assert_eq!(bytes, 0, "a memo hit replays no byte despite live growth");
    assert_eq!(group_replays(), refused, "no second replay or replay bytes");
    assert_eq!(counters(&cache).memo_records, first.memo_records);
    assert!(again.snapshots.is_empty());
    assert!(again.census_complete, "re-disclosed as settleable residue");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
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

    let cache = Arc::new(SharedCache::default());
    let before = group_replays();
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let refused = counters(&cache);
    assert_eq!(refused.memo_records, 1, "recorded with an exact stamp");
    let first = group_replays();
    assert_eq!(first.0, before.0 + 1);
    assert!(first.1 > before.1);
    // Unchanged: the next generation does not re-read the group.
    let ((index, unchanged), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
    assert_eq!(bytes, 0, "the exact-stamp memo suppresses the read");
    assert_eq!(group_replays(), first);
    assert_eq!(counters(&cache).memo_records, refused.memo_records);
    assert!(unchanged.snapshots.is_empty());
    // Any growth of the live member may cure it: one attempt.
    append_rows(
        &root.join("sessions/b.jsonl"),
        &[turn("55555555-aaaa-4aaa-8aaa-555555555555")],
    );
    let ((_, grown), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 2));
    assert!(bytes > 0, "growth must miss the exact-stamp memo");
    assert_eq!(group_replays().0, first.0 + 1, "exactly one new attempt");
    assert!(
        group_replays().1 > first.1,
        "the new replay records its bytes"
    );
    assert_eq!(counters(&cache).memo_records, refused.memo_records + 1);
    assert!(grown.snapshots.is_empty(), "the unmatched UI still refuses");
    fs::remove_dir_all(root).unwrap();
}

/// A live-member `Gap` raised mid-stream stops the reader
/// before the file's end; bytes after it cannot cure it, so the exact-stamp
/// entry is recorded and an unchanged group is not re-read.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
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

    let cache = Arc::new(SharedCache::default());
    let before = group_replays();
    let (index, _) = sampled(&root, ScanIndex::default(), 10, &cache);
    let refused = counters(&cache);
    assert_eq!(
        refused.memo_records, 1,
        "recorded although the reader stopped mid-stream: {refused:?}"
    );
    let first = group_replays();
    assert_eq!(first.0, before.0 + 1, "one mid-stream refusal");
    assert!(first.1 > before.1);
    let ((_, unchanged), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
    assert_eq!(bytes, 0, "the mid-stream gap is not re-read");
    assert_eq!(group_replays(), first, "one replay only, bytes unchanged");
    assert_eq!(counters(&cache).memo_records, refused.memo_records);
    assert!(unchanged.snapshots.is_empty());
    fs::remove_dir_all(root).unwrap();
}

/// A real from-start replay refuses inside its first member: the reconstruction
/// counter records that attempt once and exactly the prefix its reader consumed.
#[test]
fn a_group_replay_counts_once_with_its_consumed_bytes() {
    let root = temp_root("replay-count");
    let mut rows = chain_rows(OWNER, "a", "2026-10-01T10:00:00Z", 0, 3);
    rows[3] = native(OWNER, "gap", 10, 50);
    let expected = rows[..4]
        .iter()
        .map(|row| (serde_json::to_vec(row).unwrap().len() + 1) as u64)
        .sum::<u64>();
    write_rows(&root.join("sessions/a.jsonl"), &rows);
    write_rows(
        &root.join("sessions/b.jsonl"),
        &chain_rows(OWNER, "b", "2026-10-01T10:30:00Z", 30, 3),
    );
    let before = group_replays();
    let cache = Arc::new(SharedCache::default());
    let ((_, scan), bytes) = observe_consumed(|| sampled(&root, ScanIndex::default(), 10, &cache));
    assert_eq!(bytes, expected, "refuses before reading the remaining rows");
    assert_eq!(group_replays(), (before.0 + 1, before.1 + expected));
    assert_eq!(counters(&cache).memo_records, 1, "terminal group refusal");
    assert!(scan.snapshots.is_empty());
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
        let ((index, first), bytes) = observe_consumed(|| {
            with_test_state_budget(1, || sampled(&root, ScanIndex::default(), 10, &cache))
        });
        assert!(bytes > 0 && bytes < corpus_bytes(&root), "one partial read");
        let bound = counters(&cache);
        let replay = group_replays();
        assert_eq!(bound.jobs_state_bound, 1, "{bound:?}");
        assert_eq!(cache.cursor_reserved(), 0);
        assert!(first.snapshots.is_empty());
        // A new generation without a capacity or input change: no attempt.
        let ((index, _), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
        assert_eq!(bytes, 0, "never retried per generation");
        assert_eq!(group_replays(), replay);
        let parked = counters(&cache);
        assert_eq!(parked.parked_hits, 1, "{parked:?}");
        // Growth of the live member keeps it parked.
        append_rows(
            &root.join("sessions/b.jsonl"),
            &chain_rows(OWNER, "b2", "2026-10-01T10:30:00Z", 600, 2)[1..],
        );
        let ((index, _), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 2));
        assert_eq!(bytes, 0, "live growth must leave the group parked");
        assert_eq!(group_replays(), replay);
        let grown = counters(&cache);
        assert_eq!(grown.parked_hits, 2, "{grown:?}");
        // A sealed member's change wakes it: one new attempt.
        append_rows(
            &root.join("sessions/a.jsonl"),
            &[turn("66666666-aaaa-4aaa-8aaa-666666666666")],
        );
        let (_, bytes) = observe_consumed(|| {
            let (index, _) = next_generation(&root, index, &cache, 3);
            assert!(
                cache.paused_group_position().is_some(),
                "the sealed change wakes it"
            );
            pages_at(&root, index, &cache, "2026-10-06T23:03:00Z", || {
                completions(&cache) > 0
            })
        });
        assert_eq!(bytes, corpus_bytes(&root), "one new attempt after waking");
        assert_eq!(group_replays().0, replay.0 + 1);
        assert!(group_replays().1 > replay.1);
        let woken = counters(&cache);
        assert_eq!(woken.parked_hits, 2, "{woken:?}");
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
    let replay = group_replays();
    let done = with_test_limits(2048, 1024, 64, || {
        let ((mut index, first, _), bytes) = observe_consumed(|| {
            pages(&root, ScanIndex::default(), &cache, || {
                counters(&cache).jobs_paused > 0
            })
        });
        assert!(
            bytes > 0 && bytes < corpus_bytes(&root),
            "one partial attempt"
        );
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
        let ((_, done, earlier), bytes) =
            observe_consumed(|| pages(&root, index, &cache, || completions(&cache) > 0));
        assert_eq!(bytes, corpus_bytes(&root), "one restart with N+1 members");
        assert!(
            earlier.iter().all(|page| page.snapshots.is_empty()),
            "no member (the new one included) is emitted before the group"
        );
        done
    });
    let after = counters(&cache);
    assert_eq!(
        after.jobs_invalidated, 1,
        "one invalidation at resume: {after:?}"
    );
    // The invalidated partial job never completes; the replacement counts once.
    assert_eq!(group_replays().0, replay.0 + 1);
    assert!(group_replays().1 > replay.1);
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
    let prefix_bytes = corpus_bytes(&root);
    let replay = group_replays();
    let ((first, second), bytes) = observe_consumed(|| {
        with_test_limits(2048, 1024, 64, || {
            // Page until the paused job reads the live (last) member.
            let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
                cache.paused_group_position() == Some(1)
            });
            append_rows(
                &root.join("sessions/b.jsonl"),
                &chain_rows(OWNER, "b2", "2026-10-01T10:30:00Z", 600, 5)[1..],
            );
            let (mut index, first, earlier) =
                pages(&root, index, &cache, || completions(&cache) > 0);
            assert!(earlier.iter().all(|page| page.snapshots.is_empty()));
            // The appended tail stays pending; the next generation replaces
            // the body.
            index.traversal = None;
            let (_, second, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
                completions(&cache) > 1
            });
            (first, second)
        })
    });
    assert_eq!(
        bytes,
        prefix_bytes + corpus_bytes(&root),
        "exactly two complete attempts"
    );
    assert_eq!(group_replays().0, replay.0 + 2);
    assert!(group_replays().1 > replay.1);
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
    fs::remove_dir_all(root).unwrap();
}

/// A metadata-only change of a member already read, while the job
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
            let ((index, _, _), prefix_bytes) = observe_consumed(|| {
                pages(&root, ScanIndex::default(), &cache, || {
                    cache.paused_group_position() == Some(1)
                })
            });
            assert!(prefix_bytes > 0 && prefix_bytes < corpus_bytes(&root));
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
            let ((_, done, _), bytes) =
                observe_consumed(|| pages(&root, index, &cache, || completions(&cache) > 0));
            let expected = if change == "chmod" {
                corpus_bytes(&root) - prefix_bytes
            } else {
                corpus_bytes(&root)
            };
            assert_eq!(
                bytes, expected,
                "{change}: resume unchanged, restart changed exactly once"
            );
            done
        });
        let after = counters(&cache);
        if change == "chmod" {
            assert_eq!(after.jobs_invalidated, 0, "{change}: {after:?}");
            assert_eq!(input_totals(&done), input_totals(&unpaged), "{change}");
        } else {
            assert_eq!(after.jobs_invalidated, 1, "{change}: {after:?}");
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn restart_mid_job_reboots_group_once_with_one_body() {
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
        // Restart: the RAM cache and its paused job are gone; the index is
        // saved and loaded.
        drop(before);
        let path = root.join("index.json");
        index.save_fixture(&path).unwrap();
        let index = ScanIndex::load(&path).unwrap();
        let after = Arc::new(SharedCache::default());
        let replay = group_replays();
        let ((_, done, earlier), bytes) =
            observe_consumed(|| pages(&root, index, &after, || completions(&after) > 0));
        assert_eq!(bytes, corpus_bytes(&root), "the group re-boots once");
        assert_eq!(group_replays().0, replay.0 + 1);
        assert!(group_replays().1 > replay.1);
        assert!(
            earlier.iter().all(|page| page
                .snapshots
                .iter()
                .all(|snapshot| snapshot.source_session_id != OWNER)),
            "no body for the in-progress owner before its group completes"
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
fn refused_group_debt_survives_save_and_restart() {
    let root = refused_fixture();

    let cache = Arc::new(SharedCache::default());
    let (mut index, first) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(first.census_complete, "{first:?}");
    let path = root.join("index.json");
    index.save_fixture(&path).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        loaded
            .traversal
            .as_ref()
            .map(|traversal| &traversal.residue),
        index.traversal.as_ref().map(|traversal| &traversal.residue),
        "residue survives save and load"
    );
    // A new process: no memo, one bounded re-attempt, the same settleable
    // debt and no body.
    loaded.traversal = None;
    let restarted = Arc::new(SharedCache::default());
    let (_, again) = sampled(&root, loaded, 10, &restarted);
    assert!(again.snapshots.is_empty());
    assert!(again.census_complete, "{again:?}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn upload_context_change_keeps_paused_group() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = paged_corpus("scope");
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (mut index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).jobs_paused > 0
        });
        // A delivery context is no group scope input: the job resumes.
        index.active_upload_context_fingerprint = Some("other-upload-context".into());
        let (_, done, _) = pages(&root, index, &cache, || completions(&cache) > 0);
        assert!(!done.snapshots.is_empty());
    });
    let after = counters(&cache);
    assert_eq!(after.jobs_invalidated, 0, "{after:?}");
    fs::remove_dir_all(root).unwrap();
}

/// An append-curable refusal at a paged group's frozen cut
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
    live.push(
        json!({"type":"event_msg","payload":{"type":"task_started","turn_id":"late-native"}}),
    );
    live.push(turn("late-native"));
    live.push(ui(20, 620, "2026-10-01T10:10:20Z"));
    write_rows(&root.join("sessions/b.jsonl"), &live);

    let cache = Arc::new(SharedCache::default());
    let prefix_bytes = corpus_bytes(&root);
    let replay = group_replays();
    let (done, bytes) = observe_consumed(|| {
        with_test_limits(2048, 1024, 64, || {
            let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
                cache.paused_group_position() == Some(1)
            });
            // The native lands past the live member's frozen extent.
            append_rows(
                &root.join("sessions/b.jsonl"),
                &[
                    {
                        let mut row = native(OWNER, "b-30", 20, 620);
                        row["payload"]["turn_id"] = json!("late-native");
                        row
                    },
                    json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":"late-native"}}),
                ],
            );
            let (mut index, _, _) = pages(&root, index, &cache, || {
                cache.paused_group_position().is_none()
            });
            let refused = counters(&cache);
            assert_eq!(refused.memo_records, 0, "{refused:?}");
            index.traversal = None;
            let (_, done, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
                completions(&cache) > 0
            });
            done
        })
    });
    assert_eq!(
        bytes,
        prefix_bytes + corpus_bytes(&root),
        "one refusal and one new attempt"
    );
    assert_eq!(group_replays().0, replay.0 + 2);
    assert!(group_replays().1 > replay.1);

    let (_, full) = scan(&root, ScanIndex::default(), 10);
    assert_eq!(fingerprints(&done), fingerprints(&full), "a body accepted");
    fs::remove_dir_all(root).unwrap();
}

/// EOF-record handling for a paged group's live member. A quiescent live member
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
        let replay = group_replays();
        let ((_, again), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
        assert_eq!(bytes, 0, "no re-read after genuine EOF");
        assert_eq!(group_replays(), replay);
        assert!(again.snapshots.is_empty());
    });
    fs::remove_dir_all(root).unwrap();
}

/// Probes are capped by the page's remaining singleton
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
    let (_, result) = with_test_limits(2048, 1, 64, || {
        sampled(&root, ScanIndex::default(), 10, &cache)
    });
    let after = counters(&cache);
    assert_eq!(after.memo_records, 0, "{after:?}");
    assert!(result.snapshots.is_empty());
    assert!(result.unreadable_path_count > 0, "strict AliasParser debt");
    fs::remove_dir_all(root).unwrap();
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

/// The own-page cure. A group read first leaves the shared
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
    // Probes read line 0 and the first native.
    let probes = head_bytes(&root.join("sessions/c.jsonl"), 2)
        + head_bytes(&root.join("sessions/d.jsonl"), 2);
    // A two-member group that sorts first and charges its headers, probes
    // and body to the shared page before `c`/`d` boot. Groups are read in key
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
    // A header read charges at most one 1 KiB buffer; a filler member's probe,
    // if it probes, reads up to its first native (line 3).
    let len = |name: &str| {
        fs::metadata(root.join(format!("sessions/{name}.jsonl")))
            .unwrap()
            .len()
    };
    let header = |name: &str| len(name).min(1024);
    let filler_probes = head_bytes(&root.join("sessions/f1.jsonl"), 4)
        + head_bytes(&root.join("sessions/f2.jsonl"), 4);
    // The filler's headers, probes and body fit the page at both totals, so
    // both charge the same work before `c`/`d` boot. Left over at the
    // ordinary total: at most `filler_probes + 256` less `c`/`d`'s headers,
    // short of their probes. At the first-import total another threshold.
    let singleton = header("f1") + header("f2") + filler_probes + len("f1") + len("f2") + 256;
    let other_headers = header("c") + header("d");
    assert!(filler_probes + 256 < other_headers + probes, "short at 64");
    assert!(len("c") + len("d") > singleton, "a paged group");
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

    let paged_group = inventory_groups(&root)
        .into_iter()
        .find(|group| group.owner == OTHER)
        .expect("the paged group");
    let own_page_asked = |cache: &SharedCache| {
        cache.group_own_page(&Scope("group-fixture".into()), &job_key(&paged_group), None)
    };
    let cache = Arc::new(SharedCache::default());
    with_test_limits(8192, singleton, 64, || {
        let (mut index, first) = sampled(&root, ScanIndex::default(), 10, &cache);
        assert_eq!(other(&first).0, 0, "held on the shared page");
        assert!(own_page_asked(&cache), "the cure takes a page of its own");

        index.traversal = None;
        let (_, joined, _) = pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
            completions(&cache) == 1
        });
        let after = counters(&cache);
        assert_eq!(after.parked_hits, 0, "{after:?}");
        assert_eq!(after.jobs_certified, 1, "{after:?}");
        assert_eq!(other(&joined), expected, "counted once, as unpaged");
    });

    // The first-import page total: the shared page's remainder now covers
    // the probes, so the group orders on that page, asks for no page of its
    // own and joins once, as unpaged. The threshold is unchanged, so it is
    // still a paged (cursor) group.
    let cache = Arc::new(SharedCache::default());
    with_test_limits(8192, singleton, 64, || {
        let flagged = ScanIndex {
            first_import_pending: true,
            ..ScanIndex::default()
        };
        let (index, first) = sampled(&root, flagged, 10, &cache);
        assert!(index.first_import_pending, "the flag rides the page");
        assert!(!own_page_asked(&cache), "no own page at the larger total");
        let mut published = first.snapshots;
        if completions(&cache) == 0 {
            let (_, last, earlier) = pages(&root, index, &cache, || {
                assert!(!own_page_asked(&cache), "no own page at the larger total");
                completions(&cache) == 1
            });
            for page in earlier.into_iter().chain([last]) {
                published.extend(page.snapshots);
            }
        }
        let after = counters(&cache);
        assert_eq!(after.parked_hits, 0, "{after:?}");
        assert_eq!(after.jobs_certified, 1, "{after:?}");
        assert!(after.jobs_started >= 1, "a paged group: {after:?}");
        let joined = published
            .iter()
            .filter(|snapshot| snapshot.source_session_id == OTHER)
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            (joined.len(), joined.into_iter().collect::<BTreeSet<_>>()),
            expected,
            "counted once, as unpaged"
        );
    });
    fs::remove_dir_all(root).unwrap();
}

/// An owner whose group sorts before `owner`'s in page selection order. Group
/// keys hash the home path, which differs every run, so it is searched for.
fn owner_sorting_before(root: &Path, owner: &str) -> String {
    let home = inventory_groups(root)
        .into_iter()
        .find(|group| group.owner == owner)
        .expect("the group")
        .home;
    let key = super::super::group_key(&home, owner);
    (0..u64::from(u32::MAX))
        .map(|i| format!("aaaaaaaa-bbbb-4ccc-8ddd-{i:012x}"))
        .find(|candidate| super::super::group_key(&home, candidate) < key)
        .expect("an owner whose group sorts first")
}

/// Control: a probe cut by `PROBE_BYTES` itself, not by the page's
/// remainder, is the same at both page totals. The group keeps chronological
/// order, is refused strict, asks for no page of its own and parks; the next
/// generation is a parked hit that publishes nothing.
#[test]
fn probe_bytes_bound_order_parks_at_both_page_totals() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("probe-bytes-park");
    // About 1.2 MiB of padding before `c`'s first native: its probe passes
    // `PROBE_BYTES` (1 MiB) whatever room the page has.
    write_probe_order(&root, OTHER, ["c", "d"], 300, 0);
    let group = inventory_groups(&root)
        .into_iter()
        .find(|group| group.owner == OTHER)
        .expect("the group");
    let own_page_asked = |cache: &SharedCache| {
        cache.group_own_page(&Scope("group-fixture".into()), &job_key(&group), None)
    };
    // The remainder after the two header reads covers a whole `PROBE_BYTES`
    // probe at both totals, and the group is still larger than the
    // threshold (a paged group).
    let singleton = (1 << 20) + 64 * 1024;
    assert!(corpus_bytes(&root) > singleton, "a paged group");
    for first_import in [false, true] {
        let cache = Arc::new(SharedCache::default());
        with_test_limits(8 << 20, singleton, 64, || {
            let index = ScanIndex {
                first_import_pending: first_import,
                ..ScanIndex::default()
            };
            let (index, first) = sampled(&root, index, 10, &cache);
            assert!(
                first
                    .snapshots
                    .iter()
                    .all(|snapshot| snapshot.source_session_id != OTHER),
                "strict in chronological order (first import {first_import})"
            );
            assert!(
                !own_page_asked(&cache),
                "a PROBE_BYTES order never asks for its own page"
            );
            let parked = counters(&cache).parked_hits;
            let (_, quiet) = next_generation(&root, index, &cache, 1);
            let after = counters(&cache);
            assert_eq!(after.parked_hits, parked + 1, "parked: {after:?}");
            assert!(quiet
                .snapshots
                .iter()
                .all(|snapshot| snapshot.source_session_id != OTHER));
            assert!(!own_page_asked(&cache));
        });
    }
    fs::remove_dir_all(root).unwrap();
}

/// A group within the threshold whose body does not fit the page's remainder
/// after a group read first waits whole for a later page at the ordinary
/// total: a requeue with no page of its own. At the first-import total the
/// same body fits the first page. Either way it is counted once, as unpaged.
#[test]
fn whole_group_body_defers_at_the_ordinary_total_and_fits_the_first_import_total() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("group-body-defer");
    // Trailing padding makes each member large next to its header charge.
    let padded = |mut rows: Vec<Value>| {
        rows.extend((0..8).map(|i| {
            json!({"type": "event_msg", "timestamp": "2026-10-01T10:59:00Z", "payload": {
                "type": "agent_message", "message": format!("{i}:{}", "p".repeat(4096))}})
        }));
        rows
    };
    write_rows(
        &root.join("sessions/c.jsonl"),
        &padded(member(OTHER, "r-c", 100, 100)),
    );
    write_rows(
        &root.join("sessions/d.jsonl"),
        &padded(member(OTHER, "r-d", 200, 300)),
    );
    let group_bytes = corpus_bytes(&root);
    let filler = owner_sorting_before(&root, OTHER);
    write_rows(
        &root.join("sessions/f1.jsonl"),
        &padded(member(&filler, "f-1", 100, 100)),
    );
    write_rows(
        &root.join("sessions/f2.jsonl"),
        &padded(member(&filler, "f-2", 200, 300)),
    );
    assert_eq!(first_group_owner(&root), filler, "the filler is read first");
    let group = inventory_groups(&root)
        .into_iter()
        .find(|group| group.owner == OTHER)
        .expect("the group");
    let own_page_asked = |cache: &SharedCache| {
        cache.group_own_page(&Scope("group-fixture".into()), &job_key(&group), None)
    };
    // Both equal groups are within the threshold, so each is read whole. One
    // fits an ordinary page; both fit the first-import total (2.5 groups).
    let singleton = group_bytes + group_bytes / 4 + 8 * 1024;
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
    assert!(expected.0 > 0, "the group joins unpaged");
    for first_import in [false, true] {
        let cache = Arc::new(SharedCache::default());
        with_test_limits(8 << 20, singleton, 64, || {
            let index = ScanIndex {
                first_import_pending: first_import,
                ..ScanIndex::default()
            };
            let (index, first) = sampled(&root, index, 10, &cache);
            let after = counters(&cache);
            if first_import {
                assert_eq!(other(&first), expected, "the body fits the larger page");
                assert_eq!(after.deferred, 0, "{after:?}");
            } else {
                assert_eq!(other(&first).0, 0, "the whole group waits");
                assert!(after.deferred >= 1, "{after:?}");
                assert!(!own_page_asked(&cache), "a requeue, not an own page");
                let (_, second) = sampled(&root, index, 10, &cache);
                assert_eq!(other(&second), expected, "counted once, as unpaged");
            }
        });
    }
    fs::remove_dir_all(root).unwrap();
}

/// A memoized group larger than the singleton budget
/// reaches its memo hit without the cursor slot while a singleton's job
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
    b.iter_mut()
        .filter(|r| r["type"] == "token_usage_record")
        .nth(1)
        .unwrap()["payload"]["response_id"] = json!("");
    write_rows(&root.join("sessions/b.jsonl"), &b);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (index, _, _) = pages(&root, ScanIndex::default(), &cache, || {
            counters(&cache).memo_records == 1
        });
        let recorded = counters(&cache);
        let replay = group_replays();
        // A large singleton takes the slot and pauses in it.
        write_rows(
            &root.join("sessions/s.jsonl"),
            &chain_rows(OTHER, "s", "2026-10-01T11:00:00Z", 0, 30),
        );
        let ((mut index, _, _), prefix_bytes) = observe_consumed(|| {
            pages(&root, index, &cache, || {
                counters(&cache).jobs_paused > recorded.jobs_paused
            })
        });
        let paused = counters(&cache);
        assert_eq!(completions(&cache), 0, "{paused:?}");
        // The next generation: the group's lookup runs while `s` holds it.
        index.traversal = None;
        let (_, bytes) = observe_consumed(|| {
            pages_at(&root, index, &cache, "2026-10-06T23:01:00Z", || {
                completions(&cache) == 1
            })
        });
        assert_eq!(
            group_replays(),
            replay,
            "no group job or group replay bytes"
        );
        assert_eq!(
            prefix_bytes + bytes,
            fs::metadata(root.join("sessions/s.jsonl")).unwrap().len(),
            "only the singleton reads, once"
        );
        let after = counters(&cache);
        assert_eq!(after.deferred, paused.deferred, "{after:?}");
        assert_eq!(
            after.deferred_rotation, paused.deferred_rotation,
            "{after:?}"
        );
        assert_eq!(cache.rotation_waiters_for_test(), 0, "{after:?}");
    });
    fs::remove_dir_all(root).unwrap();
}

/// The group parser is configured once from every member's
/// evidence and the proof follows the accumulator's own V2 decision (made on
/// the first owned record, after the proof was built). The fixture's UI
/// is unbound-span, which a V2 group holds; inactive, it replays.
#[test]
fn counting_v2_decision_reaches_the_group_proof() {
    let (root, _) = counting_v2_unbound_fixture();
    assert_eq!(
        refused(replay_group(group_of(&root), &ScanIndex::default())),
        Some((JoinRefusal::V2UnboundUi, 1))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retained_parked_group_and_sealed_dependencies_ignore_ctime_only_changes() {
    use std::os::unix::fs::PermissionsExt;
    for change in [
        "chmod_live",
        "chmod_sealed",
        "append_sealed",
        "replace_sealed",
    ] {
        let root = paged_corpus("wake-content");
        let cache = Arc::new(SharedCache::default());
        with_test_limits(2048, 1024, 64, || {
            let ((index, _), first_bytes) = observe_consumed(|| {
                with_test_state_budget(1, || sampled(&root, ScanIndex::default(), 10, &cache))
            });
            assert!(
                first_bytes > 0 && first_bytes < corpus_bytes(&root),
                "one partial attempt"
            );
            assert_eq!(counters(&cache).jobs_state_bound, 1);
            let replay = group_replays();
            let ((index, _), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
            assert_eq!(bytes, 0, "{change}: unchanged parked group never retries");
            assert_eq!(group_replays(), replay);
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
                "replace_sealed" => {
                    let modified = fs::metadata(&path).unwrap().modified().unwrap();
                    let replacement = path.with_extension("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    File::options()
                        .write(true)
                        .open(&replacement)
                        .unwrap()
                        .set_modified(modified)
                        .unwrap();
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
            let ((index, _), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 2));
            let after = counters(&cache);
            if change.starts_with("chmod") {
                assert_eq!(after.parked_hits, 2, "{change}: {after:?}");
                assert_eq!(bytes, 0, "{change}: zero wakes");
                assert_eq!(group_replays(), replay);
            } else {
                assert_eq!(after.parked_hits, 1, "{change}: {after:?}");
                assert!(bytes > 0, "{change}: must wake");
                assert!(cache.paused_group_position().is_some());
                let (_, rest) = observe_consumed(|| {
                    pages_at(&root, index, &cache, "2026-10-06T23:02:00Z", || {
                        completions(&cache) > 0
                    })
                });
                assert_eq!(
                    bytes + rest,
                    corpus_bytes(&root),
                    "{change}: one new attempt"
                );
                assert_eq!(group_replays().0, replay.0 + 1, "{change}: one completion");
                assert!(group_replays().1 > replay.1);
            }
        });
        fs::remove_dir_all(root).unwrap();
    }
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
    // The shared boot boundary precedes the parser, member swap and legacy
    // tee. Those internal helpers receive only members admitted here.
    for position in 0..group.members.len() {
        let mut boot = GroupBoot::new(group.clone(), &index);
        boot.identified = position;
        boot.group.members[position] = compressed.clone();
        assert_refused(CodexZstCause::GroupReadUnsupported, || {
            assert!(matches!(boot.identify(None, &index, None), Boot::Strict));
            assert_eq!(
                boot.identified, position,
                "refused before member acquisition"
            );
        });
    }
    let metadata = CodexTitleMetadata::default();
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
            cache: None,
            index: &index,
        })
        .unwrap();
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

mod independent {
    use super::*;
    include!("independent_tests.rs");
}
