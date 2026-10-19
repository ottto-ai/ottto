//! P2 group StreamProof, ordinal domain and census fencing tests (§n P2).
//! Every fixture is synthetic; no provider account content. Scaled budgets
//! come from `codex_cursor::with_test_limits` only.
use super::super::tests::{fixture, member, replay_group, scan, usage};
use super::*;
use crate::transcript_acquisition::Scope;
use sampled_scan::codex_cursor::{with_test_limits, Counters};
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
        scan_root: PathBuf::from("/fixture/sessions"),
        path: PathBuf::from(format!("/fixture/sessions/{name}")),
        size_bytes: size,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    }
}

/// `plan_group` over header rows and file names (distinct sizes).
fn plan(members: &[(Value, String)]) -> std::result::Result<GroupPlan, JoinRefusal> {
    let headers = members
        .iter()
        .zip(100u64..)
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
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        limit,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope("group-fixture".into()));
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
    // A thread id no member's file carries, or two members carry.
    assert_eq!(
        plan(&[origin.clone(), base(UNKNOWN, 3, 3)]),
        Err(JoinRefusal::AmbiguousPredecessor)
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
