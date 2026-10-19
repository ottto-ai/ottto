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
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        collected_at,
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
