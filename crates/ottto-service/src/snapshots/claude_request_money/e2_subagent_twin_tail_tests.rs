//! A subagent stored in two homes counts each shared request once: a held
//! response inside the copy slack before the later home's birth counts at
//! the earlier home only.
use super::*;
use crate::snapshots::claude_request_census::{
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};

const STEM: &str = "agent-a1";
/// Slot 27: twin requests the page removes from a later home.
const REMOVED: &str = "copy_prefix_twin_page_removed";
const MISSED: &str = "twin_drop_missed";
/// The later home's birth, after T0.
const LATER: i128 = 100_000_000_000;

fn member() -> String {
    format!("{ROOT}_{STEM}")
}
/// The provider time `nanos` (UTC ns).
fn clock(nanos: i128) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
/// 114 ms before a home born at `born`: inside the 2 s copy slack.
fn tail(born: i128) -> String {
    clock(born - 114_000_000)
}
fn zero(id: &str, at: &str) -> Value {
    let mut value = line(id, at, 0);
    value["message"]["usage"]["output_tokens"] = json!(0);
    value
}
/// One subagent's homes, born at `births`, indexed and observed.
fn homes(names: &[&str], births: &[i128]) -> (Vec<PathBuf>, ScanIndex) {
    let dir = scratch("subagent-twin-tail");
    let mut index = ScanIndex::default();
    let paths = names
        .iter()
        .zip(births)
        .map(|(home, birth)| {
            let path = dir
                .join(home)
                .join(ROOT)
                .join(format!("subagents/{STEM}.jsonl"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture\n").unwrap();
            let key = local_index_key(&path);
            index.files.insert(key.clone(), entry());
            index
                .claude_money_birth_store
                .record_observation(&member(), &key, *birth);
            path
        })
        .collect();
    (paths, index)
}
fn remove(paths: &[PathBuf]) {
    fs::remove_dir_all(paths[0].ancestors().nth(4).unwrap()).unwrap();
}
/// s1 and s2 more than 2 s before the later home's birth, s3 inside the slack.
fn shared() -> Vec<Value> {
    vec![
        line("s1", &at(10), 10),
        line("s2", &at(20), 20),
        line("s3", &tail(t0() + LATER), 30),
    ]
}
/// The session after the page: (requests, removed, input, output).
fn body(items: Vec<SnapshotItem>, index: &ScanIndex) -> (u64, u64, u64, u64) {
    publish(items, None, TelemetryRead::Loaded, index)
        .iter()
        .filter(|item| item.source_session_id == member())
        .fold((0, 0, 0, 0), |(r, x, i, o), item| {
            (
                r + item.request_count,
                x + item.removed_request_count.unwrap_or(0),
                i + item.input_tokens,
                o + item.output_tokens,
            )
        })
}
/// Two homes (a at T0, z at T0 + 100 s) parsed undecided onto one page.
fn page(a: &[Value], z: &[Value]) -> (Vec<PathBuf>, ScanIndex, Vec<SnapshotItem>) {
    let (paths, index) = homes(&["a", "z"], &[t0(), t0() + LATER]);
    let items = vec![
        parse_undecided(&paths[0], Some(t0()), &index, a),
        parse_undecided(&paths[1], Some(t0() + LATER), &index, z),
    ];
    (paths, index, items)
}

/// [money] T1: the slack tail counts once, at the earlier home. The later
/// home removes all three; its own-request count loses the dropped tail.
#[test]
fn slack_tail_counts_once_at_the_earlier_home() {
    let (paths, index, mut items) = page(&shared(), &shared());
    assert!(fold(&items[1]).twin_pending);
    assert_eq!(fold(&items[1]).own_requests, 1, "the tail is an own turn");
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    let z = fold(&items[1]);
    assert_eq!((z.entity.totals().1, z.entity.removed_requests), (0, 3));
    assert_eq!(z.own_requests, 0);
    assert!(z.entity.certificate_ok && !z.entity.held);
    assert_eq!(diag.get(REMOVED), Some(&3));
    assert_eq!(diag.get(MISSED), None);
    assert_eq!(body(items, &index), (3, 3, 60, 3));
    remove(&paths);
}

/// [money] T2: an own turn after the shared tail stays counted.
#[test]
fn own_turn_after_the_tail_is_kept() {
    let mut z = shared();
    z.push(line("o1", &at(130), 40));
    let (paths, index, mut items) = page(&shared(), &z);
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    let z = fold(&items[1]);
    assert_eq!((z.entity.totals().1, z.entity.removed_requests), (1, 3));
    assert_eq!(z.own_requests, 1);
    assert_eq!(diag.get(REMOVED), Some(&3));
    assert_eq!(body(items, &index), (4, 3, 100, 4));
    remove(&paths);
}

/// [control] T3b: the earlier home off the page, known only by its current
/// census, proves no removal: the later home counts every id, disclosed.
#[test]
fn earlier_home_known_only_by_census_proves_nothing() {
    for state in ["absent", "unreadable"] {
        let (paths, mut index) = homes(&["a", "z"], &[t0(), t0() + LATER]);
        let mut hashes = ["s1", "s2", "s3"].map(claude_request_hash).to_vec();
        hashes.sort_unstable();
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            "fixture",
            1,
            ClaudeRequestCensusShape::Exact,
            hashes,
        );
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&local_index_key(&paths[0]), record);
        fs::remove_file(&paths[0]).unwrap();
        if state == "unreadable" {
            fs::create_dir(&paths[0]).unwrap();
        }
        let mut items = vec![parse_undecided(
            &paths[1],
            Some(t0() + LATER),
            &index,
            &shared(),
        )];
        take_diag();
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let z = fold(&items[0]);
        assert_eq!(
            (z.entity.totals().1, z.entity.removed_requests),
            (3, 0),
            "{state}"
        );
        assert_eq!(diag.get("copy_uncovered"), Some(&2), "{state}");
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (None, None));
        remove(&paths);
    }
}

/// [money] T5: a subagent is placed under its root's starting account,
/// whatever its own markers say. Dropping the tail removes it from that
/// account once: the placement equals that of a tail the later home skips
/// natively, and the root's own switch keeps both of its accounts.
#[test]
fn dropped_tail_leaves_root_placement_unchanged() {
    let place = |tail_at: String| {
        let (paths, index) = homes(&["a", "z"], &[t0(), t0() + LATER]);
        let root = paths[0]
            .ancestors()
            .nth(3)
            .unwrap()
            .join(format!("{ROOT}.jsonl"));
        fs::write(&root, b"fixture\n").unwrap();
        let sub = |id: &str, at: &str, input| {
            let mut value = line(id, at, input);
            value["agentId"] = json!("a1");
            value["isSidechain"] = json!(true);
            value
        };
        let (s1, s2, s3) = (
            sub("s1", &at(10), 10),
            sub("s2", &at(20), 20),
            sub("s3", &tail_at, 30),
        );
        let earlier = [org_marker(ORG_B), s1.clone(), s2.clone(), s3.clone()];
        // The later home switches account on the row it drops.
        let later = [
            org_marker(ORG_A),
            s1,
            s2,
            switch_context(),
            org_marker(ORG_B),
            s3,
            sub("o1", &at(130), 40),
        ];
        let root_lines = [
            org_marker(ORG_A),
            line("r1", &at(1), 5),
            switch_context(),
            org_marker(ORG_B),
            line("r2", &at(140), 7),
        ];
        let items = tag_owned(
            vec![
                parse_undecided(&root, Some(t0()), &index, &root_lines),
                parse_undecided(&paths[0], Some(t0()), &index, &earlier),
                parse_undecided(&paths[1], Some(t0() + LATER), &index, &later),
            ],
            &index,
        );
        remove(&paths);
        items
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    (
                        org_amounts(item),
                        item.request_count,
                        item.removed_request_count,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let dropped = place(tail(t0() + LATER));
    let (a, b) = (org_hash(ORG_A), org_hash(ORG_B));
    assert_eq!(
        dropped[&member()],
        (BTreeMap::from([(a.clone(), (100, 4))]), 4, Some(3))
    );
    assert_eq!(dropped[ROOT].0, BTreeMap::from([(a, (5, 1)), (b, (7, 1))]));
    let skipped = place(clock(t0() + LATER - 3_000_000_000));
    assert_eq!(dropped, skipped);
}

/// [control] T6 (i): a tail more than 2 s before birth is a native skip, as
/// before: removed and counted in slot 27 by the skipped arm.
#[test]
fn tail_outside_the_slack_stays_a_native_skip() {
    let mut lines = shared();
    lines[2] = line("s3", &clock(t0() + LATER - 3_000_000_000), 30);
    let (paths, index, mut items) = page(&lines, &lines);
    assert_eq!(fold(&items[1]).own_requests, 0);
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    assert_eq!(fold(&items[1]).entity.removed_requests, 3);
    assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&3), None));
    assert_eq!(body(items, &index), (3, 3, 60, 3));
    remove(&paths);
}

/// [control] T6 (ii): a forked first line, held by the root on the page and
/// by the earlier home, is removed once. The twin pass drops it and counts
/// it in slot 27; the family pass then finds it skipped. Money as before.
#[test]
fn forked_first_line_is_removed_once() {
    let fork = line("fork", &clock(t0() + LATER - 500_000_000), 5);
    let earlier = [fork.clone(), line("s1", &at(10), 10)];
    let mut later = earlier.to_vec();
    later.push(line("o1", &at(130), 40));
    let (paths, index, mut items) = page(&earlier, &later);
    let root = paths[1]
        .ancestors()
        .nth(3)
        .unwrap()
        .join(format!("{ROOT}.jsonl"));
    fs::write(&root, b"fixture\n").unwrap();
    items.insert(
        0,
        parse_undecided(&root, Some(t0()), &index, &[line("r1", &at(1), 3), fork]),
    );
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    let z = fold(&items[2]);
    assert_eq!((z.entity.totals().1, z.entity.removed_requests), (1, 2));
    assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&2), None));
    // The earlier home's root is not on the page: it keeps the fork.
    assert_eq!(diag.get("family_copy_deferred"), Some(&1));
    assert_eq!(body(items, &index), (3, 2, 55, 3));
    remove(&paths);
}

/// [control] T6 (iii): a subagent with no twin, whose tail is inside the
/// slack, keeps today's decision: its copies count, disclosed.
#[test]
fn lone_subagent_with_a_slack_tail_is_unchanged() {
    let (paths, index) = homes(&["z"], &[t0() + LATER]);
    let mut items = vec![parse_undecided(
        &paths[0],
        Some(t0() + LATER),
        &index,
        &shared(),
    )];
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    let z = fold(&items[0]);
    assert_eq!((z.entity.totals().1, z.entity.removed_requests), (3, 0));
    assert_eq!(diag.get("copy_uncovered"), Some(&2));
    assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (None, None));
    remove(&paths);
}

/// [control] T6 (iv): a zero-usage response in both homes is never dropped;
/// the session counts the nonzero union.
#[test]
fn zero_usage_response_in_both_homes_is_not_dropped() {
    let mut lines = shared();
    lines.insert(2, zero("nil", &clock(t0() + LATER - 500_000_000)));
    let (paths, index, mut items) = page(&lines, &lines);
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    assert_eq!(fold(&items[1]).entity.removed_requests, 3);
    assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&3), None));
    assert_eq!(body(items, &index), (3, 3, 60, 3));
    remove(&paths);
}

/// [money] T8: a grandfathered later home (COPY mark, accepted body, no
/// stored removal) keeps its accepted skips and drops only the slack tail:
/// n, not n + 1. A second read is identical.
#[test]
fn grandfathered_later_home_only_drops_the_tail() {
    let (paths, mut index) = homes(&["a", "z"], &[t0(), t0() + LATER]);
    let key = local_index_key(&paths[1]);
    index
        .claude_money_birth_store
        .set_money_marks(&key, money_mark::COPY);
    crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test(&mut index, &key);
    let mut later = shared();
    later.push(line("o1", &at(130), 40));
    let read = |index: &ScanIndex| {
        let mut items = vec![
            parse_undecided(&paths[0], Some(t0()), index, &shared()),
            parse_undecided(&paths[1], Some(t0() + LATER), index, &later),
        ];
        assert!(fold(&items[1]).grandfathered && !fold(&items[1]).twin_pending);
        assert_eq!(fold(&items[1]).own_requests, 2);
        take_diag();
        decide_page_copies(&mut items, index, None);
        let diag = take_diag();
        let z = fold(&items[1]);
        assert!(z.grandfathered);
        assert_eq!((z.entity.totals().1, z.entity.removed_requests), (1, 3));
        assert_eq!(z.own_requests, 1);
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&1), None));
        publish(items, None, TelemetryRead::Loaded, index)
    };
    let first = read(&index);
    let session = first
        .iter()
        .find(|item| item.source_session_id == member())
        .unwrap();
    assert_eq!(
        (session.request_count, session.removed_request_count),
        (4, Some(3))
    );
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(read(&index)).unwrap()
    );
    remove(&paths);
}

/// [money] T9: held responses with no or an unparseable time are never
/// dropped, before or after the later home's first own turn or with none:
/// no panic, counted, disclosed, own requests unchanged.
#[test]
fn untimed_held_responses_stay_counted() {
    let untimed = || {
        let mut none = line("u1", &at(30), 15);
        none.as_object_mut().unwrap().remove("timestamp");
        let mut bad = line("u2", &at(40), 25);
        bad["timestamp"] = json!("not a time");
        [none, bad]
    };
    let s1 = line("s1", &at(10), 10);
    let own = line("o1", &at(130), 40);
    let [u1, u2] = untimed();
    let orders = [
        vec![s1.clone(), own.clone(), u1.clone(), u2.clone()],
        vec![s1.clone(), u1.clone(), u2.clone(), own.clone()],
        vec![s1.clone(), u1.clone(), u2.clone()],
    ];
    for later in orders {
        let owned = u64::from(later.len() == 4);
        take_diag();
        let (paths, index, mut items) = page(&[s1.clone(), u1.clone(), u2.clone()], &later);
        assert!(take_diag().get("untimed_record").is_some_and(|n| *n >= 2));
        let before = fold(&items[1]).own_requests;
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let z = fold(&items[1]);
        assert_eq!(
            (z.entity.totals().1, z.entity.removed_requests),
            (2 + owned, 1)
        );
        assert_eq!(z.own_requests, before);
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&1), None));
        remove(&paths);
    }
}

/// [money] T10: three homes b < a < z, the tail inside the slack of a and
/// z: counted once at b, removed once by each later home. Equal births
/// order by location, so either page order gives the same body.
#[test]
fn three_homes_count_the_tail_once() {
    let a_born = t0() + LATER - 500_000_000;
    let lines = [
        line("s1", &at(10), 10),
        line("s2", &at(20), 20),
        line("s3", &tail(a_born), 30),
    ];
    for (births, reversed) in [
        ([t0(), a_born, t0() + LATER], false),
        ([t0(), t0() + LATER, t0() + LATER], false),
        ([t0(), t0() + LATER, t0() + LATER], true),
    ] {
        let (paths, index) = homes(&["b", "a", "z"], &births);
        let mut items = paths
            .iter()
            .zip(births)
            .map(|(path, birth)| parse_undecided(path, Some(birth), &index, &lines))
            .collect::<Vec<_>>();
        if reversed {
            items.reverse();
        }
        take_diag();
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let counted = items
            .iter()
            .map(|item| fold(item).entity.totals().1)
            .sum::<u64>();
        assert_eq!(counted, 3, "{births:?} {reversed}");
        assert!(items
            .iter()
            .all(|item| fold(item).entity.removed_requests <= 3));
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&6), None));
        assert_eq!(body(items, &index), (3, 6, 60, 3), "{births:?} {reversed}");
        remove(&paths);
    }
}

/// [money] T11: a drop whose grain cannot give the request back leaves it
/// counted, disclosed, and slot 27 counts only successes.
#[test]
fn missed_drop_stays_counted_and_disclosed() {
    let (paths, index, mut items) = page(&shared(), &shared());
    // Test-only skew: the tail's grain key no longer finds its counted grain.
    let occurrence = items[1]
        .claude_usage_occurrences
        .values_mut()
        .max_by_key(|occurrence| occurrence.sequence)
        .unwrap();
    occurrence.model = Some("claude-skewed".into());
    let disclosed = fold(&items[1]).disclosed;
    take_diag();
    decide_page_copies(&mut items, &index, None);
    let diag = take_diag();
    let z = fold(&items[1]);
    assert_eq!((z.entity.totals().1, z.entity.removed_requests), (1, 2));
    assert_eq!(z.own_requests, 1);
    assert_eq!(z.disclosed, disclosed + 1);
    assert!(z.entity.certificate_ok);
    assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&2), Some(&1)));
    remove(&paths);
}

/// [money] T12: a held response inside the slack after the later home's
/// first own turn drops only from 2026-11-05Z; before then it stays counted.
#[test]
fn held_tail_after_an_own_turn_drops_only_from_the_cutoff() {
    for (base, drops) in [(t0(), false), (SUBAGENT_TWIN_FROM + 600_000_000_000, true)] {
        let (paths, index) = homes(&["a", "z"], &[base, base + LATER]);
        let s1 = line("s1", &clock(base + 10_000_000_000), 10);
        let s2 = line("s2", &tail(base + LATER), 30);
        let own = line("o1", &clock(base + LATER - 1_000_000_000), 40);
        let mut items = vec![
            parse_undecided(&paths[0], Some(base), &index, &[s1.clone(), s2.clone()]),
            parse_undecided(&paths[1], Some(base + LATER), &index, &[s1, own, s2]),
        ];
        take_diag();
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let z = fold(&items[1]);
        let dropped = u64::from(drops);
        assert_eq!(
            (z.entity.totals().1, z.entity.removed_requests),
            (2 - dropped, 1 + dropped)
        );
        assert_eq!(diag.get(REMOVED), Some(&(1 + dropped)));
        assert_eq!(diag.get(MISSED), None);
        remove(&paths);
    }
}

/// [money] T13: a zero-usage held id before the first own turn, in the
/// grain of a later own response (and, second, in no counted grain), is
/// never dropped: nothing is subtracted, the own response still counts.
#[test]
fn zero_usage_held_id_never_subtracts_an_own_response() {
    for model in ["claude-haiku-4-5", "claude-sonnet-4-5"] {
        let mut nil = zero("nil", &clock(t0() + LATER - 1_000_000_000));
        nil["message"]["model"] = json!(model);
        let held = [line("s1", &at(10), 10), nil];
        let mut later = held.to_vec();
        later.push(line("own", &at(130), 40));
        let (paths, index, mut items) = page(&held, &later);
        assert!(fold(&items[1]).twin_pending);
        take_diag();
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let z = fold(&items[1]);
        assert_eq!(
            (z.entity.totals().1, z.entity.removed_requests),
            (1, 1),
            "{model}"
        );
        assert_eq!(z.entity.totals().0.input, 40, "{model}");
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&1), None));
        remove(&paths);
    }
}
