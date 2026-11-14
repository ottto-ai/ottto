//! A subagent stored in two homes counts each shared request once: a held
//! response inside the copy slack before the later home's birth counts at
//! the earlier home only.
use super::*;

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

/// [money] T1: the slack tail counts once, at the earlier home: the later
/// home removes all three shared requests and its own-request count loses
/// the dropped tail. An own turn after the tail stays counted (T2).
#[test]
fn slack_tail_counts_once_at_the_earlier_home() {
    for own in [false, true] {
        let mut later = shared();
        if own {
            later.push(line("o1", &at(130), 40));
        }
        let owned = u64::from(own);
        let (paths, index, mut items) = page(&shared(), &later);
        assert!(fold(&items[1]).twin_pending);
        assert_eq!(fold(&items[1]).own_requests, 1 + owned, "the tail is own");
        take_diag();
        decide_page_copies(&mut items, &index, None);
        let diag = take_diag();
        let z = fold(&items[1]);
        assert_eq!((z.entity.totals().1, z.entity.removed_requests), (owned, 3));
        assert_eq!(z.own_requests, owned);
        assert!(z.entity.certificate_ok && !z.entity.held);
        assert_eq!((diag.get(REMOVED), diag.get(MISSED)), (Some(&3), None));
        assert_eq!(
            body(items, &index),
            (3 + owned, 3, 60 + 40 * owned, 3 + owned)
        );
        remove(&paths);
    }
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
