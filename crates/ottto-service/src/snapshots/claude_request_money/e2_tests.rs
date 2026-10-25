use super::*;
use crate::claude_local_otel::{ClaudeApiEvidenceRead, ClaudeTraceOwnershipLoadReport};
use crate::snapshots::tests::{complete_api_row, complete_trace_row};
use crate::snapshots::{
    apply_claude_code_line, ClaudeRemovedUsage, ScanIndexEntry, SnapshotAccumulator, SnapshotSource,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const ROOT: &str = "a0000000-0000-4000-8000-00000000000a";
/// Birth of the first file; `complete_api_row` reports this hour.
const T0: &str = "2026-08-02T07:00:00Z";
const HOUR: &str = "2026-08-02T07:00:00Z";

fn t0() -> i128 {
    rfc3339_unix_nanos(T0).unwrap()
}
fn at(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(t0() + i128::from(seconds) * 1_000_000_000)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
fn line(id: &str, clock: &str, input: u64) -> Value {
    json!({"type":"assistant","version":"2.1.309","sessionId":ROOT,"timestamp":clock,
        "requestId":id,"message":{"id":format!("msg-{id}"),"model":"claude-haiku-4-5",
        "usage":{"input_tokens":input,"output_tokens":1}}})
}
fn versioned(mut value: Value, version: &str) -> Value {
    value["version"] = json!(version);
    value
}
fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-e2-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}
/// A root transcript path in its own scratch directory, written to disk.
fn root_file(name: &str) -> PathBuf {
    let path = scratch(name).join(format!("{ROOT}.jsonl"));
    fs::write(&path, b"fixture\n").unwrap();
    path
}
fn entry() -> ScanIndexEntry {
    serde_json::from_value(
        json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fixture"}),
    )
    .unwrap()
}
fn parse(path: &Path, birth: Option<i128>, index: &ScanIndex, lines: &[Value]) -> SnapshotItem {
    let mut a = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let opened = fs::File::open(path).unwrap().metadata().unwrap();
    a.claude_file_birth = ClaudeFileBirth::observe(path, Some(&opened));
    if let Some(birth) = birth {
        a.claude_file_birth.set_birth_for_test(birth);
    }
    for value in lines {
        apply_claude_code_line(value, &mut a);
    }
    a.finalize_claude_responses_e2(None, Some(ReadContext { index, path }));
    a.into_items(path, "2026-08-02T09:00:00Z", "fixture".into(), None)
        .remove(0)
}
/// Parse, then record the read like the scan does (birth + indexed path).
fn parse_and_remember(
    path: &Path,
    birth: i128,
    index: &mut ScanIndex,
    lines: &[Value],
) -> SnapshotItem {
    let item = parse(path, Some(birth), index, lines);
    remember_birth(index, path, item.claude_money.as_deref().unwrap());
    index.files.insert(local_index_key(path), entry());
    item
}
fn restart(index: &ScanIndex) -> ScanIndex {
    serde_json::from_slice(&serde_json::to_vec(index).unwrap()).unwrap()
}
fn fold(item: &SnapshotItem) -> &FileFold {
    item.claude_money.as_deref().unwrap()
}
fn requests(item: &SnapshotItem, origin: Option<ClaudeRequestUsageOrigin>) -> u64 {
    fold(item)
        .entity
        .grains
        .iter()
        .filter(|((_, o), _)| *o == origin)
        .map(|(_, grain)| grain.requests)
        .sum()
}
const MATCHED: Option<ClaudeRequestUsageOrigin> = Some(ClaudeRequestUsageOrigin::TelemetryMatched);
const UNPRICED: Option<ClaudeRequestUsageOrigin> =
    Some(ClaudeRequestUsageOrigin::TelemetryUnpriced);
const REPORTED: Option<ClaudeRequestUsageOrigin> =
    Some(ClaudeRequestUsageOrigin::TelemetryReported);

fn row(id: &str, sequence: u64, input: u64) -> ClaudeLocalOtelEvidence {
    complete_api_row(ROOT, id, sequence, input, 1, 0)
}
fn refingerprint(mut row: ClaudeLocalOtelEvidence) -> ClaudeLocalOtelEvidence {
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
/// The live sidecar reader over exactly these rows for ROOT.
fn sidecar(rows: &[ClaudeLocalOtelEvidence]) -> ClaudeApiEvidenceRead {
    let support = scratch("support");
    let dir = support.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&dir).unwrap();
    let body = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(
        dir.join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes()))),
        body,
    )
    .unwrap();
    let read = ClaudeApiEvidenceRead::load(&support, [ROOT.to_owned()]).unwrap();
    fs::remove_dir_all(support).unwrap();
    read
}
fn api_report(read: &ClaudeApiEvidenceRead) -> ClaudeLocalOtelLoadReport {
    ClaudeLocalOtelLoadReport {
        evidence: read.evidence.clone(),
        health: Default::default(),
    }
}
/// The page path with the gate on: attach, side calls, finish.
fn publish(
    mut items: Vec<SnapshotItem>,
    read: Option<&ClaudeApiEvidenceRead>,
    telemetry: TelemetryRead,
    index: &ScanIndex,
) -> Vec<SnapshotItem> {
    if let Some(read) = read {
        attach_page(&mut items, read);
        side_calls_page(
            &mut items,
            &api_report(read),
            &ClaudeTraceOwnershipLoadReport::default(),
            index,
        );
    }
    with_enabled(|| finish_page(&mut items, index, telemetry));
    items
}
fn rows_of(item: &SnapshotItem) -> impl Iterator<Item = &crate::snapshots::SnapshotModelUsage> {
    item.model_usage.iter().chain(
        item.usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage),
    )
}
fn cleanup(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}

#[test]
fn e2_thinking_300_matches_an_otel_zero_and_rejects_a_different_count() {
    let p = root_file("thinking");
    let index = ScanIndex::default();
    let mut thinking = line("r", &at(1), 10);
    thinking["message"]["usage"]["output_tokens"] = json!(301);
    thinking["message"]["usage"]["output_tokens_details"] = json!({"thinking_tokens":300});
    let item = parse(&p, Some(t0()), &index, std::slice::from_ref(&thinking));
    let mut otel = complete_api_row(ROOT, "r", 1, 10, 301, 0);
    assert_eq!(otel.reasoning_output_tokens, 0);
    let got = publish(
        vec![item],
        Some(&sidecar(&[otel.clone()])),
        TelemetryRead::Loaded,
        &index,
    );
    assert_eq!(got[0].reasoning_output_tokens, 300, "transcript tokens win");
    assert_eq!(got[0].telemetry_owned_complete, Some(true));
    assert_eq!(
        got[0].cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0001")
    );
    otel.reasoning_output_tokens = 299;
    let mut items = vec![parse(&p, Some(t0()), &index, &[thinking])];
    attach_page(&mut items, &sidecar(&[refingerprint(otel)]));
    assert_eq!(requests(&items[0], MATCHED), 0);
    assert_eq!(requests(&items[0], None), 1);
    assert_eq!(fold(&items[0]).disclosed, 1, "incompatible row disclosed");
    cleanup(&[&p]);
}

#[test]
fn e2_model_less_record_attaches_through_its_native_fallback_key() {
    let p = root_file("model-none");
    let index = ScanIndex::default();
    let mut bare = line("b", &at(2), 20);
    bare["message"].as_object_mut().unwrap().remove("model");
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("a", &at(1), 10), bare],
    )];
    assert_eq!(fold(&items[0]).model_fallbacks.len(), 1);
    attach_page(&mut items, &sidecar(&[row("b", 2, 20)]));
    let f = fold(&items[0]);
    assert_eq!(
        (requests(&items[0], MATCHED), requests(&items[0], None)),
        (1, 1)
    );
    assert_eq!(f.disclosed, 0);
    assert_eq!(f.entity.totals().0.input, 30);
    cleanup(&[&p]);
}

#[test]
fn e2_untimed_record_attaches_from_the_bucket_fallback() {
    let p = root_file("untimed");
    let index = ScanIndex::default();
    let mut untimed = line("b", &at(2), 20);
    untimed.as_object_mut().unwrap().remove("timestamp");
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("a", &at(1), 10), untimed],
    )];
    assert_eq!(
        fold(&items[0]).disclosed,
        1,
        "untimed root record disclosed"
    );
    assert_eq!(fold(&items[0]).entity.totals().1, 2);
    attach_page(&mut items, &sidecar(&[row("b", 2, 20)]));
    assert_eq!(
        (requests(&items[0], MATCHED), requests(&items[0], None)),
        (1, 1)
    );
    assert_eq!(fold(&items[0]).disclosed, 1, "the attach discloses nothing");
    cleanup(&[&p]);
}

#[test]
fn e2_hour_boundary_keeps_the_transcript_hour() {
    let p = root_file("hour");
    let index = ScanIndex::default();
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("r", "2026-08-02T07:59:59.900Z", 10)],
    )];
    let mut late = row("r", 1, 10);
    late.observed_at = "2026-08-02T08:00:01Z".into();
    attach_page(&mut items, &sidecar(&[refingerprint(late)]));
    let buckets = fold(&items[0])
        .entity
        .grains
        .keys()
        .map(|(key, origin)| (key.0.as_str(), *origin))
        .collect::<Vec<_>>();
    assert_eq!(buckets, vec![(HOUR, MATCHED)]);
    cleanup(&[&p]);
}

#[test]
fn e2_otel_only_fast_speed_and_effort_join_the_reported_key() {
    let p = root_file("speed");
    let index = ScanIndex::default();
    let items = vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])];
    let estimated = fold(&items[0])
        .entity
        .grains
        .keys()
        .next()
        .unwrap()
        .0
        .clone();
    assert!(!estimated.2.contains_key("speed_mode"));
    let mut items = items;
    attach_page(&mut items, &sidecar(&[row("r", 1, 10)]));
    let ((key, origin), _) = fold(&items[0]).entity.grains.iter().next().unwrap();
    assert_eq!(*origin, MATCHED);
    assert!(key.2.contains_key("speed_mode"), "OTEL speed joins the key");
    assert_eq!(
        key.2.get("reasoning_effort").map(String::as_str),
        Some("high")
    );
    let got = publish(items, None, TelemetryRead::Loaded, &index);
    assert!(rows_of(&got[0]).all(|row| row.reasoning_effort.as_deref() == Some("high")));
    cleanup(&[&p]);
}

#[test]
fn e2_failed_or_missing_telemetry_read_is_never_complete() {
    let p = root_file("failed");
    let index = ScanIndex::default();
    let lines = [line("r", &at(1), 10)];
    let read = sidecar(&[row("r", 1, 10)]);
    let ok = publish(
        vec![parse(&p, Some(t0()), &index, &lines)],
        Some(&read),
        TelemetryRead::Loaded,
        &index,
    );
    assert_eq!(ok[0].telemetry_owned_complete, Some(true));
    let failed = publish(
        vec![parse(&p, Some(t0()), &index, &lines)],
        Some(&read),
        TelemetryRead::Failed,
        &index,
    );
    assert_eq!(failed[0].telemetry_owned_complete, Some(false));
    let unread = publish(
        vec![parse(&p, Some(t0()), &index, &lines)],
        None,
        TelemetryRead::Loaded,
        &index,
    );
    assert_eq!(unread[0].telemetry_owned_complete, Some(false));
    assert!(unread[0].cost.is_none());
    cleanup(&[&p]);
}

#[test]
fn e2_oversized_sidecar_is_incomplete_and_attaches_nothing() {
    let p = root_file("oversized");
    let index = ScanIndex::default();
    let support = scratch("oversized-support");
    let dir = support.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&dir).unwrap();
    fs::File::create(dir.join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes()))))
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let read = ClaudeApiEvidenceRead::load(&support, [ROOT.to_owned()]).unwrap();
    let mut items = vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])];
    attach_page(&mut items, &read);
    assert!(fold(&items[0]).telemetry.read);
    assert!(!fold(&items[0]).telemetry.complete);
    let got = publish(items, None, TelemetryRead::Loaded, &index);
    assert_eq!(got[0].telemetry_owned_complete, Some(false));
    assert!(got[0].cost.is_none());
    assert_eq!(got[0].request_count, 1);
    fs::remove_dir_all(support).unwrap();
    cleanup(&[&p]);
}

#[test]
fn e2_path_twins_attach_the_row_once() {
    let first = root_file("twin-a");
    let copy = root_file("twin-b");
    let mut index = ScanIndex::default();
    let own = parse_and_remember(&first, t0(), &mut index, &[line("r", &at(1), 10)]);
    let twin = parse(
        &copy,
        Some(t0() + 60_000_000_000),
        &index,
        &[line("r", &at(1), 10), line("o", &at(61), 20)],
    );
    assert_eq!(fold(&twin).entity.removed_requests, 1, "the copy is held");
    for order in [vec![own.clone(), twin.clone()], vec![twin, own]] {
        let read = sidecar(&[row("r", 1, 10)]);
        let mut items = order;
        attach_page(&mut items, &read);
        attach_page(&mut items, &read); // a second call moves nothing
        assert_eq!(items.iter().map(|i| requests(i, MATCHED)).sum::<u64>(), 1);
        let got = publish(items, None, TelemetryRead::Loaded, &index);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].request_count, got[0].input_tokens), (2, 30));
        assert_eq!(got[0].removed_request_count, Some(1));
        assert_eq!(
            got[0].cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0001")
        );
    }
    cleanup(&[&first, &copy]);
}

#[test]
fn e2_unpriced_row_is_telemetry_unpriced() {
    let p = root_file("unpriced");
    let index = ScanIndex::default();
    let mut unpriced = row("r", 1, 10);
    unpriced.cost_usd_micros = None;
    let got = publish(
        vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])],
        Some(&sidecar(&[refingerprint(unpriced)])),
        TelemetryRead::Loaded,
        &index,
    );
    assert!(got[0].cost.is_none());
    assert_eq!(got[0].telemetry_owned_complete, Some(true));
    assert!(rows_of(&got[0]).all(|row| {
        row.cost_usd.is_none()
            && row
                .selector_context
                .get("request_usage_origin")
                .map(String::as_str)
                == Some("telemetry_unpriced")
    }));
    cleanup(&[&p]);
}

#[test]
fn e2_priced_and_unpriced_rows_in_one_hour_stay_separate() {
    let p = root_file("mixed");
    let index = ScanIndex::default();
    let mut unpriced = row("u", 2, 20);
    unpriced.cost_usd_micros = None;
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("p", &at(1), 10), line("u", &at(2), 20)],
    )];
    attach_page(
        &mut items,
        &sidecar(&[row("p", 1, 10), refingerprint(unpriced)]),
    );
    assert_eq!(
        (requests(&items[0], MATCHED), requests(&items[0], UNPRICED)),
        (1, 1)
    );
    let got = publish(items, None, TelemetryRead::Loaded, &index);
    assert_eq!(got[0].request_count, 2);
    assert_eq!(
        got[0].cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0001")
    );
    let origins = got[0].usage_buckets[0]
        .model_usage
        .iter()
        .map(|row| row.selector_context["request_usage_origin"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        origins,
        BTreeSet::from(["telemetry_matched", "telemetry_unpriced"])
    );
    cleanup(&[&p]);
}

#[test]
fn e2_move_then_copy_across_restart_counts_each_request_once() {
    let a = root_file("move-a");
    let b = root_file("move-b");
    let c = root_file("move-c");
    let history = [line("h1", &at(1), 1), line("h2", &at(2), 2)];
    let mut index = ScanIndex::default();
    parse_and_remember(&a, t0(), &mut index, &history);
    let mut index = restart(&index);
    // Move: A is gone, B is a new inode born later with A's history.
    fs::remove_file(&a).unwrap();
    index.files.remove(&local_index_key(&a));
    let moved = [
        history[0].clone(),
        history[1].clone(),
        line("h3", &at(70), 4),
    ];
    let b_moved = parse_and_remember(&b, t0() + 60_000_000_000, &mut index, &moved);
    assert_eq!(
        fold(&b_moved).entity.totals().1,
        3,
        "a move inherits the cutoff"
    );
    assert_eq!(fold(&b_moved).birth(), Some(t0()));
    let mut index = restart(&index);
    // Copy of the live B: its history is held, its own line counts.
    let copied = [
        moved[0].clone(),
        moved[1].clone(),
        moved[2].clone(),
        line("h4", &at(130), 8),
    ];
    for _pass in 0..2 {
        stage_twins(
            &mut index,
            &[(&b, t0() + 60_000_000_000), (&c, t0() + 120_000_000_000)],
        );
        let b_item = parse(&b, Some(t0() + 60_000_000_000), &index, &moved);
        let c_item = parse_and_remember(&c, t0() + 120_000_000_000, &mut index, &copied);
        assert_eq!(fold(&c_item).entity.removed_requests, 3);
        let got = publish(vec![b_item, c_item], None, TelemetryRead::Loaded, &index);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].request_count, got[0].input_tokens), (4, 15));
        assert_eq!(got[0].removed_request_count, Some(3));
        index = restart(&index);
    }
    cleanup(&[&a, &b, &c]);
}

#[test]
fn e2_restored_twins_both_prebirth_skip_exactly_one_never_both() {
    let history = [line("h1", &at(-100), 1), line("h2", &at(-90), 2)];
    for (x_birth, y_birth) in [(0, 5), (5, 0), (0, 0)] {
        let x = root_file("restored-x");
        let y = root_file("restored-y");
        let (x_birth, y_birth) = (
            t0() + x_birth * 1_000_000_000,
            t0() + y_birth * 1_000_000_000,
        );
        let mut index = ScanIndex::default();
        parse_and_remember(&x, x_birth, &mut index, &history);
        parse_and_remember(&y, y_birth, &mut index, &history);
        let mut index = restart(&index);
        stage_twins(&mut index, &[(&x, x_birth), (&y, y_birth)]);
        let xs = parse(&x, Some(x_birth), &index, &history);
        let ys = parse(&y, Some(y_birth), &index, &history);
        let skipped = [&xs, &ys]
            .iter()
            .filter(|item| fold(item).entity.removed_requests == 2)
            .count();
        assert_eq!(skipped, 1, "births {x_birth} {y_birth}");
        let got = publish(
            vec![xs.clone(), ys.clone()],
            None,
            TelemetryRead::Loaded,
            &index,
        );
        assert_eq!(
            (got[0].request_count, got[0].removed_request_count),
            (2, Some(2))
        );
        // The surviving original is deleted: the held copy counts again.
        let (kept, held) = if fold(&xs).entity.removed_requests == 0 {
            (&x, (&y, y_birth))
        } else {
            (&y, (&x, x_birth))
        };
        fs::remove_file(kept).unwrap();
        stage_twins(&mut index, &[(&x, x_birth), (&y, y_birth)]);
        let alone = parse(held.0, Some(held.1), &index, &history);
        assert_eq!(fold(&alone).entity.removed_requests, 0);
        assert_eq!(fold(&alone).entity.totals().1, 2);
        cleanup(&[&x, &y]);
    }
}

#[test]
fn e2_writer_certificate_refuses_mixed_versions_in_either_order() {
    let p = root_file("writers");
    let index = ScanIndex::default();
    let copy = |version| versioned(line("c", &at(-100), 10), version);
    for (copy_version, first, second, certified) in [
        ("2.1.309", "2.1.309", "2.1.309", true),
        ("2.0.0", "2.1.310", "2.1.310", true),
        ("2.1.309", "2.1.309", "99.0.0", false),
        ("2.1.309", "99.0.0", "2.1.309", false),
        ("2.1.309", "2.1.309", "2.1.310", false),
        ("2.1.309", "2.1.310", "2.1.309", false),
    ] {
        let lines = [
            copy(copy_version),
            versioned(line("o1", &at(1), 20), first),
            versioned(line("o2", &at(2), 30), second),
        ];
        let got = parse(&p, Some(t0()), &index, &lines);
        let f = fold(&got);
        let case = format!("{copy_version} {first} {second}");
        assert_eq!(f.entity.removed_requests, u64::from(certified), "{case}");
        assert_eq!(f.entity.totals().1, 3 - u64::from(certified), "{case}");
        assert_eq!(f.disclosed, u64::from(!certified), "{case}");
    }
    cleanup(&[&p]);
}

#[test]
fn e2_exact_removal_totals() {
    let p = root_file("removal");
    let index = ScanIndex::default();
    let mut copy = line("c", &at(-100), 10);
    copy["message"]["usage"]["output_tokens"] = json!(4);
    copy["message"]["usage"]["cache_read_input_tokens"] = json!(7);
    let got = publish(
        vec![parse(
            &p,
            Some(t0()),
            &index,
            &[copy, line("o1", &at(1), 20), line("o2", &at(2), 30)],
        )],
        None,
        TelemetryRead::Loaded,
        &index,
    );
    assert_eq!((got[0].request_count, got[0].input_tokens), (2, 50));
    assert_eq!((got[0].output_tokens, got[0].cache_read_tokens), (2, 0));
    assert_eq!(got[0].removed_request_count, Some(1));
    assert_eq!(
        got[0].removed_usage,
        Some(ClaudeRemovedUsage {
            input_tokens: 10,
            output_tokens: 4,
            cache_read_tokens: 7,
            ..Default::default()
        })
    );
    cleanup(&[&p]);
}

#[test]
fn e2_side_call_goes_to_the_trace_named_subagent_else_the_root() {
    let p = root_file("side");
    let agent = p
        .parent()
        .unwrap()
        .join(ROOT)
        .join("subagents/agent-abc.jsonl");
    fs::create_dir_all(agent.parent().unwrap()).unwrap();
    fs::write(&agent, b"fixture\n").unwrap();
    let index = ScanIndex::default();
    let mut sub = line("s", &at(3), 30);
    sub["agentId"] = json!("abc");
    sub["isSidechain"] = json!(true);
    let mut items = vec![
        parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)]),
        parse(&agent, Some(t0()), &index, &[sub]),
    ];
    let subagent = items[1].source_session_id.clone();
    assert_eq!(subagent, format!("{ROOT}_agent-abc"));
    let read = sidecar(&[
        row("r", 1, 10),
        row("s", 3, 30),
        row("named", 4, 40),
        row("orphan", 5, 50),
    ]);
    attach_page(&mut items, &read);
    assert!(items
        .iter()
        .all(|item| !fold(item).telemetry.side_calls_done));
    let trace = ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            ROOT.to_owned(),
            vec![complete_trace_row(ROOT, "named", "abc")],
        )]),
        ..Default::default()
    };
    side_calls_page(&mut items, &api_report(&read), &trace, &index);
    let (root, sub) = (fold(&items[0]), fold(&items[1]));
    assert_eq!((requests(&items[1], REPORTED), sub.root_fallbacks), (1, 0));
    assert_eq!((requests(&items[0], REPORTED), root.root_fallbacks), (1, 1));
    assert_eq!((root.side_requests, sub.side_requests), (1, 1));
    assert_eq!(root.side.input, 50);
    assert_eq!(sub.side.input, 40);
    let got = publish(items, None, TelemetryRead::Loaded, &index);
    let by_session = got
        .iter()
        .map(|item| {
            (
                item.source_session_id.as_str(),
                (item.request_count, item.input_tokens),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(by_session[ROOT], (2, 60));
    assert_eq!(by_session[subagent.as_str()], (2, 70));
    assert!(got
        .iter()
        .all(|item| item.telemetry_owned_complete == Some(true)));
    let _ = fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn e2_resolver_conflict_is_counted_and_emitted() {
    let p = root_file("conflict");
    let index = ScanIndex::default();
    let a = line("x", &at(1), 10);
    let mut b = a.clone();
    b["message"]["model"] = json!("other-model");
    let item = parse(&p, Some(t0()), &index, &[a, b, line("own", &at(2), 1)]);
    assert_eq!(fold(&item).entity.resolver_conflicts, 1);
    assert_eq!(fold(&item).entity.totals().1, item.request_count);
    let got = publish(vec![item], None, TelemetryRead::Loaded, &index);
    assert_eq!(got[0].resolver_conflict_count, Some(1));
    let clean = publish(
        vec![parse(&p, Some(t0()), &index, &[line("own", &at(2), 1)])],
        None,
        TelemetryRead::Loaded,
        &index,
    );
    assert_eq!(clean[0].resolver_conflict_count, None);
    assert!(serde_json::to_value(&clean[0])
        .unwrap()
        .get("resolver_conflict_count")
        .is_none());
    cleanup(&[&p]);
}

#[test]
fn e2_withheld_session_keeps_every_item_unchanged_for_the_hold() {
    let first = root_file("withheld-a");
    let copy = root_file("withheld-b");
    let index = ScanIndex::default();
    let canonical = |items: &[SnapshotItem]| {
        items
            .iter()
            .map(|item| {
                crate::canonical_json::canonicalize(&serde_json::to_value(item).unwrap()).unwrap()
            })
            .collect::<Vec<_>>()
    };
    let page = || {
        vec![
            parse(&first, Some(t0()), &index, &[line("r", &at(1), 10)]),
            parse(&copy, Some(t0()), &index, &[line("o", &at(2), 20)]),
        ]
    };
    // Held (absent twin, uncertified, ...): both paths stay, untouched, and
    // the session is returned so the caller holds it (owed, not settled).
    let mut items = page();
    items[0].claude_money.as_deref_mut().unwrap().entity.held = true;
    let before = canonical(&items);
    let withheld = with_enabled(|| finish_page(&mut items, &index, TelemetryRead::Loaded));
    assert_eq!(withheld, BTreeSet::from([ROOT.to_owned()]));
    assert_eq!(items.len(), 2, "no path of a withheld session is dropped");
    assert_eq!(canonical(&items), before);
    assert!(items
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    // Not held: one summed body, nothing withheld.
    let mut items = page();
    let withheld = with_enabled(|| finish_page(&mut items, &index, TelemetryRead::Loaded));
    assert!(withheld.is_empty());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].request_count, 2);
    // Gate off withholds nothing and changes nothing.
    let mut items = page();
    items[0].claude_money.as_deref_mut().unwrap().entity.held = true;
    let before = canonical(&items);
    assert!(finish_page(&mut items, &index, TelemetryRead::Loaded).is_empty());
    assert_eq!(canonical(&items), before);
    cleanup(&[&first, &copy]);
}

#[test]
fn e2_gate_off_keeps_canonical_bytes_and_fingerprint() {
    let p = root_file("dark");
    let index = ScanIndex::default();
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("c", &at(-100), 5), line("r", &at(1), 10)],
    )];
    let before = items
        .iter()
        .map(|item| {
            crate::canonical_json::canonicalize(&serde_json::to_value(item).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    let fingerprint = items[0].snapshot_fingerprint.clone();
    let read = sidecar(&[row("r", 1, 10), row("side", 2, 7)]);
    attach_page(&mut items, &read);
    side_calls_page(
        &mut items,
        &api_report(&read),
        &ClaudeTraceOwnershipLoadReport::default(),
        &index,
    );
    finish_page(&mut items, &index, TelemetryRead::Loaded);
    let after = items
        .iter()
        .map(|item| {
            crate::canonical_json::canonicalize(&serde_json::to_value(item).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(before, after);
    assert_eq!(items[0].snapshot_fingerprint, fingerprint);
    assert!(items[0].removed_usage.is_none());
    assert!(items[0].resolver_conflict_count.is_none());
    cleanup(&[&p]);
}

#[test]
fn e2_unknown_birth_counts_and_discloses_every_response() {
    let p = root_file("unknown");
    let index = ScanIndex::default();
    let got = parse(
        &p,
        None,
        &index,
        &[line("old", &at(-86_400), 11), line("own", &at(1), 22)],
    );
    let f = fold(&got);
    assert_eq!(f.entity.totals().1, 2);
    assert_eq!(f.entity.removed_requests, 0);
    assert_eq!(f.disclosed, 2);
    cleanup(&[&p]);
}

#[test]
fn e2_subagents_are_exempt_even_when_written_in_a_burst() {
    let p = root_file("subagent");
    let agent = p
        .parent()
        .unwrap()
        .join(ROOT)
        .join("subagents/agent-abc123.jsonl");
    let mut value = line("old", &at(-86_400), 10);
    value["agentId"] = json!("abc123");
    value["isSidechain"] = json!(true);
    let got = parse(&agent, Some(t0()), &ScanIndex::default(), &[value]);
    let f = fold(&got);
    assert_eq!(f.entity.totals().1, 1);
    assert_eq!(f.entity.removed_requests, 0);
    assert_eq!(f.disclosed, 0);
    cleanup(&[&p]);
}

#[test]
fn e2_native_resolver_owns_progressive_and_idless_decisions() {
    let p = root_file("resolver");
    let index = ScanIndex::default();
    let progressive = line("progress", &at(1), 10);
    let mut final_record = progressive.clone();
    final_record["message"]["usage"]["input_tokens"] = json!(20);
    let mut message_only = line("unused", &at(1), 30);
    message_only.as_object_mut().unwrap().remove("requestId");
    let got = parse(
        &p,
        Some(t0()),
        &index,
        &[progressive, final_record, message_only],
    );
    assert_eq!(fold(&got).entity.totals().1, got.request_count);
    assert_eq!(fold(&got).entity.totals().0.input, got.input_tokens);
    cleanup(&[&p]);
}

#[test]
fn e2_diagnostic_fields_are_nonzero_only() {
    assert_eq!(serde_json::to_value(Counts::default()).unwrap(), json!({}));
    assert_eq!(
        serde_json::to_value(Counts([1, 2, 0, 0, 0, 3, 0, 1])).unwrap(),
        json!({"fold_us":1,"responses":2,"side_call_root_fallback":3,"dark_unexplained":1})
    );
}

/// Exercise T4's actual index walk and one metadata probe per twin. Only physical
/// birth is injected, as in parse(); Linux has no portable set-creation-time API.
fn stage_twins(index: &mut ScanIndex, paths: &[(&Path, i128)]) {
    let mut page = crate::snapshots::claude_history_upgrade::HistoryPage::default();
    for (path, _) in paths {
        index.stage_claude_history_twins(&local_index_key(path), &mut page);
    }
    for (path, birth) in paths {
        let key = local_index_key(path);
        let Some(member) = session_member(path) else {
            continue;
        };
        let opened = fs::metadata(path).ok().map(|m| {
            let mut opened =
                crate::snapshots::claude_context_file_birth::ClaudeOpenedBirth::from_metadata(&m);
            opened.birth = u64::try_from(*birth).unwrap();
            opened
        });
        let size = index.files.get(&key).map_or(0, |e| e.size_bytes);
        index
            .claude_money_birth_store
            .stage_opened(&member, &key, opened, size);
    }
}

#[test]
fn e2_first_ever_restored_root_twins_stage_before_either_fold() {
    for reverse in [false, true] {
        let early = root_file("first-early");
        let later = root_file("first-later");
        let history = [line("h1", &at(-100), 1), line("h2", &at(-90), 2)];
        let mut index = ScanIndex::default();
        index.files.insert(local_index_key(&early), entry());
        index.files.insert(local_index_key(&later), entry());
        assert!(index.claude_money_birth_store.is_empty());
        let mut paths = vec![
            (&early as &Path, t0()),
            (&later as &Path, t0() + 5_000_000_000),
        ];
        if reverse {
            paths.reverse();
        }
        stage_twins(&mut index, &paths);
        // No seeded/discarded parse and no restart before these first results.
        let items = paths
            .iter()
            .map(|(path, birth)| parse(path, Some(*birth), &index, &history))
            .collect::<Vec<_>>();
        assert_eq!(
            items.iter().map(|i| fold(i).entity.totals().1).sum::<u64>(),
            2
        );
        assert_eq!(
            items
                .iter()
                .map(|i| fold(i).entity.removed_requests)
                .sum::<u64>(),
            2
        );
        let got = publish(items, None, TelemetryRead::Loaded, &index);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].request_count, got[0].input_tokens), (2, 3));
        assert_eq!(got[0].removed_request_count, Some(2));
        cleanup(&[&early, &later]);
    }
}

fn agent_file(name: &str) -> PathBuf {
    let root = scratch(name);
    let path = root.join(ROOT).join("subagents/agent-abc.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"fixture\n").unwrap();
    path
}

#[test]
fn e2_subagent_twins_identical_and_overlapping_count_once_in_both_orders() {
    for overlap in [false, true] {
        for reverse in [false, true] {
            let early = agent_file("sub-early");
            let later = agent_file("sub-later");
            let own = |id, seconds, input| {
                let mut value = line(id, &at(seconds), input);
                value["agentId"] = json!("abc");
                value["isSidechain"] = json!(true);
                value
            };
            let history = vec![own("a", 1, 10), own("b", 2, 20)];
            let mut later_lines = history.clone();
            if overlap {
                later_lines.push(own("c", 61, 30));
            }
            let mut index = ScanIndex::default();
            index.files.insert(local_index_key(&early), entry());
            index.files.insert(local_index_key(&later), entry());
            stage_twins(
                &mut index,
                &[(&early, t0()), (&later, t0() + 60_000_000_000)],
            );
            let first = parse(&early, Some(t0()), &index, &history);
            let second = parse(&later, Some(t0() + 60_000_000_000), &index, &later_lines);
            assert_eq!(
                fold(&first).entity.totals().1,
                2,
                "earliest subagent counts fully"
            );
            assert_eq!(fold(&second).entity.removed_requests, 2);
            let mut items = vec![first, second];
            if reverse {
                items.reverse();
            }
            let got = publish(
                items,
                Some(&sidecar(&[row("a", 1, 10), row("b", 2, 20)])),
                TelemetryRead::Loaded,
                &index,
            );
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].request_count, 2 + u64::from(overlap));
            assert_eq!(got[0].input_tokens, if overlap { 60 } else { 30 });
            assert_eq!(got[0].removed_request_count, Some(2));
            assert_eq!(
                got[0].cost.as_ref().unwrap().total_cost_usd.as_deref(),
                Some("0.0002")
            );
            fs::remove_dir_all(early.ancestors().nth(3).unwrap()).unwrap();
            fs::remove_dir_all(later.ancestors().nth(3).unwrap()).unwrap();
        }
    }
}

#[test]
fn e2_recreated_or_truncated_original_cannot_witness_a_copy() {
    for truncated in [false, true] {
        let early = root_file("stale-early");
        let later = root_file("stale-later");
        let history = [line("h", &at(-100), 10)];
        let original_bytes = serde_json::to_vec(&history[0]).unwrap();
        fs::write(&early, &original_bytes).unwrap();
        let old_handle = fs::File::open(&early).unwrap();
        let mut index = ScanIndex::default();
        parse_and_remember(&early, t0(), &mut index, &history);
        index
            .files
            .get_mut(&local_index_key(&early))
            .unwrap()
            .size_bytes = original_bytes.len() as u64;
        index.files.insert(local_index_key(&later), entry());
        // Keep the old inode open, so unlink/create cannot recycle it.
        if !truncated {
            fs::remove_file(&early).unwrap();
        }
        fs::write(&early, b"x").unwrap();
        let current = fs::metadata(&early).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                current.ino() == old_handle.metadata().unwrap().ino(),
                truncated
            );
        }
        let mut index = restart(&index); // generation/extent evidence survives restart
        stage_twins(
            &mut index,
            &[
                (&early, t0() + 120_000_000_000),
                (&later, t0() + 60_000_000_000),
            ],
        );
        let early_item = parse(
            &early,
            Some(t0() + 120_000_000_000),
            &index,
            &[line("u", &at(121), 20)],
        );
        let later_item = parse(&later, Some(t0() + 60_000_000_000), &index, &history);
        assert_eq!(fold(&later_item).entity.removed_requests, 0);
        assert_eq!(fold(&later_item).entity.totals().1, 1);
        assert!(fold(&later_item).disclosed > 0);
        let got = publish(
            vec![early_item, later_item],
            None,
            TelemetryRead::Loaded,
            &index,
        );
        assert_eq!((got[0].request_count, got[0].input_tokens), (2, 30));
        assert_eq!(got[0].removed_request_count, None);
        cleanup(&[&early, &later]);
    }
}

fn without_version(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("version");
    value
}

#[test]
fn e2_missing_own_writer_invalidates_known_prefix_and_both_own_orders() {
    let path = root_file("missing-writer");
    let index = ScanIndex::default();
    for order in [0, 1, 2] {
        let prefix = line("prefix", &at(-100), 10);
        let a = line("a", &at(1), 20);
        let b = line("b", &at(2), 30);
        let lines = match order {
            0 => vec![prefix, without_version(a)],
            1 => vec![prefix, without_version(a), b],
            _ => vec![prefix, a, without_version(b)],
        };
        let item = parse(&path, Some(t0()), &index, &lines);
        assert_eq!(fold(&item).entity.removed_requests, 0);
        assert_eq!(fold(&item).entity.totals().1, lines.len() as u64);
        assert!(fold(&item).disclosed > 0);
        let got = publish(vec![item], None, TelemetryRead::Loaded, &index);
        assert_eq!(got[0].request_count, lines.len() as u64);
    }
    cleanup(&[&path]);
}

#[test]
fn e2_all_prebirth_twins_require_known_response_writers() {
    for missing in [false, true] {
        let early = root_file("unknown-early");
        let later = root_file("unknown-later");
        let mut index = ScanIndex::default();
        index.files.insert(local_index_key(&early), entry());
        index.files.insert(local_index_key(&later), entry());
        stage_twins(
            &mut index,
            &[(&early, t0()), (&later, t0() + 60_000_000_000)],
        );
        let original = line("h", &at(-100), 10);
        let copy = if missing {
            without_version(original.clone())
        } else {
            versioned(original.clone(), "99.0.0")
        };
        let item = parse(&later, Some(t0() + 60_000_000_000), &index, &[copy]);
        assert_eq!(fold(&item).entity.removed_requests, 0);
        assert_eq!(fold(&item).entity.totals().1, 1);
        assert!(fold(&item).disclosed > 0);
        let got = publish(
            vec![parse(&early, Some(t0()), &index, &[original]), item],
            None,
            TelemetryRead::Loaded,
            &index,
        );
        assert_eq!((got[0].request_count, got[0].input_tokens), (2, 20));
        cleanup(&[&early, &later]);
    }
}
