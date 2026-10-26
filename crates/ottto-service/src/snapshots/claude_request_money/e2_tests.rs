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
    let opened = fs::File::open(path).and_then(|file| file.metadata()).ok();
    a.claude_file_birth = ClaudeFileBirth::observe(path, opened.as_ref());
    if let Some(birth) = birth {
        a.claude_file_birth.set_birth_for_test(birth);
    } else {
        a.claude_file_birth.forget_birth_for_test();
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
        .filter(|((_, o, _), _)| *o == origin)
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
        .map(|(key, origin, _)| (key.0.as_str(), *origin))
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
    let ((key, origin, _), _) = fold(&items[0]).entity.grains.iter().next().unwrap();
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
    index.files.insert(local_index_key(&copy), entry());
    stage_twins(
        &mut index,
        &[(&first, t0()), (&copy, t0() + 60_000_000_000)],
    );
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

#[test]
fn e2_reported_selector_inputs_match_p1_with_legacy_output_kept() {
    use super::super::body::reported_live_key;
    use super::super::rows::ClaudeApiRow;
    let p = root_file("selector-parity");
    let index = ScanIndex::default();
    for native_model in [true, false] {
        for native_clock in [true, false] {
            for native_effort in [None, Some("low")] {
                for speed in ["", "fast"] {
                    for effort in ["high", "unknown", ""] {
                        let mut value = line("r", &at(1), 10);
                        if !native_model {
                            value["message"].as_object_mut().unwrap().remove("model");
                        }
                        if !native_clock {
                            value.as_object_mut().unwrap().remove("timestamp");
                        }
                        let item = parse(&p, Some(t0()), &index, &[line("seed", &at(0), 1), value]);
                        let mut occurrence = item.claude_usage_occurrences["r"].clone();
                        occurrence.reasoning_effort = native_effort.map(str::to_owned);
                        let mut api = row("r", 1, 10);
                        api.speed = speed.to_owned();
                        api.effort = effort.to_owned();
                        api.observed_at = at(3601); // fallback clock is another hour
                        let api_view = ClaudeApiRow {
                            request_hash: claude_request_hash("r"),
                            tokens: Default::default(),
                            cost_micros: api.cost_usd_micros,
                            clock: u64::try_from((t0() / 1_000_000_000) + 3601).unwrap(),
                            model: &api.model,
                            speed: &api.speed,
                            effort: &api.effort,
                        };
                        for occurrence in [Some(&occurrence), None] {
                            let legacy = reported_live_key(&api_view, occurrence).unwrap();
                            let mut e2 =
                                reported_key(&api, occurrence, &SelectorCapture::default())
                                    .unwrap();
                            let kept_effort = e2.2.remove("reasoning_effort");
                            assert_eq!(e2, legacy, "same model, speed, selectors and hour");
                            let expected_effort = occurrence
                                .and_then(|o| o.reasoning_effort.as_deref())
                                .or_else(|| {
                                    crate::snapshots::CLAUDE_EFFORT_TIERS
                                        .contains(&effort)
                                        .then_some(effort)
                                });
                            assert_eq!(
                                kept_effort.as_deref(),
                                expected_effort,
                                "E2 intentionally retains effort"
                            );
                            assert_eq!(
                                legacy.0,
                                if occurrence.is_some() && native_clock {
                                    HOUR
                                } else {
                                    "2026-08-02T08:00:00Z"
                                }
                            );
                        }
                    }
                }
            }
        }
    }
    cleanup(&[&p]);
}

#[test]
fn e2_membership_hash_collision_never_substitutes_for_exact_request_identity() {
    let p = root_file("membership-collision");
    let index = ScanIndex::default();
    let items = vec![parse(&p, Some(t0()), &index, &[line("native", &at(1), 10)])];
    let mut view = family_membership(&items, &[0]);
    // Force an accelerator collision. The request map/set, not the hash,
    // decides ownership and side-call subtraction.
    view.entries[0] = membership_hash("other") & !view.member_mask;
    assert_eq!(holders(&items, &view, "other"), Holders::None);
    assert!(!matching_members(&view, "other")
        .any(|i| items[i].claude_usage_request_ids.contains("other")));
    cleanup(&[&p]);
}

#[test]
fn e2_large_family_join_and_pipeline_are_bounded_in_dark_and_enabled_modes() {
    use crate::snapshots::claude_request_census::{
        record_claude_request_census, ClaudeRequestCensusParse,
    };
    const MEMBERS: usize = 736;
    const ROWS: usize = 70_000;
    const OFF_PAGE: usize = 2048;
    let dir = scratch("large-family");
    let root = dir.join(format!("{ROOT}.jsonl"));
    let agents = dir.join(ROOT).join("subagents");
    fs::create_dir_all(&agents).unwrap();
    let mut index = ScanIndex::default();
    let id = |i: usize| format!("req-{i:06}");
    let mut items = Vec::with_capacity(MEMBERS);
    for member in 0..MEMBERS {
        let path = if member == 0 {
            root.clone()
        } else {
            agents.join(format!("agent-{member}.jsonl"))
        };
        let lines = (member..ROWS)
            .step_by(MEMBERS)
            .map(|i| {
                let request = if i < MEMBERS {
                    id(i)
                } else {
                    format!("native-{i:06}")
                };
                line(&request, &at(1), 10)
            })
            .collect::<Vec<_>>();
        items.push(parse(&path, Some(t0()), &index, &lines));
    }
    // An off-page member is parsed through the native resolver and recorded
    // through the actual census writer, rather than hand-feeding holder sets.
    let off_page_path = agents.join("agent-off-page.jsonl");
    let off_page_lines = (MEMBERS..MEMBERS + OFF_PAGE)
        .map(|i| line(&id(i), &at(1), 10))
        .collect::<Vec<_>>();
    let off_page = parse(&off_page_path, Some(t0()), &index, &off_page_lines);
    record_claude_request_census(
        &mut index,
        ClaudeRequestCensusParse {
            path: &off_page_path,
            index_key: &local_index_key(&off_page_path),
            source_file_fingerprint: &"a".repeat(64),
            census_window_end: "2026-08-02T09:00:00Z",
            complete: true,
            lossy: false,
            source_verified: true,
            itemless_request_hashes: Vec::new(),
            opened_birth: None,
            modified_unix_seconds: 1,
        },
        &[off_page],
    );
    let rows = (0..ROWS)
        .map(|i| {
            let mut api = row(&id(i), i as u64 + 1, 10);
            api.observed_at = at(1); // sequence is not a seconds field
            refingerprint(api)
        })
        .collect::<Vec<_>>();
    let read = sidecar(&rows); // canonical permissive reader, including health
    let api = api_report(&read);
    let trace = ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            ROOT.to_owned(),
            (MEMBERS..ROWS)
                .filter(|i| i % 2 == 0)
                .map(|i| complete_trace_row(ROOT, &id(i), "735"))
                .collect(),
        )]),
        ..Default::default()
    };
    let members = (0..MEMBERS).collect::<Vec<_>>();
    let start = Instant::now();
    let view = family_membership(&items, &members);
    let counts = join(
        read.session_report(ROOT).unwrap(),
        |key| holders(&items, &view, key),
        |_, _| true,
        |_| {},
    );
    let join_time = start.elapsed();
    assert_eq!(
        (counts.matched, counts.unheld, counts.disclosed),
        (MEMBERS, ROWS - MEMBERS, 0)
    );
    // The optimized target is 20 ms; portable debug CI gets scheduling and
    // instrumentation margin. Fingerprints/row placement are timed below.
    let join_budget = Duration::from_millis(if cfg!(debug_assertions) { 500 } else { 20 });
    assert!(
        join_time < join_budget,
        "family membership/join took {join_time:?}"
    );
    assert_eq!(
        view.entries.capacity() * std::mem::size_of::<u64>(),
        ROWS * 8
    );
    drop(view);
    let wire = |items: &[SnapshotItem]| {
        items
            .iter()
            .map(|item| {
                (
                    crate::canonical_json::canonicalize(&serde_json::to_value(item).unwrap())
                        .unwrap(),
                    item.snapshot_fingerprint.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let before = wire(&items);
    for enabled in [false, true] {
        // Wall clock without the allocation probe: its born-pointer table
        // locks and walks on every allocation and free of every thread.
        let mut page = items.clone();
        take_stages();
        let start = Instant::now();
        attach_page(&mut page, &read);
        side_calls_page(&mut page, &api, &trace, &index);
        let enrichment_time = start.elapsed();
        let stages = take_stages();
        // The same work on an identical page, for the born-in-scope peak only.
        let mut probed = items.clone();
        let probe_start = Instant::now();
        let (_, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
            attach_page(&mut probed, &read);
            side_calls_page(&mut probed, &api, &trace, &index);
        });
        let probed_time = probe_start.elapsed();
        take_stages();
        assert!(page.iter().zip(&probed).all(|(a, b)| {
            fold(a).entity.grains == fold(b).entity.grains
                && fold(a).side_requests == fold(b).side_requests
        }));
        drop(probed);
        assert!(page
            .iter()
            .all(|item| fold(item).telemetry.membership.entries.is_empty()));
        assert_eq!(
            page.iter().map(|item| requests(item, MATCHED)).sum::<u64>(),
            MEMBERS as u64
        );
        assert_eq!(
            page.iter()
                .map(|item| requests(item, REPORTED))
                .sum::<u64>(),
            (ROWS - MEMBERS - OFF_PAGE) as u64
        );
        assert_eq!(
            fold(&page[MEMBERS - 1]).side_requests,
            ((ROWS - MEMBERS - OFF_PAGE) / 2) as u64
        );
        assert_eq!(
            page.iter()
                .map(|item| fold(item).root_fallbacks)
                .sum::<u64>(),
            ((ROWS - MEMBERS - OFF_PAGE) / 2) as u64
        );
        assert!(
            allocation.requested_peak_with_overlap <= 2 * 1024 * 1024,
            "attach+side-call born-in-scope allocation peak: {allocation:?}"
        );
        let finish_start = Instant::now();
        let withheld = if enabled {
            with_enabled(|| finish_page(&mut page, &index, TelemetryRead::Loaded))
        } else {
            finish_page(&mut page, &index, TelemetryRead::Loaded)
        };
        assert!(withheld.is_empty());
        let pipeline_time = enrichment_time + finish_start.elapsed();
        assert!(
            pipeline_time < Duration::from_secs(30),
            "real pipeline took {pipeline_time:?}"
        );
        if enabled {
            assert_eq!(page.len(), MEMBERS);
            assert_eq!(
                page.iter().map(|item| item.request_count).sum::<u64>(),
                (2 * ROWS - MEMBERS - OFF_PAGE) as u64
            );
            assert!(page
                .iter()
                .all(|item| item.telemetry_owned_complete == Some(false)));
        } else {
            assert_eq!(
                wire(&page),
                before,
                "dark mode preserves all bytes and fingerprints"
            );
        }
        eprintln!("F3_PERF rows={ROWS} members={MEMBERS} off_page={OFF_PAGE} enabled={enabled} membership_join_us={} attach_side_us={} attach_side_probed_us={} pipeline_us={} born_peak_bytes={} not_rss=true",
            join_time.as_micros(), enrichment_time.as_micros(), probed_time.as_micros(), pipeline_time.as_micros(), allocation.requested_peak_with_overlap);
        eprintln!(
            "F3_PERF stages enabled={enabled} {}",
            stages
                .iter()
                .map(|(stage, spent)| format!("{stage}_us={}", spent.as_micros()))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    fs::remove_dir_all(dir).unwrap();
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
        let mut paths: Vec<(&Path, i128)> = vec![(&early, t0()), (&later, t0() + 5_000_000_000)];
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
    for (truncated, partial) in [(false, false), (false, true), (true, false), (true, true)] {
        let early = root_file("stale-early");
        let later = root_file("stale-later");
        let mut historical = line("h", &at(-100), 10);
        historical["fixture_padding"] = json!("h".repeat(512));
        let history = [historical];
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
        let mut replacement = line("u", &at(121), 20);
        if !truncated {
            replacement["fixture_padding"] = json!("u".repeat(1024));
        }
        fs::write(&early, serde_json::to_vec(&replacement).unwrap()).unwrap();
        let current = fs::metadata(&early).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                current.ino() == old_handle.metadata().unwrap().ino(),
                truncated
            );
        }
        assert_eq!(
            current.len() < original_bytes.len() as u64,
            truncated,
            "new-inode case grows, so identity alone must reject it; truncation case shrinks"
        );
        let mut later_lines = history.to_vec();
        if partial {
            later_lines.push(line("own", &at(61), 40));
        }
        fs::write(
            &later,
            later_lines
                .iter()
                .map(|line| serde_json::to_string(line).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut index = restart(&index); // generation/extent evidence survives restart
        stage_twins(
            &mut index,
            &[
                (&early, t0() + 120_000_000_000),
                (&later, t0() + 60_000_000_000),
            ],
        );
        let early_item = parse(&early, Some(t0() + 120_000_000_000), &index, &[replacement]);
        let later_item = parse(&later, Some(t0() + 60_000_000_000), &index, &later_lines);
        assert_eq!(fold(&later_item).entity.removed_requests, 0);
        assert_eq!(fold(&later_item).entity.totals().1, 1 + u64::from(partial));
        assert!(fold(&later_item).disclosed > 0);
        let got = publish(
            vec![early_item, later_item],
            None,
            TelemetryRead::Loaded,
            &index,
        );
        assert_eq!(
            (got[0].request_count, got[0].input_tokens),
            (2 + u64::from(partial), if partial { 70 } else { 30 })
        );
        assert_eq!(got[0].removed_request_count, Some(0));
        assert_eq!(got[0].removed_usage, Some(ClaudeRemovedUsage::default()));
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
    for order in [0, 1, 2, 3, 4] {
        let prefix = line("prefix", &at(-100), 10);
        let a = line("a", &at(1), 20);
        let b = line("b", &at(2), 30);
        let lines = match order {
            0 => vec![prefix, without_version(a)],
            1 => vec![prefix, without_version(a), b],
            2 => vec![prefix, a, without_version(b)],
            3 => {
                let mut missing = without_version(a);
                missing.as_object_mut().unwrap().remove("timestamp");
                vec![prefix, missing, b]
            }
            _ => {
                let mut missing = without_version(b);
                missing.as_object_mut().unwrap().remove("timestamp");
                vec![prefix, a, missing]
            }
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

const ORG_A: &str = "11111111-1111-4111-8111-111111111111";
const ORG_B: &str = "22222222-2222-4222-8222-222222222222";
fn org_marker(org: &str) -> Value {
    json!({"type":"attachment","sessionId":ROOT,
        "attachment":{"type":"credential_org","organizationUuid":org}})
}
fn switch_context() -> Value {
    json!({"type":"attachment","sessionId":ROOT,
        "attachment":{"type":"session_context","context":{"userEmail":"synthetic@example.invalid"}}})
}
fn org_hash(org: &str) -> String {
    ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap()
}
fn tag_owned(mut items: Vec<SnapshotItem>, index: &ScanIndex) -> Vec<SnapshotItem> {
    let api = ClaudeLocalOtelLoadReport::default();
    let trace = ClaudeTraceOwnershipLoadReport::default();
    let per_file_originals = claude_request_identity::capture_request_owned_originals(&items);
    // Production's legacy map collapses twins; E2 activity must not use it.
    let originals = items
        .iter()
        .filter_map(|item| {
            item.session_account_evidence
                .clone()
                .map(|original| (item.source_session_id.clone(), original))
        })
        .collect();
    let evidence = claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
        .with_native_originals(&originals);
    claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
    let disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    let ownership = claude_request_identity::TranscriptOwnership::after_census(index, &disposition);
    let activity = claude_request_identity::stage_request_owned_activity(
        &items,
        &evidence,
        &ownership,
        &per_file_originals,
    );
    let withheld = finish_page(&mut items, index, TelemetryRead::Loaded);
    assert!(
        withheld.is_empty(),
        "identity doubt must never withhold money"
    );
    let outcome = claude_request_identity::apply_scan_with_ownership(
        &mut items,
        &evidence,
        BTreeMap::new(),
        &ownership,
    );
    claude_request_identity::publish_request_owned_activity(&items, activity);
    assert_eq!(outcome.sent, items.len());
    assert_eq!(outcome.ineligible, 0);
    items
}
fn assert_evidence_referenced(item: &SnapshotItem) {
    let referenced = rows_of(item)
        .flat_map(|row| {
            row.evidence_ref.into_iter().chain(
                row.identity_parts
                    .iter()
                    .flatten()
                    .filter_map(|part| part.evidence_ref),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        referenced,
        (0..item.request_evidence.len() as u16).collect()
    );
}

#[test]
fn e2_identity_mixed_login_inherits_earlier_native_request_and_rereads_identically() {
    with_enabled(|| {
        let path = root_file("identity-mixed");
        let index = ScanIndex::default();
        // Lexical request-id order is deliberately unrelated to native order.
        let lines = vec![
            org_marker(ORG_A),
            line("z", &at(1), 10),
            line("y", &at(2), 20),
            switch_context(),
            org_marker(ORG_B),
            line("b", &at(3), 30),
            line("a", &at(4), 40),
        ];
        let run = || tag_owned(vec![parse(&path, Some(t0()), &index, &lines)], &index).remove(0);
        let item = run();
        assert_eq!((item.request_count, item.input_tokens), (4, 100));
        assert_eq!(item.usage_buckets.len(), 1);
        assert_eq!(
            item.usage_buckets[0].model_usage.len(),
            1,
            "wire selector rows remain unique"
        );
        let parts = item.model_usage[0].identity_parts.as_ref().unwrap();
        let amounts = parts
            .iter()
            .map(|part| {
                let evidence = &item.request_evidence[usize::from(part.evidence_ref.unwrap())];
                (
                    evidence.provider_workspace_hash.clone().unwrap(),
                    (part.input_tokens, part.request_count),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(amounts[&org_hash(ORG_A)], (30, 2));
        assert_eq!(amounts[&org_hash(ORG_B)], (70, 2));
        assert_evidence_referenced(&item);
        assert_eq!(
            serde_json::to_vec(&item).unwrap(),
            serde_json::to_vec(&run()).unwrap()
        );
        assert!(fold(&item).accounts.as_ref().unwrap().mixed);
        assert_eq!(fold(&item).accounts.as_ref().unwrap().inherited, 2);
        let mut admissions = crate::snapshots::claude_request_accounts::MixedUploads::default();
        admissions.admit_request_identity(&item);
        assert!(
            admissions.permits_request_identity(&item),
            "formerly refused mixed body reaches upload admission"
        );
        let mut bound_index = ScanIndex::default();
        bound_index.session_account_bindings.insert(
            crate::snapshots::sha256_hex(&["session_owner:v1", "synthetic-machine", ROOT]),
            crate::snapshots::SessionAccountBinding {
                account_identifier_hash: "b".repeat(64),
                workspace_identifier_hash: None,
            },
        );
        let mut upload_items = vec![item.clone()];
        assert!(
            bound_index
                .bind_session_accounts_with_mixed(
                    SnapshotSource::ClaudeCode,
                    "synthetic-machine",
                    &mut upload_items,
                    &[],
                    &admissions,
                )
                .is_empty(),
            "existing binding admits exact mixed contract-5 body"
        );
        assert_eq!(
            serde_json::to_vec(&item).unwrap(),
            serde_json::to_vec(&upload_items[0]).unwrap()
        );
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_conflict_counts_whole_session_under_starting_account() {
    with_enabled(|| {
        let path = root_file("identity-conflict");
        let index = ScanIndex::default();
        let lines = vec![
            org_marker(ORG_A),
            line("a", &at(1), 10),
            switch_context(),
            org_marker(ORG_B),
            line("b", &at(2), 20),
            org_marker("invalid"),
            line("c", &at(3), 30),
        ];
        let item = tag_owned(vec![parse(&path, Some(t0()), &index, &lines)], &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (3, 60));
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str())
        );
        assert!(
            rows_of(&item).all(|row| row.identity_parts.is_none() && row.evidence_ref == Some(0))
        );
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_subagent_inherits_root_and_unknown_root_stays_unknown() {
    with_enabled(|| {
        for known in [true, false] {
            let path = root_file("identity-agent");
            let agent = path
                .parent()
                .unwrap()
                .join(ROOT)
                .join("subagents/agent-abc.jsonl");
            fs::create_dir_all(agent.parent().unwrap()).unwrap();
            fs::write(&agent, b"fixture\n").unwrap();
            let index = ScanIndex::default();
            let mut root_lines = if known {
                vec![org_marker(ORG_A)]
            } else {
                Vec::new()
            };
            root_lines.push(line("root", &at(1), 10));
            let mut sub = line("child", &at(2), 20);
            sub["agentId"] = json!("abc");
            sub["isSidechain"] = json!(true);
            let items = tag_owned(
                vec![
                    parse(&agent, Some(t0()), &index, &[org_marker(ORG_B), sub]),
                    parse(&path, Some(t0()), &index, &root_lines),
                ],
                &index,
            );
            let item = items
                .iter()
                .find(|item| item.source_session_id.contains("_agent-"))
                .unwrap();
            assert_eq!((item.request_count, item.input_tokens), (1, 20));
            if known {
                assert_eq!(item.request_evidence.len(), 1);
                assert_eq!(
                    item.request_evidence[0].provider_workspace_hash.as_deref(),
                    Some(org_hash(ORG_A).as_str())
                );
                assert_evidence_referenced(item);
            } else {
                assert!(item.request_evidence.is_empty());
                assert!(rows_of(item).all(|row| row.evidence_ref.is_none()
                    && row.account_identifier_hash.is_none()
                    && row.identity_parts.is_none()));
            }
            cleanup(&[&path]);
        }
    });
}

#[test]
fn e2_identity_single_account_bytes_unchanged_by_repeated_same_org_evidence() {
    with_enabled(|| {
        let path = root_file("identity-single");
        let index = ScanIndex::default();
        let first = line("a", &at(1), 10);
        let second = line("b", &at(2), 20);
        let one = tag_owned(
            vec![parse(
                &path,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), first.clone(), second.clone()],
            )],
            &index,
        )
        .remove(0);
        let repeated = tag_owned(
            vec![parse(
                &path,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), first, org_marker(ORG_A), second],
            )],
            &index,
        )
        .remove(0);
        assert_eq!(
            serde_json::to_vec(&one).unwrap(),
            serde_json::to_vec(&repeated).unwrap()
        );
        assert!(!fold(&one).accounts.as_ref().unwrap().mixed);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_later_org_cannot_claim_unknown_start_or_other_session() {
    with_enabled(|| {
        let path = root_file("identity-no-lookahead");
        let index = ScanIndex::default();
        let item = tag_owned(
            vec![parse(
                &path,
                Some(t0()),
                &index,
                &[
                    line("first", &at(1), 10),
                    org_marker(ORG_B),
                    line("later", &at(2), 20),
                ],
            )],
            &index,
        )
        .remove(0);
        assert_eq!(item.request_count, 2);
        assert!(item.request_evidence.is_empty());
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_conflicting_markers_on_one_request_fall_back_without_splitting() {
    with_enabled(|| {
        let path = root_file("identity-same-request-conflict");
        let index = ScanIndex::default();
        let item = tag_owned(
            vec![parse(
                &path,
                Some(t0()),
                &index,
                &[
                    org_marker(ORG_A),
                    switch_context(),
                    org_marker(ORG_B),
                    line("one", &at(1), 10),
                ],
            )],
            &index,
        )
        .remove(0);
        assert_eq!((item.request_count, item.input_tokens), (1, 10));
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str())
        );
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_attach_unpriced_and_side_calls_keep_account_partition() {
    with_enabled(|| {
        let path = root_file("identity-attached");
        let index = ScanIndex::default();
        let mut items = vec![parse(
            &path,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("a", &at(1), 10),
                switch_context(),
                org_marker(ORG_B),
                line("b", &at(2), 20),
                line("c", &at(3), 30),
            ],
        )];
        let mut unpriced = row("c", 3, 30);
        unpriced.cost_usd_micros = None;
        let read = sidecar(&[
            row("a", 1, 10),
            row("b", 2, 20),
            refingerprint(unpriced),
            row("side", 4, 40),
        ]);
        attach_page(&mut items, &read);
        side_calls_page(
            &mut items,
            &api_report(&read),
            &ClaudeTraceOwnershipLoadReport::default(),
            &index,
        );
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (4, 100));
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0003")
        );
        let reported = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context
                    .get("request_usage_origin")
                    .map(String::as_str)
                    == Some("telemetry_reported")
            })
            .unwrap();
        let evidence = &item.request_evidence[usize::from(reported.evidence_ref.unwrap())];
        assert_eq!(
            evidence.provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str()),
            "side call has target starting account"
        );
        let unpriced = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context
                    .get("request_usage_origin")
                    .map(String::as_str)
                    == Some("telemetry_unpriced")
            })
            .unwrap();
        let evidence = &item.request_evidence[usize::from(unpriced.evidence_ref.unwrap())];
        assert_eq!(
            evidence.provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_B).as_str())
        );
        assert!(unpriced.cost_usd.is_none());
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_telemetry_contradiction_falls_back_whole_session() {
    with_enabled(|| {
        use crate::claude_local_otel::{
            ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin,
            ClaudeIdentityDisposition, ClaudeRequestIdentityEvidence,
        };
        let path = root_file("identity-telemetry-conflict");
        let index = ScanIndex::default();
        let mut items = vec![parse(
            &path,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("a", &at(1), 10),
                switch_context(),
                org_marker(ORG_B),
                line("b", &at(2), 20),
            ],
        )];
        let mut conflicting = row("b", 2, 20);
        let attribute = |hash| ClaudeIdentityAttributeEvidence {
            origin: ClaudeIdentityAttributeOrigin::LogRecord,
            disposition: ClaudeIdentityDisposition::Complete,
            resource_hash: None,
            log_record_hash: Some(hash),
        };
        conflicting.request_identity = Some(ClaudeRequestIdentityEvidence {
            identity_hash_scheme: "provider-sha256:v1".into(),
            account: attribute("a".repeat(64)),
            organization: attribute(org_hash(ORG_A)),
            disposition: ClaudeIdentityDisposition::Complete,
        });
        let read = sidecar(&[row("a", 1, 10), refingerprint(conflicting)]);
        attach_page(&mut items, &read);
        let api = api_report(&read);
        let trace = ClaudeTraceOwnershipLoadReport::default();
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (2, 30));
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str())
        );
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_copied_requests_leave_only_referenced_new_account_evidence() {
    with_enabled(|| {
        let path = root_file("identity-copy");
        let index = ScanIndex::default();
        let item = tag_owned(
            vec![parse(
                &path,
                Some(t0() + 100_000_000_000),
                &index,
                &[
                    org_marker(ORG_A),
                    line("copied", &at(1), 10),
                    switch_context(),
                    org_marker(ORG_B),
                    line("own", &at(101), 20),
                ],
            )],
            &index,
        )
        .remove(0);
        assert_eq!((item.request_count, item.input_tokens), (1, 20));
        assert_eq!(item.removed_request_count, Some(1));
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_B).as_str())
        );
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_final_grouping_includes_disjoint_path_twins_in_either_order() {
    with_enabled(|| {
        for reverse in [false, true] {
            let path_a = root_file("identity-twin-a");
            let path_b = root_file("identity-twin-b");
            let index = ScanIndex::default();
            let a = parse(
                &path_a,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), line("a", &at(1), 10)],
            );
            let b = parse(
                &path_b,
                Some(t0()),
                &index,
                &[org_marker(ORG_B), line("b", &at(2), 20)],
            );
            let items = if reverse { vec![b, a] } else { vec![a, b] };
            let items = tag_owned(items, &index);
            assert_eq!(items.len(), 1);
            assert_eq!((items[0].request_count, items[0].input_tokens), (2, 30));
            assert_eq!(items[0].request_evidence.len(), 2);
            let parts = items[0].model_usage[0].identity_parts.as_ref().unwrap();
            assert_eq!(parts.iter().map(|part| part.request_count).sum::<u64>(), 2);
            assert_evidence_referenced(&items[0]);
            cleanup(&[&path_a, &path_b]);
        }
    });
}

fn identity_api_row(id: &str, sequence: u64, input: u64, org: &str) -> ClaudeLocalOtelEvidence {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
        ClaudeRequestIdentityEvidence,
    };
    let mut row = row(id, sequence, input);
    let attribute = |hash| ClaudeIdentityAttributeEvidence {
        origin: ClaudeIdentityAttributeOrigin::LogRecord,
        disposition: ClaudeIdentityDisposition::Complete,
        resource_hash: None,
        log_record_hash: Some(hash),
    };
    row.request_identity = Some(ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".into(),
        account: attribute("a".repeat(64)),
        organization: attribute(org_hash(org)),
        disposition: ClaudeIdentityDisposition::Complete,
    });
    refingerprint(row)
}

#[test]
fn e2_identity_twin_native_mapping_survives_side_pass_before_reconciliation() {
    with_enabled(|| {
        for reverse in [false, true] {
            let a = root_file("identity-native-a");
            let b = root_file("identity-native-b");
            let index = ScanIndex::default();
            let first = parse(
                &a,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), line("a", &at(1), 10)],
            );
            let second = parse(
                &b,
                Some(t0()),
                &index,
                &[org_marker(ORG_B), line("b", &at(2), 20)],
            );
            let mut items = if reverse {
                vec![second, first]
            } else {
                vec![first, second]
            };
            let read = sidecar(&[
                identity_api_row("a", 1, 10, ORG_A),
                identity_api_row("b", 2, 20, ORG_B),
            ]);
            attach_page(&mut items, &read);
            let api = api_report(&read);
            let trace = ClaudeTraceOwnershipLoadReport::default();
            side_calls_page(&mut items, &api, &trace, &index);
            let evidence =
                claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
            claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
            assert!(items
                .iter()
                .all(|item| !fold(item).accounts.as_ref().unwrap().conflict));
            let items = tag_owned(items, &index);
            assert_eq!((items[0].request_count, items[0].input_tokens), (2, 30));
            assert_eq!(items[0].request_evidence.len(), 2);
            assert_evidence_referenced(&items[0]);
            cleanup(&[&a, &b]);
        }
    });
}

#[test]
fn e2_identity_marker_cap_keeps_starting_org_with_or_without_different_binding() {
    with_enabled(|| {
        for count in [64, 65] {
            for bound in [None, Some("b".repeat(64))] {
                let path = root_file("identity-marker-cap");
                let index = ScanIndex::default();
                let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
                accumulator.account_identifier_hash = bound;
                accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
                accumulator.claude_file_birth.set_birth_for_test(t0());
                for i in 0..count {
                    apply_claude_code_line(&org_marker(ORG_A), &mut accumulator);
                    apply_claude_code_line(
                        &line(&format!("r-{i}"), &at(i + 1), 1),
                        &mut accumulator,
                    );
                }
                accumulator.finalize_claude_responses_e2(
                    None,
                    Some(ReadContext {
                        index: &index,
                        path: &path,
                    }),
                );
                let item = accumulator
                    .into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None)
                    .remove(0);
                let item = tag_owned(vec![item], &index).remove(0);
                assert_eq!(item.request_count, count as u64);
                assert_eq!(item.request_evidence.len(), 1);
                assert_eq!(
                    item.request_evidence[0].provider_workspace_hash.as_deref(),
                    Some(org_hash(ORG_A).as_str())
                );
                assert_eq!(fold(&item).accounts.as_ref().unwrap().conflict, count == 65);
                assert_evidence_referenced(&item);
                cleanup(&[&path]);
            }
        }
    });
}

#[test]
fn e2_identity_conflicting_account_attributes_with_complete_org_use_starting_account() {
    with_enabled(|| {
        use crate::claude_local_otel::ClaudeIdentityDisposition;
        let path = root_file("identity-account-conflict");
        let index = ScanIndex::default();
        let mut items = vec![parse(
            &path,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("a", &at(1), 10),
                switch_context(),
                org_marker(ORG_B),
                line("b", &at(2), 20),
            ],
        )];
        let mut conflict = identity_api_row("b", 2, 20, ORG_B);
        let identity = conflict.request_identity.as_mut().unwrap();
        identity.account.resource_hash = Some("c".repeat(64));
        identity.account.disposition = ClaudeIdentityDisposition::Conflict;
        identity.disposition = ClaudeIdentityDisposition::Conflict;
        let read = sidecar(&[identity_api_row("a", 1, 10, ORG_A), refingerprint(conflict)]);
        attach_page(&mut items, &read);
        let api = api_report(&read);
        let trace = ClaudeTraceOwnershipLoadReport::default();
        side_calls_page(&mut items, &api, &trace, &index);
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (2, 30));
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0002")
        );
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str())
        );
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_final_twin_union_over_authority_cap_falls_back_to_starting_org() {
    with_enabled(|| {
        let a = root_file("identity-cap-a");
        let b = root_file("identity-cap-b");
        let index = ScanIndex::default();
        let lines = |offset| {
            let mut lines = vec![
                org_marker(ORG_A),
                line(&format!("first-{offset}"), &at(1), 1),
            ];
            for i in 1..10 {
                let ordinal = offset + i;
                lines.push(json!({"type":"attachment","sessionId":ROOT,"attachment":{"type":"session_context","context":{"userEmail":format!("synthetic-{ordinal}@example.invalid")}}}));
                lines.push(org_marker(&format!(
                    "33333333-3333-4333-8333-{ordinal:012x}"
                )));
                lines.push(line(&format!("r-{ordinal}"), &at(i + 1), 1));
            }
            lines
        };
        let items = vec![
            parse(&a, Some(t0()), &index, &lines(0)),
            parse(&b, Some(t0()), &index, &lines(9)),
        ];
        assert!(items
            .iter()
            .all(|item| !fold(item).accounts.as_ref().unwrap().conflict));
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (20, 20));
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_A).as_str())
        );
        assert!(
            rows_of(&item).all(|row| row.identity_parts.is_none() && row.evidence_ref == Some(0))
        );
        assert_evidence_referenced(&item);
        cleanup(&[&a, &b]);
    });
}

#[test]
fn e2_identity_inherited_counter_streams_union_of_native_twin_requests() {
    with_enabled(|| {
        let a = root_file("identity-count-a");
        let b = root_file("identity-count-b");
        let index = ScanIndex::default();
        let one = parse(
            &a,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("first", &at(1), 1),
                line("shared", &at(2), 1),
            ],
        );
        let two = parse(
            &b,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("first", &at(1), 1),
                line("shared", &at(2), 1),
                line("new", &at(3), 1),
            ],
        );
        for items in [vec![one.clone(), two.clone()], vec![two, one]] {
            let counts =
                serde_json::to_value(claude_request_identity::page_identity_counts(&items))
                    .unwrap();
            assert_eq!(counts, json!({"claude_inherited_org_requests":2}));
        }
        cleanup(&[&a, &b]);
    });
}

#[test]
fn e2_identity_disjoint_inherited_counter_exceeds_each_twin_in_both_orders() {
    with_enabled(|| {
        let a = root_file("identity-count-disjoint-a");
        let b = root_file("identity-count-disjoint-b");
        let index = ScanIndex::default();
        let one = parse(
            &a,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("first-a", &at(1), 1),
                line("a-one", &at(2), 1),
                line("a-two", &at(3), 1),
            ],
        );
        let two = parse(
            &b,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("first-b", &at(1), 1),
                line("b-one", &at(2), 1),
                line("b-two", &at(3), 1),
            ],
        );
        for items in [vec![one.clone(), two.clone()], vec![two, one]] {
            assert_eq!(
                serde_json::to_value(claude_request_identity::page_identity_counts(&items))
                    .unwrap(),
                json!({"claude_inherited_org_requests":4})
            );
        }
        cleanup(&[&a, &b]);
    });
}

#[test]
fn e2_identity_inherited_counter_excludes_held_copies_and_restores_counted_copies() {
    with_enabled(|| {
        let path = root_file("identity-count-copy");
        let index = ScanIndex::default();
        for restore in [false, true] {
            let version = if restore { "unknown" } else { "2.1.309" };
            let item = parse(
                &path,
                Some(t0() + 100_000_000_000),
                &index,
                &[
                    org_marker(ORG_A),
                    versioned(line("prefix", &at(1), 1), version),
                    versioned(line("inherited-copy", &at(2), 1), version),
                    versioned(line("own", &at(101), 1), version),
                ],
            );
            assert_eq!(
                fold(&item).entity.removed_requests,
                if restore { 0 } else { 2 }
            );
            let counts =
                serde_json::to_value(claude_request_identity::page_identity_counts(&[item]))
                    .unwrap();
            assert_eq!(
                counts,
                json!({"claude_inherited_org_requests":if restore { 2 } else { 1 }})
            );
        }
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_external_billing_keeps_cost_without_subscription_identity() {
    with_enabled(|| {
        for (field, value) in [("auth_mode", "api_key"), ("billing_provider", "bedrock")] {
            let path = root_file("identity-external");
            let index = ScanIndex::default();
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
            accumulator.claude_file_birth.set_birth_for_test(t0());
            accumulator
                .current_selector
                .insert(field, value.into(), "synthetic_native_route");
            for line in [org_marker(ORG_A), line("one", &at(1), 10)] {
                apply_claude_code_line(&line, &mut accumulator);
            }
            accumulator.finalize_claude_responses_e2(
                None,
                Some(ReadContext {
                    index: &index,
                    path: &path,
                }),
            );
            let mut items =
                accumulator.into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None);
            assert!(finish_page(&mut items, &index, TelemetryRead::Loaded).is_empty());
            assert!(rows_of(&items[0])
                .any(|row| !crate::snapshots::claude_request_accounts::local_subscription(row)));
            let api = ClaudeLocalOtelLoadReport::default();
            let trace = ClaudeTraceOwnershipLoadReport::default();
            let evidence =
                claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
            let outcome =
                claude_request_identity::apply_scan(&mut items, &evidence, BTreeMap::new());
            assert_eq!(outcome.ineligible, 1);
            assert_eq!((items[0].request_count, items[0].input_tokens), (1, 10));
            assert!(items[0].request_evidence.is_empty());
            assert!(rows_of(&items[0])
                .all(|row| row.evidence_ref.is_none() && row.identity_parts.is_none()));
            cleanup(&[&path]);
        }
    });
}

#[test]
fn e2_identity_provisional_unknown_twin_does_not_poison_later_marked_twin() {
    with_enabled(|| {
        for reverse in [false, true] {
            let a = root_file("identity-retained-a");
            let b = root_file("identity-retained-b");
            let index = ScanIndex::default();
            let mut first = parse(&a, Some(t0()), &index, &[line("a", &at(1), 10)]);
            // Native Desktop metadata/account owner installs this after the finalizer.
            crate::snapshots::set_session_account_hash(&mut first, Some(&"a".repeat(64)));
            let second = parse(
                &b,
                Some(t0()),
                &index,
                &[org_marker(ORG_B), line("b", &at(2), 20)],
            );
            let mut items = if reverse {
                vec![second, first]
            } else {
                vec![first, second]
            };
            let read = sidecar(&[row("a", 1, 10), identity_api_row("b", 2, 20, ORG_B)]);
            attach_page(&mut items, &read);
            let api = api_report(&read);
            let trace = ClaudeTraceOwnershipLoadReport::default();
            side_calls_page(&mut items, &api, &trace, &index);
            let evidence =
                claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
            claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
            assert!(items
                .iter()
                .all(|item| !fold(item).accounts.as_ref().unwrap().conflict));
            let items = tag_owned(items, &index);
            assert_eq!((items[0].request_count, items[0].input_tokens), (2, 30));
            assert_eq!(items[0].request_evidence.len(), 2);
            assert!(items[0]
                .request_evidence
                .iter()
                .any(|entry| entry.provider_workspace_hash.as_deref()
                    == Some(org_hash(ORG_B).as_str())));
            assert_evidence_referenced(&items[0]);
            cleanup(&[&a, &b]);
        }
    });
}

#[test]
fn e2_identity_desktop_request_still_publishes_validated_recent_activity() {
    with_enabled(|| {
        let path = root_file("identity-desktop-activity");
        let index = ScanIndex::default();
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap();
        let event = now - time::Duration::seconds(2);
        let clock = event
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut desktop = line("desktop-recent", &clock, 10);
        desktop["entrypoint"] = json!("claude-desktop");
        let mut item = parse(&path, Some(t0()), &index, &[org_marker(ORG_A), desktop]);
        item.collected_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let account = "d".repeat(64);
        item.session_account_evidence = Some(crate::snapshots::SessionAccountEvidence {
            provider: "anthropic",
            account_identifier_hash: Some(account.clone()),
            provider_workspace_hash: Some(org_hash(ORG_A)),
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "claude_desktop_original:v1",
            identity_disposition: Some("complete"),
            source_created_at: Some(clock),
        });
        let item = tag_owned(vec![item], &index).remove(0);
        assert_eq!(item.request_count, 1);
        assert_eq!(
            crate::desktop_recent::saved().at(&account, &org_hash(ORG_A)),
            Some(event)
        );
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_recent_desktop_activity_survives_discarded_twin_in_both_orders() {
    with_enabled(|| {
        for reverse in [false, true] {
            let cli = root_file("identity-activity-cli-twin");
            let desktop_path = root_file("identity-activity-desktop-twin");
            let index = ScanIndex::default();
            let mut older = parse(
                &cli,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), line("old-cli", &at(1), 10)],
            );
            let now = time::OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .unwrap();
            let event = now - time::Duration::seconds(2);
            let clock = event
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            let mut desktop = line("recent-twin", &clock, 20);
            desktop["entrypoint"] = json!("claude-desktop");
            let mut recent = parse(
                &desktop_path,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), desktop],
            );
            let collected = now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            recent.collected_at = collected.clone();
            let account = if reverse { "17" } else { "18" }.repeat(32);
            assert_eq!(
                crate::desktop_recent::saved().at(&account, &org_hash(ORG_A)),
                None,
                "each ordering must publish its own activity, not reuse process-global state"
            );
            recent.session_account_evidence = Some(crate::snapshots::SessionAccountEvidence {
                provider: "anthropic",
                account_identifier_hash: Some(account.clone()),
                provider_workspace_hash: Some(org_hash(ORG_A)),
                identity_hash_scheme: "provider-sha256:v1",
                evidence_source: "claude_desktop_original:v1",
                identity_disposition: Some("complete"),
                source_created_at: Some(clock),
            });
            older.source_file_fingerprint = Some("synthetic-cli-physical-source".into());
            recent.source_file_fingerprint = Some("synthetic-desktop-physical-source".into());
            older.session_account_evidence = Some(crate::snapshots::SessionAccountEvidence {
                provider: "anthropic",
                account_identifier_hash: None,
                provider_workspace_hash: None,
                identity_hash_scheme: "provider-sha256:v1",
                evidence_source: "claude_desktop_original:v1",
                identity_disposition: Some("missing"),
                source_created_at: None,
            });
            let mut items = if reverse {
                vec![recent, older]
            } else {
                vec![older, recent]
            };
            for item in &mut items {
                item.collected_at = collected.clone();
            }
            let items = tag_owned(items, &index);
            assert_eq!(items.len(), 1);
            assert_eq!((items[0].request_count, items[0].input_tokens), (2, 30));
            assert_eq!(
                crate::desktop_recent::saved().at(&account, &org_hash(ORG_A)),
                Some(event)
            );
            cleanup(&[&cli, &desktop_path]);
        }
    });
}
