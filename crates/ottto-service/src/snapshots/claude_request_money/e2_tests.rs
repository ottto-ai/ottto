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
    a.finalize_claude_responses_e2(Some(ReadContext {
        index,
        path,
        twins: &Default::default(),
    }));
    let mut items = a.into_items(path, "2026-08-02T09:00:00Z", "fixture".into(), None);
    // The page's copy decision, as the scan runs it; `publish` decides again
    // over the whole page, where a parsed witness proves its own requests.
    decide_page_copies(&mut items, index);
    items.remove(0)
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
    decide_page_copies(&mut items, index);
    if let Some(read) = read {
        attach_page(&mut items, read);
        side_calls_page(
            &mut items,
            &api_report(read),
            &ClaudeTraceOwnershipLoadReport::default(),
            index,
        );
    }
    with_enabled(|| finish_page(&mut items, index, telemetry, &mut Default::default()));
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
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
            Some(&sidecar(std::slice::from_ref(&otel))),
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
    });
}

#[test]
fn e2_model_less_record_attaches_through_its_native_fallback_key() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_untimed_record_attaches_from_the_bucket_fallback() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_hour_boundary_keeps_the_transcript_hour() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_otel_only_fast_speed_and_effort_join_the_reported_key() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_failed_or_missing_telemetry_read_is_never_complete() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_oversized_sidecar_is_incomplete_and_attaches_nothing() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_path_twins_attach_the_row_once() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_unpriced_row_is_telemetry_unpriced() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_priced_and_unpriced_rows_in_one_hour_stay_separate() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_move_then_copy_across_restart_counts_each_request_once() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_restored_twins_both_prebirth_skip_exactly_one_never_both() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
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
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_side_call_goes_to_the_trace_named_subagent_else_the_root() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
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
    });
}

#[test]
fn e2_side_call_waits_while_the_walk_has_not_listed_the_named_members_directory() {
    // A trace-named member the walk has not discovered may still have a
    // transcript that counts the row: the root holds rather than count it
    // twice. Once the family directory is listed, a member still without a
    // transcript falls back to the root (COST Q3).
    with_enabled(|| {
        let p = root_file("side-wait");
        let family = p.parent().unwrap().join(ROOT);
        let read = sidecar(&[row("r", 1, 10), row("named", 4, 40)]);
        let trace = ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(
                ROOT.to_owned(),
                vec![complete_trace_row(ROOT, "named", "abc")],
            )]),
            ..Default::default()
        };
        for (queued, held) in [
            (vec![family.clone()], true),
            (vec![family.join("subagents")], true),
            (vec![p.parent().unwrap().join("other-session")], false),
            (vec![], false),
        ] {
            let index = queued_traversal(&queued, &[]);
            let mut items = vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])];
            attach_page(&mut items, &read);
            let unresolved = side_calls_page(&mut items, &api_report(&read), &trace, &index);
            let root = fold(&items[0]);
            assert_eq!(unresolved.contains(ROOT), held, "{queued:?}");
            assert_eq!(root.entity.held, held, "{queued:?}");
            assert_eq!(root.telemetry.side_calls_done, !held, "{queued:?}");
            assert_eq!(
                (root.side_requests, root.root_fallbacks),
                if held { (0, 0) } else { (1, 1) },
                "{queued:?}"
            );
        }
        let _ = fs::remove_dir_all(p.parent().unwrap());
    });
}

fn queued_traversal(queued: &[PathBuf], candidates: &[PathBuf]) -> ScanIndex {
    let paths = |paths: &[PathBuf]| {
        paths
            .iter()
            .map(|path| json!({"scan_root": "/", "path": path}))
            .collect::<Vec<_>>()
    };
    ScanIndex {
        traversal: Some(
            serde_json::from_value(json!({
                "context_fingerprint": "queued",
                "census_window_end": "2026-01-01T00:00:00Z",
                "scan_roots": [],
                "pending_directories": paths(queued),
                "pending_candidates": paths(candidates),
                "observed_index_keys": [],
                "reconciliation_upper_bound": null,
                "reconciliation_after": null,
                "reconciliation_started": false,
                "counts": {},
            }))
            .unwrap(),
        ),
        ..ScanIndex::default()
    }
}

#[test]
fn e2_gate_on_defers_a_root_whose_family_directory_is_queued() {
    let project = PathBuf::from("/projects/p");
    let waiting = project.join(format!("{ROOT}.jsonl"));
    let listed = project.join("3338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let member = project.join(ROOT).join("subagents/agent-abc.jsonl");
    let behind = project.join("behind.jsonl");
    let mut index = queued_traversal(
        &[project.join(ROOT).join("subagents")],
        std::slice::from_ref(&behind),
    );
    let mut traversal = index.traversal.take().unwrap();
    let mut selected = [&waiting, &listed, &member]
        .into_iter()
        .map(|path| serde_json::from_value(json!({"scan_root": "/", "path": path})).unwrap())
        .collect::<Vec<ScanTraversalPath>>();
    defer_roots_of_queued_families(&mut selected, &mut traversal);
    fn paths<'a>(candidates: impl IntoIterator<Item = &'a ScanTraversalPath>) -> Vec<PathBuf> {
        candidates
            .into_iter()
            .map(|candidate| candidate.path.clone())
            .collect()
    }
    // The member and the root with no queued family stay; the deferred root
    // is read next, ahead of the queue.
    assert_eq!(paths(&selected), vec![listed.clone(), member]);
    assert_eq!(
        paths(&traversal.pending_candidates),
        vec![waiting.clone(), behind]
    );
    // Once the walk lists the directory nothing is deferred.
    traversal.pending_directories.clear();
    let mut again = vec![traversal.pending_candidates.pop_front().unwrap()];
    defer_roots_of_queued_families(&mut again, &mut traversal);
    assert_eq!(paths(&again), vec![waiting]);
}

#[test]
fn e2_resolver_conflict_is_counted_and_emitted() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
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
    // Gate on publishes, so it parses gate on too: dark keeps no grains.
    let mut items = with_enabled(page);
    items[0].claude_money.as_deref_mut().unwrap().entity.held = true;
    let before = canonical(&items);
    let mut reasons = BTreeMap::new();
    let withheld =
        with_enabled(|| finish_page(&mut items, &index, TelemetryRead::Loaded, &mut reasons));
    assert_eq!(reasons, BTreeMap::from([("request_owned_held", 1)]));
    assert_eq!(withheld, BTreeSet::from([ROOT.to_owned()]));
    assert_eq!(items.len(), 2, "no path of a withheld session is dropped");
    assert_eq!(canonical(&items), before);
    assert!(items
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    // Not held: one summed body, nothing withheld.
    let mut items = with_enabled(page);
    let withheld = with_enabled(|| {
        finish_page(
            &mut items,
            &index,
            TelemetryRead::Loaded,
            &mut Default::default(),
        )
    });
    assert!(withheld.is_empty());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].request_count, 2);
    // Gate off withholds nothing and changes nothing.
    let mut items = with_disabled(page);
    items[0].claude_money.as_deref_mut().unwrap().entity.held = true;
    let before = canonical(&items);
    assert!(with_disabled(|| finish_page(
        &mut items,
        &index,
        TelemetryRead::Loaded,
        &mut Default::default()
    ))
    .is_empty());
    assert_eq!(canonical(&items), before);
    cleanup(&[&first, &copy]);
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
        serde_json::to_value(Counts::work([1, 2, 0, 0, 0, 3, 0])).unwrap(),
        json!({"fold_us":1,"responses":2,"side_call_root_fallback":3})
    );
    let tally = PrefixTally {
        unproven_requests: 4,
        unproven_idless: 1,
        priced_requests: 2,
        cost_micros: 700,
        reused: 0,
        ..PrefixTally::default()
    };
    assert_eq!(
        serde_json::to_value(Counts::prefix(&tally)).unwrap(),
        json!({"copy_prefix_unproven_requests":5,"copy_prefix_unproven_files":1,
            "copy_prefix_unproven_priced_requests":2,"copy_prefix_unproven_cost_micros":700})
    );
    assert_eq!(
        serde_json::to_value(Counts::removal_store(3, 0)).unwrap(),
        json!({"copy_removal_stored":3})
    );
}

#[test]
fn e2_reported_selector_inputs_keep_model_speed_effort_and_hour() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
                            let item =
                                parse(&p, Some(t0()), &index, &[line("seed", &at(0), 1), value]);
                            let mut occurrence = item.claude_usage_occurrences["r"].clone();
                            occurrence.reasoning_effort = native_effort.map(str::to_owned);
                            let mut api = row("r", 1, 10);
                            api.speed = speed.to_owned();
                            api.effort = effort.to_owned();
                            api.observed_at = at(3601); // fallback clock is another hour
                            for occurrence in [Some(&occurrence), None] {
                                let mut e2 =
                                    reported_key(&api, occurrence, &SelectorCapture::default())
                                        .unwrap();
                                let kept_effort = e2.2.remove("reasoning_effort");
                                assert_eq!(
                                    e2.1,
                                    occurrence
                                        .and_then(|o| o.model.as_deref())
                                        .unwrap_or(&api.model)
                                );
                                assert_eq!(
                                    e2.2.get("speed_mode").map(String::as_str),
                                    (!speed.is_empty()).then_some(speed)
                                );
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
                                    e2.0,
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
    })
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
fn e2_membership_view_lists_each_request_set_and_occurrence_id_once() {
    let p = root_file("membership-union");
    let index = ScanIndex::default();
    let mut items = vec![parse(
        &p,
        Some(t0()),
        &index,
        &[line("b", &at(1), 10), line("d", &at(2), 10)],
    )];
    let occurrence = items[0].claude_usage_occurrences["b"].clone();
    items[0].claude_usage_request_ids.insert("a".into());
    items[0].claude_usage_request_ids.insert("e".into());
    items[0]
        .claude_usage_occurrences
        .insert("c".into(), occurrence.clone());
    items[0]
        .claude_usage_occurrences
        .insert("f".into(), occurrence);
    let ids = item_request_ids(&items[0]).cloned().collect::<Vec<_>>();
    assert_eq!(ids.len(), 6, "no id twice: {ids:?}");
    assert_eq!(
        ids.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from(["a", "b", "c", "d", "e", "f"].map(String::from))
    );
    let view = family_membership(&items, &[0]);
    assert_eq!(view.entries.capacity(), 6);
    for id in ["a", "b", "c", "d", "e", "f"] {
        assert_eq!(matching_members(&view, id).collect::<Vec<_>>(), [0usize]);
    }
    cleanup(&[&p]);
}

/// Side calls reuse one key per (model, speed, effort, UTC hour): the
/// placement reads the clock only for its hour bucket, offsets included.
#[test]
fn e2_side_call_key_reuse_is_exact_per_utc_hour() {
    let clocks = [
        "2026-08-02T07:00:00Z",
        "2026-08-02T07:59:59.999999999Z",
        "2026-08-02T09:30:00+02:00",
        "2026-08-02T08:00:00Z",
        "2026-08-02T03:15:00-05:00",
    ];
    let base = SelectorCapture::default();
    for a in clocks {
        for b in clocks {
            let (mut x, mut y) = (row("x", 1, 10), row("y", 2, 10));
            x.observed_at = a.into();
            y.observed_at = b.into();
            let hour = |clock: &str| rfc3339_unix_nanos(clock).unwrap().div_euclid(HOUR_NANOS);
            let key = reported_key(&x, None, &base);
            assert!(key.is_some());
            assert_eq!(
                key == reported_key(&y, None, &base),
                hour(a) == hour(b),
                "{a} vs {b}"
            );
        }
    }
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
    // The gate is a build constant: each mode parses its own page.
    let parse_page = |index: &ScanIndex| {
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
            items.push(parse(&path, Some(t0()), index, &lines));
        }
        items
    };
    let items = with_disabled(|| parse_page(&index));
    let items_enabled = with_enabled(|| parse_page(&index));
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
            unchanged_source: false,
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
    // The optimized target is 20 ms. The debug budget is only a flaky-timing
    // guard against gross regressions (shared Linux runners measured 182-507
    // ms), not a correctness assertion: the real gate is the optimized Mac
    // benchmark. Fingerprints/row placement are timed below.
    let join_budget = Duration::from_millis(if cfg!(debug_assertions) { 2_000 } else { 20 });
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
        let in_mode = |run: &mut dyn FnMut()| {
            if enabled {
                with_enabled(run)
            } else {
                with_disabled(run)
            }
        };
        let parsed = if enabled { &items_enabled } else { &items };
        // Wall clock without the allocation probe: its born-pointer table
        // locks and walks on every allocation and free of every thread.
        // Fresh row copies per pass: no fingerprint result carried over.
        let api = api_report(&read);
        let mut page = parsed.clone();
        take_stages();
        let start = Instant::now();
        in_mode(&mut || {
            attach_page(&mut page, &read);
            side_calls_page(&mut page, &api, &trace, &index);
        });
        drop(api);
        let enrichment_time = start.elapsed();
        let stages = take_stages();
        // The same work on an identical page, for the born-in-scope peak only.
        // Dark attach moves the tally, not grains: one probed pass per mode.
        let (allocation, probed_time) = {
            let api = api_report(&read);
            let mut probed = parsed.clone();
            let probe_start = Instant::now();
            let mut allocation = None;
            in_mode(&mut || {
                allocation = Some(
                    crate::retry_allocation_probe::measure_caller_thread(|| {
                        attach_page(&mut probed, &read);
                        side_calls_page(&mut probed, &api, &trace, &index);
                    })
                    .1,
                );
            });
            let probed_time = probe_start.elapsed();
            take_stages();
            assert!(page.iter().zip(&probed).all(|(a, b)| {
                fold(a).entity.grains == fold(b).entity.grains
                    && fold(a).entity.totals() == fold(b).entity.totals()
                    && fold(a).entity.estimated_requests() == fold(b).entity.estimated_requests()
                    && fold(a).side_requests == fold(b).side_requests
            }));
            (allocation.unwrap(), probed_time)
        };
        assert!(page
            .iter()
            .all(|item| fold(item).telemetry.membership.entries.is_empty()));
        // Both modes: matched requests left the estimate, and the family
        // counts every transcript request plus each unheld reported one.
        assert_eq!(
            page.iter()
                .map(|item| fold(item).entity.estimated_requests())
                .sum::<u64>(),
            (ROWS - MEMBERS) as u64
        );
        assert_eq!(
            page.iter()
                .map(|item| fold(item).entity.totals().1)
                .sum::<u64>(),
            (2 * ROWS - MEMBERS - OFF_PAGE) as u64
        );
        if enabled {
            // Grain detail exists only with the gate on.
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
        }
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
        // The bound covers attach and side calls outside the gate, as it
        // always has. Gate on adds the identity owner's root-account
        // inheritance and account-keyed grains: reported by F3_PERF below.
        assert!(
            enabled || allocation.requested_peak_with_overlap <= 2 * 1024 * 1024,
            "attach+side-call born-in-scope allocation peak: {allocation:?}"
        );
        let finish_start = Instant::now();
        let withheld = if enabled {
            with_enabled(|| {
                finish_page(
                    &mut page,
                    &index,
                    TelemetryRead::Loaded,
                    &mut Default::default(),
                )
            })
        } else {
            with_disabled(|| {
                finish_page(
                    &mut page,
                    &index,
                    TelemetryRead::Loaded,
                    &mut Default::default(),
                )
            })
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
    // Same-run comparison on fresh copies of the first 10,000 rows: the
    // blanked-copy rule, the first check, and a second check that reuses
    // each row's kept result. All three must agree.
    let sample = read.evidence[ROOT][..10_000].to_vec();
    let start = Instant::now();
    let copy_rule = sample
        .iter()
        .map(|row| reference_fingerprint_ok(row, &row.fingerprint, |r| r.fingerprint.clear()))
        .collect::<Vec<_>>();
    let copy_rule_time = start.elapsed();
    let start = Instant::now();
    let first = sample
        .iter()
        .map(|row| validate_claude_api_row(row, ROOT))
        .collect::<Vec<_>>();
    let first_time = start.elapsed();
    let start = Instant::now();
    let again = sample
        .iter()
        .map(|row| validate_claude_api_row(row, ROOT))
        .collect::<Vec<_>>();
    let again_time = start.elapsed();
    assert!(copy_rule.iter().all(|valid| *valid));
    assert_eq!(first, copy_rule);
    assert_eq!(again, copy_rule);
    eprintln!(
        "F3_PERF fingerprint rows={} copy_rule_us={} first_check_us={} kept_result_us={}",
        sample.len(),
        copy_rule_time.as_micros(),
        first_time.as_micros(),
        again_time.as_micros()
    );
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
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
        for reverse in [false, true] {
            let early = root_file("first-early");
            let later = root_file("first-later");
            let history = [line("h1", &at(-100), 1), line("h2", &at(-90), 2)];
            let mut index = ScanIndex::default();
            index.files.insert(local_index_key(&early), entry());
            index.files.insert(local_index_key(&later), entry());
            assert!(index.claude_money_birth_store.is_empty());
            let mut paths: Vec<(&Path, i128)> =
                vec![(&early, t0()), (&later, t0() + 5_000_000_000)];
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
    })
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
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_recreated_or_truncated_original_cannot_witness_a_copy() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

fn without_version(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("version");
    value
}

#[test]
fn e2_missing_own_writer_invalidates_known_prefix_and_both_own_orders() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
}

#[test]
fn e2_all_prebirth_twins_require_known_response_writers() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
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
    })
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
fn tag_owned(items: Vec<SnapshotItem>, index: &ScanIndex) -> Vec<SnapshotItem> {
    tag_owned_with_fallbacks(items, index, 0)
}
fn tag_owned_with_fallbacks(
    mut items: Vec<SnapshotItem>,
    index: &ScanIndex,
    expected_fallbacks: usize,
) -> Vec<SnapshotItem> {
    decide_page_copies(&mut items, index);
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
    let withheld = finish_page(
        &mut items,
        index,
        TelemetryRead::Loaded,
        &mut Default::default(),
    );
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
    assert!(expected_fallbacks <= items.len());
    assert_eq!(outcome.sent, items.len() - expected_fallbacks);
    assert_eq!(outcome.fallback, expected_fallbacks);
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
fn e2_identity_conflict_preserves_own_and_earlier_orgs() {
    with_enabled(|| {
        let path = root_file("identity-conflict");
        let mut index = ScanIndex::default();
        index.session_account_bindings.insert(
            crate::snapshots::sha256_hex(&["session_owner:v1", "synthetic-machine", ROOT]),
            crate::snapshots::SessionAccountBinding {
                account_identifier_hash: "c".repeat(64),
                workspace_identifier_hash: None,
            },
        );
        let lines = vec![
            org_marker(ORG_A),
            line("a", &at(1), 10),
            switch_context(),
            org_marker(ORG_B),
            line("b", &at(2), 20),
            org_marker("invalid"),
            line("c", &at(3), 30),
        ];
        let mut items = vec![parse(&path, Some(t0()), &index, &lines)];
        claude_request_identity::retain_root_accounts(&mut items, &index, "synthetic-machine");
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (3, 60));
        // R2-2: conflict fallback cannot erase B or its later inherited share.
        assert_eq!(
            org_amounts(&item),
            BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (50, 2)),])
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
        assert_eq!(item.request_evidence.len(), 1);
        assert_eq!(
            item.request_evidence[0].provider_workspace_hash.as_deref(),
            Some(org_hash(ORG_B).as_str())
        );
        let parts = item.model_usage[0].identity_parts.as_ref().unwrap();
        assert_eq!(
            parts
                .iter()
                .find(|part| part.evidence_ref.is_none())
                .map(|part| (part.input_tokens, part.request_count)),
            Some((10, 1))
        );
        assert_eq!(
            parts
                .iter()
                .find(|part| part.evidence_ref == Some(0))
                .map(|part| (part.input_tokens, part.request_count)),
            Some((20, 1))
        );
        assert!(!fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
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
fn e2_identity_mid_session_request_with_two_orgs_goes_to_the_starting_account() {
    // R3-N2 (QUOTA): two different trusted orgs on one later request are
    // never guessed (neither the first nor the last); the request goes to
    // the starting account, counted, and a later markerless request inherits it.
    const ORG_C: &str = "33333333-3333-4333-8333-333333333333";
    with_enabled(|| {
        let path = root_file("identity-mid-session-pair");
        let index = ScanIndex::default();
        let item = tag_owned(
            vec![parse(
                &path,
                Some(t0()),
                &index,
                &[
                    org_marker(ORG_A),
                    line("a", &at(1), 10),
                    switch_context(),
                    org_marker(ORG_B),
                    json!({"type":"attachment","sessionId":ROOT,
                        "attachment":{"type":"session_context",
                            "context":{"userEmail":"other@example.invalid"}}}),
                    org_marker(ORG_C),
                    line("b", &at(2), 20),
                    line("c", &at(3), 30),
                ],
            )],
            &index,
        )
        .remove(0);
        assert_eq!((item.request_count, item.input_tokens), (3, 60));
        let accounts = fold(&item).accounts.as_ref().unwrap();
        assert!(accounts.conflict, "the pair is counted as a conflict");
        assert!(!accounts.mixed);
        assert_eq!(
            org_amounts(&item),
            BTreeMap::from([(org_hash(ORG_A), (60, 3))])
        );
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_two_org_request_with_its_own_telemetry_login_goes_to_the_starting_account() {
    // SOURCE R2-N2: the R3-N2 pair request also carries its own exact
    // telemetry login. Two orgs on one request are never guessed, and the
    // login does not move it either: starting account, counted.
    const ORG_C: &str = "33333333-3333-4333-8333-333333333333";
    with_enabled(|| {
        let path = root_file("identity-pair-own-login");
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
                json!({"type":"attachment","sessionId":ROOT,
                    "attachment":{"type":"session_context",
                        "context":{"userEmail":"other@example.invalid"}}}),
                org_marker(ORG_C),
                line("b", &at(2), 20),
                line("c", &at(3), 30),
            ],
        )];
        let mut own = row("b", 2, 20);
        own.account_identifier_hash = Some("b".repeat(64));
        let read = sidecar(&[refingerprint(own)]);
        attach_page(&mut items, &read);
        let api = api_report(&read);
        let trace = ClaudeTraceOwnershipLoadReport::default();
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
        let item = tag_owned(items, &index).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (3, 60));
        let accounts = fold(&item).accounts.as_ref().unwrap();
        assert!(accounts.conflict, "the pair is counted as a conflict");
        assert!(!accounts.mixed);
        assert_eq!(
            org_amounts(&item),
            BTreeMap::from([(org_hash(ORG_A), (60, 3))])
        );
        let login_b = "b".repeat(64);
        assert!(
            rows_of(&item).all(|row| {
                row.account_identifier_hash.as_deref() != Some(login_b.as_str())
                    && row.identity_parts.iter().flatten().all(|part| {
                        part.account_identifier_hash.as_deref() != Some(login_b.as_str())
                    })
            }),
            "the pair request's own login does not move it"
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
fn e2_identity_telemetry_contradiction_preserves_own_orgs() {
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
        assert_eq!(
            org_amounts(&item),
            BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (20, 1)),])
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
                accumulator.finalize_claude_responses_e2(Some(ReadContext {
                    index: &index,
                    path: &path,
                    twins: &Default::default(),
                }));
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
fn e2_identity_conflicting_account_attributes_preserve_complete_own_orgs() {
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
        assert_eq!(
            org_amounts(&item),
            BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (20, 1)),])
        );
        assert!(fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_final_twin_union_over_authority_cap_withholds_unproved_identity() {
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
        let item = tag_owned_with_fallbacks(items, &index, 1).remove(0);
        assert_eq!((item.request_count, item.input_tokens), (20, 20));
        // SOURCE: overflowing proof cannot be replaced by the starting org.
        // The old uniform-retry expectation would manufacture that identity.
        assert!(item.request_evidence.is_empty());
        assert!(rows_of(&item).all(|row| row.identity_parts.is_none()
            && row.evidence_ref.is_none()
            && row.account_identifier_hash.is_none()));
        assert_eq!(
            item.request_identity_refusals, 1,
            "the bucket row lost proof"
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
            accumulator.finalize_claude_responses_e2(Some(ReadContext {
                index: &index,
                path: &path,
                twins: &Default::default(),
            }));
            let mut items =
                accumulator.into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None);
            assert!(finish_page(
                &mut items,
                &index,
                TelemetryRead::Loaded,
                &mut Default::default()
            )
            .is_empty());
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

#[test]
fn e2_identity_unqualified_markerless_twins_use_known_session_start_in_both_orders() {
    with_enabled(|| {
        for same_start in [false, true] {
            for reverse in [false, true] {
                let a = root_file("identity-known-twin");
                let b = root_file("identity-markerless-twin");
                let index = ScanIndex::default();
                let mut known = parse(
                    &a,
                    Some(t0()),
                    &index,
                    &[org_marker(ORG_A), line("known", &at(2), 20)],
                );
                let mut markerless =
                    parse(&b, Some(t0()), &index, &[line("markerless", &at(1), 10)]);
                if same_start {
                    known.source_started_at = Some(at(1));
                    markerless.source_started_at = Some(at(1));
                }
                assert!(crate::snapshots::exact_session_account_hash(&markerless).is_none());
                let mut items = if reverse {
                    vec![markerless, known]
                } else {
                    vec![known, markerless]
                };
                claude_request_identity::inherit_root_accounts(&mut items, false);
                assert!(items
                    .iter()
                    .all(|item| !fold(item).accounts.as_ref().unwrap().conflict));
                claude_request_identity::inherit_root_accounts(&mut items, true);
                let counts =
                    serde_json::to_value(claude_request_identity::page_identity_counts(&items))
                        .unwrap();
                assert!(counts.get("claude_identity_conflict_fallbacks").is_none());
                assert_eq!(counts["claude_inherited_org_requests"], 1);
                let item = tag_owned(items, &index).remove(0);
                assert_eq!((item.request_count, item.input_tokens), (2, 30));
                assert_eq!(item.request_evidence.len(), 1);
                assert_eq!(
                    item.request_evidence[0].provider_workspace_hash.as_deref(),
                    Some(org_hash(ORG_A).as_str())
                );
                assert!(rows_of(&item)
                    .all(|row| row.evidence_ref == Some(0) && row.identity_parts.is_none()));
                assert_evidence_referenced(&item);
                cleanup(&[&a, &b]);
            }
        }
    });
}

#[test]
fn e2_identity_changed_child_only_page_inherits_durable_root_binding_after_restart() {
    with_enabled(|| {
        let root = root_file("identity-off-page-root");
        let agent = root
            .parent()
            .unwrap()
            .join(ROOT)
            .join("subagents/agent-abc.jsonl");
        fs::create_dir_all(agent.parent().unwrap()).unwrap();
        fs::write(&agent, b"fixture\n").unwrap();
        let mut index = ScanIndex::default();
        // The real account owner persists this key. The root transcript is
        // unchanged and absent from the incremental page after restart.
        index.session_account_bindings.insert(
            crate::snapshots::sha256_hex(&["session_owner:v1", "synthetic-machine", ROOT]),
            crate::snapshots::SessionAccountBinding {
                account_identifier_hash: "c".repeat(64),
                workspace_identifier_hash: None,
            },
        );
        index.files.insert(local_index_key(&root), entry());
        let index = restart(&index);
        let mut sub = line("changed-child", &at(3), 30);
        sub["agentId"] = json!("abc");
        sub["isSidechain"] = json!(true);
        for machine in ["synthetic-machine", "other-machine"] {
            let mut items = vec![parse(
                &agent,
                Some(t0()),
                &index,
                &[org_marker(ORG_B), sub.clone()],
            )];
            claude_request_identity::retain_root_accounts(&mut items, &index, machine);
            side_calls_page(&mut items, &Default::default(), &Default::default(), &index);
            let item = tag_owned(items, &index).remove(0);
            assert_eq!((item.request_count, item.input_tokens), (1, 30));
            if machine == "synthetic-machine" {
                assert!(rows_of(&item)
                    .all(|row| row.account_identifier_hash.as_deref()
                        == Some("c".repeat(64).as_str())));
                assert_eq!(item.request_evidence.len(), 1);
            } else {
                assert!(item.request_evidence.is_empty());
                assert!(rows_of(&item).all(|row| row.account_identifier_hash.is_none()));
            }
            assert_evidence_referenced(&item);
        }
        cleanup(&[&root]);
    });
}

#[test]
fn e2_identity_branch_and_resume_prefix_markers_cannot_claim_own_requests() {
    with_enabled(|| {
        for operation in ["/branch", "/resume"] {
            for fresh_marker in [false, true] {
                let path = root_file("identity-prefix-marker");
                let index = ScanIndex::default();
                let mut old_marker = org_marker(ORG_A);
                old_marker["timestamp"] = json!(at(1));
                let mut lines = vec![old_marker, line("copied", &at(2), 10)];
                // Same-session copied history without explicit fork provenance:
                // birth is the only evidence that these markers are inherited.
                lines.push(json!({"type":"user", "sessionId":ROOT,"timestamp":at(100),"message":{"role":"user","content":operation}}));
                if fresh_marker {
                    let mut own_marker = org_marker(ORG_B);
                    own_marker["timestamp"] = json!(at(100));
                    lines.push(own_marker);
                }
                lines.push(line("own", &at(101), 20));
                if fresh_marker {
                    let mut repeated = org_marker(ORG_B);
                    repeated["timestamp"] = json!(at(102));
                    lines.push(repeated);
                    lines.push(line("own-repeat", &at(103), 30));
                }
                let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
                accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
                accumulator
                    .claude_file_birth
                    .set_birth_for_test(t0() + 100_000_000_000);
                accumulator.account_identifier_hash = Some("b".repeat(64));
                for value in &lines {
                    apply_claude_code_line(value, &mut accumulator);
                }
                accumulator.finalize_claude_responses_e2(Some(ReadContext {
                    index: &index,
                    path: &path,
                    twins: &Default::default(),
                }));
                let item = accumulator
                    .into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None)
                    .remove(0);
                let item = tag_owned(vec![item], &index).remove(0);
                assert_eq!(
                    (
                        item.request_count,
                        item.input_tokens,
                        item.removed_request_count
                    ),
                    if fresh_marker {
                        (2, 50, Some(1))
                    } else {
                        (1, 20, Some(1))
                    }
                );
                assert!(!fold(&item).accounts.as_ref().unwrap().conflict);
                assert_eq!(item.request_evidence.len(), 1);
                if fresh_marker {
                    assert_eq!(
                        item.request_evidence[0].provider_workspace_hash.as_deref(),
                        Some(org_hash(ORG_B).as_str())
                    );
                } else {
                    assert!(item.request_evidence[0].provider_workspace_hash.is_none());
                    assert!(
                        rows_of(&item).all(|row| row.account_identifier_hash.as_deref()
                            == Some("b".repeat(64).as_str()))
                    );
                }
                assert_evidence_referenced(&item);
                cleanup(&[&path]);
            }
        }
    });
}

#[test]
fn e2_identity_markerless_desktop_keeps_d1_shape_and_recent_activity() {
    with_enabled(|| {
        let path = root_file("identity-markerless-desktop");
        let index = ScanIndex::default();
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap();
        let event = now - time::Duration::seconds(2);
        let clock = event
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let account = "29".repeat(32);
        assert_eq!(
            crate::desktop_recent::saved().at(&account, &org_hash(ORG_A)),
            None
        );
        let mut desktop = line("markerless-desktop", &clock, 10);
        desktop["entrypoint"] = json!("claude-desktop");
        let mut item = parse(&path, Some(t0()), &index, &[desktop]);
        item.collected_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        item.session_account_evidence = Some(crate::snapshots::SessionAccountEvidence {
            provider: "anthropic",
            account_identifier_hash: Some(account.clone()),
            provider_workspace_hash: Some(org_hash(ORG_A)),
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "claude_desktop_original:v1",
            identity_disposition: Some("complete"),
            source_created_at: Some(clock),
        });
        crate::snapshots::set_session_account_hash(&mut item, Some(&account));
        let mut items = vec![item];
        let api = ClaudeLocalOtelLoadReport::default();
        let trace = ClaudeTraceOwnershipLoadReport::default();
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        let disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
        let ownership =
            claude_request_identity::TranscriptOwnership::after_census(&index, &disposition);
        let originals = claude_request_identity::capture_request_owned_originals(&items);
        claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
        let activity = claude_request_identity::stage_request_owned_activity(
            &items, &evidence, &ownership, &originals,
        );
        assert!(finish_page(
            &mut items,
            &index,
            TelemetryRead::Loaded,
            &mut Default::default()
        )
        .is_empty());
        let before = serde_json::to_vec(&items).unwrap();
        let outcome = claude_request_identity::apply_scan_with_ownership(
            &mut items,
            &evidence,
            BTreeMap::new(),
            &ownership,
        );
        assert_eq!((outcome.sent, outcome.ineligible), (0, 1));
        assert_eq!(serde_json::to_vec(&items).unwrap(), before);
        claude_request_identity::publish_request_owned_activity(&items, activity);
        assert_eq!(
            crate::desktop_recent::saved().at(&account, &org_hash(ORG_A)),
            Some(event)
        );
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_failed_tag_restores_activity_and_refusals() {
    with_enabled(|| {
        let path = root_file("identity-failed-tag");
        let index = ScanIndex::default();
        let mut items = vec![parse(
            &path,
            Some(t0()),
            &index,
            &[org_marker(ORG_A), line("one", &at(1), 10)],
        )];
        assert!(finish_page(
            &mut items,
            &index,
            TelemetryRead::Loaded,
            &mut Default::default()
        )
        .is_empty());
        items[0].source_started_at = Some("2026-08-02T10:00:00+03:00".into());
        items[0].source_last_activity_at = Some("2026-08-02T10:00:01+03:00".into());
        items[0].source_ended_at = Some("2026-08-02T10:00:01+03:00".into());
        items[0].model_usage[0].input_tokens += 1; // final wire cannot be reproduced
        items[0].request_identity_refusals = 7;
        let before = serde_json::to_vec(&items).unwrap();
        let api = ClaudeLocalOtelLoadReport::default();
        let trace = ClaudeTraceOwnershipLoadReport::default();
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        let disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
        let ownership =
            claude_request_identity::TranscriptOwnership::after_census(&index, &disposition);
        let outcome = claude_request_identity::apply_scan_with_ownership(
            &mut items,
            &evidence,
            BTreeMap::new(),
            &ownership,
        );
        assert_eq!((outcome.sent, outcome.ineligible), (0, 1));
        assert_eq!(serde_json::to_vec(&items).unwrap(), before);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_twin_start_fills_only_unmarked_prefix_before_own_org_run() {
    with_enabled(|| {
        for reverse in [false, true] {
            let a = root_file("identity-prefix-twin-a");
            let b = root_file("identity-prefix-twin-b");
            let index = ScanIndex::default();
            let known = parse(
                &a,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), line("a", &at(1), 10)],
            );
            let mixed = parse(
                &b,
                Some(t0()),
                &index,
                &[
                    line("prefix", &at(2), 20),
                    org_marker(ORG_B),
                    line("own-b", &at(3), 30),
                ],
            );
            let item = tag_owned(
                if reverse {
                    vec![mixed, known]
                } else {
                    vec![known, mixed]
                },
                &index,
            )
            .remove(0);
            let amounts = item.model_usage[0]
                .identity_parts
                .as_ref()
                .unwrap()
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
            assert_eq!(amounts[&org_hash(ORG_B)], (30, 1));
            assert!(!fold(&item).accounts.as_ref().unwrap().conflict);
            assert_evidence_referenced(&item);
            cleanup(&[&a, &b]);
        }
    });
}

#[test]
fn e2_identity_retained_session_binding_fills_only_missing_native_shares() {
    with_enabled(|| {
        let path = root_file("identity-retained-start");
        let mut index = ScanIndex::default();
        index.session_account_bindings.insert(
            crate::snapshots::sha256_hex(&["session_owner:v1", "synthetic-machine", ROOT]),
            crate::snapshots::SessionAccountBinding {
                account_identifier_hash: "c".repeat(64),
                workspace_identifier_hash: None,
            },
        );
        let index = restart(&index);
        let mut items = vec![parse(
            &path,
            Some(t0()),
            &index,
            &[
                line("start", &at(1), 10),
                org_marker(ORG_B),
                line("own-b", &at(2), 20),
            ],
        )];
        claude_request_identity::retain_root_accounts(&mut items, &index, "synthetic-machine");
        let item = tag_owned(items, &index).remove(0);
        let parts = item.model_usage[0].identity_parts.as_ref().unwrap();
        assert_eq!(
            parts
                .iter()
                .find(
                    |part| part.account_identifier_hash.as_deref() == Some("c".repeat(64).as_str())
                )
                .map(|part| (part.input_tokens, part.request_count)),
            Some((10, 1))
        );
        let own = parts
            .iter()
            .find(|part| part.account_identifier_hash.is_none())
            .unwrap();
        assert_eq!((own.input_tokens, own.request_count), (20, 1));
        assert_eq!(
            item.request_evidence[usize::from(own.evidence_ref.unwrap())]
                .provider_workspace_hash
                .as_deref(),
            Some(org_hash(ORG_B).as_str())
        );
        assert!(!fold(&item).accounts.as_ref().unwrap().conflict);
        assert_evidence_referenced(&item);
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_three_contradictory_start_twins_preserve_own_orgs_deterministically() {
    with_enabled(|| {
        let a = root_file("identity-start-conflict-a");
        let b = root_file("identity-start-conflict-b");
        let c = root_file("identity-start-conflict-c");
        let index = ScanIndex::default();
        let source = [
            (&a, ORG_A, "a"),
            (&b, ORG_B, "b"),
            (&c, "33333333-3333-4333-8333-333333333333", "c"),
        ];
        for order in [
            [0, 1, 2],
            [2, 1, 0],
            [1, 0, 2],
            [2, 0, 1],
            [0, 2, 1],
            [1, 2, 0],
        ] {
            let items = order
                .iter()
                .map(|i| {
                    let (path, org, id) = source[*i];
                    parse(
                        path,
                        Some(t0()),
                        &index,
                        &[org_marker(org), line(id, &at(1), 10)],
                    )
                })
                .collect();
            let item = tag_owned(items, &index).remove(0);
            assert_eq!((item.request_count, item.input_tokens), (3, 30));
            assert!(fold(&item).accounts.as_ref().unwrap().conflict);
            // R2-2: even a real same-kind conflict cannot override own orgs.
            assert_eq!(
                org_amounts(&item),
                source
                    .iter()
                    .map(|(_, org, _)| (org_hash(org), (10, 1)))
                    .collect()
            );
            assert_evidence_referenced(&item);
        }
        cleanup(&[&a, &b, &c]);
    });
}

#[test]
fn e2_identity_copied_prefix_cannot_choose_subagent_or_side_call_start() {
    with_enabled(|| {
        let path = root_file("identity-own-start");
        let agent = path
            .parent()
            .unwrap()
            .join(ROOT)
            .join("subagents/agent-abc.jsonl");
        fs::create_dir_all(agent.parent().unwrap()).unwrap();
        fs::write(&agent, b"fixture\n").unwrap();
        let index = ScanIndex::default();
        let mut old = org_marker(ORG_A);
        old["timestamp"] = json!(at(1));
        let mut own = org_marker(ORG_B);
        own["timestamp"] = json!(at(100));
        let root = parse(
            &path,
            Some(t0() + 100_000_000_000),
            &index,
            &[
                old,
                line("copied", &at(2), 10),
                own,
                line("own", &at(101), 20),
            ],
        );
        assert_eq!(
            fold(&root)
                .accounts
                .as_ref()
                .unwrap()
                .starting
                .as_ref()
                .unwrap()
                .org
                .as_deref(),
            Some(org_hash(ORG_B).as_str())
        );
        let mut child = line("child", &at(102), 30);
        child["agentId"] = json!("abc");
        child["isSidechain"] = json!(true);
        let child = parse(&agent, Some(t0()), &index, &[org_marker(ORG_A), child]);
        let mut items = vec![root, child];
        let read = sidecar(&[row("own", 1, 20), row("child", 2, 30), row("side", 3, 40)]);
        attach_page(&mut items, &read);
        side_calls_page(
            &mut items,
            &api_report(&read),
            &ClaudeTraceOwnershipLoadReport::default(),
            &index,
        );
        let items = tag_owned(items, &index);
        assert_eq!(items.iter().map(|item| item.request_count).sum::<u64>(), 3);
        for item in &items {
            assert_eq!(item.request_evidence.len(), 1);
            assert_eq!(
                item.request_evidence[0].provider_workspace_hash.as_deref(),
                Some(org_hash(ORG_B).as_str())
            );
            assert!(rows_of(item)
                .all(|row| row.evidence_ref == Some(0) && row.identity_parts.is_none()));
            assert_evidence_referenced(item);
        }
        assert!(items
            .iter()
            .flat_map(|item| &item.model_usage)
            .any(|row| row
                .selector_context
                .get("request_usage_origin")
                .map(String::as_str)
                == Some("telemetry_reported")));
        cleanup(&[&path]);
    });
}

#[test]
fn e2_identity_marker_overflow_drops_excluded_starting_witness() {
    with_enabled(|| {
        for bound in [None, Some("c".repeat(64))] {
            let path = root_file("identity-copy-marker-overflow");
            let index = ScanIndex::default();
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
            accumulator
                .claude_file_birth
                .set_birth_for_test(t0() + 100_000_000_000);
            accumulator.account_identifier_hash = bound.clone();
            let mut lines = vec![
                org_marker(ORG_A),
                line("copied", &at(1), 10),
                line("own", &at(101), 20),
            ];
            for _ in 0..64 {
                lines.push(org_marker(ORG_A));
            }
            for value in &lines {
                apply_claude_code_line(value, &mut accumulator);
            }
            accumulator.finalize_claude_responses_e2(Some(ReadContext {
                index: &index,
                path: &path,
                twins: &Default::default(),
            }));
            let item = accumulator
                .into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None)
                .remove(0);
            let item = tag_owned(vec![item], &index).remove(0);
            assert_eq!(
                (
                    item.request_count,
                    item.input_tokens,
                    item.removed_request_count
                ),
                (1, 20, Some(1))
            );
            assert!(fold(&item).accounts.as_ref().unwrap().conflict);
            assert!(org_amounts(&item).is_empty());
            assert!(rows_of(&item).all(|row| row.account_identifier_hash == bound));
            assert_evidence_referenced(&item);
            cleanup(&[&path]);
        }
    });
}

/// Fold final rows by organization, preserving the actual token/request shares.
fn org_amounts(item: &SnapshotItem) -> BTreeMap<String, (u64, u64)> {
    let mut amounts = BTreeMap::<String, (u64, u64)>::new();
    for row in &item.model_usage {
        if let Some(parts) = &row.identity_parts {
            for part in parts {
                if let Some(org) = part.evidence_ref.and_then(|at| {
                    item.request_evidence[usize::from(at)]
                        .provider_workspace_hash
                        .clone()
                }) {
                    let into = amounts.entry(org).or_default();
                    into.0 += part.input_tokens;
                    into.1 += part.request_count;
                }
            }
        } else if let Some(org) = row.evidence_ref.and_then(|at| {
            item.request_evidence[usize::from(at)]
                .provider_workspace_hash
                .clone()
        }) {
            let into = amounts.entry(org).or_default();
            into.0 += row.input_tokens;
            into.1 += row.request_count;
        }
    }
    amounts
}

#[test]
fn e2_identity_restored_timed_prefix_keeps_every_counted_org() {
    with_enabled(|| {
        for partial in [false, true] {
            let path = root_file("identity-restored-timed");
            let index = ScanIndex::default();
            let mut a = org_marker(ORG_A);
            a["timestamp"] = json!(at(1));
            let mut b = org_marker(ORG_B);
            b["timestamp"] = json!(at(3));
            let mut lines = vec![
                a,
                line("a", &at(2), 10),
                switch_context(),
                b,
                line("b", &at(4), 20),
            ];
            if partial {
                // A partial restore has no allowlisted writer certificate.
                lines.push(versioned(
                    line("restored-own", &at(101), 30),
                    "unknown-writer",
                ));
            }
            let parsed = parse(&path, Some(t0() + 100_000_000_000), &index, &lines);
            assert_eq!(fold(&parsed).entity.removed_requests, 0);
            let item = tag_owned(vec![parsed], &index).remove(0);
            assert_eq!(
                org_amounts(&item),
                BTreeMap::from([
                    (org_hash(ORG_A), (10, 1)),
                    (org_hash(ORG_B), if partial { (50, 2) } else { (20, 1) }),
                ])
            );
            assert_eq!(item.request_count, if partial { 3 } else { 2 });
            assert_evidence_referenced(&item);
            cleanup(&[&path]);
        }
    });
}

#[test]
fn e2_identity_proven_original_excludes_prefix_without_lending_its_org() {
    with_enabled(|| {
        let original = root_file("identity-real-original");
        let copy = root_file("identity-real-branch");
        let mut index = ScanIndex::default();
        let mut marker = org_marker(ORG_A);
        marker["timestamp"] = json!(at(1));
        let original_item = parse_and_remember(
            &original,
            t0(),
            &mut index,
            &[marker.clone(), line("original", &at(2), 10)],
        );
        for fresh in [false, true] {
            // The page's metadata probe witnesses the live original (F1c).
            stage_twins(
                &mut index,
                &[(&original, t0()), (&copy, t0() + 100_000_000_000)],
            );
            let mut lines = vec![marker.clone(), line("original", &at(2), 10)];
            if fresh {
                let mut own = org_marker(ORG_B);
                // Identity follows the counted request, not this stale clock.
                own["timestamp"] = json!(at(1));
                lines.push(own);
            }
            lines.push(line("branch-own", &at(101), 20));
            // Give the copy its own login. An unbound same-session path twin
            // legitimately inherits A from the original at page settlement;
            // that cannot distinguish session fallback from prefix leakage.
            let login = "c".repeat(64);
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(&copy, None);
            accumulator
                .claude_file_birth
                .set_birth_for_test(t0() + 100_000_000_000);
            accumulator.account_identifier_hash = Some(login.clone());
            for value in &lines {
                apply_claude_code_line(value, &mut accumulator);
            }
            accumulator.finalize_claude_responses_e2(Some(ReadContext {
                index: &index,
                path: &copy,
                twins: &Default::default(),
            }));
            let item = accumulator
                .into_items(&copy, "2026-08-02T09:00:00Z", "fixture".into(), None)
                .remove(0);
            assert_eq!(fold(&item).entity.removed_requests, 1);
            assert_eq!(
                org_amounts(
                    &tag_owned(vec![item.clone(), original_item.clone()], &index).remove(0)
                )
                .get(&org_hash(ORG_A)),
                Some(&(10, 1))
            );
            if !fresh {
                assert!(fold(&item)
                    .entity
                    .grains
                    .keys()
                    .all(
                        |(_, _, account)| account.as_ref().and_then(|key| key.login.as_deref())
                            == Some(login.as_str())
                    ));
            }
            let item = tag_owned(vec![original_item.clone(), item], &index).remove(0);
            assert_eq!((item.request_count, item.input_tokens), (2, 30));
            assert_eq!(
                org_amounts(&item),
                if fresh {
                    BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (20, 1))])
                } else {
                    BTreeMap::from([(org_hash(ORG_A), (10, 1))])
                }
            );
            assert_evidence_referenced(&item);
        }
        cleanup(&[&original, &copy]);
    });
}

#[test]
fn e2_identity_equal_start_login_org_twins_keep_own_orgs_with_binding() {
    with_enabled(|| {
        // Durable, qualified telemetry and Desktop-bound login variants.
        for login_source in [0, 1, 2] {
            for reverse in [false, true] {
                let a = root_file("identity-equal-org");
                let b = root_file("identity-equal-login");
                let mut index = ScanIndex::default();
                let login = "c".repeat(64);
                let mut known = parse(
                    &a,
                    Some(t0()),
                    &index,
                    &[
                        org_marker(ORG_A),
                        line("a", &at(1), 10),
                        switch_context(),
                        org_marker(ORG_B),
                        line("b", &at(2), 20),
                    ],
                );
                let mut markerless = parse(&b, Some(t0()), &index, &[line("login", &at(1), 30)]);
                known.source_started_at = Some(at(1));
                markerless.source_started_at = Some(at(1));
                if login_source == 0 {
                    index.session_account_bindings.insert(
                        crate::snapshots::sha256_hex(&[
                            "session_owner:v1",
                            "synthetic-machine",
                            ROOT,
                        ]),
                        crate::snapshots::SessionAccountBinding {
                            account_identifier_hash: login.clone(),
                            workspace_identifier_hash: None,
                        },
                    );
                } else {
                    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
                    accumulator.claude_file_birth = ClaudeFileBirth::observe(&b, None);
                    accumulator.claude_file_birth.set_birth_for_test(t0());
                    if login_source == 2 {
                        accumulator.account_identifier_hash = Some(login.clone());
                    }
                    apply_claude_code_line(&line("login", &at(1), 30), &mut accumulator);
                    accumulator.finalize_claude_responses_e2(Some(ReadContext {
                        index: &index,
                        path: &b,
                        twins: &Default::default(),
                    }));
                    markerless = accumulator
                        .into_items(&b, "2026-08-02T09:00:00Z", "fixture".into(), None)
                        .remove(0);
                    if login_source == 1 {
                        // Exact account already qualified by the account owner.
                        crate::snapshots::set_session_account_hash(&mut markerless, Some(&login));
                    }
                }
                let mut items = if reverse {
                    vec![markerless, known]
                } else {
                    vec![known, markerless]
                };
                if login_source == 0 {
                    let index = restart(&index);
                    claude_request_identity::retain_root_accounts(
                        &mut items,
                        &index,
                        "synthetic-machine",
                    );
                }
                let api = ClaudeLocalOtelLoadReport::default();
                let trace = ClaudeTraceOwnershipLoadReport::default();
                let evidence =
                    claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
                claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
                side_calls_page(&mut items, &Default::default(), &Default::default(), &index);
                assert!(items
                    .iter()
                    .all(|item| !fold(item).accounts.as_ref().unwrap().conflict));
                let item = tag_owned(items, &index).remove(0);
                assert_eq!(
                    org_amounts(&item),
                    BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (20, 1))])
                );
                assert_eq!((item.request_count, item.input_tokens), (3, 60));
                assert_evidence_referenced(&item);
                cleanup(&[&a, &b]);
            }
        }
    });
}

#[test]
fn e2_identity_copy_rebuild_keeps_later_marker_boundary_and_cost_attachment() {
    with_enabled(|| {
        for bound in [None, Some("c".repeat(64))] {
            let path = root_file("identity-copy-boundary");
            let index = ScanIndex::default();
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
            accumulator
                .claude_file_birth
                .set_birth_for_test(t0() + 100_000_000_000);
            accumulator.account_identifier_hash = bound;
            for value in [
                org_marker(ORG_A),
                line("copy", &at(1), 10),
                line("unmarked-own", &at(101), 20),
                org_marker(ORG_B),
                line("b", &at(102), 30),
                line("b-inherited", &at(103), 40),
            ] {
                apply_claude_code_line(&value, &mut accumulator);
            }
            accumulator.finalize_claude_responses_e2(Some(ReadContext {
                index: &index,
                path: &path,
                twins: &Default::default(),
            }));
            let mut items =
                accumulator.into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None);
            let read = sidecar(&[
                row("unmarked-own", 1, 20),
                row("b", 2, 30),
                row("b-inherited", 3, 40),
            ]);
            attach_page(&mut items, &read);
            assert_eq!(
                requests(&items[0], MATCHED),
                3,
                "rebuilt account keys must match native grain keys"
            );
            let item = tag_owned(items, &index).remove(0);
            assert_eq!(
                org_amounts(&item),
                BTreeMap::from([(org_hash(ORG_B), (70, 2))])
            );
            assert_eq!(
                (
                    item.request_count,
                    item.input_tokens,
                    item.removed_request_count
                ),
                (3, 90, Some(1))
            );
            assert_eq!(
                item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
                Some("0.0003")
            );
            assert_evidence_referenced(&item);
            cleanup(&[&path]);
        }
    });
}

#[test]
fn e2_identity_conflicting_twin_bindings_clear_root_fallback_in_every_order() {
    with_enabled(|| {
        let a = root_file("identity-bound-conflict-a");
        let b = root_file("identity-bound-conflict-b");
        let c = root_file("identity-bound-conflict-c");
        let agent = a
            .parent()
            .unwrap()
            .join(ROOT)
            .join("subagents/agent-abc.jsonl");
        fs::create_dir_all(agent.parent().unwrap()).unwrap();
        fs::write(&agent, b"fixture\n").unwrap();
        let index = ScanIndex::default();
        let parse_bound = |path: &Path, org: Option<&str>, login: &str| {
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(path, None);
            accumulator.claude_file_birth.set_birth_for_test(t0());
            accumulator.account_identifier_hash = Some(login.repeat(64));
            if let Some(org) = org {
                apply_claude_code_line(&org_marker(org), &mut accumulator);
            }
            apply_claude_code_line(&line(login, &at(1), 10), &mut accumulator);
            accumulator.finalize_claude_responses_e2(Some(ReadContext {
                index: &index,
                path,
                twins: &Default::default(),
            }));
            accumulator
                .into_items(path, "2026-08-02T09:00:00Z", "fixture".into(), None)
                .remove(0)
        };
        let roots = [
            parse_bound(&a, Some(ORG_A), "c"),
            parse_bound(&b, Some(ORG_B), "c"),
            parse_bound(&c, None, "d"),
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut sub = line("child", &at(2), 5);
            sub["agentId"] = json!("abc");
            sub["isSidechain"] = json!(true);
            let mut items = order
                .iter()
                .map(|at| roots[*at].clone())
                .collect::<Vec<_>>();
            items.push(parse(&agent, Some(t0()), &index, &[sub]));
            claude_request_identity::inherit_root_accounts(&mut items, false);
            assert!(items.iter().take(3).all(|item| fold(item)
                .accounts
                .as_ref()
                .unwrap()
                .fallback
                .is_none()));
            assert!(fold(items.last().unwrap())
                .accounts
                .as_ref()
                .unwrap()
                .starting
                .is_none());
            let items = tag_owned(items, &index);
            let child = items
                .iter()
                .find(|item| item.source_session_id.contains("_agent-"))
                .unwrap();
            assert!(child.request_evidence.is_empty());
            let root = items
                .iter()
                .find(|item| item.source_session_id == ROOT)
                .unwrap();
            assert_eq!(
                org_amounts(root),
                BTreeMap::from([(org_hash(ORG_A), (10, 1)), (org_hash(ORG_B), (10, 1))])
            );
            assert_evidence_referenced(root);
        }
        cleanup(&[&a, &b, &c]);
    });
}

// ---- I4b ----

fn sub_line(id: &str, seconds: i64, input: u64) -> Value {
    let mut value = line(id, &at(seconds), input);
    value["agentId"] = json!("abc");
    value["isSidechain"] = json!(true);
    value
}
fn remove_agent_scratch(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_dir_all(path.ancestors().nth(3).unwrap());
    }
}

#[test]
fn e2_side_call_named_member_without_transcript_falls_back_to_the_root() {
    // Grain detail exists only with the gate on: dark keeps no grain map.
    with_enabled(|| {
        let p = root_file("side-ghost");
        let agent = p
            .parent()
            .unwrap()
            .join(ROOT)
            .join("subagents/agent-abc.jsonl");
        fs::create_dir_all(agent.parent().unwrap()).unwrap();
        fs::write(&agent, b"fixture\n").unwrap();
        let index = ScanIndex::default();
        let mut items = vec![
            parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)]),
            parse(&agent, Some(t0()), &index, &[sub_line("s", 3, 30)]),
        ];
        let read = sidecar(&[row("r", 1, 10), row("s", 3, 30), row("ghost", 4, 40)]);
        attach_page(&mut items, &read);
        // The trace names agent `zzz`: no transcript of it exists anywhere.
        let trace = ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(
                ROOT.to_owned(),
                vec![complete_trace_row(ROOT, "ghost", "zzz")],
            )]),
            ..Default::default()
        };
        let unresolved = side_calls_page(&mut items, &api_report(&read), &trace, &index);
        assert!(unresolved.is_empty(), "the census walk decided");
        let (root, sub) = (fold(&items[0]), fold(&items[1]));
        assert_eq!((requests(&items[0], REPORTED), root.root_fallbacks), (1, 1));
        assert_eq!((requests(&items[1], REPORTED), sub.root_fallbacks), (0, 0));
        assert_eq!(root.side.input, 40, "counted once, on the root");
        let _ = fs::remove_dir_all(p.parent().unwrap());
    });
}

#[test]
fn e2_side_call_census_deadline_counts_nothing_and_reports_the_family() {
    let p = root_file("side-deadline");
    let index = ScanIndex::default();
    let mut items = vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])];
    let read = sidecar(&[row("r", 1, 10), row("side", 2, 20)]);
    attach_page(&mut items, &read);
    let unresolved = crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
        side_calls_page(
            &mut items,
            &api_report(&read),
            &ClaudeTraceOwnershipLoadReport::default(),
            &index,
        )
    });
    assert_eq!(unresolved, BTreeSet::from([ROOT.to_owned()]));
    assert_eq!(
        fold(&items[0]).side_requests,
        0,
        "never counted on a deadline"
    );
    assert!(!fold(&items[0]).telemetry.side_calls_done);
    // The next page's walk completes and counts the side call once.
    let mut items = vec![parse(&p, Some(t0()), &index, &[line("r", &at(1), 10)])];
    attach_page(&mut items, &read);
    let unresolved = side_calls_page(
        &mut items,
        &api_report(&read),
        &ClaudeTraceOwnershipLoadReport::default(),
        &index,
    );
    assert!(unresolved.is_empty());
    assert_eq!(fold(&items[0]).side_requests, 1);
    cleanup(&[&p]);
}

#[test]
fn e2_equal_birth_subagent_twins_count_once_in_both_orders() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
        for reverse in [false, true] {
            let early = agent_file("equal-sub-a");
            let later = agent_file("equal-sub-b");
            let birth = t0() + 60_000_000_000;
            let history = vec![sub_line("a", 1, 10), sub_line("b", 2, 20)];
            let mut index = ScanIndex::default();
            index.files.insert(local_index_key(&early), entry());
            index.files.insert(local_index_key(&later), entry());
            let mut paths: Vec<(&Path, i128)> = vec![(&early, birth), (&later, birth)];
            if reverse {
                paths.reverse();
            }
            stage_twins(&mut index, &paths);
            let items = paths
                .iter()
                .map(|(path, birth)| parse(path, Some(*birth), &index, &history))
                .collect::<Vec<_>>();
            assert_eq!(
                items
                    .iter()
                    .map(|i| fold(i).entity.removed_requests)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([0, 2]),
                "the (birth, location) order names exactly one copy"
            );
            let got = publish(items, None, TelemetryRead::Loaded, &index);
            assert_eq!(got.len(), 1);
            assert_eq!((got[0].request_count, got[0].input_tokens), (2, 30));
            assert_eq!(got[0].removed_request_count, Some(2));
            remove_agent_scratch(&[&early, &later]);
        }
    })
}

#[test]
fn e2_absent_subagent_twin_holds_its_session() {
    // Publication runs with the gate on, so the parse does too: dark
    // keeps no grain map to publish.
    with_enabled(|| {
        let early = agent_file("absent-sub-early");
        let later = agent_file("absent-sub-later");
        let mut index = ScanIndex::default();
        let first = parse_and_remember(&early, t0(), &mut index, &[sub_line("a", 1, 10)]);
        let page = |index: &ScanIndex| {
            parse(
                &later,
                Some(t0() + 60_000_000_000),
                index,
                &[sub_line("b", 61, 20)],
            )
        };
        let second = page(&index);
        remember_birth(&mut index, &later, fold(&second));
        index.files.insert(local_index_key(&later), entry());
        let session = second.source_session_id.clone();
        assert_eq!(session, format!("{ROOT}_agent-abc"));
        // The earlier path is indexed and on disk but not on this page.
        let mut items = vec![page(&index)];
        let mut reasons = BTreeMap::new();
        let withheld =
            with_enabled(|| finish_page(&mut items, &index, TelemetryRead::Loaded, &mut reasons));
        assert_eq!(withheld, BTreeSet::from([session]));
        assert_eq!(reasons, BTreeMap::from([("absent_twin", 1)]));
        reasons.clear();
        // Both paths on the page: one body, nothing withheld.
        let mut items = vec![first, page(&index)];
        let withheld =
            with_enabled(|| finish_page(&mut items, &index, TelemetryRead::Loaded, &mut reasons));
        assert!(withheld.is_empty());
        assert!(reasons.is_empty());
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].request_count, 2);
        remove_agent_scratch(&[&early, &later]);
    })
}

#[test]
fn e2_moved_copy_partial_branch_certifies_writers_from_the_effective_cutoff() {
    let p = root_file("moved-writer");
    let opened = fs::metadata(&p).ok();
    let physical = t0() + 120_000_000_000;
    for (moved, own_version, certified) in [
        // Moved by copy: its own run lies between the effective cutoff and
        // the physical birth, by one known writer other than the prefix's.
        (true, "2.1.310", true),
        // The same run seen from the physical birth has no own line.
        (false, "2.1.310", false),
        // An unknown own writer never certifies.
        (true, "2.0.99", false),
    ] {
        let mut birth = ClaudeFileBirth::observe(&p, opened.as_ref());
        birth.set_birth_for_test(physical);
        let mut birth = birth.with_minimum(moved.then(t0));
        birth.observe_response_writer(Some("2.1.309"), Some(&at(-100)));
        birth.observe_response_writer(Some(own_version), Some(&at(10)));
        assert_eq!(
            birth.writer_certified(Some(1)),
            certified,
            "moved={moved} own={own_version}"
        );
    }
    cleanup(&[&p]);
}

#[test]
fn e2_twin_index_spells_root_and_subagent_members_once() {
    let root_a = root_file("groups-a");
    let root_b = root_file("groups-b");
    let agent_a = agent_file("groups-c");
    let agent_b = agent_file("groups-d");
    let solo = scratch("groups-e")
        .join(ROOT)
        .join("subagents/agent-solo.jsonl");
    fs::create_dir_all(solo.parent().unwrap()).unwrap();
    fs::write(&solo, b"fixture\n").unwrap();
    let mut index = ScanIndex::default();
    for path in [&root_a, &root_b, &agent_a, &agent_b, &solo] {
        index.files.insert(local_index_key(path), entry());
    }
    let groups =
        crate::snapshots::claude_history_upgrade::claude_path_twin_groups(&index, &BTreeSet::new());
    let sub = format!("{ROOT}_agent-abc");
    assert_eq!(
        groups.keys().cloned().collect::<Vec<_>>(),
        vec![ROOT.to_owned(), sub.clone()]
    );
    for path in [&root_a, &root_b, &agent_a, &agent_b] {
        let member = session_member(path).unwrap();
        assert_eq!(groups[member.as_ref()].len(), 2, "one spelling per member");
    }
    assert!(!groups.contains_key(session_member(&solo).unwrap().as_ref()));
    assert_eq!(
        selected_twin_roots([agent_a.as_path(), solo.as_path()].into_iter(), &groups),
        BTreeSet::from([ROOT.to_owned()])
    );
    let twins = std::cell::OnceCell::new();
    let context = ReadContext {
        index: &index,
        path: &agent_b,
        twins: &twins,
    };
    assert!(context.indexed(&sub, location_key(&local_index_key(&agent_a))));
    assert!(!context.indexed(
        session_member(&solo).unwrap().as_ref(),
        location_key(&local_index_key(&solo))
    ));
    assert!(
        twins
            .get()
            .unwrap()
            .contains_key(session_member(&agent_b).unwrap().as_ref()),
        "the page index is built once"
    );
    // A page member keeps its single known path (a new copy's original),
    // which is never a twin group for selection or the absent-twin hold.
    let solo_member = session_member(&solo).unwrap().into_owned();
    let page = crate::snapshots::claude_history_upgrade::claude_path_twin_groups(
        &index,
        &BTreeSet::from([solo_member.clone()]),
    );
    assert_eq!(page[&solo_member].len(), 1);
    assert_eq!(
        selected_twin_roots([solo.as_path()].into_iter(), &page),
        BTreeSet::new()
    );
    let fresh = scratch("groups-f")
        .join(ROOT)
        .join("subagents/agent-solo.jsonl");
    let context = ReadContext {
        index: &index,
        path: &fresh,
        twins: &Default::default(),
    };
    assert!(
        context.indexed(&solo_member, location_key(&local_index_key(&solo))),
        "an unindexed copy finds its member's only indexed path"
    );
    let _ = fs::remove_dir_all(fresh.ancestors().nth(3).unwrap());
    cleanup(&[&root_a, &root_b]);
    remove_agent_scratch(&[&agent_a, &agent_b, &solo]);
}

/// The sidecar fingerprint rule before F3b: hash the blanked clone's JSON
/// and compare the formatted string.
fn reference_fingerprint_ok<T: serde::Serialize + Clone>(
    row: &T,
    fingerprint: &str,
    blank: impl FnOnce(&mut T),
) -> bool {
    let mut canonical = row.clone();
    blank(&mut canonical);
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).unwrap())
    ) == fingerprint
}

#[test]
fn e2_fingerprint_check_matches_the_blanked_copy_rule_on_every_shape() {
    use crate::snapshots::{
        claude_api_evidence_fingerprint_is_valid, claude_trace_evidence_fingerprint_is_valid,
    };
    let valid = row("req-a", 1, 10);
    let mut apis = vec![valid.clone(), identity_api_row("req-b", 2, 10, "org")];
    let mut tampered = valid.clone();
    tampered.input_tokens += 1;
    apis.push(tampered);
    let mut upper = valid.clone();
    upper.fingerprint = upper
        .fingerprint
        .to_uppercase()
        .replace("SHA256:", "sha256:");
    apis.push(upper);
    let mut short = valid.clone();
    short.fingerprint.pop();
    apis.push(short);
    let mut bare = valid.clone();
    bare.fingerprint = bare.fingerprint.replace("sha256:", "");
    apis.push(bare);
    // JSON escapes in the two leading fields must not shift the blanked value.
    let mut escaped = valid.clone();
    escaped.capture_revision = "claude_api_request:v2\"\\\u{1}".into();
    apis.push(refingerprint(escaped.clone()));
    escaped.fingerprint = "sha256:\"\\".into();
    apis.push(escaped);
    let mut empty = valid.clone();
    empty.fingerprint.clear();
    apis.push(empty);
    let mut expected = Vec::new();
    for api in &apis {
        let want = reference_fingerprint_ok(api, &api.fingerprint, |r| r.fingerprint.clear());
        expected.push(want);
        assert_eq!(
            claude_api_evidence_fingerprint_is_valid(api),
            want,
            "{api:?}"
        );
    }
    assert_eq!(
        expected,
        [true, true, false, false, false, false, true, false, false]
    );
    let trace = complete_trace_row(ROOT, "req-a", "7");
    let mut traces = vec![trace.clone()];
    let mut moved = trace.clone();
    moved.agent_id = "8".into();
    traces.push(moved);
    let mut quoted = trace;
    quoted.capture_revision = "\"".into();
    traces.push(quoted);
    for trace in &traces {
        let want = reference_fingerprint_ok(trace, &trace.fingerprint, |r| r.fingerprint.clear());
        assert_eq!(claude_trace_evidence_fingerprint_is_valid(trace), want);
    }
}

#[test]
fn e2_identity_incomplete_clock_survives_discarded_twin_in_both_orders() {
    with_enabled(|| {
        for reverse in [false, true] {
            let path_a = root_file("identity-clock-twin-a");
            let path_b = root_file("identity-clock-twin-b");
            let index = ScanIndex::default();
            let a = parse(
                &path_a,
                Some(t0()),
                &index,
                &[org_marker(ORG_A), line("a", &at(1), 10)],
            );
            let mut b = parse(
                &path_b,
                Some(t0()),
                &index,
                &[org_marker(ORG_B), line("b", &at(2), 20)],
            );
            b.claude_usage_occurrences
                .get_mut("b")
                .unwrap()
                .event_clock_complete = false;
            let items = tag_owned(if reverse { vec![b, a] } else { vec![a, b] }, &index);
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].request_count, 2);
            let display = items[0].claude_account_display.as_deref().unwrap();
            assert_eq!(display.current.status, "unknown");
            assert_eq!(
                display.current.unknown_reason.as_deref(),
                Some("request_order_unavailable")
            );
            cleanup(&[&path_a, &path_b]);
        }
    });
}
