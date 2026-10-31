//! Codex usage counting V2: the eight COST regressions, the counting-version
//! decision and its acknowledgement-evidence transitions. Token numbers mirror
//! the saved minimal sequences S1-S3; every fixture is synthetic.
use super::codex_counting_version::{self, AckEvidence, CountingVersion};
use super::codex_usage_occurrence::{OccurrenceCounters, T6};
use super::*;
use serde_json::json;

const SESSION: &str = "0199f7a0-0000-7000-8000-00000000c0de";
/// 2026-09-21T14:13:20Z.
const CUTOVER: i64 = 1_790_000_000_000;
const POST: &str = "2026-10-18T10:00:00Z";
const PRE: &str = "2026-09-01T10:00:00Z";
const MODEL: &str = "gpt-5.6-sol";
/// S1: one response, then its equal-total re-emission before an abort.
const S1: T6 = [31_143, 0, 0, 420, 169, 31_563];
/// S2: two responses of one turn, with the thread counter before the first.
const S2_FIRST: T6 = [226_675, 225_408, 0, 1_143, 399, 227_818];
const S2_SECOND: T6 = [228_308, 0, 0, 782, 201, 229_090];
const S2_BASE: T6 = [36_339_992, 34_588_032, 0, 150_617, 41_641, 36_490_609];
/// S3: a UI epoch reset whose first post-reset `last` equals its total.
const S3_RESET: T6 = [220_126, 0, 0, 266, 51, 220_392];
const S3_NEXT: T6 = [226_117, 219_904, 0, 261, 69, 226_378];
const S3_NEXT_TOTAL: T6 = [446_243, 219_904, 0, 527, 120, 446_770];

fn tokens(t: T6) -> Value {
    json!({
        "input_tokens": t[0],
        "cached_input_tokens": t[1],
        "cache_write_input_tokens": t[2],
        "output_tokens": t[3],
        "reasoning_output_tokens": t[4],
        "total_tokens": t[5],
    })
}

fn sum(left: T6, right: T6) -> T6 {
    let mut out = left;
    for (slot, value) in out.iter_mut().zip(right) {
        *slot += value;
    }
    out
}

fn header(timestamp: &str) -> Value {
    json!({"timestamp": timestamp, "type": "session_meta",
        "payload": {"id": SESSION, "timestamp": timestamp, "source": "cli"}})
}

fn started(timestamp: &str, turn: &str) -> Value {
    json!({"timestamp": timestamp, "type": "event_msg",
        "payload": {"type": "task_started", "turn_id": turn}})
}

fn context(timestamp: &str, turn: &str) -> Value {
    json!({"timestamp": timestamp, "type": "turn_context",
        "payload": {"turn_id": turn, "model": MODEL}})
}

fn completed(timestamp: &str, turn: &str) -> Value {
    json!({"timestamp": timestamp, "type": "event_msg",
        "payload": {"type": "task_complete", "turn_id": turn}})
}

fn aborted(timestamp: &str, turn: &str) -> Value {
    json!({"timestamp": timestamp, "type": "event_msg",
        "payload": {"type": "turn_aborted", "turn_id": turn}})
}

fn ui(timestamp: &str, last: T6, total: T6) -> Value {
    json!({"timestamp": timestamp, "type": "event_msg", "payload": {"type": "token_count",
        "info": {"last_token_usage": tokens(last), "total_token_usage": tokens(total), "model": MODEL}}})
}

fn cumulative_ui(timestamp: &str, total: T6) -> Value {
    json!({"timestamp": timestamp, "type": "event_msg", "payload": {"type": "token_count",
        "info": {"total_token_usage": tokens(total), "model": MODEL}}})
}

fn native(timestamp: &str, turn: &str, response: &str, usage: T6, after: T6) -> Value {
    json!({"timestamp": timestamp, "type": "token_usage_record", "payload": {
        "thread_id": SESSION, "turn_id": turn, "response_id": response,
        "usage": tokens(usage), "thread_token_usage": tokens(after)}})
}

fn hour(index: i64) -> String {
    OffsetDateTime::from_unix_timestamp(1_792_281_600 + index * 3_600)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

struct Run {
    item: Option<SnapshotItem>,
    v2: bool,
    counters: Option<OccurrenceCounters>,
    pending: Option<(u64, UsageTotals)>,
}

impl Run {
    /// `input, cache_read, cache_write, output, reasoning`.
    fn money(&self) -> [u64; 5] {
        self.item.as_ref().map_or([0; 5], |item| {
            [
                item.input_tokens,
                item.cache_read_tokens,
                item.cache_creation_5m_tokens,
                item.output_tokens,
                item.reasoning_output_tokens,
            ]
        })
    }
    fn counters(&self) -> &OccurrenceCounters {
        self.counters.as_ref().expect("V2 counters")
    }
    fn wire(&self) -> Value {
        serde_json::to_value(self.item.as_ref().expect("item")).unwrap()
    }
}

fn five(t: T6) -> [u64; 5] {
    [t[0], t[1], t[2], t[3], t[4]]
}

/// `None` is an unconfigured (Legacy) parser.
fn run(values: &[Value], evidence: Option<AckEvidence>) -> Run {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    if let Some(evidence) = evidence {
        codex_counting_version::configure(&mut accumulator, evidence, Some(CUTOVER));
    }
    for value in values {
        apply_codex_line(value, &mut accumulator);
    }
    let v2 = accumulator.codex_counting_v2();
    let counting = accumulator.codex_counting.as_deref();
    let counters = counting.and_then(|counting| counting.counters().cloned());
    let pending = counting.and_then(|counting| counting.open_turn_ui_pending());
    let path = PathBuf::from(format!(
        "/synthetic/sessions/rollout-2026-10-18T10-00-00-{SESSION}.jsonl"
    ));
    let mut items = accumulator.into_items(&path, "2026-10-21T00:00:00Z", "fp".into(), None);
    assert!(items.len() <= 1);
    Run {
        item: items.pop(),
        v2,
        counters,
        pending,
    }
}

fn v2(values: &[Value]) -> Run {
    let run = run(values, Some(AckEvidence::None));
    assert!(run.v2, "post-cutover root with no ACK evidence selects V2");
    run
}

fn legacy(values: &[Value]) -> Run {
    let run = run(values, None);
    assert!(!run.v2);
    run
}

/// Exercise the production source factory and physical JSONL reader, with the
/// compiled cutover unchanged. Legacy uses the same factory without a test cutover.
fn run_price_source(values: &[Value], active: bool) -> Run {
    let _cutover = active.then(|| codex_counting_version::TestCutover::set(0));
    let root = crate::test_scratch::unique_path("ottto-v2-price");
    fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("rollout-2026-08-31T23-00-00-{SESSION}.jsonl"));
    let text: String = values.iter().map(|value| format!("{value}\n")).collect();
    fs::write(&path, &text).unwrap();
    let mut file = File::open(&path).unwrap();
    let identity = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: root.clone(),
        path: path.clone(),
        size_bytes: text.len() as u64,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: "synthetic-price".into(),
        legacy_source_file_fingerprint: "synthetic-price".into(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: identity.clone(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    };
    let metadata = CodexTitleMetadata::default();
    let mut parser = sampled_scan::new_source_parser(
        file,
        &candidate,
        SnapshotSource::Codex,
        &metadata,
        None,
        None,
        false,
        false,
        false,
        &ScanIndex::default(),
    )
    .unwrap();
    while !parser.step().unwrap() {}
    let v2 = parser.accumulator.codex_counting_v2();
    assert_eq!(
        v2, active,
        "source factory selects the intended counting version"
    );
    let counting = parser.accumulator.codex_counting.as_deref();
    let counters = counting.and_then(|counting| counting.counters().cloned());
    let pending = counting.and_then(|counting| counting.open_turn_ui_pending());
    let mut parsed = parser
        .finish(
            &identity,
            &path,
            "2026-10-21T00:00:00Z",
            "synthetic-price".into(),
            Some(&metadata),
            None,
            None,
        )
        .unwrap();
    // Legacy's native-only control has positive usage evidence but no
    // supported money rows; its existing empty-file diagnostic is expected.
    if !parsed.snapshots.is_empty() {
        assert_eq!(parsed.recognized_usage_drop_count, 0);
    }
    assert_eq!(parsed.ownership_incomplete_file_count, 0);
    assert!(parsed.snapshots.len() <= 1);
    fs::remove_dir_all(root).unwrap();
    Run {
        item: parsed.snapshots.pop(),
        v2,
        counters,
        pending,
    }
}

type PriceRows = BTreeMap<(String, String, Option<String>), [u64; 6]>;

/// Five money dimensions plus request_count, grouped independently of selector
/// provenance (native and UI correctly name different sources).
fn price_rows(run: &Run) -> PriceRows {
    let mut rows = PriceRows::new();
    for bucket in &run.item.as_ref().expect("snapshot").usage_buckets {
        for row in &bucket.model_usage {
            let key = (
                bucket.bucket_start.clone(),
                row.model.clone(),
                row.selector_context.get("context_bucket").cloned(),
            );
            let totals = rows.entry(key).or_default();
            for (slot, value) in totals.iter_mut().zip([
                row.input_tokens,
                row.cache_read_tokens,
                row.cache_creation_5m_tokens,
                row.output_tokens,
                row.reasoning_output_tokens,
                row.request_count,
            ]) {
                *slot += value;
            }
        }
    }
    rows
}

fn assert_price_rows(run: &Run, expected: &PriceRows) {
    let rows = price_rows(run);
    assert_eq!(&rows, expected);
    let mut summed = [0; 6];
    for row in rows.values() {
        for (slot, value) in summed.iter_mut().zip(row) {
            *slot += value;
        }
    }
    let item = run.item.as_ref().unwrap();
    let money = run.money();
    assert_eq!(
        summed,
        [
            money[0],
            money[1],
            money[2],
            money[3],
            money[4],
            item.request_count
        ],
        "sum across price buckets equals the unsplit session total"
    );
}

#[test]
fn codex_v2_native_price_buckets_match_legacy_per_hour_model_and_dimension() {
    let model = "gpt-6.1-sol";
    let cases = [
        // Own request time, immediately before and exactly at the effective date.
        (
            "2026-08-31T23:59:59Z",
            model,
            [400_000, 0, 0, 10, 1, 400_010],
            None,
        ),
        (
            "2026-09-01T00:00:00Z",
            model,
            [272_001, 0, 0, 11, 2, 272_012],
            Some("long"),
        ),
        // Inclusive prompt at the line stays short even when almost all cached.
        (
            "2026-10-18T10:01:00Z",
            model,
            [272_000, 270_000, 1_000, 12, 3, 272_012],
            Some("short"),
        ),
        (
            "2026-10-18T10:02:00Z",
            model,
            [272_001, 0, 123, 13, 4, 272_014],
            Some("long"),
        ),
        (
            "2026-10-18T10:03:00Z",
            model,
            [300_000, 290_000, 1_000, 14, 5, 300_014],
            Some("long"),
        ),
        // No catalog line, and no leakage from a preceding derived long bucket.
        (
            "2026-10-18T11:00:00Z",
            "gpt-5.4-mini",
            [300_000, 20, 30, 15, 6, 300_015],
            None,
        ),
        (
            "2026-10-18T12:00:00Z",
            "unknown",
            [300_000, 40, 50, 16, 7, 300_016],
            None,
        ),
        ("2026-10-18T13:00:00Z", model, [0, 0, 0, 17, 8, 17], None),
    ];
    let mut values = vec![header("2026-08-31T23:00:00Z")];
    let mut total = [0; 6];
    let mut expected = PriceRows::new();
    for (index, (timestamp, model, usage, bucket)) in cases.into_iter().enumerate() {
        let turn = format!("turn-price-{index}");
        let mut ctx = context(timestamp, &turn);
        ctx["payload"]["model"] = json!(model);
        total = sum(total, usage);
        let mut ui = ui(timestamp, usage, total);
        ui["payload"]["info"]["model"] = json!(model);
        values.extend([
            started(timestamp, &turn),
            ctx,
            native(timestamp, &turn, &format!("resp-{index}"), usage, total),
            ui,
            completed(timestamp, &turn),
        ]);
        let hour = activity_bucket_from_timestamp(timestamp).unwrap().0;
        let row = expected
            .entry((hour, model.into(), bucket.map(str::to_string)))
            .or_default();
        for (slot, value) in row
            .iter_mut()
            .zip([usage[0], usage[1], usage[2], usage[3], usage[4], 1])
        {
            *slot += value;
        }
    }
    let legacy = run_price_source(&values, false);
    let counted = run_price_source(&values, true);
    assert_price_rows(&legacy, &expected);
    assert_price_rows(&counted, &expected);
    assert_eq!(counted.counters().native_counted, cases.len() as u64);
    for row in &counted.item.as_ref().unwrap().model_usage {
        if row.selector_context.contains_key("context_bucket") {
            assert_eq!(
                row.selector_sources
                    .get("context_bucket")
                    .map(String::as_str),
                Some("derived_from_native_usage")
            );
        }
    }
}

#[test]
fn codex_v2_native_price_bucket_requires_own_time_and_preserves_explicit_line_bucket() {
    for (own_time, explicit, bucket) in [(false, false, None), (true, true, Some("short"))] {
        let usage = [300_000, 290_000, 1_000, 10, 2, 300_010];
        let mut ctx = context(POST, "turn-price");
        ctx["payload"]["model"] = json!("gpt-6.1-sol");
        let mut native = native(POST, "turn-price", "resp-price", usage, usage);
        let mut ui = ui(POST, usage, usage);
        ui["payload"]["info"]["model"] = json!("gpt-6.1-sol");
        for line in [&mut native, &mut ui] {
            if !own_time {
                line.as_object_mut().unwrap().remove("timestamp");
            }
            if explicit {
                line["payload"]["context_bucket"] = json!("short");
            }
        }
        let values = [
            header(POST),
            started(POST, "turn-price"),
            ctx,
            native,
            ui,
            completed(POST, "turn-price"),
        ];
        let expected = PriceRows::from([(
            (
                "2026-10-18T10:00:00Z".into(),
                "gpt-6.1-sol".into(),
                bucket.map(str::to_string),
            ),
            [300_000, 290_000, 1_000, 10, 2, 1],
        )]);
        for active in [false, true] {
            assert_price_rows(&run_price_source(&values, active), &expected);
        }
    }
}

#[test]
fn codex_v2_native_only_compaction_and_overlap_price_the_original_prompt() {
    let first = [200_000, 100_000, 1_000, 20, 4, 200_020];
    let long = [300_000, 200_000, 2_000, 30, 6, 300_030];
    for overlap in [false, true] {
        let mut ctx = context(POST, "turn-price");
        ctx["payload"]["model"] = json!("gpt-6.1-sol");
        let mut values = vec![header(POST), started(POST, "turn-price"), ctx];
        if overlap {
            values.push(native(POST, "turn-price", "resp-first", first, first));
        }
        let after = if overlap {
            [400_000, 250_000, 2_500, 40, 8, 400_040]
        } else {
            long
        };
        let mut compaction = native(POST, "turn-price", "resp-compaction", long, after);
        compaction["payload"]["response_kind"] = json!("compaction");
        // Duplicate compaction restatement must not add another request.
        values.extend([
            compaction.clone(),
            compaction,
            completed(POST, "turn-price"),
        ]);
        let key = |bucket: &str| {
            (
                "2026-10-18T10:00:00Z".into(),
                "gpt-6.1-sol".into(),
                Some(bucket.into()),
            )
        };
        let expected = if overlap {
            // Only 200K of this 300K prompt is uncovered, but ALL admitted money
            // still belongs to its original request's long price bucket.
            PriceRows::from([
                (key("short"), [200_000, 100_000, 1_000, 20, 4, 1]),
                (key("long"), [200_000, 150_000, 1_500, 20, 4, 1]),
            ])
        } else {
            PriceRows::from([(key("long"), [300_000, 200_000, 2_000, 30, 6, 1])])
        };
        let counted = run_price_source(&values, true);
        assert_price_rows(&counted, &expected);
        assert_eq!(counted.counters().native_chain_overlap, u64::from(overlap));
        assert_eq!(
            counted.counters().native_inside_holed_coverage,
            u64::from(overlap)
        );
        assert_eq!(counted.counters().native_restated, u64::from(!overlap));
        assert!(
            run_price_source(&values, false).item.is_none(),
            "Legacy has no UI money to count"
        );
    }
}

#[test]
fn codex_v2_equal_total_repeat_is_dropped_and_legacy_is_unchanged() {
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        ui("2026-10-18T10:00:15Z", S1, S1),
        ui("2026-10-18T10:00:20Z", S1, S1),
        aborted("2026-10-18T10:00:21Z", "turn-1"),
    ];
    assert_eq!(legacy(&values).money(), five(sum(S1, S1)));
    let counted = v2(&values);
    assert_eq!(counted.money(), five(S1));
    assert_eq!(counted.counters().ui_equal_total_repeat, 1);
    assert_eq!(counted.counters().ui_equal_total_repeat_usage[0], S1[0]);
}

#[test]
fn codex_v2_real_reset_counts_first_post_reset_last() {
    let first_last = [100, 0, 0, 10, 1, 110];
    let pre_reset_total = [9_659_248, 9_216_896, 0, 21_146, 3_331, 9_680_394];
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        ui("2026-10-18T10:00:10Z", first_last, pre_reset_total),
        ui("2026-10-18T10:00:20Z", S3_RESET, S3_RESET),
        ui("2026-10-18T10:00:34Z", S3_NEXT, S3_NEXT_TOTAL),
        completed("2026-10-18T10:00:40Z", "turn-1"),
    ];
    let expected = five(sum(sum(first_last, S3_RESET), S3_NEXT));
    let counted = v2(&values);
    assert_eq!(counted.money(), expected);
    assert_eq!(counted.counters().ui_equal_total_repeat, 0);
    assert_eq!(legacy(&values).money(), expected);
}

#[test]
fn codex_v2_native_turn_counts_compaction_once_and_inherited_base_never() {
    let compaction = [50_000, 0, 0, 9_000, 0, 59_000];
    let first_after = sum(S2_BASE, S2_FIRST);
    let compaction_after = sum(first_after, compaction);
    let second_after = sum(compaction_after, S2_SECOND);
    let ui_total = [35_819_594, 34_328_832, 0, 135_576, 42_040, 35_955_170];
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        native(
            "2026-10-18T10:00:10Z",
            "turn-1",
            "resp-1",
            S2_FIRST,
            first_after,
        ),
        ui("2026-10-18T10:00:11Z", S2_FIRST, ui_total),
        ui("2026-10-18T10:30:00Z", S2_FIRST, ui_total),
        native(
            "2026-10-18T10:30:05Z",
            "turn-1",
            "resp-c",
            compaction,
            compaction_after,
        ),
        native(
            "2026-10-18T10:30:06Z",
            "turn-1",
            "resp-c",
            compaction,
            compaction_after,
        ),
        native(
            "2026-10-18T10:30:20Z",
            "turn-1",
            "resp-2",
            S2_SECOND,
            second_after,
        ),
        ui("2026-10-18T10:30:21Z", S2_SECOND, sum(ui_total, S2_SECOND)),
        completed("2026-10-18T10:30:30Z", "turn-1"),
    ];
    let counted = v2(&values);
    // The first native's non-zero `before` is the inherited thread base: only
    // its own usage counts. The compaction native counts once.
    assert_eq!(
        counted.money(),
        five(sum(sum(S2_FIRST, compaction), S2_SECOND))
    );
    let counters = counted.counters();
    assert_eq!(counters.native_counted, 3);
    assert_eq!(counters.native_restated, 1);
    assert_eq!(counters.native_conflict, 0);
    assert_eq!(counted.item.as_ref().unwrap().request_count, 3);
    // Legacy counts the UI stream: the re-emission, never the compaction.
    assert_eq!(
        legacy(&values).money(),
        five(sum(sum(S2_FIRST, S2_FIRST), S2_SECOND))
    );
}

#[test]
fn codex_v2_inherited_cumulative_base_is_not_counted() {
    let inherited = [5_000, 4_000, 0, 500, 50, 5_500];
    let grown = [5_600, 4_000, 0, 560, 50, 6_160];
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        cumulative_ui("2026-10-18T10:00:10Z", inherited),
        cumulative_ui("2026-10-18T10:00:20Z", grown),
        completed("2026-10-18T10:00:30Z", "turn-1"),
    ];
    let counted = v2(&values);
    assert_eq!(counted.money(), [600, 0, 0, 60, 0]);
    assert_eq!(counted.counters().v2_cumulative_base_uncounted, 1);
    assert_eq!(legacy(&values).money(), five(grown));
}

#[test]
fn codex_v2_pre_native_and_unbound_ui_stay_counted_without_subtraction() {
    let unbound = [1_000, 0, 0, 100, 10, 1_100];
    let turn = [2_000, 1_000, 0, 200, 20, 2_200];
    let values = [
        header(POST),
        ui("2026-10-18T10:00:05Z", unbound, unbound),
        ui("2026-10-18T10:00:06Z", unbound, unbound),
        started("2026-10-18T10:00:10Z", "turn-1"),
        context("2026-10-18T10:00:11Z", "turn-1"),
        ui("2026-10-18T10:00:20Z", turn, sum(unbound, turn)),
        completed("2026-10-18T10:00:30Z", "turn-1"),
    ];
    // Unbound-span UI keeps today's rule, including its repeat.
    let expected = five(sum(sum(unbound, unbound), turn));
    assert_eq!(legacy(&values).money(), expected);
    let mut previous = [0; 5];
    for end in 1..=values.len() {
        let prefix = v2(&values[..end]);
        let money = prefix.money();
        assert!(
            money
                .iter()
                .zip(&previous)
                .all(|(now, before)| now >= before),
            "published money never decreases: prefix {end}"
        );
        previous = money;
        if end == values.len() - 1 {
            // The open UI-only turn is visible local debt, not published.
            assert_eq!(money, five(sum(unbound, unbound)));
            let (events, usage) = prefix.pending.expect("open turn debt");
            assert_eq!((events, usage.input_tokens), (1, turn[0]));
        }
    }
    let counted = v2(&values);
    assert_eq!(counted.money(), expected);
    assert_eq!(counted.counters().ui_in_unbound_span, 2);
}

#[test]
fn codex_v2_pending_row_cap_flushes_once_without_double_count() {
    let rows = codex_usage_occurrence::MAX_PENDING_ROWS as i64;
    let step = [1_000, 0, 0, 10, 1, 1_010];
    let mut values = vec![
        header(&hour(-1)),
        started(&hour(-1), "turn-1"),
        context(&hour(-1), "turn-1"),
    ];
    let mut total = [0; 6];
    for index in 0..=rows {
        total = sum(total, step);
        values.push(ui(&hour(index), step, total));
    }
    let cap_prefix = v2(&values[..values.len() - 1]);
    assert_eq!(cap_prefix.money(), [0; 5], "64 staged rows publish nothing");
    assert_eq!(cap_prefix.pending.unwrap().0, rows as u64);
    // The 65th distinct row flushes the turn; later UI publishes directly and
    // a native for the flushed turn adds nothing.
    values.push(native(&hour(rows), "turn-1", "resp-1", step, step));
    total = sum(total, step);
    values.push(ui(&hour(rows + 1), step, total));
    values.push(completed(&hour(rows + 1), "turn-1"));
    let counted = v2(&values);
    let events = (rows + 2) as u64;
    let expected = [step[0] * events, 0, 0, step[3] * events, step[4] * events];
    assert_eq!(counted.money(), expected);
    let counters = counted.counters();
    assert_eq!(counters.pending_overflow_flushes, 1);
    assert_eq!(counters.native_after_ui_flush, 1);
    assert_eq!(counters.native_counted, 0);
    assert_eq!(legacy(&values).money(), expected);
}

#[test]
fn codex_v2_reopened_closed_turn_never_regains_native_authority() {
    let usage = [3_000, 0, 0, 300, 30, 3_300];
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        ui("2026-10-18T10:00:10Z", usage, usage),
        started("2026-10-18T10:00:11Z", "turn-1"),
        native("2026-10-18T10:00:12Z", "turn-1", "resp-1", usage, usage),
        completed("2026-10-18T10:00:20Z", "turn-1"),
    ];
    let mut previous = [0; 5];
    for end in 1..=values.len() {
        let money = v2(&values[..end]).money();
        assert!(money
            .iter()
            .zip(&previous)
            .all(|(now, before)| now >= before));
        previous = money;
    }
    let counted = v2(&values);
    assert_eq!(counted.money(), five(usage));
    let counters = counted.counters();
    assert_eq!(counters.turn_reopened, 1);
    assert_eq!(counters.native_after_turn_closed, 1);
    assert_eq!(counters.native_counted, 0);
    assert_eq!(legacy(&values).money(), five(usage));

    // A closure whose start was never bound is final too: the id reopens only
    // as an unbound span and its native adds nothing.
    for close in [completed as fn(&str, &str) -> Value, aborted] {
        let values = [
            header(POST),
            context("2026-10-18T10:00:02Z", "turn-1"),
            ui("2026-10-18T10:00:10Z", usage, usage),
            close("2026-10-18T10:00:11Z", "turn-1"),
            started("2026-10-18T10:00:12Z", "turn-1"),
            native("2026-10-18T10:00:13Z", "turn-1", "resp-1", usage, usage),
            completed("2026-10-18T10:00:20Z", "turn-1"),
        ];
        let counted = v2(&values);
        assert_eq!(counted.money(), five(usage));
        let counters = counted.counters();
        assert_eq!(counters.turn_reopened, 1);
        assert_eq!(counters.native_after_turn_closed, 1);
        assert_eq!(counters.native_counted, 0);
        assert_eq!(legacy(&values).money(), five(usage));
    }

    // Far beyond the exact ring: the filter still holds turn-1 closed. The
    // hit is unconfirmed, its native counts 0, and UI in the span keeps the
    // unbound rule, so V2 equals Legacy and nothing is counted twice.
    let at = |second: usize| {
        format!(
            "2026-10-18T{:02}:{:02}:{:02}Z",
            11 + second / 3_600,
            second / 60 % 60,
            second % 60
        )
    };
    let step = [100, 0, 0, 10, 1, 110];
    let mut values = values.to_vec();
    let mut total = usage;
    let later_turns = 4 * codex_usage_occurrence::MAX_CLOSED_TURN_IDS;
    for index in 0..later_turns {
        let turn = format!("turn-later-{index}");
        total = sum(total, step);
        values.extend([
            started(&at(4 * index), &turn),
            context(&at(4 * index + 1), &turn),
            ui(&at(4 * index + 2), step, total),
            completed(&at(4 * index + 3), &turn),
        ]);
    }
    let late = [7_000, 0, 0, 700, 70, 7_700];
    let end = 4 * later_turns;
    values.extend([
        started(&at(end), "turn-1"),
        native(&at(end + 1), "turn-1", "resp-2", late, sum(usage, late)),
        ui(&at(end + 2), step, sum(total, step)),
        completed(&at(end + 3), "turn-1"),
    ]);
    let counted = v2(&values);
    let counters = counted.counters();
    assert_eq!(counters.turn_reopened, 1);
    assert_eq!(
        counters.closed_filter_hit_unconfirmed, 2,
        "started + native"
    );
    assert_eq!(counters.closed_filter_hit_unconfirmed_native_usage, late);
    assert_eq!(counters.native_counted, 0);
    assert_eq!(counters.ui_in_unbound_span, 1);
    assert_eq!(counted.money(), legacy(&values).money());
    assert_eq!(counted.money(), five(sum(total, step)));
}

#[test]
fn codex_v2_overlapping_native_counts_only_uncovered_part() {
    let first = [100, 0, 0, 10, 0, 110];
    let second_usage = [100, 0, 0, 10, 0, 110];
    let second_after = [150, 0, 0, 15, 0, 165];
    let values = [
        header(POST),
        started("2026-10-18T10:00:01Z", "turn-1"),
        context("2026-10-18T10:00:02Z", "turn-1"),
        native("2026-10-18T10:00:10Z", "turn-1", "resp-1", first, first),
        native(
            "2026-10-18T10:00:20Z",
            "turn-1",
            "resp-2",
            second_usage,
            second_after,
        ),
        completed("2026-10-18T10:00:30Z", "turn-1"),
    ];
    let counted = v2(&values);
    assert_eq!(counted.money(), [150, 0, 0, 15, 0]);
    let counters = counted.counters();
    assert_eq!(counters.native_chain_overlap, 1);
    assert_eq!(counters.native_chain_overlap_covered, [50, 0, 0, 5, 0, 55]);
}

#[test]
fn codex_v2_legacy_selection_is_byte_identical_to_unconfigured_parse() {
    let values = |timestamp: &str| {
        vec![
            header(timestamp),
            started("2026-10-18T10:00:01Z", "turn-1"),
            context("2026-10-18T10:00:02Z", "turn-1"),
            native(
                "2026-10-18T10:00:10Z",
                "turn-1",
                "resp-1",
                S2_FIRST,
                sum(S2_BASE, S2_FIRST),
            ),
            ui("2026-10-18T10:00:11Z", S2_FIRST, S2_FIRST),
            ui("2026-10-18T10:00:12Z", S2_FIRST, S2_FIRST),
            completed("2026-10-18T10:00:20Z", "turn-1"),
        ]
    };
    for (timestamp, evidence) in [
        (PRE, AckEvidence::None),
        (PRE, AckEvidence::V2Marked),
        (POST, AckEvidence::LegacyAcked),
    ] {
        let fixture = values(timestamp);
        let selected = run(&fixture, Some(evidence));
        assert!(!selected.v2);
        assert!(selected.counters.is_none());
        assert_eq!(selected.wire(), legacy(&fixture).wire());
    }
}

fn entry(fingerprint: Option<&str>, v2: bool) -> ScanIndexEntry {
    let mut entry: ScanIndexEntry = serde_json::from_value(json!({
        "size_bytes": 1, "modified_unix_seconds": 1, "modified_unix_nanos": 1,
        "source_file_fingerprint": "source", "last_snapshot_fingerprint": fingerprint,
        "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
    }))
    .unwrap();
    entry.codex_counting_v2 = v2;
    entry
}

#[test]
fn codex_counting_version_decision_is_stable() {
    let decide =
        |record: &Value, evidence| codex_counting_version::decide(record, evidence, Some(CUTOVER));
    let post = header(POST);
    assert_eq!(decide(&post, AckEvidence::None), CountingVersion::V2);
    assert_eq!(decide(&post, AckEvidence::V2Marked), CountingVersion::V2);
    assert_eq!(
        decide(&post, AckEvidence::LegacyAcked),
        CountingVersion::Legacy
    );
    assert_eq!(
        decide(&header(PRE), AckEvidence::None),
        CountingVersion::Legacy
    );
    assert_eq!(
        codex_counting_version::decide(&post, AckEvidence::None, None),
        CountingVersion::Legacy,
        "no compiled cutover keeps every session Legacy"
    );
    let mut continuation = header(POST);
    continuation["payload"]["history_base"] = json!({"thread_id": SESSION});
    assert_eq!(
        decide(&continuation, AckEvidence::None),
        CountingVersion::Legacy
    );
    let mut undated = header(POST);
    undated["payload"]
        .as_object_mut()
        .unwrap()
        .remove("timestamp");
    assert_eq!(decide(&undated, AckEvidence::None), CountingVersion::Legacy);
    let first_usage = ui(POST, S1, S1);
    assert_eq!(
        decide(&first_usage, AckEvidence::None),
        CountingVersion::Legacy
    );
    // Inactive, a group's member view is never traversed, so the group scan
    // allocates nothing for counting; active, it reads the members' evidence.
    let unpolled = std::iter::from_fn(|| -> Option<&'static ScanIndexEntry> {
        panic!("an inactive group must not read member evidence")
    });
    assert_eq!(
        codex_counting_version::group_evidence(unpolled),
        AckEvidence::None
    );
    let marked = entry(Some("body"), true);
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    assert_eq!(
        codex_counting_version::group_evidence([&marked]),
        AckEvidence::V2Marked
    );
}

#[test]
fn codex_counting_ack_bool_moves_with_its_entry_through_selected_restore() {
    let key = "/synthetic/sessions/rollout.jsonl".to_string();
    let mut committed = ScanIndex::default();
    committed
        .files
        .insert(key.clone(), entry(Some("old-body"), false));
    let mut working = committed.clone();
    working
        .files
        .insert(key.clone(), entry(Some("new-body"), true));
    let refused = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    let kept = &refused.files[&key];
    assert_eq!(
        (
            kept.last_snapshot_fingerprint.as_deref(),
            kept.codex_counting_v2
        ),
        (Some("old-body"), false)
    );
    let accepted = working.committable_subset(
        &committed,
        &BTreeSet::from(["new-body".to_string()]),
        &BTreeMap::new(),
    );
    let settled = &accepted.files[&key];
    assert_eq!(
        (
            settled.last_snapshot_fingerprint.as_deref(),
            settled.codex_counting_v2
        ),
        (Some("new-body"), true)
    );
    // Persisted only when set; an older binary's index loads as unmarked.
    let saved = serde_json::to_value(settled).unwrap();
    assert_eq!(saved["codex_counting_v2"], json!(true));
    let unmarked = serde_json::to_value(entry(Some("body"), false)).unwrap();
    assert!(unmarked.get("codex_counting_v2").is_none());
    let reloaded: ScanIndexEntry = serde_json::from_value(unmarked).unwrap();
    assert!(!reloaded.codex_counting_v2);
    assert_eq!(AckEvidence::of_view([&reloaded]), AckEvidence::LegacyAcked);
}

#[test]
fn codex_counting_ack_bool_survives_twin_alias_and_rekeyed_entries() {
    let marked = entry(Some("body"), true);
    let legacy_acked = entry(Some("body"), false);
    let unacknowledged_twin = entry(None, false);
    assert_eq!(
        AckEvidence::of_view([&unacknowledged_twin, &marked]),
        AckEvidence::V2Marked
    );
    assert_eq!(
        AckEvidence::of_view([&legacy_acked, &unacknowledged_twin]),
        AckEvidence::LegacyAcked
    );
    assert_eq!(
        AckEvidence::of_view([&unacknowledged_twin]),
        AckEvidence::None
    );
    // COST rule 2: any Legacy ACK dominates any V2 mark, in either order.
    for view in [[&marked, &legacy_acked], [&legacy_acked, &marked]] {
        assert_eq!(AckEvidence::of_view(view), AckEvidence::LegacyAcked);
    }
    // Re-keyed (migrate) and re-recorded (alias) entries keep the mark with
    // their acknowledged fingerprint.
    let path = PathBuf::from("/synthetic/sessions/rollout.jsonl");
    let candidate = || CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: path.clone(),
        size_bytes: 2,
        modified_unix_seconds: 2,
        modified_unix_nanos: 2,
        source_file_fingerprint: "source-2".into(),
        legacy_source_file_fingerprint: "legacy".into(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    };
    let mut index = ScanIndex::default();
    index
        .files
        .insert(local_index_key(&path), entry(Some("body"), true));
    index.migrate(candidate());
    assert!(index.files[&local_index_key(&path)].codex_counting_v2);
    index.record(candidate(), Some("body".into()), ScanParseOutcome::Snapshot);
    assert!(index.files[&local_index_key(&path)].codex_counting_v2);
}

#[test]
fn codex_counting_destination_loss_rederives_only_from_its_own_index() {
    let post = header(POST);
    let decide = |index: &ScanIndex| {
        let evidence = AckEvidence::of_view(index.files.get("/synthetic/sessions/rollout.jsonl"));
        codex_counting_version::decide(&post, evidence, Some(CUTOVER))
    };
    let mut marked = ScanIndex::default();
    marked.files.insert(
        "/synthetic/sessions/rollout.jsonl".into(),
        entry(Some("body"), true),
    );
    let mut old_binary = ScanIndex::default();
    old_binary.files.insert(
        "/synthetic/sessions/rollout.jsonl".into(),
        entry(Some("body"), false),
    );
    assert_eq!(decide(&marked), CountingVersion::V2);
    assert_eq!(decide(&old_binary), CountingVersion::Legacy);
    // Disclosed residual R1: a lost or rotated destination index has no ACK
    // evidence, so an old-binary-acknowledged post-cutover session re-derives V2.
    assert_eq!(decide(&ScanIndex::default()), CountingVersion::V2);
}

#[test]
fn codex_counting_retained_reduction_reuse_requires_the_same_rule() {
    let decided = |values: &[Value], evidence| {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        codex_counting_version::configure(&mut accumulator, evidence, Some(CUTOVER));
        for value in values {
            apply_codex_line(value, &mut accumulator);
        }
        accumulator.codex_counting.unwrap()
    };
    let fresh = |evidence| codex_usage_occurrence::CodexCounting::new(evidence, Some(CUTOVER));
    let v2_state = decided(&[header(POST)], AckEvidence::None);
    assert!(v2_state.reusable_under(&fresh(AckEvidence::V2Marked)));
    assert!(!v2_state.reusable_under(&fresh(AckEvidence::LegacyAcked)));
    let acked_legacy = decided(&[header(POST)], AckEvidence::LegacyAcked);
    assert!(acked_legacy.reusable_under(&fresh(AckEvidence::LegacyAcked)));
    assert!(!acked_legacy.reusable_under(&fresh(AckEvidence::None)));

    // A paused cursor job, checked against its recorded view, applies the
    // same predicate as the retained reduction's `old.filter`.
    let evidences = [
        AckEvidence::None,
        AckEvidence::V2Marked,
        AckEvidence::LegacyAcked,
    ];
    for decided_under in evidences {
        let mut paused = SnapshotAccumulator::new(SnapshotSource::Codex);
        codex_counting_version::configure(&mut paused, decided_under, Some(CUTOVER));
        apply_codex_line(&header(POST), &mut paused);
        for now in evidences {
            assert_eq!(
                codex_counting_version::reusable_under_view(
                    &paused,
                    &codex_counting_version::view(now, CUTOVER)
                ),
                codex_counting_version::reusable(
                    paused.codex_counting.as_deref(),
                    Some(&fresh(now))
                ),
            );
        }
        assert!(!codex_counting_version::reusable_under_view(
            &paused, "legacy"
        ));
    }
    let inactive = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert!(codex_counting_version::reusable_under_view(
        &inactive, "legacy"
    ));
    assert!(!codex_counting_version::reusable_under_view(
        &inactive,
        &codex_counting_version::view(AckEvidence::None, CUTOVER)
    ));
}

#[test]
fn codex_v2_staged_turn_charge_stays_within_the_stated_bound() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let rows = codex_usage_occurrence::MAX_PENDING_ROWS as i64;
    let step = [1_000, 0, 0, 10, 1, 1_010];
    let mut values = vec![
        header(&hour(-1)),
        started(&hour(-1), "turn-1"),
        context(&hour(-1), "turn-1"),
    ];
    let mut total = [0; 6];
    for index in 0..rows {
        total = sum(total, step);
        values.push(ui(&hour(index), step, total));
    }
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    codex_counting_version::configure(&mut accumulator, AckEvidence::None, Some(CUTOVER));
    for value in &values {
        apply_codex_line(value, &mut accumulator);
    }
    let counting = accumulator.codex_counting.as_deref().unwrap();
    assert_eq!(counting.open_turn_ui_pending().unwrap().0, rows as u64);
    let fixed = std::mem::size_of::<codex_usage_occurrence::CodexCounting>()
        + codex_usage_occurrence::max_fixed_heap_bytes();
    let bound = fixed + codex_usage_occurrence::max_pending_heap_bytes();
    let charged = crate::heap_layout_bound::bound(counting, usize::MAX).unwrap();
    assert!(charged <= bound, "charged {charged} > stated bound {bound}");
}

/// Activation freezes one instant, 2026-10-26T12:00:00Z; it must never move.
#[test]
fn codex_counting_v2_compiled_cutover_is_frozen() {
    assert_eq!(
        codex_counting_version::CODEX_COUNTING_V2_CUTOVER_UNIX_MS,
        Some(1_793_016_000_000)
    );
}
