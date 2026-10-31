//! Retained Claude response records (R1a): realistic per-response charge, the
//! per-step visit walk of a long tool-heavy session, and byte parity between a
//! retained-then-tailed read and an independent full read.
//! No fixture content comes from a provider account.
use super::*;
use crate::heap_layout_bound::HeapLayoutBound;
use crate::transcript_acquisition::{FullReason, ReadMode, Scope};
use crate::transcript_cache::Retained;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "5e551011-0000-4000-8000-00000000a1a1";
const MODEL: &str = "claude-fable-5-1";
const SHELL: &str = "Bash";
const CHROME: [&str; 3] = [
    "mcp__claude-in-chrome__computer",
    "mcp__claude-in-chrome__navigate",
    "mcp__claude-in-chrome__read_page",
];
static NEXT: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ottto-r1a-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, AtomicOrdering::Relaxed)
    ))
}

struct TempJsonl {
    dir: PathBuf,
    path: PathBuf,
}
impl TempJsonl {
    fn new(label: &str) -> Self {
        let dir = unique_dir(label);
        let root = dir.join("home/.claude/projects");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("{SESSION}.jsonl"));
        Self { dir, path }
    }
    fn append(&self, rows: &[Value]) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        for row in rows {
            serde_json::to_writer(&mut file, row).unwrap();
            file.write_all(b"\n").unwrap();
        }
    }
}
impl Drop for TempJsonl {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// `2026-10-06T..` with millisecond precision; `seconds` stays within the day.
fn at(seconds: u64, millis: u64) -> String {
    format!(
        "2026-10-06T{:02}:{:02}:{:02}.{millis:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn envelope(kind: &str, uuid: String, timestamp: String) -> Value {
    json!({
        "parentUuid": null,
        "isSidechain": false,
        "userType": "external",
        "cwd": "/work/r1a-fixture",
        "sessionId": SESSION,
        "version": "2.1.40",
        "gitBranch": "main",
        "type": kind,
        "uuid": uuid,
        "timestamp": timestamp,
    })
}

/// One Claude Code turn as current writers persist it: the user row that
/// prompted it, then one assistant row per content block (thinking, text, one
/// row per tool use) sharing the response ids, each with cumulative usage and
/// the usage-level selectors. Every tenth response is written Fable style: the
/// terminal block first, then the earlier partial blocks. Every tenth response
/// (another one) adds a selector only on its terminal block.
fn realistic_turn(index: usize, tools: &[&str]) -> Vec<Value> {
    let base = 20 * index as u64;
    let mut user = envelope("user", format!("u{index:07}"), at(base, 0));
    user["message"] = if index == 0 {
        json!({"role": "user", "content": "Check the compact record fixture."})
    } else {
        json!({"role": "user", "content": [{
            "type": "tool_result",
            "tool_use_id": format!("toolu_01{:08}00", index - 1),
            "content": "ok",
        }]})
    };
    let request_id = format!("req_011CU{index:019}");
    let message_id = format!("msg_01R1A{index:019}");
    let assistant = |block: usize, offset_millis: u64, content: Value, output: u64, late: bool| {
        let mut row = envelope(
            "assistant",
            format!("a{index:07}-{block}"),
            at(base + 1 + offset_millis / 1000, offset_millis % 1000),
        );
        row["requestId"] = json!(request_id);
        row["effort"] = json!("high");
        let mut usage = json!({
            "input_tokens": 4,
            "cache_creation_input_tokens": 300 + index as u64,
            "cache_read_input_tokens": 40_000 + 120 * index as u64,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 0,
                "ephemeral_1h_input_tokens": 300 + index as u64,
            },
            "output_tokens": output,
            "service_tier": "standard",
            "speed": "standard",
        });
        if late {
            usage["inference_geo"] = json!("us");
        }
        row["message"] = json!({
            "id": message_id,
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": [content],
            "stop_reason": null,
            "stop_sequence": null,
            "usage": usage,
        });
        row
    };
    let late_selector = index % 10 == 3;
    let mut blocks = vec![
        assistant(
            0,
            0,
            json!({"type": "thinking", "thinking": "Plan the next step.", "signature": "c2ln"}),
            6,
            false,
        ),
        assistant(
            1,
            900,
            json!({"type": "text", "text": "Running the next check."}),
            6,
            false,
        ),
    ];
    for (tool_index, tool) in tools.iter().enumerate() {
        blocks.push(assistant(
            2 + tool_index,
            1800 + 700 * tool_index as u64,
            json!({
                "type": "tool_use",
                "id": format!("toolu_01{index:08}{tool_index:02}"),
                "name": tool,
                "input": {"command": "true"},
            }),
            120 + tool_index as u64,
            late_selector && tool_index + 1 == tools.len(),
        ));
    }
    if index % 10 == 7 {
        blocks.rotate_right(1);
    }
    let mut rows = vec![user];
    rows.extend(blocks);
    rows
}

fn title_rows() -> Vec<Value> {
    vec![
        json!({"type": "summary", "sessionId": SESSION, "summary": "Compact Claude records", "leafUuid": "u0000000"}),
        json!({"type": "ai-title", "sessionId": SESSION, "aiTitle": "R1a realistic fixture"}),
    ]
}

fn realistic_rows(responses: Range<usize>, tools: &[&str]) -> Vec<Value> {
    let mut rows = if responses.start == 0 {
        title_rows()
    } else {
        Vec::new()
    };
    for index in responses {
        rows.extend(realistic_turn(index, tools));
    }
    rows
}

fn charge<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    crate::heap_layout_bound::bound(value, usize::MAX)
}

fn native_parser(path: &Path) -> (OwnedJsonlParser, String) {
    let mut file = File::open(path).unwrap();
    let expected = opened_object_identity(SnapshotSource::ClaudeCode, &mut file).unwrap();
    let parser = OwnedJsonlParser::new(
        file,
        path,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        Some(&CodexTitleMetadata::default()),
        None,
        None,
        false,
        true,
    )
    .unwrap();
    (parser, expected)
}

/// One native acquisition: reuse `old` if the reader accepts it, read to EOF,
/// retain a copy within the entry limit, then finish natively.
fn acquire(
    path: &Path,
    old: Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    now: u64,
) -> (
    Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    ReadMode,
    Value,
) {
    let scope = Scope("r1a-native".into());
    let (mut parser, expected) = native_parser(path);
    let debt = old.as_ref().and_then(|old| old.checkpoint.audit_debt());
    let mode = parser.prepare_acquisition(old, &scope, debt, now).unwrap();
    while !parser.step().unwrap() {}
    let acquisition = parser
        .retain_reduction(
            &scope,
            now,
            sampled_scan::RetainBudget::granted_unclassified(crate::transcript_cache::ENTRY_BYTES),
        )
        .unwrap()
        .unwrap();
    let retained = acquisition.reduction.map(|state| Retained {
        checkpoint: acquisition.checkpoint,
        state,
    });
    let parsed = parser
        .finish(
            &expected,
            path,
            NOW,
            "native-fixture".into(),
            Some(&CodexTitleMetadata::default()),
            Some(&ClaudeTitleMetadata::default()),
            None,
        )
        .unwrap();
    let mut items = parsed.snapshots;
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut items,
        SnapshotUploadPolicy::default(),
    );
    (retained, mode, serde_json::to_value(items).unwrap())
}

fn oracle(path: &Path) -> Value {
    let mut items =
        parse_claude_code_jsonl_file_with_artifacts(path, NOW, "native-fixture".into(), false)
            .unwrap();
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut items,
        SnapshotUploadPolicy::default(),
    );
    serde_json::to_value(items).unwrap()
}

/// Retain after every row boundary, tail the rest, and require the tailed
/// output to equal an independent full read of the whole file.
fn assert_every_split_tails_with_full_parity(label: &str, rows: &[Value]) {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for split in 1..rows.len() {
        let file = TempJsonl::new(label);
        file.append(&rows[..split]);
        let (retained, mode, _) = acquire(&file.path, None, 100);
        assert_eq!(mode, ReadMode::Full(FullReason::StateMissing));
        assert!(
            retained.is_some(),
            "{label}: the prefix through row {split} was not retained"
        );
        file.append(&rows[split..]);
        let (_, mode, tailed) = acquire(&file.path, retained, 101);
        assert_eq!(mode, ReadMode::Tail, "{label}: split {split}");
        assert_eq!(tailed, oracle(&file.path), "{label}: split {split}");
    }
}

fn full_item(rows: &[Value]) -> SnapshotItem {
    let file = TempJsonl::new("full-item");
    file.append(rows);
    parse_claude_code_jsonl_file(&file.path, NOW, "fp".into())
        .unwrap()
        .into_iter()
        .next()
        .expect("snapshot")
}

fn speed_record(timestamp: Option<&str>, top_level: bool) -> Value {
    let mut usage = json!({"input_tokens": 12, "output_tokens": 7, "cache_read_input_tokens": 40});
    let mut row = json!({
        "type": "assistant",
        "sessionId": SESSION,
        "requestId": "req_sources",
        "message": {"id": "msg_sources", "model": MODEL, "role": "assistant"},
    });
    if top_level {
        row["speed"] = json!("standard");
    } else {
        usage["speed"] = json!("standard");
    }
    row["message"]["usage"] = usage;
    if let Some(timestamp) = timestamp {
        row["timestamp"] = json!(timestamp);
    }
    row
}

/// M-review F6: records with equal selector context but different sources,
/// where a record equal to its physical predecessor sorts last by provider
/// time. A "same as previous" dedupe would change the uploaded source.
#[test]
fn claude_equal_context_differing_sources_keep_parity_at_every_split() {
    let user = json!({"type": "user", "sessionId": SESSION, "timestamp": "2026-10-06T10:00:00Z", "message": {"role": "user", "content": "work"}});
    // Provider order r2, r1, r3: the terminal source is r3's top-level `speed`.
    let stamped = vec![
        user.clone(),
        speed_record(Some("2026-10-06T10:00:02Z"), false),
        speed_record(Some("2026-10-06T10:00:01Z"), true),
        speed_record(Some("2026-10-06T10:00:03Z"), true),
    ];
    // One unstamped record keeps physical order: the terminal source is r3's.
    let unstamped = vec![
        user,
        speed_record(Some("2026-10-06T10:00:02Z"), true),
        speed_record(Some("2026-10-06T10:00:01Z"), false),
        speed_record(None, false),
    ];
    for (label, rows, source) in [
        ("sources-stamped", &stamped, "speed"),
        ("sources-unstamped", &unstamped, "message.usage.speed"),
    ] {
        let item = full_item(rows);
        assert_eq!(item.request_count, 1, "{label}");
        let usage = &item.model_usage[0];
        assert_eq!(
            usage.selector_context.get("speed_mode").map(String::as_str),
            Some("standard"),
            "{label}"
        );
        assert_eq!(
            usage.selector_sources.get("speed_mode").map(String::as_str),
            Some(source),
            "{label}"
        );
        assert_every_split_tails_with_full_parity(label, rows);
    }
}

/// The Fable out-of-order writer and a late selector on a progressive
/// response (fixtures of the existing native parse tests) stay exact when the
/// response spans the retained boundary.
#[test]
fn claude_out_of_order_and_late_selector_responses_keep_parity_at_every_split() {
    let out_of_order: Vec<Value> = [
        r#"{"timestamp":"2026-09-11T08:31:20Z","sessionId":"claude-progressive-order","type":"user","message":{"role":"user","content":"work"}}"#,
        r#"{"timestamp":"2026-09-11T08:31:22.985Z","sessionId":"claude-progressive-order","type":"assistant","requestId":"req_progressive_order","speed":"standard","message":{"id":"msg_progressive_order","model":"claude-fable-5-1","usage":{"input_tokens":32,"output_tokens":1026,"cache_read_input_tokens":960010,"cache_creation":{"ephemeral_1h_input_tokens":6006}}}}"#,
        r#"{"timestamp":"2026-09-11T08:31:29.473Z","sessionId":"claude-progressive-order","type":"assistant","requestId":"req_progressive_order","speed":"standard","message":{"id":"msg_progressive_order","model":"claude-fable-5-1","usage":{"input_tokens":32,"output_tokens":1026,"cache_read_input_tokens":960010,"cache_creation":{"ephemeral_1h_input_tokens":6006}}}}"#,
        r#"{"timestamp":"2026-09-11T08:31:22.985Z","sessionId":"claude-progressive-order","type":"assistant","requestId":"req_progressive_order","message":{"id":"msg_progressive_order","model":"claude-fable-5-1","usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation":{"ephemeral_1h_input_tokens":6006}}}}"#,
        r#"{"timestamp":"2026-09-11T08:31:29.473Z","sessionId":"claude-progressive-order","type":"assistant","requestId":"req_progressive_order","message":{"id":"msg_progressive_order","model":"claude-fable-5-1","usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation":{"ephemeral_1h_input_tokens":6006}}}}"#,
    ]
    .iter()
    .map(|row| serde_json::from_str(row).unwrap())
    .collect();
    let late_selector: Vec<Value> = [
        r#"{"timestamp":"2026-08-02T09:00:00Z","type":"user","sessionId":"11111111-2222-3333-4444-555555555555","isSidechain":true,"message":{"role":"user","content":"work"}}"#,
        r#"{"timestamp":"2026-08-02T09:00:01Z","type":"assistant","sessionId":"11111111-2222-3333-4444-555555555555","isSidechain":true,"requestId":"req_progress","message":{"id":"msg_progress","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":2,"cache_read_input_tokens":30}}}"#,
        r#"{"timestamp":"2026-08-02T09:00:02Z","type":"assistant","sessionId":"11111111-2222-3333-4444-555555555555","isSidechain":true,"requestId":"req_progress","speed":"standard","message":{"id":"msg_progress","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":19,"cache_read_input_tokens":30}}}"#,
    ]
    .iter()
    .map(|row| serde_json::from_str(row).unwrap())
    .collect();
    let item = full_item(&out_of_order);
    assert_eq!((item.output_tokens, item.request_count), (1_026, 1));
    assert_eq!(
        item.model_usage[0]
            .selector_context
            .get("context_bucket")
            .map(String::as_str),
        Some("long")
    );
    let item = full_item(&late_selector);
    assert_eq!((item.output_tokens, item.request_count), (19, 1));
    assert_eq!(
        item.model_usage[0]
            .selector_sources
            .get("speed_mode")
            .map(String::as_str),
        Some("speed")
    );
    assert_every_split_tails_with_full_parity("out-of-order", &out_of_order);
    assert_every_split_tails_with_full_parity("late-selector", &late_selector);
}

/// Titles, the first prompt, tool uses, Fable replays and a late selector in a
/// short realistic session: every retained boundary tails to the full output.
#[test]
fn claude_realistic_session_keeps_parity_at_every_split() {
    let rows = realistic_rows(0..9, &[SHELL, CHROME[1]]);
    let item = full_item(&rows);
    assert_eq!(item.request_count, 9);
    assert!(item.session_display_name.is_some());
    assert!(item.session_start.is_some());
    assert!(item
        .tool_usage
        .as_ref()
        .is_some_and(|tools| tools.len() >= 2));
    let sources = &item.model_usage[0].selector_sources;
    assert!(sources.contains_key("service_tier") && sources.contains_key("speed_mode"));
    assert_every_split_tails_with_full_parity("realistic", &rows);
}

fn selector(fields: &[(&str, &str, &str)]) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    for (field, value, source) in fields {
        selector.insert(field, (*value).to_string(), source);
    }
    selector
}

/// Every retained record decodes to exactly the record the unchanged merge
/// consumed before compaction, across each redundancy the encoding drops:
/// request-slot strings (consistent or not), text shared with the first
/// record, `\u{1f}` inside ids, empty strings, observed and default costs,
/// interned and overflowed selectors with equal context but different
/// sources, malformed or equal timestamps and tool-use maps.
#[test]
fn claude_compact_records_decode_exactly() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    let text = |options: &[Option<&str>], pick: usize| options[pick].map(str::to_string);
    let models = [None, Some(MODEL), Some("claude-opus-4-8"), Some("")];
    let efforts = [None, Some("high"), Some("low")];
    let request_ids = [None, Some("req_a"), Some("req\u{1f}b"), Some("")];
    let timestamps = [
        None,
        Some("2026-10-06T10:00:01Z"),
        Some("2026-10-06T10:00:01.000Z"),
        Some("not a time"),
        Some("2026-10-06T10:00:00Z"),
    ];
    let pool = [
        SelectorCapture::default(),
        selector(&[("speed_mode", "standard", "speed")]),
        selector(&[("speed_mode", "standard", "message.usage.speed")]),
        selector(&[
            ("service_tier", "standard", "message.usage.service_tier"),
            ("speed_mode", "fast", "speed"),
        ]),
    ];
    let mut table = ClaudeSelectorTable::default();
    // Leave two free slots so later distinct selectors overflow inline.
    for filler in 0..62 {
        let filler = selector(&[("region_mode", format!("r{filler}").as_str(), "region")]);
        assert!(matches!(
            table.intern(filler),
            CompactClaudeSelector::Interned(_)
        ));
    }
    let mut inline = 0;
    for response in 0..400 {
        let mut expected = Vec::new();
        let mut observation: Option<ClaudeResponseObservation> = None;
        for physical_sequence in 0..1 + next(6) {
            let model = text(&models, next(models.len()));
            let reasoning_effort = text(&efforts, next(efforts.len()));
            let request_id = text(&request_ids, next(request_ids.len()));
            let timestamp = text(&timestamps, next(timestamps.len()));
            let mut usage = UsageTotals {
                input_tokens: next(50) as u64,
                output_tokens: next(500) as u64,
                cache_read_tokens: next(90_000) as u64,
                cache_creation_1h_tokens: next(3) as u64,
                request_count: 1,
                ..UsageTotals::default()
            };
            if next(5) == 0 {
                usage.costs = UsageCosts {
                    observed: true,
                    reported: next(2) == 0,
                    total: Some(next(1_000) as u128),
                    ..UsageCosts::default()
                };
            }
            let token = |value: usize| (value % 3 != 0).then_some(value as u64);
            let mut cache_slot = RequestSlot {
                request_ref: request_id.clone().unwrap_or_default(),
                occurred_at: timestamp.clone().unwrap_or_default(),
                model: model.clone(),
                effort: reasoning_effort.clone(),
                prompt_tokens: token(next(900)),
                cache_read_tokens: token(next(900)),
                cache_creation_tokens: token(next(900)),
                uncached_tokens: token(next(900)),
                output_tokens: token(next(900)),
            };
            match next(8) {
                0 => cache_slot.request_ref = "req_elsewhere".into(),
                1 => cache_slot.model = None,
                _ => {}
            }
            let selector = if next(9) == 0 {
                selector(&[("region_mode", format!("late{response}").as_str(), "region")])
            } else {
                pool[next(pool.len())].clone()
            };
            let tool_uses = (0..next(3))
                .map(|tool| {
                    (
                        format!("toolu_{response}_{tool}"),
                        format!("Tool{}", next(2)),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let computed_effective_input_context = (next(2) == 0).then_some(next(99_999) as u64);
            expected.push(ClaudeResponseRecord {
                cache_slot: cache_slot.clone(),
                physical_sequence: physical_sequence as u64,
                usage: usage.clone(),
                model: model.clone(),
                selector: selector.clone(),
                reasoning_effort: reasoning_effort.clone(),
                request_id: request_id.clone(),
                timestamp: timestamp.clone(),
                computed_effective_input_context,
                tool_uses: tool_uses.clone(),
            });
            let interned = table.intern(selector);
            inline += usize::from(matches!(interned, CompactClaudeSelector::Inline(_)));
            match observation.as_mut() {
                None => {
                    observation = Some(ClaudeResponseObservation::new(
                        response as u64,
                        usage,
                        model,
                        interned,
                        reasoning_effort,
                        request_id,
                        timestamp,
                        None,
                        computed_effective_input_context,
                        tool_uses,
                        cache_slot,
                    ));
                }
                Some(observation) => assert!(observation.push(
                    usage,
                    model,
                    interned,
                    reasoning_effort,
                    request_id,
                    timestamp,
                    computed_effective_input_context,
                    tool_uses,
                    cache_slot,
                )),
            }
        }
        let observation = observation.expect("at least one record");
        let decoded =
            claude_response_records::decode_records(observation.records.into_vec(), &table);
        assert_eq!(decoded, Some(expected), "response {response}");
    }
    assert!(inline > 0, "no selector overflowed the interned table");
}

fn decoded_baseline_charge(book: ClaudeResponseBook) -> usize {
    let (responses, selectors) = book.into_parts();
    // BASE kept all records decoded for the whole read, not just one response.
    let decoded: Vec<_> = responses
        .into_iter()
        .map(|response| {
            claude_response_records::decode_records(response.records.into_vec(), &selectors)
                .unwrap()
        })
        .collect();
    crate::heap_layout_bound::completed_bound(&decoded, usize::MAX).unwrap()
}

#[test]
fn claude_native_finish_peak_covers_decode_output_and_retained_copy() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = TempJsonl::new("finish-peak");
    fixture.append(&realistic_rows(0..120, &[SHELL, CHROME[0]]));
    let (mut parser, expected) = native_parser(&fixture.path);
    let scope = Scope("r1a-finish-peak".into());
    parser.prepare_acquisition(None, &scope, None, 1).unwrap();
    while !parser.step().unwrap() {}
    let active = charge(&parser.accumulator).unwrap();
    let extra = parser
        .accumulator
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    let baseline = decoded_baseline_charge(parser.accumulator.claude_responses.clone());
    let budget = parser
        .accumulator
        .claude_responses
        .finish_copy_budget(crate::transcript_cache::ENTRY_BYTES)
        .unwrap();
    let retained = parser
        .retain_reduction(
            &scope,
            1,
            sampled_scan::RetainBudget::granted_unclassified(budget),
        )
        .unwrap()
        .unwrap();
    let retained_charge = charge(&retained).unwrap();
    assert!(retained.reduction.is_some());
    // Born-pointer audit: freeing the pre-existing compact parser cannot hide
    // newly allocated decoded records, sorting scratch or output allocations.
    let (parsed, actual) = crate::retry_allocation_probe::measure_caller_thread(|| {
        parser
            .finish(
                &expected,
                &fixture.path,
                NOW,
                "finish-peak".into(),
                None,
                None,
                None,
            )
            .unwrap()
    });
    let output = crate::heap_layout_bound::completed_bound(&parsed, budget).unwrap();
    assert!(
        extra + output >= actual.requested_peak_with_overlap,
        "decode_extra={extra} output={output} actual={actual:?}"
    );
    let charged_peak = active + retained_charge + extra + output;
    let measured_peak_bound = active + retained_charge + actual.requested_peak_with_overlap;
    assert!(charged_peak >= measured_peak_bound);
    eprintln!("R1A_FINISH_PEAK responses=120 active={active} retained={retained_charge} decoded_baseline={baseline} decode_extra={extra} output={output} born_finish_peak={} charged_peak={charged_peak} measured_peak_bound={measured_peak_bound}", actual.requested_peak_with_overlap);
    drop(retained);
}

// #665 X_out (R1a R8; hunk map T1, T3-T6). Receipts: `X_OUT_T3`, `X_OUT_T1`.

fn x_out_identity(tag: &str) -> crate::context_footprint::RepositoryIdentity {
    crate::context_footprint::RepositoryIdentity {
        repository_hash: Some(format!("hash-{tag}")),
        repository_label: Some(format!("label-{tag}")),
        repository_label_source: Some("git_remote".to_string()),
        repository_identity_source: Some("git".to_string()),
        workspace_kind: Some("git_repo".to_string()),
    }
}

/// Rows of one case under their own workspace (the identity cache is global).
fn with_cwd(mut rows: Vec<Value>, cwd: &str) -> Vec<Value> {
    for row in &mut rows {
        if row.get("cwd").is_some() {
            row["cwd"] = json!(cwd);
        }
    }
    rows
}

/// [behaviour] A native finish must fit the output governor and decode reserve.
fn assert_x_out_covers_finish(label: &str, rows: &[Value], title: &ClaudeTitleMetadata) {
    let fixture = TempJsonl::new(label);
    fixture.append(rows);
    let (mut parser, expected) = native_parser(&fixture.path);
    while !parser.step().unwrap() {}
    if let Some(workspace) = parser.accumulator.workspace_path.clone() {
        assert_ne!(workspace, Path::new("/work/r1a-fixture"));
        repository_identity_cache()
            .lock()
            .unwrap()
            .insert(workspace, (SystemTime::now(), x_out_identity(label)));
    }
    let identity = parser
        .accumulator
        .workspace_path
        .as_deref()
        .and_then(peek_repository_identity);
    let peak = parser
        .accumulator
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    let x_out = parser
        .finish_output_bound(
            FinishOutputInput {
                path: &fixture.path,
                collected_at: NOW,
                source_file_fingerprint: "x-out-fixture",
                opened_object_identity: &expected,
                title_metadata: Some(title),
                attribution: false,
                repository_identity: identity.as_ref(),
            },
            usize::MAX,
        )
        .expect("finish output bound");
    let (parsed, actual) = crate::retry_allocation_probe::measure_caller_thread(|| {
        parser
            .finish_with_repository_identity(
                &expected,
                &fixture.path,
                NOW,
                "x-out-fixture".into(),
                None,
                Some(title),
                None,
                identity,
                None,
            )
            .unwrap()
    });
    assert!(!parsed.snapshots.is_empty());
    let output = crate::heap_layout_bound::completed_bound(&parsed, usize::MAX).unwrap();
    assert!(output <= x_out, "output={output} > x_out={x_out}");
    assert!(actual.requested_peak_with_overlap <= x_out + peak);
}

/// [behaviour] One finish-allocation guard for the Claude output governor.
#[test]
fn x_out_t1_bounds_the_finished_claude_file() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    assert_x_out_covers_finish(
        "representative-finish",
        &with_cwd(realistic_rows(0..3, &[SHELL, CHROME[0]]), "/work/x-out"),
        &ClaudeTitleMetadata::default(),
    );
}

// Kept: changed by train #949 (main version; snap-diag had deleted it).

/// A value's completed heap, without its inline slot (T5 compares fields
/// whose containers differ: `OwnedVec` before the move, `Vec` after).
fn completed_heap_only<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    crate::heap_layout_bound::completed_bound(value, usize::MAX)?
        .checked_sub(std::mem::size_of_val(value))
}

/// For each assistant row of `rows`, `edit(row_index, row)`.
fn edit_assistant(mut rows: Vec<Value>, mut edit: impl FnMut(usize, &mut Value)) -> Vec<Value> {
    for (index, row) in rows.iter_mut().enumerate() {
        if row["type"] == "assistant" {
            edit(index, row);
        }
    }
    rows
}

/// What a finished item holds from its responses, the outputs X_out family
/// R bounds: request ids, occurrences, cache requests, tool usage, model and
/// bucket rows. The rows also carry text `finish_output_bound` charges
/// outside R (account hash, cost text), so this over-measures R.
fn family_r_measured(item: &SnapshotItem) -> Option<usize> {
    completed_heap_only(&item.claude_usage_request_ids)?
        .checked_add(completed_heap_only(&item.claude_usage_occurrences)?)?
        .checked_add(completed_heap_only(&item.cache_requests)?)?
        .checked_add(completed_heap_only(&item.tool_usage)?)?
        .checked_add(completed_heap_only(&item.model_usage)?)?
        .checked_add(completed_heap_only(&item.usage_buckets)?)
}

/// What a T1 case adds around its file (fresh-r1 N1, N3).
#[derive(Default)]
struct FinishCase<'a> {
    /// Runs on the read accumulator before X_out is taken: rows that exist
    /// before `finish` (N1). Family R then bounds only part of the item.
    prepare: Option<&'a dyn Fn(&mut SnapshotAccumulator)>,
}

/// What one T1 case measured.
struct FinishReceipt {
    x_out: usize,
    decode_peak: usize,
    born: usize,
    /// Gate on: the kept fold's completed heap and X_out's E term.
    fold: Option<(usize, usize)>,
}

/// `assert_x_out_covers_finish` with `case`'s additions, and its receipt.
fn assert_x_out_covers_finish_with(
    label: &str,
    rows: &[Value],
    title: &ClaudeTitleMetadata,
    case: FinishCase<'_>,
) -> (Vec<SnapshotItem>, FinishReceipt) {
    let fixture = TempJsonl::new(label);
    fixture.append(rows);
    let (mut parser, expected) = native_parser(&fixture.path);
    while !parser.step().unwrap() {}
    if let Some(prepare) = case.prepare {
        prepare(&mut parser.accumulator);
    }
    if let Some(workspace) = parser.accumulator.workspace_path.clone() {
        // The cache is global: a warm identity under the shared fixture
        // workspace would leak into every concurrent production scan of it.
        assert_ne!(
            workspace,
            Path::new("/work/r1a-fixture"),
            "{label}: give the case its own workspace (`with_cwd`)"
        );
        repository_identity_cache()
            .lock()
            .unwrap()
            .insert(workspace, (SystemTime::now(), x_out_identity(label)));
    }
    let identity = parser
        .accumulator
        .workspace_path
        .as_deref()
        .and_then(peek_repository_identity);
    let responses = parser.accumulator.claude_responses.values().count();
    let peak = parser
        .accumulator
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    let family_r = parser
        .accumulator
        .claude_responses
        .completion_bounds(usize::MAX)
        .and_then(|bounds| bounds.output)
        .unwrap_or_else(|| panic!("{label}: family R refused"));
    let moved_before = (
        completed_heap_only(&parser.accumulator.claude_file_birth),
        completed_heap_only(&parser.accumulator.claude_compaction_observations),
        completed_heap_only(&parser.accumulator.claude_org_markers),
    );
    let x_out = parser
        .finish_output_bound(
            FinishOutputInput {
                path: &fixture.path,
                collected_at: NOW,
                source_file_fingerprint: "x-out-fixture",
                opened_object_identity: &expected,
                title_metadata: Some(title),
                attribution: false,
                repository_identity: identity.as_ref(),
            },
            usize::MAX,
        )
        .unwrap_or_else(|| panic!("{label}: X_out refused"));
    let money = Some({
        let keys = parser
            .accumulator
            .claude_responses
            .completion_bounds(usize::MAX)
            .and_then(|bounds| bounds.fold)
            .unwrap_or_else(|| panic!("{label}: fold keys refused"));
        parser
            .accumulator
            .e2_fold_output_bound(&fixture.path, keys, usize::MAX)
            .unwrap_or_else(|| panic!("{label}: E refused"))
    });
    let (parsed, actual) = crate::retry_allocation_probe::measure_caller_thread(|| {
        parser
            .finish_with_repository_identity(
                &expected,
                &fixture.path,
                NOW,
                "x-out-fixture".into(),
                None,
                Some(title),
                None,
                identity,
                None,
            )
            .unwrap()
    });
    let output = crate::heap_layout_bound::completed_bound(&parsed, usize::MAX).unwrap();
    let born = actual.requested_peak_with_overlap;
    eprintln!(
        "X_OUT_T1 case={label} responses={responses} items={} x_out={x_out} output={output} decode_peak={peak} born_finish_peak={born} output_slack={} peak_slack={} born_ratio={:.4}",
        parsed.snapshots.len(),
        x_out - output.min(x_out),
        (x_out + peak) - born.min(x_out + peak),
        born as f64 / (x_out + peak) as f64,
    );
    // T4: no JSON capacity on a Claude item.
    for item in &parsed.snapshots {
        assert!(item.cache_observations.is_none(), "{label}");
        assert!(item.cache_observations_state.is_none(), "{label}");
        assert!(item.cache_base_head_etag.is_none(), "{label}");
    }
    // T5: family M fields are no larger after the move.
    if let [item] = parsed.snapshots.as_slice() {
        let after = (
            completed_heap_only(&item.claude_file_birth),
            completed_heap_only(&item.claude_context_curve_boundaries),
            completed_heap_only(&item.claude_org_markers),
        );
        let le = |after: Option<usize>, before: Option<usize>| {
            after
                .zip(before)
                .is_some_and(|(after, before)| after <= before)
        };
        assert!(
            le(after.0, moved_before.0)
                && le(after.1, moved_before.1)
                && le(after.2, moved_before.2),
            "{label}: T5 after={after:?} before={moved_before:?}"
        );
    }
    // T1: the finished value is within X_out, and what it holds from its
    // responses is within family R.
    eprintln!("X_OUT_T1 case={label} family=composed measured={output} bound={x_out}");
    if let ([item], None) = (parsed.snapshots.as_slice(), case.prepare) {
        let measured = family_r_measured(item).expect("finished item measured");
        eprintln!("X_OUT_T1 case={label} family=R measured={measured} bound={family_r}");
        assert!(
            measured <= family_r,
            "{label}: family R measured={measured} > bound={family_r}"
        );
    }
    assert!(output <= x_out, "{label}: output={output} > x_out={x_out}");
    // E: the fold the finish keeps is within its itemized term.
    let fold = money.map(|money| {
        let measured = parsed
            .snapshots
            .iter()
            .try_fold(0usize, |bytes, item| {
                bytes.checked_add(completed_heap_only(&item.claude_money)?)
            })
            .expect("folds measured");
        eprintln!("X_OUT_T1 case={label} family=E measured={measured} bound={money}");
        assert!(
            measured <= money,
            "{label}: fold measured={measured} > E={money}"
        );
        (measured, money)
    });
    // T6: everything born in finish coexists within X_out plus the decode peak.
    assert!(
        born <= x_out + peak,
        "{label}: born_finish_peak={born} > x_out={x_out} + decode_peak={peak}"
    );
    (
        parsed.snapshots,
        FinishReceipt {
            x_out,
            decode_peak: peak,
            born,
            fold,
        },
    )
}

/// E's worst shapes (gate on), at twice the largest X_out fixture (the
/// allocation audit's 65,536 live slots overflow at 512): every response
/// its own hour, selector and grain (every third naming no model, every
/// fourth id-less); the same responses all copied in before the file's
/// birth, so the finish restores them through `absorb_grains` (the moment a
/// held body and its clone coexist); and org-marker runs split by the birth,
/// so own requests inherit copied markers (inherited bodies, the accounts'
/// rebuild). The kept fold is measured as T1 measures (its completed heap)
/// against E, and everything born in finish against X_out (T6).
#[test]
fn x_out_e2_fold_worst_shapes_stay_within_e() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }

    const RESPONSES: usize = 256;
    const START: i64 = 1_790_000_000;
    let hour = |index: usize| {
        time::OffsetDateTime::from_unix_timestamp(START + 3600 * index as i64)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let birth_at = |index: usize| i128::from(START + 3600 * index as i64) * 1_000_000_000;
    let rows = |markers: bool| {
        let mut rows = title_rows();
        for index in 0..RESPONSES {
            if markers && index % 32 == 0 {
                rows.push(json!({"type": "attachment", "sessionId": SESSION,
                    "timestamp": hour(index), "attachment": {"type": "credential_org",
                    "organizationUuid": format!("{:08}-1111-4111-8111-111111111111", index / 32)}}));
            }
            rows.extend(edit_assistant(realistic_turn(index, &[SHELL]), |_, row| {
                row["timestamp"] = json!(hour(index));
                row["message"]["usage"]["inference_geo"] = json!(format!("geo-{index:04}"));
                if index % 3 == 2 {
                    row["message"].as_object_mut().unwrap().remove("model");
                }
                if index % 4 == 3 {
                    row.as_object_mut().unwrap().remove("requestId");
                }
            }));
        }
        rows
    };
    // The fixture file is born now, after every response: name its birth.
    let own = |accumulator: &mut SnapshotAccumulator| {
        accumulator
            .claude_file_birth
            .set_birth_for_test(i128::from(START - 86_400) * 1_000_000_000);
    };
    let all_copied = |accumulator: &mut SnapshotAccumulator| {
        accumulator
            .claude_file_birth
            .set_birth_for_test(birth_at(RESPONSES + 24));
    };
    let split = |accumulator: &mut SnapshotAccumulator| {
        accumulator
            .claude_file_birth
            .set_birth_for_test(birth_at(RESPONSES / 2));
    };
    // (label, markers, prepare, grains at least, copies restored)
    for (label, markers, prepare, grains, restored) in [
        (
            "e2-own-hours",
            false,
            Some(&own as &dyn Fn(&mut SnapshotAccumulator)),
            RESPONSES,
            0,
        ),
        (
            "e2-all-copied",
            false,
            Some(&all_copied as &dyn Fn(&mut SnapshotAccumulator)),
            RESPONSES,
            RESPONSES,
        ),
        (
            "e2-markers-split",
            true,
            Some(&split as &dyn Fn(&mut SnapshotAccumulator)),
            RESPONSES / 2,
            RESPONSES / 2,
        ),
    ] {
        claude_request_money::e2::take_diag();
        let (items, receipt) = assert_x_out_covers_finish_with(
            label,
            &with_cwd(rows(markers), &format!("/work/x-out-{label}")),
            &ClaudeTitleMetadata::default(),
            FinishCase { prepare },
        );
        let [item] = items.as_slice() else {
            panic!("{label}: {} items", items.len());
        };
        let fold = item.claude_money.as_deref().expect("a gate-on fold");
        let (measured, bound) = receipt.fold.expect("gate on");
        let diag = claude_request_money::e2::take_diag();
        eprintln!(
            "X_OUT_E2 case={label} grains={} measured={measured} bound={bound} x_out={} born={} decode_peak={} diag={diag:?}",
            fold.entity.grains.len(),
            receipt.x_out,
            receipt.born,
            receipt.decode_peak,
        );
        // Exactly the copies came back through `absorb_grains`, disclosed;
        // the id-less quarter (every fourth response) under its own reason.
        let disclosed = |reason| diag.get(reason).copied().unwrap_or(0);
        assert_eq!(
            disclosed("copy_unproven") + disclosed("copy_idless"),
            restored as u64,
            "{label}: {diag:?}"
        );
        assert_eq!(
            disclosed("copy_idless"),
            restored as u64 / 4,
            "{label}: {diag:?}"
        );
        // The worst shape happened: every counted response its own grain.
        assert!(
            fold.entity.grains.len() >= grains,
            "{label}: {} grains",
            fold.entity.grains.len()
        );
    }
}
