//! Retained Claude response records (R1a): realistic per-response charge, the
//! per-step visit walk of a long tool-heavy session, and byte parity between a
//! retained-then-tailed read and an independent full read.
//! No fixture content comes from a provider account.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
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
/// Retained charge allowed per realistic response once records are compact.
const PER_RESPONSE_TARGET_BYTES: usize = 4 * 1024;
/// Retained copy allowed for a 600-response realistic session.
const COPY_TARGET_BYTES_AT_600: usize = 2 * 1024 * 1024;
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
    fn root(&self) -> PathBuf {
        self.dir.join("home/.claude/projects")
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

fn parser_for(rows: &[Value]) -> SnapshotAccumulator {
    let mut parser = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    for row in rows {
        apply_claude_code_line(row, &mut parser);
    }
    parser
}

fn charge<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    crate::heap_layout_bound::bound(value, usize::MAX)
}

#[test]
fn claude_realistic_records_meet_the_per_response_charge_target() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let baseline = charge(&parser_for(&title_rows())).expect("baseline charge");
    let mut failures = Vec::new();
    for responses in [300, 600] {
        let parser = parser_for(&realistic_rows(0..responses, &[SHELL]));
        let active = charge(&parser).expect("active charge within the visit limit");
        let copy = charge(&parser.clone()).expect("copy charge within the visit limit");
        let per_response = active.saturating_sub(baseline) / responses;
        let copy_per_response = copy.saturating_sub(baseline) / responses;
        eprintln!(
            "R1A_CHARGE responses={responses} baseline_bytes={baseline} active_bytes={active} copy_bytes={copy} active_per_response={per_response} copy_per_response={copy_per_response}"
        );
        if per_response > PER_RESPONSE_TARGET_BYTES {
            failures.push(format!(
                "responses={responses}: active charge {per_response} B per response > {PER_RESPONSE_TARGET_BYTES} (active={active} copy={copy})"
            ));
        }
        if responses == 600 && copy > COPY_TARGET_BYTES_AT_600 {
            failures.push(format!(
                "responses=600: retained copy {copy} B > {COPY_TARGET_BYTES_AT_600}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn claude_realistic_record_charge_covers_requested_allocations() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let rows = realistic_rows(0..120, &[SHELL, CHROME[0]]);
    let (parser, actual) = crate::retry_allocation_probe::measure(|| parser_for(&rows));
    let active = charge(&parser).unwrap();
    assert!(
        active >= actual.requested_live as usize,
        "active={active} requested={}",
        actual.requested_live
    );
    let (copy, actual) = crate::retry_allocation_probe::measure(|| parser.clone());
    let copied = charge(&copy).unwrap();
    assert!(
        copied >= actual.requested_live as usize,
        "copy={copied} requested={}",
        actual.requested_live
    );
}

#[test]
fn claude_tool_heavy_seen_tool_use_walk_stays_under_the_visit_limit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut visits = Vec::new();
    for responses in [500, 2000] {
        let parser = parser_for(&realistic_rows(0..responses, &CHROME));
        let mut counter = Counter::new(usize::MAX);
        // Only the Claude-owned seen-tool-use conversion is in this slice.
        // The shared capability buckets remain a BTreeMap pending clearance.
        let walked = parser
            .seen_claude_capability_tool_uses
            .heap_bound(&mut counter)
            .is_some();
        let mut whole = Counter::new(usize::MAX);
        let whole_walked = parser.heap_bound(&mut whole).is_some();
        eprintln!(
            "R1A_VISITS responses={responses} chrome_tool_uses={} walked={walked} visits={} bytes={}",
            responses * CHROME.len(),
            counter.visits_for_test(),
            counter.bytes
        );
        eprintln!(
            "R1A_SHARED_VISIT_RESIDUAL responses={responses} walked={whole_walked} visits={}",
            whole.visits_for_test()
        );
        assert!(
            walked,
            "responses={responses}: the retained walk refused after {} visits",
            counter.visits_for_test()
        );
        visits.push(counter.visits_for_test());
    }
    assert_eq!(
        visits[0], visits[1],
        "per-step visits grow with history: {visits:?}"
    );
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

fn production_scan(
    file: &TempJsonl,
    index: ScanIndex,
    cache: Option<Arc<sampled_scan::SharedCache>>,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let source = SnapshotSource::ClaudeCode;
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(&file.root()),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope("r1a-production".into()));
    }
    let mut modes = (0, 0, 0);
    loop {
        if let Some(context) = scan.sampling.as_ref() {
            modes = (
                context.full_files,
                context.tail_files,
                context.unchanged_files,
            );
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    source,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(source, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan, modes);
            }
        }
    }
}

fn production_body(mut scan: SourceScanResult) -> Value {
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    serde_json::to_value(scan.snapshots).unwrap()
}

/// A 600-response realistic session retains its reader state, so the next
/// append tails, and the tailed output equals an independent full read. The
/// retained boundary falls inside response 600.
#[test]
fn claude_realistic_600_response_session_tails_with_full_read_parity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let file = TempJsonl::new("production-600");
    let mut rows = realistic_rows(0..600, &[SHELL]);
    let mut appended = realistic_rows(600..608, &[SHELL, CHROME[2]]);
    rows.extend(appended.drain(..2));
    file.append(&rows);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, modes) = production_scan(&file, ScanIndex::default(), Some(cache.clone()));
    assert_eq!(modes, (1, 0, 0));
    file.append(&appended);
    let (_, tail, modes) = production_scan(&file, index, Some(cache));
    let (_, full, _) = production_scan(&file, ScanIndex::default(), None);
    let tail = production_body(tail);
    let full = production_body(full);
    assert_eq!(tail, full);
    let item = &full[0];
    assert_eq!(item["request_count"], json!(608));
    assert!(
        item["session_display_name"].is_string(),
        "{}",
        item["session_display_name"]
    );
    assert!(item["session_start"].is_object());
    assert!(item["tool_usage"]
        .as_array()
        .is_some_and(|tools| tools.len() >= 2));
    let usage = item["model_usage"].as_array().expect("model usage");
    assert!(usage
        .iter()
        .any(|row| row["selector_context"].get("context_bucket").is_some()));
    assert!(usage
        .iter()
        .any(|row| row["selector_sources"].get("region_mode").is_some()));
    assert_eq!(modes, (0, 1, 0), "the 600-response session did not tail");
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

/// Review R1a-F1: identical accepted progressive observations amplify their
/// three selectors on decode even though resolve collapses to one occurrence.
fn progressive_rows(count: usize) -> Vec<Value> {
    let mut row = realistic_turn(0, &[])[2].clone();
    row["requestId"] = json!("req_1");
    row["message"]["id"] = json!("msg_1");
    row["message"]["usage"]["inference_geo"] = json!("us");
    vec![row; count]
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
fn claude_near_cap_decode_is_reserved_before_retention_without_changing_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const STATE: usize = 32_505_856;
    let rows = progressive_rows(MAX_CLAUDE_RECORDS_PER_RESPONSE);
    let parser = parser_for(&rows);
    assert_eq!(
        parser.claude_response_record_count,
        MAX_CLAUDE_RECORDS_PER_RESPONSE
    );
    assert_eq!(parser.dropped_usage_record_count, 0);
    let compact = charge(&parser).unwrap();
    let extra = parser
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    let baseline = decoded_baseline_charge(parser.claude_responses.clone());
    assert!(
        extra > STATE,
        "must exercise the review's over-budget decode"
    );
    assert!(
        extra >= baseline,
        "real decoded record layout must be covered"
    );
    assert!(parser.claude_responses.finish_copy_budget(STATE).is_none());
    assert!(parser
        .claude_responses
        .finish_copy_budget(extra - 1)
        .is_none());
    assert_eq!(parser.claude_responses.finish_copy_budget(extra), Some(0));
    // The layout preflight itself must never allocate a decoded record.
    let (preflight, allocation) = crate::retry_allocation_probe::measure(|| {
        parser.claude_responses.decode_peak_bound(usize::MAX)
    });
    assert_eq!(preflight, Some(extra));
    assert_eq!(allocation.allocations, 0);
    drop(parser);

    let fixture = TempJsonl::new("near-cap-finish");
    fixture.append(&rows);
    // Entire parser/finish lifetime is born inside this probe, so dropping the
    // compact input cannot offset an unobserved pre-existing allocation.
    let ((parsed, before_finish), actual) = crate::retry_allocation_probe::measure(|| {
        let (mut native, expected) = native_parser(&fixture.path);
        while !native.step().unwrap() {}
        let before = crate::retry_allocation_probe::stats().requested_peak_with_overlap;
        let scope = Scope("r1a-near-cap".into());
        // A zero preflight budget declines reuse, never native usage/output.
        assert!(native
            .retain_reduction(
                &scope,
                1,
                sampled_scan::RetainBudget::granted_unclassified(0)
            )
            .unwrap()
            .is_none());
        let parsed = native
            .finish(
                &expected,
                &fixture.path,
                NOW,
                "near-cap".into(),
                None,
                None,
                None,
            )
            .unwrap();
        (parsed, before)
    });
    assert_eq!(parsed.dropped_usage_record_count, 0);
    assert_eq!(parsed.recognized_usage_drop_count, 0);
    assert_eq!(parsed.snapshots.len(), 1);
    assert!(
        actual.requested_peak_with_overlap > before_finish,
        "probe must observe decoding/finish, not just parser construction"
    );
    let output = crate::heap_layout_bound::completed_bound(&parsed, usize::MAX).unwrap();
    assert!(compact + extra + output >= actual.requested_peak_with_overlap);
    eprintln!("R1A_NEAR_CAP records={} compact={compact} decoded_baseline={baseline} decode_extra={extra} pre_finish_peak={before_finish} finish_peak={} output={output} retention=false",
        rows.len(), actual.requested_peak_with_overlap);
    // Exercise the production budget hook, not just the arithmetic helper.
    // The tiny resolved output must not admit a copy whose decode peak failed.
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(&fixture, ScanIndex::default(), Some(cache.clone()));
    fixture.append(&[
        json!({"type": "summary", "sessionId": SESSION, "summary": "Near-cap response"}),
    ]);
    let (_, sampled, modes) = production_scan(&fixture, index, Some(cache));
    let (_, full, _) = production_scan(&fixture, ScanIndex::default(), None);
    assert_eq!(
        modes,
        (1, 0, 0),
        "over-budget decode must decline retention before finish"
    );
    assert_eq!(production_body(sampled), production_body(full));
}

#[test]
fn claude_decode_preflight_reserves_only_the_largest_response() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let rows = progressive_rows(128);
    let mut parser = parser_for(&rows);
    let first = parser
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    for mut row in rows {
        row["requestId"] = json!("req_2");
        row["message"]["id"] = json!("msg_2");
        apply_claude_code_line(&row, &mut parser);
    }
    assert_eq!(parser.claude_responses.values().count(), 2);
    assert_eq!(
        parser.claude_responses.decode_peak_bound(usize::MAX),
        Some(first)
    );
    let budget = 4 * first;
    assert_eq!(
        parser.claude_responses.finish_copy_budget(budget),
        Some(3 * first)
    );
    // Residents+active were subtracted before this budget was split. The
    // retained copy, already-finalized output and decode peak coexist here.
    assert!(2 * (budget - first) + first <= 2 * budget);
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

#[test]
fn claude_decode_bound_covers_inline_selectors_explicit_slots_and_tools() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut selectors = ClaudeSelectorTable::default();
    let mut records = crate::owned_heap::OwnedVec::new();
    let mut expected = Vec::new();
    for index in 0..80u16 {
        let model = Some(MODEL.to_string());
        let effort = Some("high".to_string());
        let request_id = Some("req_bound".to_string());
        let timestamp = Some(at(1, u64::from(index)));
        let slot = RequestSlot {
            request_ref: if index % 2 == 0 {
                "req_bound"
            } else {
                "explicit"
            }
            .into(),
            occurred_at: timestamp.clone().unwrap(),
            model: model.clone(),
            effort: effort.clone(),
            prompt_tokens: Some(4),
            cache_read_tokens: None,
            cache_creation_tokens: None,
            uncached_tokens: None,
            output_tokens: Some(6),
        };
        let selector = selector(&[("region_mode", &format!("region-{index}"), "region")]);
        let tools = (0..index % 12)
            .map(|tool| (format!("tool-{tool}"), "Bash".into()))
            .collect::<BTreeMap<String, String>>();
        let usage = UsageTotals::default();
        expected.push(ClaudeResponseRecord {
            cache_slot: slot.clone(),
            physical_sequence: u64::from(index),
            usage: usage.clone(),
            model: model.clone(),
            selector: selector.clone(),
            reasoning_effort: effort.clone(),
            request_id: request_id.clone(),
            timestamp: timestamp.clone(),
            computed_effective_input_context: None,
            tool_uses: tools.clone(),
        });
        records.push(CompactClaudeResponseRecord::encode(
            records.first(),
            index,
            usage,
            model,
            selectors.intern(selector),
            effort,
            request_id,
            timestamp,
            None,
            tools,
            slot,
        ));
    }
    let bound =
        claude_response_records::decoded_response_peak_bound(&records, &selectors, usize::MAX)
            .unwrap();
    let real_layout = crate::heap_layout_bound::completed_bound(&expected, usize::MAX).unwrap();
    assert!(bound >= real_layout);
    let (decoded, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
        claude_response_records::decode_records(records.into_vec(), &selectors).unwrap()
    });
    assert_eq!(decoded, expected);
    assert!(bound >= allocation.requested_peak_with_overlap);
}

#[test]
fn claude_hourly_capability_buckets_remain_a_shared_visit_limit_residual() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut parser = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let start = OffsetDateTime::parse(NOW, &Rfc3339).unwrap();
    for index in 0..2000 {
        let timestamp = (start + time::Duration::hours(index as i64))
            .format(&Rfc3339)
            .unwrap();
        for mut row in realistic_turn(index, &[CHROME[0]]) {
            row["timestamp"] = json!(timestamp);
            apply_claude_code_line(&row, &mut parser);
        }
    }
    assert_eq!(parser.seen_claude_capability_tool_uses.len(), 2000);
    assert_eq!(parser.activity_capability_buckets.len(), 2000);
    assert!(charge(&parser.seen_claude_capability_tool_uses).is_some());
    let mut whole = Counter::new(usize::MAX);
    assert!(parser.heap_bound(&mut whole).is_none());
    eprintln!(
        "R1A_SHARED_VISIT_RESIDUAL hourly_tool_uses=2000 buckets=2000 walked=false visits={}",
        whole.visits_for_test()
    );
}

// #665 X_out (R1a R8; hunk map T1, T3-T6). Receipts: `X_OUT_T3`, `X_OUT_T1`.

/// `progressive_rows`, as its own response (request and message ids `tag`).
fn progressive_response(count: usize, tag: &str) -> Vec<Value> {
    progressive_rows(count)
        .into_iter()
        .map(|mut row| {
            row["requestId"] = json!(format!("req_{tag}"));
            row["message"]["id"] = json!(format!("msg_{tag}"));
            row
        })
        .collect()
}

/// T3's limits around a peak: unlimited, exact, one short, half, tiny.
fn t3_limits(peak: usize) -> Vec<usize> {
    let mut limits = vec![usize::MAX, peak, peak / 2, 1, 0];
    limits.extend(peak.checked_sub(1));
    limits.extend(peak.checked_add(1));
    limits
}

/// The 80 raw records of `claude_decode_bound_covers_inline_selectors_explicit_slots_and_tools`.
fn raw_records_80() -> (
    crate::owned_heap::OwnedVec<CompactClaudeResponseRecord>,
    ClaudeSelectorTable,
) {
    let mut selectors = ClaudeSelectorTable::default();
    let mut records = crate::owned_heap::OwnedVec::new();
    for index in 0..80u16 {
        let model = Some(MODEL.to_string());
        let effort = Some("high".to_string());
        let timestamp = Some(at(1, u64::from(index)));
        let slot = RequestSlot {
            request_ref: if index % 2 == 0 {
                "req_bound"
            } else {
                "explicit"
            }
            .into(),
            occurred_at: timestamp.clone().unwrap(),
            model: model.clone(),
            effort: effort.clone(),
            prompt_tokens: Some(4),
            cache_read_tokens: None,
            cache_creation_tokens: None,
            uncached_tokens: None,
            output_tokens: Some(6),
        };
        let selector = selector(&[("region_mode", &format!("region-{index}"), "region")]);
        let tools = (0..index % 12)
            .map(|tool| (format!("tool-{tool}"), "Bash".into()))
            .collect::<BTreeMap<String, String>>();
        records.push(CompactClaudeResponseRecord::encode(
            records.first(),
            index,
            UsageTotals::default(),
            model,
            selectors.intern(selector),
            effort,
            Some("req_bound".to_string()),
            timestamp,
            None,
            tools,
            slot,
        ));
    }
    (records, selectors)
}

/// R1a R8 (a), (b), T3: on #667's fixtures, `decode_peak_bound`,
/// `completion_bounds(..).peak`, `finish_copy_budget` and
/// `decoded_response_peak_bound` equal main's (`main_reference`, verbatim
/// `bc77deb9`) at every limit, `None` included; off a supported layout both
/// are the same `None`.
#[test]
fn x_out_t3_decode_peak_and_copy_budget_match_main() {
    use super::claude_response_records::main_reference;
    let mut two = parser_for(&progressive_rows(128));
    for row in progressive_response(128, "2") {
        apply_claude_code_line(&row, &mut two);
    }
    let books = [
        (
            "progressive_128",
            parser_for(&progressive_rows(128)).claude_responses,
        ),
        (
            "progressive_cap",
            parser_for(&progressive_rows(MAX_CLAUDE_RECORDS_PER_RESPONSE)).claude_responses,
        ),
        ("two_progressive_128", two.claude_responses),
        (
            "realistic_120",
            parser_for(&realistic_rows(0..120, &[SHELL, CHROME[0]])).claude_responses,
        ),
        ("title_only", parser_for(&title_rows()).claude_responses),
    ];
    for (label, book) in &books {
        let reference = main_reference::decode_peak_bound(book, usize::MAX);
        if !crate::heap_layout_bound::layout_supported() {
            assert_eq!(book.decode_peak_bound(usize::MAX), reference, "{label}");
            assert_eq!(
                book.completion_bounds(usize::MAX).map(|bounds| bounds.peak),
                reference,
                "{label}"
            );
            eprintln!("X_OUT_T3 fixture={label} layout_supported=false peak={reference:?}");
            continue;
        }
        let peak = reference.expect("main's peak at usize::MAX");
        let mut nones = 0usize;
        let limits = t3_limits(peak);
        for &limit in &limits {
            let expected = main_reference::decode_peak_bound(book, limit);
            nones += usize::from(expected.is_none());
            assert_eq!(
                book.decode_peak_bound(limit),
                expected,
                "{label} limit={limit}"
            );
            assert_eq!(
                book.completion_bounds(limit).map(|bounds| bounds.peak),
                expected,
                "{label} limit={limit}"
            );
        }
        for budget in
            limits
                .iter()
                .copied()
                .chain([2 * peak, 4 * peak, crate::transcript_cache::ENTRY_BYTES])
        {
            assert_eq!(
                book.finish_copy_budget(budget),
                main_reference::finish_copy_budget(book, budget),
                "{label} budget={budget}"
            );
        }
        if let Some(short) = peak.checked_sub(1) {
            assert_eq!(
                book.decode_peak_bound(short),
                None,
                "{label}: (b) at peak-1"
            );
        }
        let output = book
            .completion_bounds(usize::MAX)
            .and_then(|bounds| bounds.output);
        eprintln!(
            "X_OUT_T3 fixture={label} layout_supported=true peak={peak} limits={} none_limits={nones} output={output:?} parity=ok",
            limits.len()
        );
    }

    let (records, selectors) = raw_records_80();
    let reference = main_reference::decoded_response_peak_bound(&records, &selectors, usize::MAX);
    if let Some(peak) = reference {
        for limit in t3_limits(peak) {
            assert_eq!(
                claude_response_records::decoded_response_peak_bound(&records, &selectors, limit),
                main_reference::decoded_response_peak_bound(&records, &selectors, limit),
                "raw_80 limit={limit}"
            );
        }
    }
    eprintln!("X_OUT_T3 fixture=raw_records_80 peak={reference:?} parity=ok");
}

/// R1a R8 (c): an output term past the limit while the peak fits is
/// `Some(peak)` with `output: None`; the peak never moves.
#[test]
fn x_out_t3_output_past_the_limit_keeps_the_peak() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let book = parser_for(&realistic_rows(0..120, &[SHELL, CHROME[0]])).claude_responses;
    let full = book.completion_bounds(usize::MAX).unwrap();
    let output = full.output.expect("output at usize::MAX");
    assert!(
        output > full.peak,
        "precondition: output {output} > peak {}",
        full.peak
    );
    for limit in [full.peak, output - 1] {
        assert_eq!(
            book.completion_bounds(limit),
            Some(claude_response_records::CompletionBounds {
                peak: full.peak,
                output: None,
                fold: None,
            }),
            "limit={limit}"
        );
    }
    assert_eq!(book.completion_bounds(output), Some(full));
    eprintln!(
        "X_OUT_T3 case=c peak={} output={output} output_none_from={} parity=ok",
        full.peak, full.peak
    );
}

/// R1a R8 (d): a `record_limit_exceeded` response leaves main's peak and adds
/// nothing to the output term.
#[test]
fn x_out_t3_record_limit_exceeded_response_adds_no_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use super::claude_response_records::main_reference;
    let base = realistic_rows(0..8, &[SHELL]);
    let without = parser_for(&base).claude_responses;
    let mut rows = base;
    rows.extend(progressive_response(
        MAX_CLAUDE_RECORDS_PER_RESPONSE + 1,
        "over",
    ));
    let with = parser_for(&rows).claude_responses;
    assert_eq!(
        with.values()
            .filter(|response| response.record_limit_exceeded)
            .count(),
        1
    );
    let before = without.completion_bounds(usize::MAX).unwrap();
    let after = with.completion_bounds(usize::MAX).unwrap();
    assert_eq!(
        Some(after.peak),
        main_reference::decode_peak_bound(&with, usize::MAX)
    );
    assert_eq!(after.peak, before.peak);
    assert_eq!(after.output, before.output);
    assert!(after.output.is_some());
    eprintln!(
        "X_OUT_T3 case=d peak={} output={:?} parity=ok",
        after.peak, after.output
    );
}

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

/// For each assistant row of `rows`, `edit(row_index, row)`.
fn edit_assistant(mut rows: Vec<Value>, mut edit: impl FnMut(usize, &mut Value)) -> Vec<Value> {
    for (index, row) in rows.iter_mut().enumerate() {
        if row["type"] == "assistant" {
            edit(index, row);
        }
    }
    rows
}

/// A value's completed heap, without its inline slot (T5 compares fields
/// whose containers differ: `OwnedVec` before the move, `Vec` after).
fn completed_heap_only<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    crate::heap_layout_bound::completed_bound(value, usize::MAX)?
        .checked_sub(std::mem::size_of_val(value))
}

fn x_out_input<'a>(
    path: &'a Path,
    title: &'a ClaudeTitleMetadata,
    identity: Option<&'a crate::context_footprint::RepositoryIdentity>,
) -> FinishOutputInput<'a> {
    FinishOutputInput {
        path,
        collected_at: NOW,
        source_file_fingerprint: "x-out-fixture",
        opened_object_identity: "x-out-identity",
        title_metadata: Some(title),
        attribution: false,
        repository_identity: identity,
    }
}

/// For the `position`-th assistant row of `rows` (its response record),
/// `edit(position, row)`.
fn edit_records(mut rows: Vec<Value>, mut edit: impl FnMut(usize, &mut Value)) -> Vec<Value> {
    let mut position = 0;
    for row in &mut rows {
        if row["type"] == "assistant" {
            edit(position, row);
            position += 1;
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
    /// Finish with a launches-prepared attribution context (X_out's K facts
    /// and U2's path hash), as the scan does, instead of none.
    attribution: bool,
    /// Runs on the read accumulator before X_out is taken: rows that exist
    /// before `finish` (N1). Family R then bounds only part of the item.
    prepare: Option<&'a dyn Fn(&mut SnapshotAccumulator)>,
}

/// What one T1 case measured.
struct FinishReceipt {
    x_out: usize,
    decode_peak: usize,
    born: usize,
    /// The largest `snapshot_fingerprint` transient of a finished item, one
    /// item at a time (N1: its semantic JSON has no X_out term of its own).
    fingerprint_peak: usize,
    /// Gate on: the kept fold's completed heap and X_out's E term.
    fold: Option<(usize, usize)>,
}

/// A launch root with one launch event for `SESSION` in `fixture`'s home, as
/// `retain_release_tests::LaunchHome` builds it, and a context that has
/// prepared it.
fn launch_context(fixture: &TempJsonl) -> crate::session_attribution::SessionAttributionContext {
    use base64::Engine;
    let home = fixture.dir.join("home");
    let raw = json!({"schema":"agent_launch.v1",
        "controller_session_ref":"a9789dcf-1e4a-4a6e-8abd-f30094efb269",
        "worker_session_ref":SESSION, "relationship_kind":"launched",
        "workflow_ref":null, "pr_ref":null, "launch_ts":"2026-09-20T10:00:00Z",
        "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"})
    .to_string();
    let reduced = crate::launch_events::validate_event(&raw).unwrap();
    let events = home.join(".ottto/launch-events/processed");
    fs::create_dir_all(&events).unwrap();
    fs::write(
        events.join(format!(
            "{}.json",
            crate::launch_events::event_digest(&reduced)
        )),
        raw,
    )
    .unwrap();
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32]);
    let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
        SnapshotSource::ClaudeCode,
        &home,
        true,
        Some(&key),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap();
    while !context.prepare_launch_step(&[SESSION.to_owned()]).unwrap() {}
    assert!(context.launches_prepared(&[SESSION.to_owned()]));
    context
}

/// T1, T4, T5, T6 for one file: read it natively, take X_out exactly as the
/// proof site does (warm U3 identity), then finish inside a born-pointer
/// allocation audit. Returns the finished items.
fn assert_x_out_covers_finish(
    label: &str,
    rows: &[Value],
    title: &ClaudeTitleMetadata,
) -> Vec<SnapshotItem> {
    assert_x_out_covers_finish_with(label, rows, title, FinishCase::default()).0
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
    let attribution = case.attribution.then(|| launch_context(&fixture));
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
                attribution: attribution.is_some(),
                repository_identity: identity.as_ref(),
            },
            usize::MAX,
        )
        .unwrap_or_else(|| panic!("{label}: X_out refused"));
    let money = claude_request_money::e2::enabled().then(|| {
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
                attribution.as_ref(),
                identity,
                None,
            )
            .unwrap()
    });
    let output = crate::heap_layout_bound::completed_bound(&parsed, usize::MAX).unwrap();
    let born = actual.requested_peak_with_overlap;
    let fingerprint_peak = parsed
        .snapshots
        .iter()
        .map(|item| {
            crate::retry_allocation_probe::measure_caller_thread(|| {
                snapshot_fingerprint(SnapshotSource::ClaudeCode, item)
            })
            .1
            .requested_peak_with_overlap
        })
        .max()
        .unwrap_or(0);
    eprintln!(
        "X_OUT_T1 case={label} responses={responses} items={} x_out={x_out} output={output} decode_peak={peak} born_finish_peak={born} output_slack={} peak_slack={} born_ratio={:.4} fingerprint_peak={fingerprint_peak} attribution={}",
        parsed.snapshots.len(),
        x_out - output.min(x_out),
        (x_out + peak) - born.min(x_out + peak),
        born as f64 / (x_out + peak) as f64,
        attribution.is_some(),
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
            fingerprint_peak,
            fold,
        },
    )
}

/// T1 (adversarial sweep, R1a R8 union cases), with T4-T6 per case.
#[test]
fn x_out_t1_bounds_the_finished_claude_file() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let none = ClaudeTitleMetadata::default();
    let case = |label: &str, rows: Vec<Value>| {
        assert_x_out_covers_finish(
            label,
            &with_cwd(rows, &format!("/work/x-out-{label}")),
            &none,
        )
    };
    case("responses-0", title_rows());
    for count in [1, 2, 3, 7, 8, 9] {
        case(
            &format!("responses-{count}"),
            realistic_rows(0..count, &[SHELL, CHROME[0]]),
        );
    }
    // R1a R8 union cases: one multi-record response (thinking, text, one
    // record per tool) whose records differ in (i) selectors, (ii) tool uses,
    // (iii) whether they carry `model` (the third record is the first to);
    // then all three at once beside a second response. Selectors differ by
    // key per record, never by one key's value: a conflicting value fails the
    // whole response (`merge_claude_response_selector`), which finishes
    // nothing.
    const UNION_TOOLS: [&str; 4] = [SHELL, CHROME[0], CHROME[1], CHROME[2]];
    let distinct_selectors = |position: usize, row: &mut Value| {
        let usage = row["message"]["usage"].as_object_mut().unwrap();
        usage.remove("service_tier");
        usage.remove("speed");
        let (key, value) = [
            ("service_tier", "standard"),
            ("speed", "standard"),
            ("inference_geo", "us"),
        ][position % 3];
        usage.insert(key.to_string(), json!(value));
    };
    let late_model = |position: usize, row: &mut Value| {
        if position < 2 {
            row["message"].as_object_mut().unwrap().remove("model");
        }
    };
    let mut union_all = edit_records(realistic_turn(0, &UNION_TOOLS), |position, row| {
        distinct_selectors(position, row);
        late_model(position, row);
    });
    union_all.extend(realistic_turn(1, &[SHELL]));
    for (label, rows, responses) in [
        (
            "union-selectors",
            edit_records(realistic_turn(0, &UNION_TOOLS), distinct_selectors),
            1,
        ),
        ("union-tools", realistic_turn(0, &UNION_TOOLS), 1),
        (
            "union-late-model",
            edit_records(realistic_turn(0, &UNION_TOOLS), late_model),
            1,
        ),
        ("union-all", union_all, 2),
    ] {
        let items = case(label, rows);
        let [item] = items.as_slice() else {
            panic!(
                "{label}: {} items, the union must finish into one",
                items.len()
            );
        };
        assert_eq!(
            item.claude_usage_request_ids.len(),
            responses,
            "{label}: every response resolved"
        );
        assert!(
            !item.model_usage.is_empty() && item.model_usage.iter().all(|row| row.model == MODEL),
            "{label}: rows take the late model"
        );
    }
    let tools: Vec<String> = (0..201)
        .map(|tool| format!("mcp__x-out__tool_{tool:03}"))
        .collect();
    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    case("tools-201", realistic_rows(0..2, &tools));
    let first_request = format!("req_011CU{:019}", 0);
    case(
        "duplicate-request-ids",
        edit_assistant(realistic_rows(0..3, &[SHELL]), |_, row| {
            row["requestId"] = json!(first_request);
        }),
    );
    case(
        "missing-request-id",
        // The second turn's rows (title rows, then four rows per turn).
        edit_assistant(realistic_rows(0..3, &[SHELL]), |index, row| {
            if (7..10).contains(&index) {
                row.as_object_mut().unwrap().remove("requestId");
            }
        }),
    );
    let models = [
        "c".to_string(),
        "m".repeat(23),
        "m".repeat(24),
        "m".repeat(64),
        "m".repeat(300),
    ];
    let mut rows = Vec::new();
    for (index, model) in models.iter().enumerate() {
        rows.extend(edit_assistant(realistic_turn(index, &[SHELL]), |_, row| {
            row["message"]["model"] = json!(model);
        }));
    }
    case("model-lengths", rows);
    let mut rows = Vec::new();
    for index in 0..70 {
        rows.extend(edit_assistant(realistic_turn(index, &[SHELL]), |_, row| {
            row["message"]["usage"]["inference_geo"] = json!(format!("geo-{index:03}"));
        }));
    }
    case("selectors-70", rows);
    let mut rows = realistic_rows(0..3, &[SHELL]);
    rows.push(
        json!({"type":"system", "subtype":"compact_boundary", "sessionId": SESSION,
        "timestamp": at(100, 0), "uuid": "x-out-boundary", "parentUuid": null,
        "cwd": "/work/r1a-fixture",
        "compactMetadata": {"trigger": "auto", "preTokens": 900000, "postTokens": 4000}}),
    );
    rows.extend(realistic_rows(3..5, &[SHELL]));
    case("compaction", rows);

    let mut titled = ClaudeTitleMetadata::default();
    titled.titles.insert(
        SESSION.to_string(),
        ClaudeTitleCandidate {
            title: format!("  {}  ", "a desktop title ".repeat(12)),
            user_set: true,
        },
    );
    assert_x_out_covers_finish(
        "title",
        &with_cwd(realistic_rows(0..3, &[SHELL]), "/work/x-out-title"),
        &titled,
    );
}

/// Dark output admission must cover sparse hours and alternating copied/own
/// sequence runs, including idless copies and the restoration peak when no
/// census can prove their owner. Audit actual allocations, not a substitute
/// bound or a larger cache budget.
#[test]
fn x_out_dark_covers_sparse_hours_and_copy_restoration() {
    // Dark (gate-off) output bound by design: the test asserts !e2::enabled().
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    assert!(!claude_request_money::e2::enabled());
    let birth = rfc3339_unix_nanos(NOW).unwrap();
    let rows = edit_assistant(realistic_rows(0..128, &[SHELL]), |_, row| {
        let request = row["requestId"].as_str().unwrap();
        let ordinal = request[request.len() - 19..].parse::<i64>().unwrap();
        let offset = if ordinal % 2 == 0 {
            -(ordinal + 1) * 3600
        } else {
            ordinal * 3600
        };
        row["timestamp"] = json!(time::OffsetDateTime::from_unix_timestamp_nanos(
            birth + i128::from(offset) * 1_000_000_000
        )
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap());
        if ordinal % 4 == 0 {
            row.as_object_mut().unwrap().remove("requestId");
        }
    });
    let prepare = |accumulator: &mut SnapshotAccumulator| {
        accumulator.claude_file_birth.set_birth_for_test(birth);
    };
    let (items, _) = assert_x_out_covers_finish_with(
        "dark-sparse-copy-restore",
        &with_cwd(rows, "/work/x-out-dark-sparse-copy-restore"),
        &ClaudeTitleMetadata::default(),
        FinishCase {
            prepare: Some(&prepare),
            ..FinishCase::default()
        },
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].request_count, 128);
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
    let _gate = claude_request_money::e2::GateForTest::set(true);
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
            FinishCase {
                prepare,
                ..FinishCase::default()
            },
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
        // Exactly the copies came back through `absorb_grains`, disclosed.
        assert_eq!(
            diag.get("copy_unproven").copied().unwrap_or(0),
            restored as u64,
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

/// X_out U3 and U1 controls (c22 amendment 2): a workspace whose identity is
/// not warm in the cache, or a subagent transcript, has no X_out, so the
/// proof releases nothing; the same file with a warm identity has one.
#[test]
fn x_out_refuses_a_cold_workspace_and_a_subagent() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let workspace = "/work/x-out-cold-workspace";
    let accumulator = parser_for(&with_cwd(realistic_rows(0..3, &[SHELL]), workspace));
    assert_eq!(peek_repository_identity(Path::new(workspace)), None);
    let path = PathBuf::from(format!("/p/{SESSION}.jsonl"));
    let title = ClaudeTitleMetadata::default();
    let identity = x_out_identity("cold-control");
    assert_eq!(
        accumulator.finish_output_bound(x_out_input(&path, &title, None), usize::MAX),
        None
    );
    assert!(accumulator
        .finish_output_bound(x_out_input(&path, &title, Some(&identity)), usize::MAX)
        .is_some());
    let subagent = PathBuf::from("/p/x-out-parent/subagents/agent-x-out.jsonl");
    assert_eq!(
        accumulator
            .finish_output_bound(x_out_input(&subagent, &title, Some(&identity)), usize::MAX),
        None
    );
}

/// fresh-r1 N3: the composed T1/T6 check with a launches-prepared
/// attribution context (X_out's K facts, U2's path hash) and title metadata
/// carrying an account hash and original identity evidence (U1's per-row
/// hash, evidence strings and sets).
#[test]
fn x_out_t1_bounds_a_finish_with_attribution_and_identity_evidence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let account = "a".repeat(64);
    let mut title = ClaudeTitleMetadata::default();
    title.titles.insert(
        SESSION.to_string(),
        ClaudeTitleCandidate {
            title: "an attributed desktop title".to_string(),
            user_set: true,
        },
    );
    title
        .account_identifier_hashes
        .insert(SESSION.to_string(), BTreeSet::from([account.clone()]));
    title.original_identity_evidence.insert(
        SESSION.to_string(),
        BTreeSet::from([
            ClaudeDesktopIdentityEvidence {
                account_identifier_hash: Some(account.clone()),
                provider_workspace_hash: Some("w".repeat(64)),
                source_created_at: Some("2026-09-20T09:59:00.000Z".to_string()),
                imported: false,
            },
            ClaudeDesktopIdentityEvidence {
                account_identifier_hash: Some("b".repeat(64)),
                provider_workspace_hash: None,
                source_created_at: Some("2026-09-21T10:00:00.000Z".to_string()),
                imported: true,
            },
        ]),
    );
    let (items, receipt) = assert_x_out_covers_finish_with(
        "attributed",
        &with_cwd(realistic_rows(0..3, &[SHELL]), "/work/x-out-attributed"),
        &title,
        FinishCase {
            attribution: true,
            prepare: None,
        },
    );
    let [item] = items.as_slice() else {
        panic!("attributed: {} items", items.len());
    };
    let launched = item
        .attribution_facts
        .iter()
        .any(|fact| fact.evidence.kind == "launcher_event");
    let hashed = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
        .filter(|row| row.account_identifier_hash.as_deref() == Some(account.as_str()))
        .count();
    eprintln!(
        "X_OUT_N3 facts={} launcher_fact={launched} account_hashed_rows={hashed} session_account_evidence={} x_out={} decode_peak={} born={}",
        item.attribution_facts.len(),
        item.session_account_evidence.is_some(),
        receipt.x_out,
        receipt.decode_peak,
        receipt.born,
    );
    assert!(launched, "precondition: the launch context applied");
    assert!(hashed >= 1, "precondition: rows carry the account hash");
    assert!(
        item.session_account_evidence.is_some(),
        "precondition: the identity evidence applied"
    );
}

/// fresh-r1 N1: `finish`'s semantic JSON (`snapshot_fingerprint`) has no
/// X_out term of its own; the per-row node charge covers it
/// (`finish_output_bound`'s doc). The fact-limit scratch is charged by
/// `fact_limit_scratch_bound` (r33). A few hundred tiny rows
/// that exist before `finish` (one model each, so each is its own row; the
/// rows' smallest per-row charge), with the attribution context on: every
/// allocation born in `finish` is within X_out plus the decode peak (T6),
/// and the fingerprint's transient is within five whole
/// `(RowKey, BucketRowAccumulator)` nodes per usage row. Claude has no file
/// rows of its own before `finish` (every usage record waits in the
/// response book), so the rows are added as `add_usage_with_selector` adds
/// any row.
#[test]
fn x_out_t6_covers_tiny_file_rows_with_attribution() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const TINY_ROWS: usize = 300;
    let prepare = |accumulator: &mut SnapshotAccumulator| {
        for row in 0..TINY_ROWS {
            accumulator.add_usage_with_selector(
                Some(format!("m{row:03}")),
                UsageTotals {
                    input_tokens: 1,
                    output_tokens: 1,
                    request_count: 1,
                    ..UsageTotals::default()
                },
                SelectorCapture::default(),
                Some(&at(row as u64, 0)),
                None,
            );
        }
    };
    let (items, receipt) = assert_x_out_covers_finish_with(
        "tiny-file-rows",
        &with_cwd(realistic_rows(0..1, &[SHELL]), "/work/x-out-tiny-file-rows"),
        &ClaudeTitleMetadata::default(),
        FinishCase {
            attribution: true,
            prepare: Some(&prepare),
        },
    );
    let [item] = items.as_slice() else {
        panic!("tiny-file-rows: {} items", items.len());
    };
    let usage_rows = item.model_usage.len();
    let bucket_rows: usize = item
        .usage_buckets
        .iter()
        .map(|bucket| bucket.model_usage.len())
        .sum();
    let node = crate::heap_layout_bound::tree_node_bytes::<RowKey, BucketRowAccumulator>().unwrap();
    eprintln!(
        "X_OUT_N1 tiny_rows={TINY_ROWS} usage_rows={usage_rows} bucket_rows={bucket_rows} facts={} node={node} fingerprint_peak={} fingerprint_per_row={} five_nodes={} born={} x_out={} decode_peak={} born_ratio={:.4}",
        item.attribution_facts.len(),
        receipt.fingerprint_peak,
        receipt.fingerprint_peak / usage_rows.max(1),
        5 * node,
        receipt.born,
        receipt.x_out,
        receipt.decode_peak,
        receipt.born as f64 / (receipt.x_out + receipt.decode_peak) as f64,
    );
    assert!(
        usage_rows > TINY_ROWS,
        "precondition: every tiny row is its own row"
    );
    assert!(
        receipt.fingerprint_peak <= usage_rows * 5 * node,
        "N1: fingerprint transient {} > {usage_rows} rows x 5 nodes of {node} B",
        receipt.fingerprint_peak
    );
}

/// #665 r33 (c22: no residual may rely on slack). `fact_limit_scratch_bound`
/// covers `enforce_fact_limits` at its adversarial maximum, measured on the
/// function itself: 96 facts (four producers at the 24-fact cap), every text
/// at its cap and made of control characters, so each byte escapes to six.
/// No transcript fixture produces facts like these; the end-to-end T6 rows
/// (`x_out_t6_covers_tiny_file_rows_with_attribution`, T1 attributed) cover
/// the term inside `finish_output_bound`.
#[test]
fn x_out_fact_limit_scratch_covers_adversarial_facts() {
    use crate::session_attribution::{
        SessionAttributionFact, SessionFieldEvidence, MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES,
        MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES,
        MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES, MAX_SESSION_ATTRIBUTION_FACTS,
        MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES, MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let text = |len: usize| "\u{1}".repeat(len);
    let fact = || SessionAttributionFact {
        field: text(FACT_LITERAL_BYTES),
        value: text(MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES),
        display_label: Some(text(MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES)),
        display_label_source: Some(text(MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES)),
        evidence: SessionFieldEvidence {
            kind: text(FACT_LITERAL_BYTES),
            strength: text(FACT_LITERAL_BYTES),
            observed_at: text(NOW.len()),
            source_version: text(MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES),
            evidence_ref: text(MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES),
        },
    };
    let per_fact = 3 * FACT_LITERAL_BYTES
        + MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES
        + MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES
        + MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES
        + MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES
        + MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES
        + NOW.len();
    let count = 4 * MAX_SESSION_ATTRIBUTION_FACTS;
    let mut facts: Vec<SessionAttributionFact> = (0..count).map(|_| fact()).collect();
    let bound = fact_limit_scratch_bound(4, NOW.len()).unwrap();
    let pre_trim = count * per_fact;

    // One `to_vec` buffer at the count cap: maximal escaping, and the
    // doubling the term derives (its last buffer is exactly `128 * 2^k`).
    let buffer = serde_json::to_vec(&facts[..MAX_SESSION_ATTRIBUTION_FACTS]).unwrap();
    let json_len = (6 * per_fact + FACT_JSON_SYNTAX_BYTES) * MAX_SESSION_ATTRIBUTION_FACTS + 2;
    let last = json_len.div_ceil(128).next_power_of_two() * 128;
    assert!(
        buffer.len() >= MAX_SESSION_ATTRIBUTION_FACTS * 6 * per_fact,
        "precondition: every text byte escapes to six ({} B)",
        buffer.len()
    );
    assert!(buffer.len() <= json_len, "syntax: {} B", buffer.len());
    assert_eq!(buffer.capacity(), last, "len {}", buffer.len());
    assert!(last + last / 2 <= bound - pre_trim);
    drop(buffer);

    let ((), scratch) = crate::retry_allocation_probe::measure_caller_thread(|| {
        crate::session_attribution::enforce_fact_limits(&mut facts)
    });
    let born = scratch.requested_peak_with_overlap;
    eprintln!(
        "X_OUT_FACTS facts={count} kept={} per_fact={per_fact} pre_trim={pre_trim} born_scratch={born} json_len={json_len} json_last={last} term={} term_off={} slack={}",
        facts.len(),
        bound,
        fact_limit_scratch_bound(2, NOW.len()).unwrap(),
        bound - (pre_trim + born).min(bound),
    );
    // Two escaped facts (about 7.5 KB) fit the 8,192-byte budget; three do not.
    assert_eq!(facts.len(), 2, "precondition: the budget loop popped 22");
    assert!(
        born >= last + last / 2,
        "precondition: the last growth's old and new buffers were measured"
    );
    assert!(
        pre_trim + born <= bound,
        "fact-limit scratch {pre_trim} + {born} > term {bound}"
    );
}

/// Zero-usage Claude rows (no positive usage evidence anywhere: an itemless
/// file): `responses[i]` content-block records of response `i`, all with
/// the response's request id.
fn itemless_rows(responses: &[usize]) -> Vec<Value> {
    let mut rows = Vec::new();
    for (index, &records) in responses.iter().enumerate() {
        for record in 0..records {
            let mut row = envelope(
                "assistant",
                format!("i{index:04}-{record:05}"),
                at(
                    60 * index as u64 + (record / 1000) as u64,
                    (record % 1000) as u64,
                ),
            );
            row["requestId"] = json!(format!("req_011CI{index:019}"));
            row["message"] = json!({
                "id": format!("msg_01ITM{index:019}"),
                "type": "message",
                "role": "assistant",
                "model": MODEL,
                "content": [{"type": "text", "text": "."}],
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            });
            rows.push(row);
        }
    }
    rows
}

/// #665 r35 (c22 ruling on F2): `buffered_request_hashes_bound` charges the
/// request-hash vector the caller builds for an itemless Claude file before
/// `finish` and keeps across it. The book holds a response of more than
/// 1,562 records (past R's per-response domination), one past
/// `MAX_CLAUDE_RECORDS_PER_RESPONSE` (R charges it nothing; its 4,096 stored
/// records still feed the vector) and fifty one-record responses. The
/// vector's measured peak is within the term, its capacity is the derived
/// `4 * 2^k`, and the vector plus `finish`, in production order, stay
/// within X_out plus the decode peak.
#[test]
fn x_out_charges_buffered_request_hashes_of_an_itemless_file() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const LONG: usize = 1_600;
    const OVER: usize = 4_200;
    const SHORT: usize = 50;
    let mut shape = vec![LONG, OVER];
    shape.extend(std::iter::repeat_n(1, SHORT));
    let fixture = TempJsonl::new("itemless-hashes");
    fixture.append(&with_cwd(
        itemless_rows(&shape),
        "/work/x-out-itemless-hashes",
    ));
    let (mut parser, expected) = native_parser(&fixture.path);
    while !parser.step().unwrap() {}
    assert!(
        !parser.positive_usage_evidence,
        "precondition: no positive usage evidence (itemless)"
    );
    let book = &parser.accumulator.claude_responses;
    let stored: usize = book.values().map(|response| response.records.len()).sum();
    let over: Vec<usize> = book
        .values()
        .filter(|response| response.record_limit_exceeded)
        .map(|response| response.records.len())
        .collect();
    let longest = book
        .values()
        .filter(|response| !response.record_limit_exceeded)
        .map(|response| response.records.len())
        .max()
        .unwrap_or(0);
    assert_eq!(over, vec![MAX_CLAUDE_RECORDS_PER_RESPONSE], "precondition");
    assert!(longest > 1_562, "precondition: longest {longest}");
    assert_eq!(stored, LONG + MAX_CLAUDE_RECORDS_PER_RESPONSE + SHORT);

    if let Some(workspace) = parser.accumulator.workspace_path.clone() {
        repository_identity_cache().lock().unwrap().insert(
            workspace,
            (SystemTime::now(), x_out_identity("itemless-hashes")),
        );
    }
    let identity = parser
        .accumulator
        .workspace_path
        .as_deref()
        .and_then(peek_repository_identity);
    let title = ClaudeTitleMetadata::default();
    let peak = parser
        .accumulator
        .claude_responses
        .decode_peak_bound(usize::MAX)
        .unwrap();
    let term = buffered_request_hashes_bound(stored).unwrap();
    let x_out = parser
        .finish_output_bound(
            FinishOutputInput {
                path: &fixture.path,
                collected_at: NOW,
                source_file_fingerprint: "x-out-fixture",
                opened_object_identity: &expected,
                title_metadata: Some(&title),
                attribution: false,
                repository_identity: identity.as_ref(),
            },
            usize::MAX,
        )
        .expect("X_out");

    // The vector alone, as the caller builds it.
    let (hashes, alone) = crate::retry_allocation_probe::measure_caller_thread(|| {
        super::claude_request_census::claude_buffered_request_hashes(&parser)
    });
    let last = stored.next_power_of_two().max(4);
    let distinct = hashes.len();
    assert_eq!(hashes.capacity(), last, "the derived doubling");
    let vector_peak = alone.requested_peak_with_overlap;
    drop(hashes);

    // Production order: the vector, then `finish` beside it.
    let ((hashes, parsed), actual) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let hashes = super::claude_request_census::claude_buffered_request_hashes(&parser);
        let parsed = parser
            .finish_with_repository_identity(
                &expected,
                &fixture.path,
                NOW,
                "x-out-fixture".into(),
                None,
                Some(&title),
                None,
                identity,
                None,
            )
            .unwrap();
        (hashes, parsed)
    });
    let born = actual.requested_peak_with_overlap;
    eprintln!(
        "X_OUT_HASHES stored={stored} longest={longest} limit_exceeded={} distinct={distinct} capacity={last} vector_peak={vector_peak} term={term} x_out={x_out} decode_peak={peak} born={born} items={} born_ratio={:.4}",
        over[0],
        parsed.snapshots.len(),
        born as f64 / (x_out + peak) as f64,
    );
    drop(hashes);
    assert!(
        vector_peak <= term,
        "request-hash vector {vector_peak} > term {term}"
    );
    assert!(
        vector_peak >= 8 * (last + last / 2),
        "precondition: the last growth's old and new buffers were measured"
    );
    assert!(
        born <= x_out + peak,
        "itemless: born {born} > x_out {x_out} + decode peak {peak}"
    );
}

/// #665 r36 (AutoReview P2, U1): `desktop_title_bound` covers a desktop
/// title's normalization scratch at adversarial lengths near the sidecar
/// file cap (`MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES`): one-byte words (the
/// most words a length allows), one unbroken word, and a short title that
/// reaches `is_safe_display_title`'s allocations. Measured on
/// `normalize_display_title` with its input clone, plus the item's clone of
/// the kept title; then end to end, born within X_out plus the decode peak.
#[test]
fn x_out_u1_charges_desktop_title_normalization() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let near_cap = MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES as usize - 4 * 1024;
    let cases = [
        ("spaced", "a ".repeat(near_cap / 2)),
        ("unbroken", "x".repeat(near_cap)),
        ("safe", "  Investigate   cache\tpolicy  drift  ".to_string()),
    ];
    for (label, title) in &cases {
        let bound = desktop_title_bound(title.len()).unwrap();
        let (kept, normalized) = crate::retry_allocation_probe::measure_caller_thread(|| {
            normalize_display_title(title.clone(), "desktop_title")
        });
        let kept_len = kept.as_ref().map_or(0, String::len);
        let peak = normalized.requested_peak_with_overlap;
        let words = title.split_whitespace().count();
        eprintln!(
            "X_OUT_U1 case={label} len={} words={words} kept={kept_len} normalize_peak={peak} item_clone={kept_len} term={bound} slack={}",
            title.len(),
            bound - (peak + kept_len).min(bound),
        );
        assert!(
            peak + kept_len <= bound,
            "{label}: normalization {peak} + clone {kept_len} > term {bound}"
        );
        match *label {
            "spaced" => {
                let last = words.next_power_of_two();
                assert!(
                    peak >= 16 * (last + last / 2),
                    "precondition: the words vector's last growth was measured"
                );
            }
            "safe" => assert_eq!(kept.as_deref(), Some("Investigate cache policy drift")),
            _ => assert!(kept.is_none(), "{label}: over 120 chars is not displayed"),
        }
    }
    for (label, title) in cases {
        let mut titled = ClaudeTitleMetadata::default();
        titled.titles.insert(
            SESSION.to_string(),
            ClaudeTitleCandidate {
                title,
                user_set: true,
            },
        );
        let label = format!("u1-{label}");
        assert_x_out_covers_finish(
            &label,
            &with_cwd(
                realistic_rows(0..3, &[SHELL]),
                &format!("/work/x-out-{label}"),
            ),
            &titled,
        );
    }
}
