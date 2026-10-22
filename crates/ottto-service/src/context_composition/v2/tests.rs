//! Tests for the new-lines reader.
//!
//! Parity: reading a transcript in any number of pieces (every line
//! boundary, partial last lines, a checkpoint round trip between pieces)
//! gives the same totals as one read, and one read gives the kinds_version 1
//! golden numbers. Runs: forward-only first run, restart, crash, rewrite,
//! archive moves, line guard, stable scope key, changed-days upload and bad
//! state.

use super::super::claude::parse_claude_session;
use super::super::codex::parse_codex_session;
use super::super::measure::extract_blocks_text_and_images;
use super::super::report::{DateWindow, WorkspaceReport};
use super::super::tests::{codex_sess, sess_a, sess_b, sess_c};
use super::aggregate::{
    all_kinds, day_of, kind_from_str, kind_position, part_from_str, part_position, Aggregate,
    Contribution, Day, Sink, Window, ALL_PARTS,
};
use super::checkpoint::{CopiedMode, Index, ParseState, StoredParse};
use super::decode::{claude_never_counted, codex_never_counted, content_chars_and_images, Raw};
use super::file::{new_parse_state, read_lines, LineSink, LineStats, Source};
use super::harvest::{begin_run, run_source, Run, SourceStats};
use super::ownership::Ownership;
use super::reader::{LineEvent, LineReader};
use super::scope::{load_scope, scope_path, ScopeInfo, ScopeResolver};
use super::upload::{UploadTarget, Uploader};
use super::*;
use crate::composition_kinds::Kind;
use crate::context_footprint::sha256_hex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::{Date, Month, OffsetDateTime};

// -------------------------------------------------------------------------
// Helpers.
// -------------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    crate::test_scratch::private_dir(name)
}

fn body(records: &[Value]) -> String {
    records.iter().map(|record| format!("{record}\n")).collect()
}

fn write_records(path: &Path, records: &[Value]) {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).unwrap();
    }
    fs::write(path, body(records)).unwrap();
}

fn append_records(path: &Path, records: &[Value]) {
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(body(records).as_bytes()).unwrap();
}

fn fallback_date() -> Date {
    Date::from_calendar_date(2026, Month::July, 19).unwrap()
}

/// Days wide enough that no fixture line is dropped.
fn wide() -> Window {
    let floor = day_of(Date::from_calendar_date(2000, Month::January, 1).unwrap());
    Window {
        floor,
        period_floor: floor,
        today: day_of(Date::from_calendar_date(2100, Month::January, 1).unwrap()),
    }
}

/// Totals of one or more files read in pieces.
#[derive(Default)]
struct Reading {
    agg: Aggregate,
    ownership: Ownership,
    stats: LineStats,
    contributions: BTreeMap<u32, Contribution>,
}

impl Reading {
    /// Read `path` (file id `file_id`) ending a piece at each of `cuts`,
    /// round-tripping the parse state through its stored form between
    /// pieces, as a checkpoint does.
    fn read(&mut self, source: Source, path: &Path, file_id: u32, cuts: &[u64]) {
        let len = fs::metadata(path).unwrap().len();
        let mut state = new_parse_state(source, path, 0);
        let mut offset = 0u64;
        let mut skipping = false;
        for end in cuts.iter().copied().chain([len]) {
            state = StoredParse::from_state(&state).into_state().unwrap();
            let contribution = self.contributions.entry(file_id).or_default();
            let mut out = LineSink {
                sink: Sink {
                    agg: &mut self.agg,
                    contribution,
                    window: wide(),
                    generation: 1,
                },
                ownership: (source == Source::Claude).then_some(&mut self.ownership),
                file_id,
                fallback_day: day_of(fallback_date()),
                stats: &mut self.stats,
            };
            let file = File::open(path).unwrap();
            let read = read_lines(
                file,
                offset,
                end.max(offset),
                skipping,
                source,
                &mut state,
                &mut out,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
            out.sink.session_start(&state.session, state.min_ts);
            offset = read.offset;
            skipping = read.skipping;
        }
        assert_eq!(offset, len, "every complete line is consumed");
    }
}

fn read_whole(source: Source, paths: &[&Path]) -> Reading {
    let mut reading = Reading::default();
    for (index, path) in paths.iter().enumerate() {
        reading.read(source, path, index as u32 + 1, &[]);
    }
    reading
}

type Rows = BTreeMap<(Day, &'static str), (u64, u64, u64, u64)>;

fn v1_rows(report: &WorkspaceReport) -> Rows {
    report
        .daily
        .iter()
        .filter(|(_, bucket)| bucket.events > 0 || bucket.residency > 0)
        .map(|((date, kind), bucket)| {
            (
                (day_of(*date), kind.as_str()),
                (
                    bucket.events,
                    bucket.tokens,
                    bucket.residency,
                    bucket.images,
                ),
            )
        })
        .collect()
}

fn v2_rows(agg: &Aggregate) -> Rows {
    agg.days
        .iter()
        .filter(|(_, bucket)| bucket.events > 0 || bucket.residency > 0)
        .map(|((day, kind), bucket)| {
            (
                (*day, kind.as_str()),
                (
                    bucket.events,
                    bucket.tokens,
                    bucket.residency,
                    bucket.images,
                ),
            )
        })
        .collect()
}

fn v2_files(agg: &Aggregate) -> BTreeMap<String, (u64, u64)> {
    let mut files = BTreeMap::new();
    for (key, totals) in &agg.all_files {
        let entry: &mut (u64, u64) = files.entry(key.path.to_string()).or_default();
        entry.0 += totals.events;
        entry.1 += totals.tokens;
    }
    files
}

fn v2_sessions(agg: &Aggregate) -> BTreeMap<String, u64> {
    agg.sessions
        .iter()
        .map(|(id, totals)| {
            (
                id.to_string(),
                totals.days.values().flat_map(|kinds| kinds.values()).sum(),
            )
        })
        .collect()
}

fn v1_wide() -> DateWindow {
    DateWindow {
        floor: Date::from_calendar_date(2000, Month::January, 1).unwrap(),
        today: Date::from_calendar_date(2100, Month::January, 1).unwrap(),
    }
}

fn v1_claude(paths: &[&Path]) -> WorkspaceReport {
    let mut report = WorkspaceReport::new(v1_wide());
    for path in paths {
        parse_claude_session(path, &mut report, fallback_date(), true).unwrap();
    }
    report
}

fn v1_codex(paths: &[&Path]) -> WorkspaceReport {
    let mut report = WorkspaceReport::new(v1_wide());
    for path in paths {
        parse_codex_session(path, &mut report, fallback_date()).unwrap();
    }
    report
}

fn assert_matches_v1(report: &WorkspaceReport, reading: &Reading) {
    assert_eq!(v2_rows(&reading.agg), v1_rows(report), "daily rows");
    let v1_files: BTreeMap<String, (u64, u64)> = report
        .files
        .iter()
        .map(|(path, agg)| (path.clone(), (agg.events, agg.tokens)))
        .collect();
    assert_eq!(v2_files(&reading.agg), v1_files, "files");
    let v1_sessions: BTreeMap<String, u64> = report
        .sessions
        .iter()
        .filter(|(_, agg)| agg.total > 0)
        .map(|(id, agg)| (id.clone(), agg.total))
        .collect();
    let v2_sessions: BTreeMap<String, u64> = v2_sessions(&reading.agg)
        .into_iter()
        .filter(|(_, total)| *total > 0)
        .collect();
    assert_eq!(v2_sessions, v1_sessions, "sessions");
}

/// Offsets that end a piece: after every line, and in the middle of every
/// line (a partial last line).
fn cut_points(path: &Path) -> Vec<u64> {
    let bytes = fs::read(path).unwrap();
    let mut cuts = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            cuts.push((start + (index - start) / 2) as u64);
            cuts.push(index as u64 + 1);
            start = index + 1;
        }
    }
    cuts
}

/// Every single cut, and every line as its own piece, equal one read.
fn assert_split_parity(source: Source, paths: &[&Path]) {
    let whole = read_whole(source, paths);
    for (index, path) in paths.iter().enumerate() {
        let cuts = cut_points(path);
        for cut in &cuts {
            let mut split = Reading::default();
            for (other, other_path) in paths.iter().enumerate() {
                let pieces: &[u64] = if other == index {
                    std::slice::from_ref(cut)
                } else {
                    &[]
                };
                split.read(source, other_path, other as u32 + 1, pieces);
            }
            assert_eq!(split.agg, whole.agg, "cut at {cut} of file {index}");
        }
        let mut every_line = Reading::default();
        for (other, other_path) in paths.iter().enumerate() {
            let pieces: Vec<u64> = if other == index {
                cuts.clone()
            } else {
                Vec::new()
            };
            every_line.read(source, other_path, other as u32 + 1, &pieces);
        }
        assert_eq!(every_line.agg, whole.agg, "every line of file {index}");
    }
}

fn claude_fixture_paths(dir: &Path) -> Vec<PathBuf> {
    [("a", sess_a()), ("b", sess_b()), ("c", sess_c())]
        .into_iter()
        .map(|(name, records)| {
            let path = dir.join(format!("{name}.jsonl"));
            write_records(&path, &records);
            path
        })
        .collect()
}

// -------------------------------------------------------------------------
// Measurement and decoding.
// -------------------------------------------------------------------------

#[test]
fn content_measure_matches_v1_helper() {
    let cases = [
        Value::Null,
        json!("שלום🙂 \"quoted\" \\ back\nslash"),
        json!(17),
        json!(true),
        json!([]),
        json!({"type":"text","text":"one"}),
        json!({"type":"text","text":17}),
        json!({"type":"image","data":"ignored"}),
        json!(["a", null, 2, {"type":"input_text","text":"b"},
            {"type":"input_image"}, {"type":"output_image"},
            {"type":"output_text","text":"c"}, {"unknown":[1,2]},
            {"type":"tool_reference","tool_name":"Read"}, {"type": 5}, {"text":"no type"}]),
        json!([{"type":"text","text":"\u{1F600}\t\u{0001}"}, ""]),
    ];
    for case in cases {
        let text = serde_json::to_string(&case).unwrap();
        let raw: Box<serde_json::value::RawValue> = serde_json::from_str(&text).unwrap();
        let (chars, images) = content_chars_and_images(Raw(Some(&raw)));
        let (v1_text, v1_images) = extract_blocks_text_and_images(Some(&case));
        assert_eq!(
            (chars, images),
            (v1_text.chars().count(), v1_images),
            "{text}"
        );
    }
    assert_eq!(content_chars_and_images(Raw(None)), (0, 0));
    // A block with a duplicate key: the last value wins, as in `Value`.
    let raw: Box<serde_json::value::RawValue> =
        serde_json::from_str(r#"[{"type":"text","text":"short","text":"the longer one"}]"#)
            .unwrap();
    assert_eq!(content_chars_and_images(Raw(Some(&raw))).0, 14);
}

#[test]
fn kind_and_part_codes_round_trip() {
    for (position, part) in ALL_PARTS.iter().enumerate() {
        assert_eq!(part_position(*part), position);
        assert_eq!(part_from_str(part.as_str()), Some(*part));
    }
    for (position, kind) in all_kinds().iter().enumerate() {
        assert_eq!(kind_position(*kind), position);
        assert_eq!(kind_from_str(kind.as_str()), Some(*kind));
    }
    assert_eq!(kind_from_str("nope"), None);
}

#[test]
fn never_counted_records_are_recognised_at_the_top_level_only() {
    // Real lines carry the attachment type first; `json!` would sort keys.
    let claude = |text: &str| claude_never_counted(text.as_bytes());
    assert!(claude(
        r#"{"attachment":{"type":"prompt_snapshot","content":"x"},"type":"attachment"}"#
    ));
    assert!(claude(
        r#"{"parentUuid":null,"attachment":{"type":"deferred_tools_record"}}"#
    ));
    assert!(!claude(
        r#"{"attachment":{"type":"task_reminder"},"type":"attachment"}"#
    ));
    // Nested, not top level: decoded normally.
    assert!(!claude(
        r#"{"message":{"attachment":{"type":"prompt_snapshot"}}}"#
    ));
    // Inside a string the quotes are escaped.
    assert!(!claude(
        r#"{"text":"\"attachment\":{\"type\":\"prompt_snapshot\""}"#
    ));

    let codex = |text: &str| codex_never_counted(text.as_bytes());
    assert!(codex(
        r#"{"timestamp":"t","ordinal":6,"type":"world_state","payload":{}}"#
    ));
    assert!(codex(
        r#"{"timestamp":"t","type":"token_usage_record","payload":{}}"#
    ));
    assert!(codex(
        r#"{"timestamp":"t","type":"compacted","payload":{}}"#
    ));
    assert!(codex(
        r#"{"timestamp":"t","type":"response_item","payload":{"type":"reasoning"}}"#
    ));
    assert!(codex(
        r#"{"timestamp":"t","type":"event_msg","payload":{"type":"token_count"}}"#
    ));
    assert!(!codex(
        r#"{"timestamp":"t","type":"event_msg","payload":{"type":"item_completed"}}"#
    ));
    assert!(!codex(
        r#"{"timestamp":"t","type":"response_item","payload":{"type":"message"}}"#
    ));
    assert!(!codex(
        r#"{"payload":{"type":"reasoning"},"type":"response_item"}"#
    ));
}

#[test]
fn line_reader_reads_to_length_at_open_and_guards_long_lines() {
    let dir = scratch("composition-v2-reader");
    let path = dir.join("lines.jsonl");
    let long = "x".repeat(40);
    fs::write(&path, format!("a\n{long}\nb\npartial")).unwrap();
    let len = fs::metadata(&path).unwrap().len();
    let collect = |reader: &mut LineReader| {
        let mut out = Vec::new();
        while let Some(event) = reader.next_event().unwrap() {
            out.push(match event {
                LineEvent::Line(line) => String::from_utf8(line.to_vec()).unwrap(),
                LineEvent::TooLong => "<too long>".to_string(),
            });
        }
        out
    };
    let mut reader = LineReader::with_guard(File::open(&path).unwrap(), 0, len, false, 16).unwrap();
    assert_eq!(collect(&mut reader), ["a", "<too long>", "b"]);
    // The partial last line stays unread.
    assert_eq!(reader.position(), len - "partial".len() as u64);

    // A long line cut by the length at open keeps skipping in the next read.
    let mut reader = LineReader::with_guard(File::open(&path).unwrap(), 0, 20, false, 16).unwrap();
    assert_eq!(collect(&mut reader), ["a", "<too long>"]);
    assert!(reader.skipping());
    let resume = reader.position();
    let mut reader =
        LineReader::with_guard(File::open(&path).unwrap(), resume, len, true, 16).unwrap();
    assert_eq!(collect(&mut reader), ["b"]);
    fs::remove_dir_all(dir).unwrap();
}

// -------------------------------------------------------------------------
// Parity with one read and with the kinds_version 1 goldens.
// -------------------------------------------------------------------------

#[test]
fn claude_goldens_match_v1_and_any_split() {
    let dir = scratch("composition-v2-claude-goldens");
    let paths = claude_fixture_paths(&dir);
    let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
    let whole = read_whole(Source::Claude, &refs);
    assert_matches_v1(&v1_claude(&refs), &whole);
    // The hand-computed v1 totals (EXPECTED_CLAUDE): tokens, residency, images.
    let tokens: u64 = whole.agg.days.values().map(|bucket| bucket.tokens).sum();
    let residency: u64 = whole.agg.days.values().map(|bucket| bucket.residency).sum();
    assert_eq!((tokens, residency), (1324, 1344));
    assert_split_parity(Source::Claude, &refs);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn codex_goldens_match_v1_and_any_split() {
    let dir = scratch("composition-v2-codex-goldens");
    let fixtures: Vec<(&str, Vec<Value>)> = vec![
        ("codex", codex_sess()),
        (
            "mcp",
            vec![
                json!({"type":"session_meta","payload":{"id":"cmcp"}}),
                json!({"type":"response_item","payload":{"type":"mcp_tool_call_end",
                    "invocation":{"server":"chrome_devtools","tool":"take_snapshot"},
                    "result":{"Ok":{"content":[{"type":"text","text":"DOMDATA!!"}]}}}}),
                json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"k1","arguments":"{}"}}),
                json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"k1","output":"SH"}}),
                json!({"type":"response_item","payload":{"type":"web_search_end","query":"q"}}),
            ],
        ),
        (
            "user",
            vec![
                json!({"type":"session_meta","payload":{"id":"cuser"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user",
                    "content":[{"type":"input_text","text":"# AGENTS.md instructions for /repo"},
                        {"type":"input_text","text":"typed"},{"type":"input_image","image_url":"x"}],
                    "internal_chat_message_metadata_passthrough":{"content_item_kinds":["agents_md.instructions","user.text","user.image"]}}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[
                    {"type":"input_text","text":"<environment_context>x</environment_context>"},
                    {"type":"input_text","text":"please"}]}}),
                json!({"type":"response_item","payload":{"type":"agent_message","content":[]}}),
            ],
        ),
        (
            "ordinal-fork",
            vec![
                json!({"type":"session_meta","ordinal":0,"payload":{"id":"child","forked_from_id":"parent","thread_source":"subagent","subagent_history_start_ordinal":4}}),
                json!({"type":"session_meta","ordinal":1,"payload":{"id":"parent"}}),
                json!({"type":"response_item","ordinal":2,"payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"COPIEDDV"}]}}),
                json!({"type":"response_item","ordinal":3,"payload":{"type":"agent_message","content":[]}}),
                json!({"type":"response_item","ordinal":4,"payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"OWNDEVXX"}]}}),
                json!({"type":"response_item","ordinal":5,"payload":{"type":"agent_message","content":[]}}),
            ],
        ),
        (
            "legacy-fork",
            vec![
                json!({"type":"session_meta","payload":{"id":"legacy","forked_from_id":"parent","thread_source":"subagent"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"COPIEDDV"}]}}),
                json!({"type":"response_item","payload":{"type":"agent_message","content":[]}}),
                json!({"type":"inter_agent_communication_metadata","payload":{"trigger_turn":true}}),
                json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"OWNDEVXX"}]}}),
                json!({"type":"response_item","payload":{"type":"agent_message","content":[]}}),
            ],
        ),
        (
            "user-fork",
            vec![
                json!({"type":"session_meta","payload":{"id":"userfork","forked_from_id":"parent","thread_source":"user"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"OWNDEVXX"}]}}),
                json!({"type":"response_item","payload":{"type":"agent_message","content":[]}}),
            ],
        ),
    ];
    for (name, records) in fixtures {
        let path = dir.join(format!("{name}.jsonl"));
        write_records(&path, &records);
        let whole = read_whole(Source::Codex, &[&path]);
        assert_matches_v1(&v1_codex(&[&path]), &whole);
        assert_split_parity(Source::Codex, &[&path]);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_copied_records_count_once_in_either_order() {
    let dir = scratch("composition-v2-claude-copies");
    let attachment = |uuid: &str, session: &str| json!({"type":"attachment","uuid":uuid,"sessionId":session,"attachment":{"content":"same harness text"}});
    let turn = |uuid: &str, session: &str, id: &str| json!({"type":"assistant","uuid":uuid,"sessionId":session,"message":{"id":id,"content":[]}});
    let original = dir.join("original.jsonl");
    write_records(&original, &[attachment("u1", "A"), turn("u2", "A", "m1")]);
    let resumed = dir.join("resumed.jsonl");
    write_records(
        &resumed,
        &[
            attachment("u1", "B"),
            turn("u2", "B", "m1"),
            attachment("u3", "B"),
            turn("u4", "B", "m2"),
        ],
    );
    for order in [[&original, &resumed], [&resumed, &original]] {
        let refs: Vec<&Path> = order.iter().map(|path| path.as_path()).collect();
        let whole = read_whole(Source::Claude, &refs);
        assert_matches_v1(&v1_claude(&refs), &whole);
        assert_split_parity(Source::Claude, &refs);
    }
    // A full re-read of a file ignores its own records.
    let mut reading = read_whole(Source::Claude, &[&original, &resumed]);
    let before = reading.agg.clone();
    let contribution = reading.contributions.remove(&1).unwrap();
    reading.agg.subtract(&contribution, 1);
    reading.read(Source::Claude, &original, 1, &[]);
    assert_eq!(v2_rows(&reading.agg), v2_rows(&before));
    fs::remove_dir_all(dir).unwrap();
}

/// Deliberate differences from the kinds_version 1 reader.
#[test]
fn defined_differences_from_v1() {
    let dir = scratch("composition-v2-differences");
    // The client's prompt snapshot and deferred-tools records never count.
    let path = dir.join("snapshot.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"attachment","sessionId":"s","attachment":{"type":"task_reminder","content":"REMEMBER"}}),
            json!({"type":"assistant","sessionId":"s","message":{"id":"m1","content":[]}}),
        ],
    );
    // The client writes the attachment type first (recognised before
    // decoding); with keys in another order it is recognised after.
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(
        concat!(
            r#"{"attachment":{"type":"prompt_snapshot","content":"SYSTEM PROMPT"},"type":"attachment","sessionId":"s"}"#,
            "\n",
            r#"{"attachment":{"type":"deferred_tools_record","content":"TOOLS"},"type":"attachment","sessionId":"s"}"#,
            "\n",
            r#"{"type":"attachment","sessionId":"s","attachment":{"content":"SYSTEM PROMPT","type":"prompt_snapshot"}}"#,
            "\n",
        )
        .as_bytes(),
    )
    .unwrap();
    drop(file);
    append_records(
        &path,
        &[json!({"type":"assistant","sessionId":"s","message":{"id":"m2","content":[]}})],
    );
    let reading = read_whole(Source::Claude, &[&path]);
    assert_eq!(reading.stats.prefix_skipped, 3);
    let rows = v2_rows(&reading.agg);
    assert_eq!(rows.values().map(|row| row.0).sum::<u64>(), 1);

    // A result before its call (impossible in practice) is unmatched; a
    // call is used once.
    let path = dir.join("order.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"r1","content":"EARLY"}]}}),
            json!({"type":"assistant","sessionId":"s","message":{"id":"m1","content":[{"type":"tool_use","id":"r1","name":"Bash","input":{}}]}}),
            json!({"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"r1","content":"ONE"}]}}),
            json!({"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"r1","content":"TWO"}]}}),
        ],
    );
    let reading = read_whole(Source::Claude, &[&path]);
    let shell = reading
        .agg
        .days
        .iter()
        .filter(|((_, kind), _)| *kind == Kind::ShellOutput)
        .map(|(_, bucket)| bucket.events)
        .sum::<u64>();
    assert_eq!(shell, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn codex_inner_items_wait_with_their_open_call() {
    let dir = scratch("composition-v2-codex-items");
    let path = dir.join("items.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"session_meta","payload":{"id":"items"}}),
            json!({"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"c1","input":"run"}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","command":["zsh","-lc","cat a.md"],"cwd":"/repo","parsed_cmd":[{"type":"read","cmd":"cat a.md","name":"a.md","path":"a.md"}],"aggregated_output":"hello"}}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","item":{"type":"McpToolCall","server":"srv","tool":"t","result":{"content":[{"type":"text","text":"abc"}]}}}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","item":{"type":"Extension","kind":"web.search","results":[{"title":"x"}]}}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","item":{"type":"Reasoning","summary_text":[]}}}),
        ],
    );
    let file = File::open(&path).unwrap();
    let len = fs::metadata(&path).unwrap().len();
    let mut state = new_parse_state(Source::Codex, &path, 0);
    let mut reading = Reading::default();
    let mut contribution = Contribution::default();
    let mut out = LineSink {
        sink: Sink {
            agg: &mut reading.agg,
            contribution: &mut contribution,
            window: wide(),
            generation: 1,
        },
        ownership: None,
        file_id: 1,
        fallback_day: day_of(fallback_date()),
        stats: &mut reading.stats,
    };
    read_lines(
        file,
        0,
        len,
        false,
        Source::Codex,
        &mut state,
        &mut out,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    let stored = StoredParse::from_state(&state);
    let state = stored.into_state().unwrap();
    let call = &state.open_calls["c1"];
    assert_eq!(call.items.len(), 3);
    assert!(matches!(
        &call.items[0],
        super::checkpoint::SavedItem::Command { command, parsed, output_chars: 5, .. }
            if command == "zsh -lc cat a.md" && parsed[0] == ("read".to_string(), Some("a.md".to_string()))
    ));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn codex_head_identity_sets_copied_mode() {
    let dir = scratch("composition-v2-codex-head");
    let cases = [
        (json!({"id":"a"}), CopiedMode::Own),
        (
            json!({"id":"a","forked_from_id":"p","thread_source":"user"}),
            CopiedMode::Excluded,
        ),
        (
            json!({"id":"a","forked_from_id":"p","thread_source":"subagent"}),
            CopiedMode::UntilTrigger,
        ),
        (
            json!({"id":"a","forked_from_id":"p","subagent_history_start_ordinal":4}),
            CopiedMode::BeforeOrdinal(4),
        ),
        (
            json!({"id":"a","forked_from_id":"p","history_base":{"c":1}}),
            CopiedMode::Own,
        ),
        (
            json!({"id":"a","thread_source":"agent_created_thread","forked_from_id":"p"}),
            CopiedMode::Own,
        ),
    ];
    for (meta, expected) in cases {
        let path = dir.join("head.jsonl");
        write_records(&path, &[json!({"type":"session_meta","payload":meta})]);
        assert_eq!(new_parse_state(Source::Codex, &path, 0).copied, expected);
    }
    // Read from the middle, a legacy subagent fork is past its trigger.
    let path = dir.join("head.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"session_meta","payload":{"id":"a","forked_from_id":"p","thread_source":"subagent"}}),
        ],
    );
    assert_eq!(
        new_parse_state(Source::Codex, &path, 10).copied,
        CopiedMode::Own
    );
    fs::remove_dir_all(dir).unwrap();
}

// -------------------------------------------------------------------------
// Runs.
// -------------------------------------------------------------------------

/// Maps each folder to its own scope (a non-git folder).
#[derive(Default)]
struct FolderResolver {
    calls: usize,
}

impl ScopeResolver for FolderResolver {
    fn resolve(&mut self, cwd: &Path) -> Option<(String, ScopeInfo)> {
        self.calls += 1;
        let text = cwd.to_string_lossy();
        let scope = sha256_hex(&[text.as_ref()]);
        Some((
            scope.clone(),
            ScopeInfo {
                workspace_hash: scope,
                workspace_path: text.into_owned(),
                identity: Default::default(),
            },
        ))
    }
}

#[derive(Default)]
struct Capture {
    payloads: Vec<Value>,
    fail: bool,
}

impl Uploader for Capture {
    fn upload(&mut self, request: &Value) -> anyhow::Result<()> {
        if self.fail {
            anyhow::bail!("offline");
        }
        self.payloads.push(request.clone());
        Ok(())
    }
}

struct Env {
    root: PathBuf,
    state: PathBuf,
    workspace: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let state = root.join("state");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        Self {
            root: root.join("transcripts"),
            state,
            workspace,
        }
    }

    fn cwd(&self) -> String {
        self.workspace.to_string_lossy().into_owned()
    }

    fn run(
        &self,
        source: Source,
        now: OffsetDateTime,
        capture: Option<&mut Capture>,
    ) -> SourceStats {
        self.run_with(
            source,
            now,
            capture,
            REPAIR_BYTES_PER_DAY,
            &mut FolderResolver::default(),
        )
    }

    fn run_with(
        &self,
        source: Source,
        now: OffsetDateTime,
        capture: Option<&mut Capture>,
        repair_left: u64,
        resolver: &mut dyn ScopeResolver,
    ) -> SourceStats {
        let mut run = Run {
            state_dir: self.state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver,
            repair_left,
        };
        let target = capture.map(|capture| UploadTarget {
            uploader: capture as &mut dyn Uploader,
            machine_id: "machine-test",
            destination: "device|machine|api",
            labels_enabled: true,
        });
        fs::create_dir_all(&self.root).unwrap();
        run_source(&mut run, source, std::slice::from_ref(&self.root), target)
    }

    fn scope(&self, source: Source) -> super::scope::Scope {
        let scope_id = sha256_hex(&[self.cwd().as_str()]);
        load_scope(
            &scope_path(&self.state, source, &scope_id),
            source,
            &scope_id,
        )
        .unwrap()
        .unwrap()
    }

    fn cleanup(self) {
        let _ = fs::remove_dir_all(self.root.parent().unwrap());
    }
}

fn ts(day: Date, second: u32) -> String {
    format!(
        "{}T00:00:{:02}Z",
        super::super::measure::date_ymd(day),
        second % 60
    )
}

/// A Claude line block: an attachment, then a turn, on `day`.
fn claude_turn(cwd: &str, day: Date, n: u32) -> Vec<Value> {
    vec![
        json!({"type":"attachment","uuid":format!("att-{n}"),"sessionId":"s1","cwd":cwd,"timestamp":ts(day, n),
            "attachment":{"type":"task_reminder","content":format!("REMINDER {n}")}}),
        json!({"type":"assistant","uuid":format!("as-{n}"),"sessionId":"s1","cwd":cwd,"timestamp":ts(day, n),
            "message":{"id":format!("m{n}"),"content":[{"type":"tool_use","id":format!("t{n}"),"name":"Bash","input":{"command":"ls"}}]}}),
        json!({"type":"user","uuid":format!("re-{n}"),"sessionId":"s1","cwd":cwd,"timestamp":ts(day, n),
            "message":{"content":[{"type":"tool_result","tool_use_id":format!("t{n}"),"content":"file1\nfile2"}]}}),
    ]
}

fn base_now() -> OffsetDateTime {
    // Ten days back, so files created during a test are born after it.
    OffsetDateTime::now_utc() - time::Duration::days(10)
}

fn total_tokens(agg: &Aggregate) -> u64 {
    agg.days.values().map(|bucket| bucket.tokens).sum()
}

#[test]
fn first_run_is_forward_only_and_reads_live_files_once() {
    let env = Env::new("composition-v2-first-run");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    // A file live at install (modified now) and an old one.
    let live = env.root.join("p/live.jsonl");
    write_records(&live, &claude_turn(&cwd, day, 1));
    let old = env.root.join("p/old.jsonl");
    write_records(&old, &claude_turn(&cwd, day, 2));
    let old_time = std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600);
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(old_time)
        .unwrap();
    let stats = env.run(Source::Claude, now, None);
    assert_eq!(stats.bytes_repair, fs::metadata(&live).unwrap().len());
    assert_eq!(stats.bytes_new, 0);
    let scope = env.scope(Source::Claude);
    let first = total_tokens(&scope.agg);
    assert!(first > 0);

    // The old file only counts what is appended after install.
    append_records(&old, &claude_turn(&cwd, day, 3));
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    assert!(stats.bytes_new > 0 && stats.bytes_repair == 0);
    let second = total_tokens(&env.scope(Source::Claude).agg);
    assert_eq!(second, first * 2);

    // Same-day restart: the run gate refuses a second run today.
    let record = begin_run(&env.state, now).unwrap();
    assert!(record.is_some());
    assert!(begin_run(&env.state, now + time::Duration::hours(2))
        .unwrap()
        .is_none());
    assert!(begin_run(&env.state, now + time::Duration::days(1))
        .unwrap()
        .is_some());
    env.cleanup();
}

#[test]
fn repeated_runs_read_only_new_lines() {
    let env = Env::new("composition-v2-new-lines");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    let mut all = claude_turn(&cwd, day, 1);
    for n in 2..6 {
        let more = claude_turn(&cwd, day, n);
        append_records(&path, &more);
        all.extend(more);
        let stats = env.run(Source::Claude, now + time::Duration::hours(n as i64), None);
        assert_eq!(stats.bytes_repair, 0);
        assert_eq!(
            stats.bytes_new as usize,
            body(&claude_turn(&cwd, day, n)).len()
        );
    }
    // Equal to one read of the whole file.
    let whole_path = env.root.parent().unwrap().join("whole.jsonl");
    write_records(&whole_path, &all);
    let mut whole = Reading::default();
    whole.read(Source::Claude, &whole_path, 1, &[]);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), v2_rows(&whole.agg));
    env.cleanup();
}

#[test]
fn crash_before_scope_commit_never_double_counts() {
    let env = Env::new("composition-v2-crash");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    append_records(&path, &claude_turn(&cwd, day, 2));
    // A second file that copies records of the first (a resumed session).
    let resumed = env.root.join("p/resumed.jsonl");
    write_records(&resumed, &claude_turn(&cwd, day, 1));

    // Crash: the pins and the ownership log are written, the scope is not.
    harvest::tests::set_fail_scope_commit(true);
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    harvest::tests::set_fail_scope_commit(false);
    assert_eq!((stats.scopes_failed, stats.scopes_committed), (1, 0));
    let scope_id = sha256_hex(&[cwd.as_str()]);
    let log_dir = super::scope::ownership_dir(&env.state, Source::Claude, &scope_id);
    let log = fs::read_dir(&log_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let uncommitted = fs::metadata(&log).unwrap().len();

    env.run(Source::Claude, now + time::Duration::hours(2), None);
    // The log was cut back to its committed length before appending.
    assert_eq!(fs::metadata(&log).unwrap().len(), uncommitted);
    let mut whole = Reading::default();
    whole.read(Source::Claude, &path, 1, &[]);
    whole.read(Source::Claude, &resumed, 2, &[]);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), v2_rows(&whole.agg));
    env.cleanup();
}

/// A Claude turn that reads `file`.
fn claude_read_turn(cwd: &str, day: Date, n: u32, file: &str) -> Vec<Value> {
    vec![
        json!({"type":"assistant","uuid":format!("rd-{n}"),"sessionId":"s1","cwd":cwd,"timestamp":ts(day, n),
            "message":{"id":format!("rm{n}"),"content":[{"type":"tool_use","id":format!("r{n}"),"name":"Read","input":{"file_path":file}}]}}),
        json!({"type":"user","uuid":format!("rr-{n}"),"sessionId":"s1","cwd":cwd,"timestamp":ts(day, n),
            "message":{"content":[{"type":"tool_result","tool_use_id":format!("r{n}"),"content":format!("contents of {file} {n}")}]}}),
    ]
}

/// Every total a full re-read replaces exactly (latest-access times,
/// session start times and distinct-session counts are not replaced).
fn assert_same_totals(actual: &Aggregate, expected: &Aggregate) {
    assert_eq!(v2_rows(actual), v2_rows(expected), "daily rows");
    assert_eq!(actual.day_parts, expected.day_parts, "day parts");
    assert_eq!(actual.all_parts, expected.all_parts, "all parts");
    let files = |map: &BTreeMap<(Day, super::aggregate::FileKey), super::aggregate::FileTotals>| {
        map.iter()
            .map(|(key, totals)| (key.clone(), (totals.events, totals.tokens)))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        files(&actual.day_files),
        files(&expected.day_files),
        "day files"
    );
    let all_files = |agg: &Aggregate| {
        agg.all_files
            .iter()
            .map(|(key, totals)| (key.clone(), (totals.events, totals.tokens)))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(all_files(actual), all_files(expected), "all files");
    let tools = |agg: &Aggregate| {
        (
            agg.day_tools
                .iter()
                .map(|(key, totals)| (key.clone(), (totals.calls, totals.tokens)))
                .collect::<BTreeMap<_, _>>(),
            agg.all_tools
                .iter()
                .filter(|(_, totals)| totals.calls > 0 || totals.tokens > 0)
                .map(|(key, totals)| (key.clone(), (totals.calls, totals.tokens, totals.sessions)))
                .collect::<BTreeMap<_, _>>(),
        )
    };
    assert_eq!(tools(actual), tools(expected), "tools");
    let sessions = |agg: &Aggregate| {
        agg.sessions
            .iter()
            .map(|(id, totals)| (id.clone(), totals.days.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(sessions(actual), sessions(expected), "sessions");
}

#[test]
fn rewritten_files_are_read_again_within_the_budget() {
    let env = Env::new("composition-v2-rewrite");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    let mut records = claude_turn(&cwd, day, 1);
    records.extend(claude_read_turn(&cwd, day, 2, "/w/src/a.rs"));
    write_records(&path, &records);
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));

    // Different bytes, a new inode (via rename), other files and tools.
    let replacement = env.root.join("p/s.tmp");
    let mut records = claude_turn(&cwd, day, 7);
    records.extend(claude_read_turn(&cwd, day, 8, "/w/src/b.rs"));
    write_records(&replacement, &records);
    fs::rename(&replacement, &path).unwrap();
    // Over budget: waits, counted, nothing read.
    let stats = env.run_with(
        Source::Claude,
        now + time::Duration::days(1),
        None,
        10,
        &mut FolderResolver::default(),
    );
    assert_eq!((stats.repair_waiting, stats.bytes_repair), (1, 0));
    // Within budget the next day: replaced, not added.
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.bytes_repair, fs::metadata(&path).unwrap().len());
    let mut whole = Reading::default();
    whole.read(Source::Claude, &path, 1, &[]);
    assert_same_totals(&env.scope(Source::Claude).agg, &whole.agg);

    // A shrink is a rewrite too. The kinds it no longer holds go up as
    // zero rows, replacing the earlier upload.
    write_records(&path, &claude_turn(&cwd, day, 9)[..1]);
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(3),
        Some(&mut capture),
    );
    assert_eq!(stats.bytes_repair, fs::metadata(&path).unwrap().len());
    let mut whole = Reading::default();
    whole.read(Source::Claude, &path, 1, &[]);
    assert_same_totals(&env.scope(Source::Claude).agg, &whole.agg);
    let last = capture.payloads.last().unwrap();
    let row = |kind: &str| {
        last["daily_aggregates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["category"] == kind)
            .cloned()
    };
    let shell = row("shell_output").expect("zero row for the emptied kind");
    assert_eq!(
        (
            shell["events"].as_u64(),
            shell["tokens_entered_est"].as_u64()
        ),
        (Some(0), Some(0))
    );
    assert!(row("harness_attachments").is_some());
    env.cleanup();
}

#[test]
fn full_re_read_keeps_history_past_the_window() {
    let env = Env::new("composition-v2-rewrite-history");
    let now = base_now();
    let today = now.date();
    let oldest = today - time::Duration::days(i64::from(KEEP_DAYS - 1));
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    let mut records = claude_turn(&cwd, oldest, 1);
    records.extend(claude_turn(&cwd, today, 2));
    write_records(&path, &records);
    env.run(Source::Claude, now, None);
    let tokens = |agg: &Aggregate| {
        agg.all_parts
            .values()
            .map(|bucket| bucket.tokens)
            .sum::<u64>()
    };
    let first = tokens(&env.scope(Source::Claude).agg);

    // The next day the oldest day left the window; the file is rewritten
    // with one turn of today. The oldest day's share stays in the
    // all-history totals.
    write_records(&path, &claude_turn(&cwd, today, 3));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bytes_repair, fs::metadata(&path).unwrap().len());
    assert_eq!(tokens(&env.scope(Source::Claude).agg), first);
    env.cleanup();
}

#[test]
fn failed_read_drops_the_scope_update() {
    let env = Env::new("composition-v2-failed-read");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    append_records(&path, &claude_turn(&cwd, day, 2));
    harvest::tests::set_fail_read(true);
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    harvest::tests::set_fail_read(false);
    assert_eq!((stats.scopes_failed, stats.scopes_committed), (1, 0));
    env.run(Source::Claude, now + time::Duration::hours(2), None);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));
    env.cleanup();
}

#[test]
fn codex_archive_move_and_compression_never_read_again() {
    let env = Env::new("composition-v2-archive");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let name = "rollout-2026-10-01T00-00-00-abc.jsonl";
    let live = env.root.join("sessions/2026/10/01").join(name);
    let records = vec![
        json!({"type":"session_meta","timestamp":ts(day, 0),"payload":{"id":"abc","cwd":cwd}}),
        json!({"type":"response_item","timestamp":ts(day, 1),"payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"DEVINSTRUCT"}]}}),
        json!({"type":"response_item","timestamp":ts(day, 2),"payload":{"type":"agent_message","content":[]}}),
    ];
    write_records(&live, &records);
    env.run(Source::Codex, now, None);
    let before = env.scope(Source::Codex).agg;

    // Codex moves the rollout (same inode) to the archive.
    let archived = env.root.join("archived_sessions").join(name);
    fs::create_dir_all(archived.parent().unwrap()).unwrap();
    fs::rename(&live, &archived).unwrap();
    let stats = env.run(Source::Codex, now + time::Duration::days(1), None);
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.moved),
        (0, 0, 1)
    );
    assert_eq!(env.scope(Source::Codex).agg.days, before.days);

    // Later it is compressed: done, never read.
    let compressed = archived.with_file_name(format!("{name}.zst"));
    fs::write(&compressed, b"compressed").unwrap();
    fs::remove_file(&archived).unwrap();
    let stats = env.run(Source::Codex, now + time::Duration::days(2), None);
    assert_eq!(
        (stats.archived, stats.bytes_new + stats.bytes_repair),
        (1, 0)
    );
    env.cleanup();
}

#[test]
fn over_long_line_is_skipped_and_counted() {
    let env = Env::new("composition-v2-long-line");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    let huge = json!({"type":"attachment","sessionId":"s1","cwd":cwd,"attachment":{"type":"task_reminder","content":"x".repeat(reader::MAX_LINE_BYTES + 10)}});
    append_records(&path, &[huge]);
    append_records(&path, &claude_turn(&cwd, day, 2));
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    assert_eq!(stats.lines.too_long, 1);
    assert_eq!(total_tokens(&env.scope(Source::Claude).agg) % 2, 0);
    env.cleanup();
}

fn whole_rows(path: &Path) -> Rows {
    let mut whole = Reading::default();
    whole.read(Source::Claude, path, 1, &[]);
    v2_rows(&whole.agg)
}

#[test]
fn bad_state_reads_again_and_never_fails() {
    let env = Env::new("composition-v2-bad-state");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    let scope_id = sha256_hex(&[cwd.as_str()]);
    let scope_file = scope_path(&env.state, Source::Claude, &scope_id);

    // A bad scope state: its files are read again in full.
    fs::write(&scope_file, b"{not json").unwrap();
    append_records(&path, &claude_turn(&cwd, day, 2));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!((stats.bad_state, stats.scopes_failed), (1, 0));
    assert_eq!(stats.bytes_repair, fs::metadata(&path).unwrap().len());
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));

    // A missing one the pins know about is bad state too.
    fs::remove_file(&scope_file).unwrap();
    append_records(&path, &claude_turn(&cwd, day, 3));
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.bad_state, 1);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));

    // Bad pins: no failure, nothing read twice.
    fs::write(env.state.join("index-claude-code.json"), b"[]").unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(
        (stats.bad_state, stats.bytes_new, stats.bytes_repair),
        (1, 0, 0)
    );
    append_records(&path, &claude_turn(&cwd, day, 4));
    env.run(Source::Claude, now + time::Duration::days(4), None);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));

    // A bad run record never blocks a run.
    fs::write(env.state.join("run.json"), b"\x00").unwrap();
    assert!(begin_run(&env.state, now).unwrap().is_some());
    env.cleanup();
}

#[test]
fn rebuilt_scope_uploads_every_rebuilt_day() {
    let env = Env::new("composition-v2-rebuilt-upload");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    let later = day + time::Duration::days(1);
    write_records(&env.root.join("p/s2.jsonl"), &claude_turn(&cwd, later, 2));
    env.run(
        Source::Claude,
        now + time::Duration::days(1),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 2);

    // The rebuilt scope counts generations from the start again; the old
    // acknowledgment must not hide its days.
    let scope_id = sha256_hex(&[cwd.as_str()]);
    fs::write(scope_path(&env.state, Source::Claude, &scope_id), b"{}").unwrap();
    append_records(&path, &claude_turn(&cwd, day, 3));
    env.run(
        Source::Claude,
        now + time::Duration::days(2),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 3);
    let ymd = |date: Date| super::super::measure::date_ymd(date);
    let dates: BTreeSet<String> = capture.payloads[2]["daily_aggregates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["date"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(dates, BTreeSet::from([ymd(day), ymd(later)]));
    env.cleanup();
}

#[test]
fn changed_days_upload() {
    let env = Env::new("composition-v2-upload");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    assert_eq!(capture.payloads.len(), 1);
    let first = &capture.payloads[0];
    assert_eq!(first["kinds_version"], 2);
    assert_eq!(first["upload_mode"], "changed_days");
    let ymd = |date: Date| super::super::measure::date_ymd(date);
    assert_eq!(
        first["retention_floor"],
        ymd(day - time::Duration::days(91))
    );
    assert_eq!(first["window_end"], ymd(day));
    assert!(first["daily_aggregates"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["date"] == ymd(day)));
    assert_eq!(first["workspace_hash"], sha256_hex(&[cwd.as_str()]));

    // Nothing changed: no upload.
    env.run(
        Source::Claude,
        now + time::Duration::days(1),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 1);

    // A new session on a later day: only that day's rows. (New turns in
    // the first session would also change the first day: its open lines
    // gain residency.)
    let later = day + time::Duration::days(2);
    write_records(&env.root.join("p/s2.jsonl"), &claude_turn(&cwd, later, 2));
    env.run(
        Source::Claude,
        now + time::Duration::days(2),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 2);
    let rows = capture.payloads[1]["daily_aggregates"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row["date"] == ymd(later)));
    assert_eq!(capture.payloads[1]["window_start"], ymd(later));

    // A failed upload is retried the next day with the same days.
    write_records(
        &env.root.join("p/s3.jsonl"),
        &claude_turn(&cwd, later + time::Duration::days(1), 3),
    );
    capture.fail = true;
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(3),
        Some(&mut capture),
    );
    assert_eq!(stats.upload_failed, 1);
    capture.fail = false;
    env.run(
        Source::Claude,
        now + time::Duration::days(4),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 3);
    let dates: Vec<&str> = capture.payloads[2]["daily_aggregates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["date"].as_str().unwrap())
        .collect();
    assert!(dates.contains(&ymd(later + time::Duration::days(1)).as_str()));

    // A week later, unchanged: a refresh upload.
    env.run(
        Source::Claude,
        now + time::Duration::days(12),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 4);
    env.cleanup();
}

#[test]
fn scope_key_is_stable_across_worktrees() {
    let base = scratch("composition-v2-worktrees");
    let git = |dir: &Path, args: &[&str]| {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    let main = base.join("repo");
    fs::create_dir_all(&main).unwrap();
    git(&main, &["init", "-q"]);
    git(
        &main,
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );
    let worktree = base.join("wt-one");
    git(
        &main,
        &["worktree", "add", "-q", worktree.to_str().unwrap()],
    );
    let mut resolver = super::scope::GitScopeResolver;
    let (main_scope, main_info) = resolver.resolve(&main).unwrap();
    let (wt_scope, wt_info) = resolver.resolve(&worktree).unwrap();
    assert_eq!(main_scope, wt_scope);
    assert_eq!(main_info.workspace_hash, wt_info.workspace_hash);
    let main_text = fs::canonicalize(&main).unwrap();
    let candidates = [
        sha256_hex(&[main.to_string_lossy().as_ref()]),
        sha256_hex(&[main_text.to_string_lossy().as_ref()]),
    ];
    assert!(candidates.contains(&wt_info.workspace_hash));

    // A transcript from the worktree stays pinned after the worktree goes.
    let env_root = base.join("transcripts");
    let state = base.join("state");
    let path = env_root.join("p/s.jsonl");
    let now = base_now();
    write_records(
        &path,
        &claude_turn(&worktree.to_string_lossy(), now.date(), 1),
    );
    let run = |now: OffsetDateTime, resolver: &mut dyn ScopeResolver| {
        let mut run = Run {
            state_dir: state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver,
            repair_left: REPAIR_BYTES_PER_DAY,
        };
        run_source(
            &mut run,
            Source::Claude,
            std::slice::from_ref(&env_root),
            None,
        )
    };
    run(now, &mut super::scope::GitScopeResolver);
    git(
        &main,
        &["worktree", "remove", "--force", worktree.to_str().unwrap()],
    );
    append_records(
        &path,
        &claude_turn(&worktree.to_string_lossy(), now.date(), 2),
    );
    let stats = run(
        now + time::Duration::days(1),
        &mut super::scope::GitScopeResolver,
    );
    assert_eq!(stats.unscoped, 0);
    assert!(stats.bytes_new > 0);
    let index: Index =
        serde_json::from_slice(&fs::read(state.join("index-claude-code.json")).unwrap()).unwrap();
    assert_eq!(index.scope_info.len(), 1);
    assert_eq!(
        index.scope_info[&main_scope].workspace_hash,
        wt_info.workspace_hash
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn scope_resolution_is_cached_per_folder() {
    let env = Env::new("composition-v2-scope-cache");
    let now = base_now();
    let cwd = env.cwd();
    for n in 0..5 {
        write_records(
            &env.root.join(format!("p/s{n}.jsonl")),
            &claude_turn(&cwd, now.date(), n),
        );
    }
    let mut resolver = FolderResolver::default();
    env.run_with(
        Source::Claude,
        now,
        None,
        REPAIR_BYTES_PER_DAY,
        &mut resolver,
    );
    assert_eq!(resolver.calls, 1);
    env.cleanup();
}

#[test]
fn parse_state_round_trips() {
    let state = ParseState {
        session: "s".into(),
        copied: CopiedMode::BeforeOrdinal(3),
        min_ts: Some(5),
        ..Default::default()
    };
    let round = StoredParse::from_state(&state).into_state().unwrap();
    assert_eq!(round.copied, CopiedMode::BeforeOrdinal(3));
    assert_eq!(round.min_ts, Some(5));
    assert_eq!(&*round.session, "s");
}

// -------------------------------------------------------------------------
// Measurement (run by hand: cargo test --release ... -- --ignored).
// -------------------------------------------------------------------------

/// Bytes read, thread CPU, accounted memory and state size on a synthetic
/// workspace: a first full read, then a day of appends.
#[test]
#[ignore]
fn measure_synthetic_large_workspace() {
    let env = Env::new("composition-v2-measure");
    let now = OffsetDateTime::now_utc();
    let day = now.date();
    let cwd = env.cwd();
    let files: usize = std::env::var("COMPOSITION_MEASURE_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(400);
    let turns: u32 = std::env::var("COMPOSITION_MEASURE_TURNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    let output = "line of tool output with some width to it\n".repeat(40);
    let make = |file: usize, from: u32, to: u32| -> Vec<Value> {
        let mut records = Vec::new();
        for n in from..to {
            let uuid = |kind: &str| format!("{kind}-{file}-{n}");
            records.push(json!({"type":"attachment","uuid":uuid("att"),"sessionId":format!("s{file}"),"cwd":cwd,"timestamp":ts(day, n),
                "attachment":{"type":"task_reminder","content":"REMINDER TEXT ".repeat(20)}}));
            records.push(json!({"type":"assistant","uuid":uuid("as"),"sessionId":format!("s{file}"),"cwd":cwd,"timestamp":ts(day, n),
                "message":{"id":uuid("m"),"content":[{"type":"tool_use","id":uuid("t"),"name":if n % 3 == 0 {"Read"} else {"Bash"},"input":{"command":"ls","file_path":format!("/w/src/file{}.rs", n % 50)}}]}}));
            records.push(json!({"type":"user","uuid":uuid("re"),"sessionId":format!("s{file}"),"cwd":cwd,"timestamp":ts(day, n),
                "message":{"content":[{"type":"tool_result","tool_use_id":uuid("t"),"content":output}]}}));
        }
        records
    };
    for file in 0..files {
        write_records(
            &env.root.join(format!("p/s{file}.jsonl")),
            &make(file, 0, turns),
        );
    }
    let mut capture = Capture::default();
    let first = env.run_with(
        Source::Claude,
        now,
        Some(&mut capture),
        u64::MAX,
        &mut FolderResolver::default(),
    );
    for file in 0..files {
        append_records(
            &env.root.join(format!("p/s{file}.jsonl")),
            &make(file, turns, turns + turns / 10),
        );
    }
    let second = env.run_with(
        Source::Claude,
        now + time::Duration::hours(1),
        Some(&mut capture),
        u64::MAX,
        &mut FolderResolver::default(),
    );
    let state_bytes = dir_bytes(&env.state);
    for (label, stats) in [("first", &first), ("append", &second)] {
        println!(
            "{label}: bytes_read={} lines={} cpu_ms={} wall_ms={} peak_accounted_bytes={} scope_state_bytes={}",
            stats.bytes_new + stats.bytes_repair,
            stats.lines.lines,
            stats.cpu_micros / 1000,
            stats.wall_micros / 1000,
            stats.peak_accounted_bytes,
            stats.state_bytes,
        );
    }
    println!(
        "state_dir_bytes={state_bytes} uploads={} payload_bytes={}",
        capture.payloads.len(),
        capture
            .payloads
            .iter()
            .map(|payload| payload.to_string().len())
            .sum::<usize>()
    );
    env.cleanup();
}

fn dir_bytes(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| {
                    let path = entry.path();
                    if path.is_dir() {
                        dir_bytes(&path)
                    } else {
                        entry.metadata().map_or(0, |metadata| metadata.len())
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}
