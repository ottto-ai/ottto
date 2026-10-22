//! Tests for the new-lines reader.
//!
//! Parity: reading a transcript in any number of pieces (every line
//! boundary, partial last lines, a checkpoint round trip between pieces)
//! gives the same totals as one read, and one read gives the kinds_version 1
//! golden numbers. Runs: forward-only first run, restart, crash, rewrite,
//! archive moves, line guard, stable scope key, worktrees gone before their
//! first read, copied history, failed reads, changed-days upload, the
//! server's field rules and bad state.

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
use super::file::{new_parse_state, read_lines, LineSink, LineStats, Names, Source};
use super::harvest::{begin_run, run_source, Run, SourceStats};
use super::reader::{LineEvent, LineReader};
use super::scope::{load_scope, scope_path, ScopeInfo, ScopeResolver};
use super::upload::{UploadTarget, Uploader};
use super::*;
use crate::composition_kinds::{GitRootCache, Kind, KindsVersion};
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
struct Reading {
    agg: Aggregate,
    stats: LineStats,
    contributions: BTreeMap<u32, Contribution>,
    /// Per file id: Claude records dated before this are copied history.
    copied_before: BTreeMap<u32, i64>,
    /// kinds_version 2 as the reader runs; 1 to compare with the
    /// kinds_version 1 reader.
    kinds: KindsVersion,
    /// File names resolved against this folder as a run does; paths as
    /// written when `None`.
    workspace: Option<PathBuf>,
}

impl Default for Reading {
    fn default() -> Self {
        Self {
            agg: Aggregate::default(),
            stats: LineStats::default(),
            contributions: BTreeMap::new(),
            copied_before: BTreeMap::new(),
            kinds: KindsVersion::V2,
            workspace: None,
        }
    }
}

impl Reading {
    /// The kinds_version 1 methodology, for parity with its reader.
    fn v1() -> Self {
        Self {
            kinds: KindsVersion::V1,
            ..Self::default()
        }
    }

    /// File names as a run in `workspace` (a folder scope) keeps them.
    fn in_workspace(workspace: &Path) -> Self {
        Self {
            workspace: Some(workspace.to_path_buf()),
            ..Self::default()
        }
    }

    /// Read `path` (file id `file_id`) ending a piece at each of `cuts`,
    /// round-tripping the parse state through its stored form between
    /// pieces, as a checkpoint does.
    fn read(&mut self, source: Source, path: &Path, file_id: u32, cuts: &[u64]) {
        let len = fs::metadata(path).unwrap().len();
        let mut state = new_parse_state(source, path, 0).0;
        let mut offset = 0u64;
        let mut skipping = false;
        let base = Aggregate::default();
        let copied_before = self.copied_before.get(&file_id).copied();
        let mut cache = GitRootCache::v2();
        for end in cuts.iter().copied().chain([len]) {
            state = StoredParse::from_state(&state).into_state().unwrap();
            let contribution = self.contributions.entry(file_id).or_default();
            let mut out = LineSink {
                sink: Sink {
                    base: &base,
                    agg: &mut self.agg,
                    contribution,
                    window: wide(),
                    generation: 1,
                },
                copied_before,
                fallback_day: day_of(fallback_date()),
                stats: &mut self.stats,
                kinds: self.kinds,
                names: match &self.workspace {
                    Some(workspace) => Names::Resolve {
                        cache: &mut cache,
                        workspace,
                        repository_hash: None,
                    },
                    None => Names::Raw,
                },
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
    read_whole_as(Reading::default, source, paths)
}

/// One read of each file with the kinds_version 1 methodology.
fn read_whole_v1(source: Source, paths: &[&Path]) -> Reading {
    read_whole_as(Reading::v1, source, paths)
}

fn read_whole_as(new: fn() -> Reading, source: Source, paths: &[&Path]) -> Reading {
    let mut reading = new();
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
fn assert_split_parity(new: fn() -> Reading, source: Source, paths: &[&Path]) {
    let whole = read_whole_as(new, source, paths);
    for (index, path) in paths.iter().enumerate() {
        let cuts = cut_points(path);
        for cut in &cuts {
            let mut split = new();
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
        let mut every_line = new();
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
    let whole = read_whole_v1(Source::Claude, &refs);
    assert_matches_v1(&v1_claude(&refs), &whole);
    // The hand-computed v1 totals (EXPECTED_CLAUDE): tokens, residency, images.
    let tokens: u64 = whole.agg.days.values().map(|bucket| bucket.tokens).sum();
    let residency: u64 = whole.agg.days.values().map(|bucket| bucket.residency).sum();
    assert_eq!((tokens, residency), (1324, 1344));
    assert_split_parity(Reading::v1, Source::Claude, &refs);
    assert_split_parity(Reading::default, Source::Claude, &refs);
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
        let whole = read_whole_v1(Source::Codex, &[&path]);
        assert_matches_v1(&v1_codex(&[&path]), &whole);
        assert_split_parity(Reading::v1, Source::Codex, &[&path]);
        assert_split_parity(Reading::default, Source::Codex, &[&path]);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_copied_records_count_once_in_either_order() {
    let dir = scratch("composition-v2-claude-copies");
    let at = |second: u32| format!("2026-07-19T10:{:02}:{:02}Z", second / 60, second % 60);
    let attachment = |uuid: &str, session: &str, second: u32| json!({"type":"attachment","uuid":uuid,"sessionId":session,"timestamp":at(second),"attachment":{"content":"same harness text"}});
    let turn = |uuid: &str, session: &str, id: &str, second: u32| json!({"type":"assistant","uuid":uuid,"sessionId":session,"timestamp":at(second),"message":{"id":id,"content":[]}});
    let original = dir.join("original.jsonl");
    write_records(
        &original,
        &[attachment("u1", "A", 1), turn("u2", "A", "m1", 2)],
    );
    // A resume made later copies the first records with their timestamps.
    let resumed = dir.join("resumed.jsonl");
    write_records(
        &resumed,
        &[
            attachment("u1", "B", 1),
            turn("u2", "B", "m1", 2),
            attachment("u3", "B", 200),
            turn("u4", "B", "m2", 201),
        ],
    );
    let born = |second: i64| {
        OffsetDateTime::parse(&at(0), &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp()
            + second
    };
    // In creation order this equals kinds_version 1 (which keeps the first
    // copy read); in any other order the totals stay the same.
    let mut totals = Vec::new();
    for (order, births) in [
        ([&original, &resumed], [born(0), born(120)]),
        ([&resumed, &original], [born(120), born(0)]),
    ] {
        let refs: Vec<&Path> = order.iter().map(|path| path.as_path()).collect();
        let mut whole = Reading::v1();
        for (index, path) in refs.iter().enumerate() {
            let id = index as u32 + 1;
            whole
                .copied_before
                .insert(id, births[index] - COPIED_SLACK_SECS);
            whole.read(Source::Claude, path, id, &[]);
        }
        if totals.is_empty() {
            assert_matches_v1(&v1_claude(&refs), &whole);
        }
        totals.push((v2_rows(&whole.agg), v2_sessions(&whole.agg)));
    }
    assert_eq!(totals[0], totals[1]);
    // Within the slack a record is the transcript's own.
    let mut reading = Reading::v1();
    reading
        .copied_before
        .insert(1, born(30) - COPIED_SLACK_SECS);
    reading.read(Source::Claude, &resumed, 1, &[]);
    assert_eq!(reading.stats.lines, 4);
    assert_eq!(
        v2_rows(&reading.agg),
        v2_rows(&read_whole_v1(Source::Claude, &[&resumed]).agg)
    );
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
        .filter(|((_, kind), _)| *kind == Kind::CommandOutput)
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
    let mut state = new_parse_state(Source::Codex, &path, 0).0;
    let mut reading = Reading::default();
    let mut contribution = Contribution::default();
    let base = Aggregate::default();
    let mut out = LineSink {
        sink: Sink {
            base: &base,
            agg: &mut reading.agg,
            contribution: &mut contribution,
            window: wide(),
            generation: 1,
        },
        copied_before: None,
        fallback_day: day_of(fallback_date()),
        stats: &mut reading.stats,
        kinds: KindsVersion::V2,
        names: Names::Raw,
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
        assert_eq!(new_parse_state(Source::Codex, &path, 0).0.copied, expected);
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
        new_parse_state(Source::Codex, &path, 10).0.copied,
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
                common_dir: None,
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
    // Midnight ten days back, so files created during a test are born after
    // it and fixture lines (dated from midnight on) are not copied history.
    (OffsetDateTime::now_utc() - time::Duration::days(10)).replace_time(time::Time::MIDNIGHT)
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

    // Crash: the pins are written, the scope is not.
    let later = now + time::Duration::hours(1);
    harvest::tests::set_fail_scope_commit(true);
    let stats = env.run(Source::Claude, later, None);
    harvest::tests::set_fail_scope_commit(false);
    assert_eq!((stats.scopes_failed, stats.scopes_committed), (1, 0));

    env.run(Source::Claude, now + time::Duration::hours(2), None);
    let mut whole = Reading::default();
    whole.read(Source::Claude, &path, 1, &[]);
    // The resumed file was first seen by the crashed run.
    whole
        .copied_before
        .insert(2, later.unix_timestamp() - COPIED_SLACK_SECS);
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
    let mut whole = Reading::in_workspace(&env.workspace);
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
    let mut whole = Reading::in_workspace(&env.workspace);
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
    for emptied in ["command_output", "files_read"] {
        let zero = row(emptied).expect("zero row for the emptied kind");
        assert_eq!(
            (zero["events"].as_u64(), zero["tokens_entered_est"].as_u64()),
            (Some(0), Some(0)),
            "{emptied}"
        );
    }
    assert!(row("automatic_additions").is_some());
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
fn failed_read_counts_nothing_and_keeps_the_rest_of_the_scope() {
    let env = Env::new("composition-v2-failed-read");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    let other = env.root.join("p/other.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    write_records(&other, &claude_turn(&cwd, day, 10));
    env.run(Source::Claude, now, None);
    append_records(&path, &claude_turn(&cwd, day, 2));
    append_records(&other, &claude_turn(&cwd, day, 11));
    harvest::tests::set_fail_read(Some(&path));
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    harvest::tests::set_fail_read(None);
    assert_eq!(
        (
            stats.scopes_failed,
            stats.scopes_committed,
            stats.files_failed
        ),
        (0, 1, 1)
    );
    assert_eq!(
        stats.bytes_failed,
        body(&claude_turn(&cwd, day, 2)).len() as u64
    );
    // The other file committed; the failed one is read again next time.
    env.run(Source::Claude, now + time::Duration::hours(2), None);
    let whole = read_whole(Source::Claude, &[&path, &other]);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), v2_rows(&whole.agg));
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
    // The scope's next commit marks its checkpoint done, so pins rebuilt
    // from the scope never read it again.
    let next = now + time::Duration::days(3);
    let other = env
        .root
        .join("sessions/2026/10/02/rollout-2026-10-02T00-00-00-def.jsonl");
    write_records(
        &other,
        &[
            json!({"type":"session_meta","timestamp":ts(next.date(), 0),"payload":{"id":"def","cwd":cwd}}),
        ],
    );
    env.run(Source::Codex, next, None);
    let scope = env.scope(Source::Codex);
    assert_eq!(scope.files[name].status, super::checkpoint::Status::Done);
    env.cleanup();
}

#[test]
fn a_scope_without_pins_for_the_window_is_no_longer_refreshed() {
    let env = Env::new("composition-v2-retired-scope");
    let now = base_now();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    fs::remove_file(&path).unwrap();
    // The pins forget the file; the week-old upload is still refreshed.
    env.run(
        Source::Claude,
        now + time::Duration::days(40),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 2);
    let index = read_index(&env.state, Source::Claude);
    assert!(index.files.is_empty() && index.cwd_scopes.is_empty());
    // No pin for the whole window: left alone.
    env.run(
        Source::Claude,
        now + time::Duration::days(100),
        Some(&mut capture),
    );
    assert_eq!(capture.payloads.len(), 2);
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
    let in_worktree = |name: &str| worktree.join(name).to_string_lossy().into_owned();
    append_records(
        &path,
        &claude_read_turn(
            &worktree.to_string_lossy(),
            now.date(),
            3,
            &in_worktree("src/w.rs"),
        ),
    );
    run(now, &mut super::scope::GitScopeResolver);
    git(
        &main,
        &["worktree", "remove", "--force", worktree.to_str().unwrap()],
    );
    append_records(
        &path,
        &claude_turn(&worktree.to_string_lossy(), now.date(), 2),
    );
    append_records(
        &path,
        &claude_read_turn(
            &worktree.to_string_lossy(),
            now.date(),
            4,
            &in_worktree("src/x.rs"),
        ),
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
    // Names resolve when the line is read: a file read while its worktree
    // existed keeps its repo-relative name; one read after it was removed
    // keeps its basename. State never holds the absolute path.
    let scope = load_scope(
        &scope_path(&state, Source::Claude, &main_scope),
        Source::Claude,
        &main_scope,
    )
    .unwrap()
    .unwrap();
    let names: BTreeSet<&str> = scope.agg.all_files.keys().map(|key| &*key.path).collect();
    assert_eq!(names, BTreeSet::from(["src/w.rs", "x.rs"]));
    let stored = fs::read_to_string(scope_path(&state, Source::Claude, &main_scope)).unwrap();
    assert!(!stored.contains(&in_worktree("src")));
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

    // An open call keeps every share (kind, part, weight, file, tool).
    let ctx = crate::composition_kinds::LineCtx::v2(
        crate::composition_kinds::Agent::Claude,
        crate::composition_kinds::Request1::No,
        Some(Path::new("/w")),
        false,
        crate::composition_kinds::Author::You,
    );
    let mut state = ParseState::default();
    let calls = [
        (
            "bash",
            crate::composition_kinds::claude_tool(
                &ctx,
                "Bash",
                &json!({"command":"cat a.md b.rs && git log"}),
            ),
        ),
        (
            "mcp",
            crate::composition_kinds::claude_tool(&ctx, "mcp__github__search", &Value::Null),
        ),
    ];
    for (id, class) in &calls {
        state.open_call((*id).into(), class.clone());
    }
    assert!(calls[0].1.shares.len() == 3 && calls[1].1.shares.len() == 1);
    let round = StoredParse::from_state(&state).into_state().unwrap();
    for (id, class) in &calls {
        assert_eq!(&round.open_calls[*id].class, class, "{id}");
    }
}

#[test]
fn v2_splits_match_one_read_with_calls_open_across_a_checkpoint() {
    let dir = scratch("composition-v2-share-parity");
    let (claude, codex) = every_family("/w", fallback_date());
    for (source, records) in [(Source::Claude, claude), (Source::Codex, codex)] {
        let path = dir.join(format!("{}.jsonl", source.label()));
        write_records(&path, &records);
        assert_split_parity(Reading::default, source, &[&path]);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn results_split_over_their_shares_and_tools() {
    let dir = scratch("composition-v2-result-shares");
    let (claude, codex) = every_family("/w", fallback_date());
    let path = dir.join("claude.jsonl");
    write_records(&path, &claude);
    let reading = read_whole(Source::Claude, &[&path]);
    let parts = |agg: &Aggregate| -> BTreeMap<(String, String, Option<String>), u64> {
        agg.all_parts
            .iter()
            .map(|(slot, bucket)| {
                (
                    (
                        slot.part.as_str().to_string(),
                        slot.kind.as_str().to_string(),
                        slot.server.as_deref().map(str::to_string),
                    ),
                    bucket.tokens,
                )
            })
            .collect()
    };
    let claude_parts = parts(&reading.agg);
    let tokens = |part: &str| {
        claude_parts
            .iter()
            .filter(|((name, ..), _)| name == part)
            .map(|(_, tokens)| *tokens)
            .sum::<u64>()
    };
    // `cat README.md docs/b.md && git status`: two file reads and git
    // share the result, which sums to the result's tokens.
    let bash_tokens = tokens_for("readme text, docs text, and git status output");
    assert_eq!(tokens("shell_read") + tokens("git"), bash_tokens);
    assert!(tokens("shell_read") > 0 && tokens("git") > 0);
    let files: BTreeSet<&str> = reading.agg.all_files.keys().map(|key| &*key.path).collect();
    assert!(["/w/README.md", "/w/docs/b.md", "/w/src/a.rs"]
        .iter()
        .all(|file| files.contains(file)));
    // The add-on result is the github server's; an unmatched result is
    // "other built-in"; the instructions reload splits by file type.
    assert!(claude_parts.contains_key(&(
        "addon".to_string(),
        "other_tools".to_string(),
        Some("github".to_string())
    )));
    assert!(tokens("built_in_other") > 0);
    assert!(tokens("instructions_reloaded") > 0 && tokens("memory_reloaded") > 0);
    assert!(tokens("memory_reloaded") > tokens("instructions_reloaded"));
    // A nested instruction file is a file read; a mentioned one is not.
    assert!(files.contains("/w/sub/CLAUDE.md"));
    assert!(tokens("by_you") > 0 && tokens("web") > 0 && tokens("reminders") > 0);
    // A queued background report is not a prompt.
    assert!(tokens("background_reports") > 0);
    // One call per tool.
    let tools: BTreeMap<&str, (u64, u64)> = reading
        .agg
        .all_tools
        .iter()
        .map(|(tool, totals)| (&**tool, (totals.calls, totals.tokens)))
        .collect();
    assert_eq!(tools["Bash"], (1, bash_tokens));
    assert_eq!(tools["github/search_code"].0, 1);

    // A Codex cell: the command, the add-on call and the search each take
    // their share; the add-on share counts under its own tool and server.
    let path = dir.join("codex.jsonl");
    write_records(&path, &codex);
    let reading = read_whole(Source::Codex, &[&path]);
    let codex_parts = parts(&reading.agg);
    assert!(codex_parts.contains_key(&(
        "addon".to_string(),
        "other_tools".to_string(),
        Some("linear".to_string())
    )));
    let tools: BTreeMap<&str, u64> = reading
        .agg
        .all_tools
        .iter()
        .map(|(tool, totals)| (&**tool, totals.calls))
        .collect();
    assert_eq!(tools.get("linear/list_issues"), Some(&1));
    assert_eq!(tools.get("exec"), Some(&1));
    // The search inside the cell counts once, in the cell.
    assert_eq!(reading.stats.web_search_in_call, 1);
    let web_events: u64 = reading
        .agg
        .all_parts
        .iter()
        .filter(|(slot, _)| slot.part == crate::composition_kinds::Part::Web)
        .map(|(_, bucket)| bucket.events)
        .sum();
    assert_eq!(web_events, 1);
    // Developer text blocks classify one by one.
    let developer: BTreeSet<&str> = codex_parts
        .keys()
        .filter(|(_, kind, _)| kind == "automatic_additions")
        .map(|(part, ..)| part.as_str())
        .collect();
    assert_eq!(developer, BTreeSet::from(["environment", "other"]));
    fs::remove_dir_all(dir).unwrap();
}

fn tokens_for(text: &str) -> u64 {
    super::decode::tokens_for_chars(text.chars().count())
}

#[test]
fn top_files_count_the_sessions_that_read_them() {
    let env = Env::new("composition-v2-file-sessions");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let file = format!("{cwd}/src/shared.rs");
    let session = |name: &str, reads: u32| -> Vec<Value> {
        (0..reads)
            .flat_map(|n| claude_read_turn(&cwd, day, 10 + n, &file))
            .map(|mut record| {
                record["sessionId"] = json!(name);
                record["uuid"] = json!(format!("{name}-{}", record["uuid"].as_str().unwrap()));
                record
            })
            .collect()
    };
    // Two sessions read it; one of them five times; a subagent of the
    // first counts as that session.
    write_records(&env.root.join("p/one.jsonl"), &session("one", 5));
    write_records(&env.root.join("p/two.jsonl"), &session("two", 1));
    write_records(
        &env.root.join("p/one/subagents/agent-x.jsonl"),
        &session("one", 1),
    );
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    let row = capture.payloads[0]["top_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["relative_path_or_name"] == "src/shared.rs")
        .cloned()
        .unwrap();
    assert_eq!(row["events"], 7);
    assert_eq!(
        (&row["session_count"], &row["session_count_30d"]),
        (&json!(2), &json!(2))
    );
    // One session alone: 1, however often it read the file.
    let env_one = Env::new("composition-v2-file-sessions-one");
    let cwd_one = env_one.cwd();
    let records: Vec<Value> = (0..5)
        .flat_map(|n| claude_read_turn(&cwd_one, day, 10 + n, &format!("{cwd_one}/src/shared.rs")))
        .collect();
    write_records(&env_one.root.join("p/only.jsonl"), &records);
    let mut capture = Capture::default();
    env_one.run(Source::Claude, now, Some(&mut capture));
    let row = &capture.payloads[0]["top_files"][0];
    assert_eq!(
        (&row["events"], &row["session_count"]),
        (&json!(5), &json!(1))
    );
    env.cleanup();
    env_one.cleanup();
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
    let now = base_now();
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

// -------------------------------------------------------------------------
// Review regressions: worktrees, copied history, failures, pins, scoping,
// copies, uploads.
// -------------------------------------------------------------------------

fn git_in(dir: &Path, args: &[&str]) {
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
}

fn read_index(state: &Path, source: Source) -> Index {
    serde_json::from_slice(&fs::read(harvest::index_path(state, source)).unwrap()).unwrap()
}

#[test]
fn worktree_removed_before_its_first_read_counts_in_its_repository() {
    let base = scratch("composition-v2-wt-gone");
    let main = base.join("repo");
    fs::create_dir_all(&main).unwrap();
    git_in(&main, &["init", "-q"]);
    git_in(
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
    let root = base.join("transcripts");
    let state = base.join("state");
    let now = base_now();
    write_records(
        &root.join("p/main.jsonl"),
        &claude_turn(&main.to_string_lossy(), now.date(), 1),
    );
    let run = |now: OffsetDateTime| {
        let mut resolver = super::scope::GitScopeResolver;
        let mut run = Run {
            state_dir: state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver: &mut resolver,
            repair_left: REPAIR_BYTES_PER_DAY,
        };
        run_source(&mut run, Source::Claude, std::slice::from_ref(&root), None)
    };
    run(now);
    // Between two daily runs: a worktree is created, used and removed; an
    // hourly wake sees it while it exists.
    let worktree = base.join("wt-task");
    git_in(
        &main,
        &["worktree", "add", "-q", worktree.to_str().unwrap()],
    );
    let next = now + time::Duration::days(1);
    write_records(
        &root.join("p/task.jsonl"),
        &claude_turn(&worktree.to_string_lossy(), next.date(), 2),
    );
    let mut cache = harvest::WorktreeCache::default();
    let today = day_of(now.date());
    assert_eq!(harvest::map_worktrees(&state, today, &mut cache), 1);
    // A second wake with nothing new reads no pins and adds nothing.
    assert_eq!(harvest::map_worktrees(&state, today, &mut cache), 0);
    git_in(
        &main,
        &["worktree", "remove", "--force", worktree.to_str().unwrap()],
    );
    let stats = run(next);
    assert_eq!((stats.unscoped, stats.scan_errors), (0, 0));
    assert!(stats.bytes_new > 0);
    let index = read_index(&state, Source::Claude);
    assert_eq!(index.scope_info.len(), 1);
    let scope_id = index.files["main.jsonl"].scope.clone().unwrap();
    assert_eq!(
        index.files["task.jsonl"].scope.as_deref(),
        Some(scope_id.as_str())
    );
    let scope = load_scope(
        &scope_path(&state, Source::Claude, &scope_id),
        Source::Claude,
        &scope_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(scope.files.len(), 2);
    // The gone worktree's entry is dropped once nothing waits for it.
    assert!(!index
        .cwd_scopes
        .keys()
        .any(|folder| folder.ends_with("wt-task")));
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn bad_index_rebuilds_pins_and_keeps_every_checkpoint() {
    let env = Env::new("composition-v2-bad-index-sibling");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let a = env.root.join("p/a.jsonl");
    let b = env.root.join("p/b.jsonl");
    write_records(&a, &claude_turn(&cwd, day, 1));
    write_records(&b, &claude_turn(&cwd, day, 10));
    env.run(Source::Claude, now, None);
    assert_eq!(env.scope(Source::Claude).files.len(), 2);
    fs::write(env.state.join("index-claude-code.json"), b"[]").unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!((stats.bad_state, stats.pins_rebuilt), (1, 2));
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    append_records(&a, &claude_turn(&cwd, day, 2));
    env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(env.scope(Source::Claude).files.len(), 2);
    append_records(&b, &claude_turn(&cwd, day, 11));
    env.run(Source::Claude, now + time::Duration::days(3), None);
    let whole = read_whole(Source::Claude, &[&a, &b]);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), v2_rows(&whole.agg));
    env.cleanup();
}

#[test]
fn failing_file_is_retried_once_then_quarantined() {
    let env = Env::new("composition-v2-failed-quarantine");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    let committed = env.scope(Source::Claude).agg;
    harvest::tests::set_fail_read(Some(&path));
    let mut seen = Vec::new();
    for n in 2..5u32 {
        append_records(&path, &claude_turn(&cwd, day, n));
        let stats = env.run(Source::Claude, now + time::Duration::days(n as i64), None);
        seen.push((stats.lines.lines, stats.bytes_failed > 0, stats.quarantined));
    }
    harvest::tests::set_fail_read(None);
    // Failed, retried once (with the day's new lines), then quarantined.
    assert_eq!(seen, vec![(3, true, 0), (6, true, 1), (0, false, 0)]);
    append_records(&path, &claude_turn(&cwd, day, 5));
    let stats = env.run(Source::Claude, now + time::Duration::days(5), None);
    assert_eq!(stats.lines.lines, 0);
    assert_eq!(env.scope(Source::Claude).agg, committed);
    env.cleanup();
}

#[test]
fn resume_of_a_dormant_file_adds_residency_only_to_copied_days() {
    let env = Env::new("composition-v2-dormant-resume");
    let now = base_now();
    let day = now.date();
    let old_day = day - time::Duration::days(20);
    let cwd = env.cwd();
    let old = env.root.join("p/old.jsonl");
    write_records(&old, &claude_turn(&cwd, old_day, 1));
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600))
        .unwrap();
    let stats = env.run(Source::Claude, now, None);
    assert_eq!(
        stats.bytes_new + stats.bytes_repair,
        0,
        "dormant at install"
    );
    // A resume after install copies the old records (same ids and times).
    let next = now + time::Duration::days(1);
    let resumed = env.root.join("p/resumed.jsonl");
    let mut records = claude_turn(&cwd, old_day, 1);
    records.extend(claude_turn(&cwd, next.date(), 2));
    write_records(&resumed, &records);
    env.run(Source::Claude, next, None);
    let agg = env.scope(Source::Claude).agg;
    let on = |date: Date| -> (u64, u64) {
        agg.days
            .iter()
            .filter(|((row_day, _), _)| *row_day == day_of(date))
            .fold((0, 0), |sum, (_, bucket)| {
                (sum.0 + bucket.events, sum.1 + bucket.tokens)
            })
    };
    assert_eq!(on(old_day), (0, 0), "copied history never enters again");
    assert!(on(next.date()).1 > 0, "the resume's own lines count");
    env.cleanup();
}

/// Fails to resolve while `fail` is set.
#[derive(Default)]
struct FlakyResolver {
    fail: bool,
    inner: FolderResolver,
}

impl ScopeResolver for FlakyResolver {
    fn resolve(&mut self, cwd: &Path) -> Option<(String, ScopeInfo)> {
        (!self.fail).then(|| self.inner.resolve(cwd)).flatten()
    }
}

#[test]
fn failed_scoping_is_retried_and_unscoped_files_wait_for_a_change() {
    let env = Env::new("composition-v2-scoping-retry");
    let now = base_now();
    let cwd = env.cwd();
    write_records(
        &env.root.join("p/a.jsonl"),
        &claude_turn(&cwd, now.date(), 1),
    );
    env.run(Source::Claude, now, None);
    // A new file in another folder whose scoping fails once.
    let other = env.workspace.join("other");
    fs::create_dir_all(&other).unwrap();
    let next = now + time::Duration::days(1);
    let b = env.root.join("p/b.jsonl");
    write_records(&b, &claude_turn(&other.to_string_lossy(), next.date(), 2));
    // A new file that names no folder in its first 64 lines.
    let filler = json!({"type":"user","sessionId":"n","message":{"content":"hi"}});
    let mut records = vec![filler.clone(); 70];
    records.extend(claude_turn(&cwd, next.date(), 3));
    let nowhere = env.root.join("p/nowhere.jsonl");
    write_records(&nowhere, &records);
    let mut flaky = FlakyResolver {
        fail: true,
        ..Default::default()
    };
    let stats = env.run_with(Source::Claude, next, None, REPAIR_BYTES_PER_DAY, &mut flaky);
    assert_eq!((stats.scan_errors, stats.unscoped), (1, 1));
    // The head scan stops at 64 lines and its bytes are counted.
    let head = 64 * body(std::slice::from_ref(&filler)).len() as u64;
    assert!(stats.bytes_head >= head && stats.bytes_head < 2 * head);
    flaky.fail = false;
    let stats = env.run_with(
        Source::Claude,
        next + time::Duration::days(1),
        None,
        REPAIR_BYTES_PER_DAY,
        &mut flaky,
    );
    assert_eq!(stats.bytes_new, fs::metadata(&b).unwrap().len());
    assert_eq!(
        stats.unscoped, 0,
        "an unscoped file is scanned again only when it changes"
    );
    env.cleanup();
}

#[test]
fn larger_copy_with_the_same_read_bytes_takes_over() {
    let env = Env::new("composition-v2-larger-copy");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let first = env.root.join("a/s.jsonl");
    write_records(&first, &claude_turn(&cwd, day, 1));
    env.run(Source::Claude, now, None);
    // The session goes on in a copy in another folder; the pinned copy
    // stops growing.
    let second = env.root.join("b/s.jsonl");
    fs::create_dir_all(second.parent().unwrap()).unwrap();
    fs::copy(&first, &second).unwrap();
    append_records(&second, &claude_turn(&cwd, day, 2));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.switched, 1);
    assert_eq!(
        stats.bytes_new,
        body(&claude_turn(&cwd, day, 2)).len() as u64
    );
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&second));
    env.cleanup();
}

#[test]
fn oldest_open_call_is_evicted_first() {
    let mut state = ParseState::default();
    let class = crate::composition_kinds::CallClass::unmatched;
    assert!(!state.open_call("z-first".into(), class()));
    for n in 0..MAX_OPEN_CALLS - 1 {
        assert!(!state.open_call(format!("a{n:05}").into(), class()));
    }
    assert!(state.open_call("a-last".into(), class()));
    assert!(!state.open_calls.contains_key("z-first"));
    assert!(state.open_calls.contains_key("a00000"));
    // The order survives a checkpoint.
    let mut state = StoredParse::from_state(&state).into_state().unwrap();
    assert!(state.open_call("b-next".into(), class()));
    assert!(!state.open_calls.contains_key("a00000"));
}

#[test]
fn sources_alternate_by_day() {
    let first = |day: Day| harvest::source_order(day)[0].1;
    assert_eq!(first(10), Source::Claude);
    assert_eq!(first(11), Source::Codex);
}

#[test]
fn a_re_read_that_changes_nothing_does_not_upload() {
    let env = Env::new("composition-v2-same-content");
    let now = base_now();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    let records = claude_turn(&cwd, now.date(), 1);
    write_records(&path, &records);
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    assert_eq!(capture.payloads.len(), 1);
    // Same records, other bytes: a full re-read with the same totals.
    let spaced: String = records
        .iter()
        .map(|record| format!("{record} \n"))
        .collect();
    fs::write(&path, spaced).unwrap();
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(1),
        Some(&mut capture),
    );
    assert!(stats.bytes_repair > 0);
    assert_eq!((stats.upload_unchanged, capture.payloads.len()), (1, 1));
    let scope = env.scope(Source::Claude);
    let ack: super::upload::UploadAck = serde_json::from_slice(
        &fs::read(super::upload::ack_path(
            &env.state,
            Source::Claude,
            &scope.scope_id,
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(ack.generation, scope.generation);
    env.cleanup();
}

/// Lines of every family the reader classifies: tool calls (a shell
/// command with several parts, reads, an add-on tool), attachments (an
/// instructions reload of several files, a nested instruction file),
/// prompts, and a Codex cell with inner items.
fn every_family(cwd: &str, day: Date) -> (Vec<Value>, Vec<Value>) {
    let at = |n: u32| ts(day, n);
    let claude = vec![
        json!({"type":"attachment","uuid":"a1","sessionId":"s1","cwd":cwd,"timestamp":at(1),
            "attachment":{"type":"task_reminder","content":"REMINDER"}}),
        json!({"type":"attachment","uuid":"a2","sessionId":"s1","cwd":cwd,"timestamp":at(2),
            "attachment":{"type":"instructions","files":[{"type":"Project","path":format!("{cwd}/CLAUDE.md"),"content":"PROJECT RULES"},
                {"type":"AutoMem","path":"/m/MEMORY.md","content":"REMEMBERED NOTES AND MORE"}]}}),
        json!({"type":"attachment","uuid":"a3","sessionId":"s1","cwd":cwd,"timestamp":at(3),
            "attachment":{"type":"nested_memory","filename":format!("{cwd}/sub/CLAUDE.md"),"content":"NESTED"}}),
        json!({"type":"user","uuid":"u1","sessionId":"s1","cwd":cwd,"timestamp":at(4),
            "message":{"role":"user","content":"please look at the code"}}),
        json!({"type":"attachment","uuid":"a4","sessionId":"s1","cwd":cwd,"timestamp":at(4),
            "attachment":{"type":"queued_command","commandMode":"task-notification","prompt":"<task-notification>done</task-notification>"}}),
        json!({"type":"assistant","uuid":"as1","sessionId":"s1","cwd":cwd,"timestamp":at(5),
            "message":{"id":"m1","content":[
                {"type":"tool_use","id":"t1","name":"Read","input":{"file_path":format!("{cwd}/src/a.rs")}},
                {"type":"tool_use","id":"t2","name":"Bash","input":{"command":"cat README.md docs/b.md && git status"}},
                {"type":"tool_use","id":"t3","name":"mcp__github__search_code","input":{"q":"x"}},
                {"type":"tool_use","id":"t4","name":"WebSearch","input":{"query":"x"}}]}}),
        json!({"type":"user","uuid":"r1","sessionId":"s1","cwd":cwd,"timestamp":at(6),
            "message":{"content":[
                {"type":"tool_result","tool_use_id":"t1","content":"fn main() {}"},
                {"type":"tool_result","tool_use_id":"t2","content":"readme text, docs text, and git status output"},
                {"type":"tool_result","tool_use_id":"t3","content":"search results"},
                {"type":"tool_result","tool_use_id":"t4","content":"web results"},
                {"type":"tool_result","tool_use_id":"t-unknown","content":"orphan"}]}}),
    ];
    let codex = vec![
        json!({"timestamp":at(1),"type":"session_meta","payload":{"id":"c1","cwd":cwd}}),
        json!({"timestamp":at(2),"type":"response_item","payload":{"type":"message","role":"developer",
            "content":[{"type":"input_text","text":"<environment_context>x</environment_context>"},{"type":"input_text","text":"be careful"}]}}),
        json!({"timestamp":at(3),"type":"response_item","payload":{"type":"message","role":"user",
            "content":[{"type":"input_text","text":"fix it"}]}}),
        json!({"timestamp":at(4),"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"k1","input":"tools.exec_command({cmd: 'cat a.md'})"}}),
        json!({"timestamp":at(5),"type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution",
            "command":["zsh","-lc","cat src/b.rs"],"cwd":cwd,"parsed_cmd":[{"type":"read","path":"src/b.rs"}],"aggregated_output":"code"}}}),
        json!({"timestamp":at(5),"type":"event_msg","payload":{"type":"item_completed","item":{"type":"McpToolCall",
            "server":"linear","tool":"list_issues","result":{"content":[{"type":"text","text":"issues"}]}}}}),
        json!({"timestamp":at(5),"type":"event_msg","payload":{"type":"item_completed","item":{"type":"Extension","kind":"web.search","results":[{"t":"x"}]}}}),
        json!({"timestamp":at(5),"type":"event_msg","payload":{"type":"web_search_end","query":"q"}}),
        json!({"timestamp":at(6),"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"k1","output":"cell output with code, issues and results"}}),
        json!({"timestamp":at(7),"type":"response_item","payload":{"type":"function_call_output","call_id":"k-unknown","output":"orphan"}}),
        json!({"timestamp":at(8),"type":"response_item","payload":{"type":"agent_message","content":[]}}),
    ];
    (claude, codex)
}

/// The shared wire fixture (also read by the classifier tests).
fn wire_ids() -> (BTreeSet<String>, BTreeMap<String, String>, BTreeSet<String>) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/context-composition/kinds-v2.json"
    ))
    .unwrap();
    let strings = |value: &Value| -> BTreeSet<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect()
    };
    let part_kind = fixture["part_kind"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(part, kind)| (part.clone(), kind.as_str().unwrap().to_string()))
        .collect();
    (
        strings(&fixture["kinds"]),
        part_kind,
        strings(&fixture["top_file_parts"]),
    )
}

#[test]
fn every_id_in_a_v2_upload_is_in_the_shared_fixture() {
    let now = base_now();
    let (kinds, part_kind, file_parts) = wire_ids();
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-v2-wire-ids-{}", source.label()));
        let cwd = env.cwd();
        let (claude, codex) = every_family(&cwd, now.date());
        match source {
            Source::Claude => write_records(&env.root.join("p/s1.jsonl"), &claude),
            Source::Codex => write_records(
                &env.root.join("2026/rollout-2026-07-19T00-00-00-c1.jsonl"),
                &codex,
            ),
        }
        let mut capture = Capture::default();
        let stats = env.run(source, now, Some(&mut capture));
        assert_eq!(stats.files_read, 1, "{source:?}");
        assert_eq!(
            (stats.upload_dropped_non_v2, stats.upload_dropped_unsafe),
            (0, 0),
            "{source:?}"
        );
        assert_eq!(stats.lines.unnamed_files, 0, "{source:?}");
        let payload = &capture.payloads[0];
        assert_eq!(payload["kinds_version"], 2);
        let rows = |list: &str| payload[list].as_array().unwrap().clone();
        let kind_of = |row: &Value, key: &str| row[key].as_str().unwrap().to_string();
        for row in rows("daily_aggregates") {
            assert!(kinds.contains(&kind_of(&row, "category")), "{row}");
        }
        for row in rows("sessions") {
            assert!(kinds.contains(&kind_of(&row, "top_kind")), "{row}");
        }
        for row in rows("tools") {
            assert!(kinds.contains(&kind_of(&row, "kind")), "{row}");
        }
        for row in rows("parts") {
            assert_eq!(
                part_kind.get(&kind_of(&row, "part")),
                Some(&kind_of(&row, "kind")),
                "{row}"
            );
        }
        let files = rows("top_files");
        assert!(!files.is_empty(), "{source:?}");
        for row in &files {
            let part = kind_of(row, "part");
            assert!(file_parts.contains(&part), "{row}");
            assert_eq!(part_kind.get(&part), Some(&kind_of(row, "category")));
            // Repo-relative names, never a path.
            let name = row["relative_path_or_name"].as_str().unwrap();
            assert!(!name.starts_with('/'), "{name}");
        }
        check_server_rules(payload).unwrap();
        // Every kind the fixture lines reach is a kinds_version 2 kind.
        let scope = env.scope(source);
        assert!(scope
            .agg
            .days
            .keys()
            .all(|(_, kind)| Kind::V2.contains(kind)));
        env.cleanup();
    }
}

// The server's field rules for a kinds_version 2 upload, copied (not
// imported) from its request schema: wire ids, part to kind, display-safe
// text, lengths, caps and uniqueness.

const SERVER_PART_KIND: [(&str, &str); 31] = [
    ("shell_read", "files_read"),
    ("file_tool", "files_read"),
    ("skill_file", "files_read"),
    ("instructions_later", "files_read"),
    ("memory_file", "files_read"),
    ("git", "command_output"),
    ("search", "command_output"),
    ("tests_builds", "command_output"),
    ("other_commands", "command_output"),
    ("app_control", "computer_use"),
    ("screenshots", "computer_use"),
    ("web", "web_and_browser"),
    ("browser", "web_and_browser"),
    ("addon", "other_tools"),
    ("agent_reports", "other_tools"),
    ("background_reports", "other_tools"),
    ("built_in_other", "other_tools"),
    ("tool_descriptions_later", "automatic_additions"),
    ("lists_updated", "automatic_additions"),
    ("instructions_reloaded", "automatic_additions"),
    ("memory_reloaded", "automatic_additions"),
    ("compaction_summary", "automatic_additions"),
    ("reminders", "automatic_additions"),
    ("environment", "automatic_additions"),
    ("hook_output", "automatic_additions"),
    ("files_mentioned", "automatic_additions"),
    ("files_changed", "automatic_additions"),
    ("start_not_measured", "automatic_additions"),
    ("other", "automatic_additions"),
    ("by_you", "your_prompts"),
    ("by_agent", "your_prompts"),
];

const SERVER_FILE_FIELDS: [&str; 10] = [
    "relative_path_or_name",
    "category",
    "events",
    "tokens_entered_est",
    "last_accessed_at",
    "part",
    "events_30d",
    "tokens_entered_est_30d",
    "session_count",
    "session_count_30d",
];

const SERVER_KINDS: [&str; 7] = [
    "files_read",
    "command_output",
    "computer_use",
    "web_and_browser",
    "other_tools",
    "automatic_additions",
    "your_prompts",
];

const SERVER_FORBIDDEN_TEXT: [&str; 15] = [
    "/users/",
    "\\users\\",
    "/home/",
    "\\home\\",
    "file://",
    "transcript_path",
    "workspace_path",
    "full_transcript_path",
    "authorization:",
    "bearer ",
    "otdev_",
    "otsi_",
    "otsr_",
    "otel_",
    "otrelay_",
];

/// Display-safe text the server keeps as sent: normalized whitespace, no
/// forbidden fragment, within `max` characters.
fn server_text(field: &str, value: &Value, max: usize) -> Result<String, String> {
    let text = value.as_str().ok_or(format!("{field}: not text"))?;
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() || normalized != text {
        return Err(format!("{field}: blank or not normalized: {text:?}"));
    }
    if text.chars().count() > max {
        return Err(format!("{field}: longer than {max}"));
    }
    let lowered = text.to_lowercase();
    if let Some(fragment) = SERVER_FORBIDDEN_TEXT.iter().find(|f| lowered.contains(**f)) {
        return Err(format!("{field}: contains {fragment:?}"));
    }
    Ok(text.to_string())
}

fn ymd_date(text: &str) -> Option<Date> {
    let mut parts = text.splitn(3, '-').map(str::parse::<u32>);
    let (year, month, day) = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    Date::from_calendar_date(year as i32, Month::try_from(month as u8).ok()?, day as u8).ok()
}

fn check_server_rules(payload: &Value) -> Result<(), String> {
    let kinds: BTreeSet<&str> = SERVER_KINDS.into_iter().collect();
    let part_kind: BTreeMap<&str, &str> = SERVER_PART_KIND.into_iter().collect();
    let date = |field: &str| -> Result<Date, String> {
        let text = payload[field].as_str().ok_or(format!("{field} missing"))?;
        ymd_date(text).ok_or(format!("{field}: {text}"))
    };
    if payload["kinds_version"] != 2 {
        return Err("kinds_version".into());
    }
    let (start, end, floor) = (
        date("window_start")?,
        date("window_end")?,
        date("retention_floor")?,
    );
    if end < start || (end - start).whole_days() + 1 > 92 || floor > end {
        return Err("window".into());
    }
    for (field, min, max) in [("machine_id", 1, 128), ("workspace_hash", 16, 128)] {
        let len = payload[field].as_str().map_or(0, str::len);
        if len < min || len > max {
            return Err(format!("{field} length"));
        }
    }
    for (label, source) in [
        ("workspace_label", "workspace_label_source"),
        ("repository_label", "repository_label_source"),
    ] {
        if !payload[label].is_null() {
            let text = server_text(label, &payload[label], 255)?;
            if payload[source].is_null() {
                return Err(format!("{source} missing"));
            }
            if label == "repository_label" && (text.contains('/') || text.contains("://")) {
                return Err("repository_label".into());
            }
        }
    }
    let rows = |list: &str| payload[list].as_array().cloned().unwrap_or_default();
    let mut seen = BTreeSet::new();
    let daily = rows("daily_aggregates");
    if daily.len() > 92 * 10 {
        return Err("daily cap".into());
    }
    for row in &daily {
        let day = ymd_date(row["date"].as_str().unwrap_or("")).ok_or("daily date")?;
        let kind = row["category"].as_str().unwrap_or("");
        if day < start
            || day > end
            || !kinds.contains(kind)
            || !seen.insert((day, kind.to_string()))
        {
            return Err(format!("daily row {row}"));
        }
    }
    let files = rows("top_files");
    if files.len() > 100 {
        return Err("files cap".into());
    }
    for row in &files {
        let name = server_text("relative_path_or_name", &row["relative_path_or_name"], 512)?;
        if name.starts_with(['/', '\\', '~'])
            || name.contains(":/")
            || name.contains(":\\")
            || name.replace('\\', "/").split('/').any(|part| part == "..")
        {
            return Err(format!("file name {name}"));
        }
        let kind = row["category"].as_str().unwrap_or("");
        if !kinds.contains(kind) {
            return Err(format!("file kind {kind}"));
        }
        if let Some(part) = row["part"].as_str() {
            if part_kind.get(part) != Some(&kind) {
                return Err(format!("file part {part}"));
            }
        }
        // The file input forbids other fields; the session counts are the
        // optional non-negative integers the server adds for kinds_version 2.
        for (field, value) in row.as_object().into_iter().flatten() {
            if !SERVER_FILE_FIELDS.contains(&field.as_str()) {
                return Err(format!("file field {field}"));
            }
            if field.starts_with("session_count") && value.as_u64().is_none() {
                return Err(format!("file {field} {value}"));
            }
        }
    }
    let sessions = rows("sessions");
    if sessions.len() > 200 {
        return Err("sessions cap".into());
    }
    for row in &sessions {
        let hash = row["session_id_hash"].as_str().unwrap_or("");
        let kind = row["top_kind"].as_str().unwrap_or("");
        if hash.len() < 8
            || hash.len() > 128
            || !kinds.contains(kind)
            || !row["top_category"].is_null()
        {
            return Err(format!("session {row}"));
        }
    }
    let mut per_period: BTreeMap<(String, &str), usize> = BTreeMap::new();
    let mut unique = BTreeSet::new();
    let parts = rows("parts");
    for row in &parts {
        let (kind, part) = (
            row["kind"].as_str().unwrap_or(""),
            row["part"].as_str().unwrap_or(""),
        );
        if part_kind.get(part) != Some(&kind) {
            return Err(format!("part {part} under {kind}"));
        }
        let server = if row["server"].is_null() {
            None
        } else {
            if part != "addon" {
                return Err("server off the addon part".into());
            }
            Some(server_text("part server", &row["server"], 64)?)
        };
        let window = row["window"].as_str().unwrap_or("").to_string();
        if !unique.insert((window.clone(), part.to_string(), server)) {
            return Err(format!("repeated part {row}"));
        }
        *per_period.entry((window, "parts")).or_default() += 1;
    }
    for row in &rows("tools") {
        let label = server_text("tool label", &row["label"], 64)?;
        let server = if row["server"].is_null() {
            None
        } else {
            let server = server_text("tool server", &row["server"], 64)?;
            if !label.starts_with(&format!("{server}/")) {
                return Err(format!("tool label {label} without its server"));
            }
            Some(server)
        };
        if !kinds.contains(row["kind"].as_str().unwrap_or("")) {
            return Err(format!("tool kind {row}"));
        }
        let window = row["window"].as_str().unwrap_or("").to_string();
        if !unique.insert((window.clone(), label, server)) {
            return Err(format!("repeated tool {row}"));
        }
        *per_period.entry((window, "tools")).or_default() += 1;
    }
    for ((window, list), count) in per_period {
        let cap = if list == "parts" { 48 } else { 20 };
        if count > cap || !["30d", "all"].contains(&window.as_str()) {
            return Err(format!("{list} in {window}: {count}"));
        }
    }
    Ok(())
}

#[test]
fn a_maximal_upload_meets_the_server_field_rules() {
    use super::aggregate::{Bucket, FileKey, FileTotals, Slot, ToolTotals};
    use super::scope::{SavedIdentity, Scope};
    use crate::composition_kinds::Part;
    // Every Rust part maps to the server's kind.
    let server_parts: BTreeMap<&str, &str> = SERVER_PART_KIND.into_iter().collect();
    for part in ALL_PARTS.iter().filter(|part| part.kind().is_some()) {
        assert_eq!(
            server_parts.get(part.as_str()).copied(),
            part.kind().map(|kind| kind.as_str()),
            "{}",
            part.as_str()
        );
    }
    let now = base_now();
    let today = day_of(now.date());
    let window = Window::ending(today);
    let mut scope = Scope::new(
        "scope",
        ScopeInfo {
            workspace_hash: "f".repeat(64),
            workspace_path: "/w/repo".into(),
            identity: SavedIdentity {
                repository_hash: Some("e".repeat(64)),
                repository_label: Some("repo".into()),
                repository_label_source: Some("git_root".into()),
                repository_identity_source: Some("git_common_dir".into()),
                workspace_kind: Some("linked_worktree".into()),
                workspace_label: Some("repo".into()),
            },
            common_dir: None,
        },
    );
    let bucket = |tokens: u64| Bucket {
        events: 1,
        tokens,
        residency: tokens,
        images: 0,
    };
    let agg = &mut scope.agg;
    for day in window.floor..=today {
        for kind in Kind::V2.iter().copied().chain([Kind::ShellOutput]) {
            agg.days.insert((day, kind), bucket(10));
        }
        agg.day_generation.insert(day, 1);
    }
    let mut slots: Vec<(Slot, u64)> = ALL_PARTS
        .iter()
        .filter_map(|part| Some((Slot::plain(part.kind()?, *part), 10)))
        .collect();
    slots.push((Slot::plain(Kind::ShellOutput, Part::Unsplit), 10));
    let long_server = "s".repeat(70);
    let servers: Vec<String> = (0..14)
        .map(|n| format!("server{n}"))
        .chain(["otel_collector", &long_server, "two  spaces", "two spaces"].map(str::to_string))
        .collect();
    for (n, server) in servers.iter().enumerate() {
        let slot = Slot {
            kind: Kind::OtherTools,
            part: Part::Addon,
            server: Some(server.as_str().into()),
        };
        slots.push((slot, 10_000 - n as u64));
    }
    for (slot, tokens) in slots {
        agg.day_parts.insert((today, slot.clone()), bucket(tokens));
        agg.all_parts.insert(slot, bucket(tokens));
    }
    let long_label = format!("server1/{}", "t".repeat(80));
    let long_server_tool = format!("{long_server}/tool");
    let tools: Vec<String> = (0..30)
        .map(|n| format!("tool{n}"))
        .chain(
            [
                "otel_server/tool",
                "/Users/me/tool",
                "bearer abc",
                long_label.as_str(),
                long_server_tool.as_str(),
                "two  spaces/tool",
                "two spaces/tool",
                // The cap would end this label in a space.
                &format!("s/{} y", "x".repeat(61)),
            ]
            .map(str::to_string),
        )
        .collect();
    for (n, tool) in tools.iter().enumerate() {
        let totals = ToolTotals {
            calls: 1,
            // The special labels rank first, so the top 20 holds them.
            tokens: if n >= 30 {
                2_000 + n as u64
            } else {
                1_000 - n as u64
            },
            sessions: 1,
            kind: Some(Kind::CommandOutput),
        };
        agg.day_tools.insert((today, tool.as_str().into()), totals);
        agg.all_tools.insert(tool.as_str().into(), totals);
    }
    agg.all_tools.insert(
        "legacy".into(),
        ToolTotals {
            calls: 1,
            tokens: 5_000,
            sessions: 1,
            kind: Some(Kind::ShellOutput),
        },
    );
    for n in 0..150 {
        let key = FileKey {
            path: format!("src/file{n}.rs").into(),
            kind: Kind::FilesRead,
            part: Part::FileTool,
        };
        let totals = FileTotals {
            events: 1,
            tokens: 1_000 + n,
            last: Some(now.unix_timestamp()),
        };
        agg.day_files.insert((today, key.clone()), totals);
        agg.all_files.insert(key, totals);
    }
    for n in 0..300u64 {
        let kind = if n == 0 {
            Kind::ShellOutput
        } else {
            Kind::FilesRead
        };
        let totals = agg
            .sessions
            .entry(format!("session-{n}").into())
            .or_default();
        totals.started = Some(now.unix_timestamp());
        totals.days.insert(today, BTreeMap::from([(kind, 10 + n)]));
    }
    let mut capture = Capture::default();
    let target = UploadTarget {
        uploader: &mut capture,
        machine_id: "machine-test",
        destination: "device|machine|api",
        labels_enabled: true,
    };
    let (request, dropped) =
        super::upload::build_request(&scope, Source::Claude, &target, now, window, 0);
    let payload = serde_json::to_value(&request).unwrap();
    check_server_rules(&payload).unwrap();
    // Unsafe and long servers join "other add-ons"; unsafe tools drop.
    let part_servers: BTreeSet<&str> = payload["parts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["server"].as_str())
        .collect();
    assert!(part_servers.contains("two spaces"));
    assert!(!part_servers.contains("otel_collector"));
    assert!(!part_servers.iter().any(|server| server.len() > 64));
    assert!(payload["parts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["part"] == "addon" && row["server"].is_null()));
    let labels: BTreeSet<&str> = payload["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["label"].as_str())
        .collect();
    assert!(labels.contains(long_label.chars().take(64).collect::<String>().as_str()));
    assert!(labels.contains(format!("s/{}", "x".repeat(61)).as_str()));
    for gone in ["otel_server/tool", "/Users/me/tool", "bearer abc", "legacy"] {
        assert!(!labels.contains(gone), "{gone}");
    }
    assert!(!labels.iter().any(|label| label.starts_with(&long_server)));
    // 92 daily rows, the unsplit part (twice), the legacy tool and session.
    assert_eq!(dropped.non_v2, 92 + 2 + 1 + 1);
    // Servers (otel and long, per period) and tools (four per period).
    assert_eq!(dropped.unsafe_text, 2 * 2 + 4 * 2);
}
