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
    Contribution, Day, Sink, Slot, Window, ALL_PARTS,
};
use super::checkpoint::{
    install_path, Checkpoint, CopiedMode, Index, ParseState, Status, StoredParse,
};
use super::decode::{claude_never_counted, codex_never_counted, content_chars_and_images, Raw};
use super::file::{new_parse_state, read_lines, LineSink, LineStats, Names, Source};
use super::harvest::{begin_run, run_source, Run, SourceStats};
use super::reader::{LineEvent, LineReader};
use super::scope::{load_scope, scope_path, ScopeInfo, ScopeResolver};
use super::upload::{UploadReceipt, UploadTarget, Uploader};
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
                totals
                    .days
                    .iter()
                    .flat_map(|(_, kinds)| kinds.iter().map(|(_, tokens)| tokens))
                    .sum(),
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
    fn upload(&mut self, request: &Value) -> anyhow::Result<UploadReceipt> {
        if self.fail {
            anyhow::bail!("offline");
        }
        self.payloads.push(request.clone());
        Ok(UploadReceipt::default())
    }
}

struct Env {
    root: PathBuf,
    state: PathBuf,
    workspace: PathBuf,
}

impl Env {
    /// Both agents already installed (on an empty transcript folder, a day
    /// before `base_now`), so every file a test writes is born after the
    /// install and read from its start as new bytes.
    fn new(name: &str) -> Self {
        let env = Self::uninstalled(name);
        env.install(base_now() - time::Duration::days(1));
        env
    }

    /// No state yet: the test's first run is the install.
    fn uninstalled(name: &str) -> Self {
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

    fn install(&self, at: OffsetDateTime) {
        for source in [Source::Claude, Source::Codex] {
            let stats = self.run(source, at, None);
            assert_eq!((stats.files_checked, stats.scan_errors), (0, 0));
            assert!(install_path(&self.state, source.label()).exists());
        }
    }

    fn cwd(&self) -> String {
        self.workspace.to_string_lossy().into_owned()
    }

    fn run(
        &self,
        source: Source,
        now: OffsetDateTime,
        capture: Option<&mut dyn Uploader>,
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
        capture: Option<&mut dyn Uploader>,
        repair_left: u64,
        resolver: &mut dyn ScopeResolver,
    ) -> SourceStats {
        let mut run = Run {
            start_verdicts: crate::snapshots::start_verdict_store::load(
                &self.state,
                "synthetic-destination",
                now.unix_timestamp(),
            ),
            state_dir: self.state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver,
            repair_left,
        };
        let target = capture.map(|capture| UploadTarget {
            uploader: capture,
            machine_id: "machine-test",
            destination: "device|machine|api",
            labels_enabled: true,
            details_enabled: false,
        });
        fs::create_dir_all(&self.root).unwrap();
        run_source(&mut run, source, std::slice::from_ref(&self.root), target)
    }

    fn scope(&self, source: Source) -> super::scope::Scope {
        let scope_id = sha256_hex(&[self.cwd().as_str()]);
        let path = scope_path(&self.state, source, &scope_id);
        let mut scope = load_scope(&path, source, &scope_id).unwrap().unwrap();
        scope.load_all_shards(&path).unwrap();
        scope
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

/// Real birth time with synthetic lines dated at creation, so these
/// tests exercise the age boundary without modifying the host clock.
fn opening_verdict_fixture(env: &Env, source: Source) -> (PathBuf, OffsetDateTime, Vec<Value>) {
    let at = OffsetDateTime::now_utc();
    let (claude, codex) = every_family(&env.cwd(), at.date());
    let mut records = if source == Source::Claude {
        claude
    } else {
        codex
    };
    let path = if source == Source::Claude {
        env.root.join("p/s1.jsonl")
    } else {
        env.root.join("2026/rollout-2026-10-22T00-00-00-c1.jsonl")
    };
    write_records(&path, &records);
    let born = super::checkpoint::born_secs(&fs::metadata(&path).unwrap()).unwrap();
    let born = OffsetDateTime::from_unix_timestamp(born).unwrap();
    for row in &mut records {
        row["timestamp"] = json!(born
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap());
    }
    write_records(&path, &records);
    (path, born, records)
}

fn opening_tokens(agg: &Aggregate) -> u64 {
    agg.all_parts
        .iter()
        .filter(|(slot, _)| slot.part == crate::composition_kinds::Part::StartNotMeasured)
        .map(|(_, bucket)| bucket.tokens)
        .sum()
}

fn record_opening_verdict(
    env: &Env,
    source: Source,
    path: &Path,
    now: OffsetDateTime,
    measured: bool,
) {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.source_session_id = new_parse_state(source, path, 0).0.session.to_string();
    item.session_start = Some(Box::new(crate::snapshots::SnapshotSessionStart {
        user_turn_count: measured.then_some(1),
        ..Default::default()
    }));
    fs::create_dir_all(&env.state).unwrap();
    crate::snapshots::start_verdict_store::record(
        &env.state,
        "synthetic-destination",
        source.label(),
        [&item],
        now.unix_timestamp(),
    )
    .unwrap();
}

#[test]
fn fresh_opening_without_verdict_waits_then_reads_all_new_bytes() {
    for source in [Source::Claude, Source::Codex] {
        for installed in [false, true] {
            let env = Env::new(&format!("composition-verdict-wait-{source:?}-{installed}"));
            if installed {
                env.run(
                    source,
                    OffsetDateTime::now_utc() - time::Duration::minutes(1),
                    None,
                );
            }
            let (path, born, mut records) = opening_verdict_fixture(&env, source);
            let mut capture = Capture::default();
            let stats = env.run(
                source,
                born + time::Duration::seconds(1),
                Some(&mut capture),
            );
            assert_eq!(stats.verdict_deferred, 1);
            assert_eq!(
                (
                    stats.files_read,
                    stats.bytes_new,
                    stats.bytes_repair,
                    stats.lines.lines
                ),
                (0, 0, 0, 0)
            );
            assert!(capture.payloads.is_empty());
            let index = read_index(&env.state, source);
            assert!(index.files.is_empty(), "no pin on deferral");
            assert!(
                index.scope_generations.is_empty(),
                "no checkpoint on deferral"
            );
            assert_eq!(index.last_scan_started, Some(born.unix_timestamp()));
            // Bytes arriving while the opening waits are included tomorrow.
            let extra = json!({"type":"unused","timestamp":(born + time::Duration::hours(1)).format(&time::format_description::well_known::Rfc3339).unwrap()});
            append_records(&path, std::slice::from_ref(&extra));
            records.push(extra);
            let stats = env.run_with(
                source,
                born + time::Duration::days(1),
                Some(&mut capture),
                0,
                &mut FolderResolver::default(),
            );
            assert_eq!(
                (stats.verdict_deferred, stats.files_read, stats.new_files),
                (0, 1, 1)
            );
            assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
            assert_eq!((stats.bytes_repair, stats.repair_waiting), (0, 0));
            assert_eq!(stats.lines.lines, records.len() as u64);
            let scope = env.scope(source);
            assert!(opening_tokens(&scope.agg) > 0);
            let checkpoint = scope.files.values().next().unwrap();
            assert_eq!(checkpoint.offset, stats.bytes_new);
            assert_eq!(capture.payloads.len(), 1);
            // Late activity keeps its original day when read tomorrow.
            assert!(scope
                .agg
                .days
                .keys()
                .any(|(day, _)| *day == day_of(born.date())));
            env.cleanup();
        }
    }
}

#[test]
fn missing_opening_verdict_wait_ends_at_six_hours() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-verdict-six-hours-{source:?}"));
        let (path, born, _) = opening_verdict_fixture(&env, source);
        for age in [1, 3600, 6 * 3600 - 1] {
            let stats = env.run(source, born + time::Duration::seconds(age), None);
            assert_eq!((stats.verdict_deferred, stats.files_read), (1, 0));
            assert!(read_index(&env.state, source).files.is_empty());
        }
        let stats = env.run_with(
            source,
            born + time::Duration::hours(6),
            None,
            0,
            &mut FolderResolver::default(),
        );
        assert_eq!((stats.verdict_deferred, stats.files_read), (0, 1));
        assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
        assert!(opening_tokens(&env.scope(source).agg) > 0);
        let stats = env.run(source, born + time::Duration::days(1), None);
        assert_eq!((stats.verdict_deferred, stats.files_read), (0, 0));
        env.cleanup();
    }
}

#[test]
fn explicit_opening_verdict_does_not_defer_fresh_files() {
    for source in [Source::Claude, Source::Codex] {
        for measured in [false, true] {
            let env = Env::new(&format!(
                "composition-verdict-explicit-{source:?}-{measured}"
            ));
            let (path, born, _) = opening_verdict_fixture(&env, source);
            record_opening_verdict(&env, source, &path, born, measured);
            let stats = env.run(source, born + time::Duration::seconds(1), None);
            assert_eq!((stats.verdict_deferred, stats.files_read), (0, 1));
            assert_eq!(opening_tokens(&env.scope(source).agg) == 0, measured);
            env.cleanup();
        }
    }
}

#[test]
fn deferred_opening_uses_verdict_that_arrives_before_next_run() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-verdict-arrival-{source:?}"));
        let (path, born, _) = opening_verdict_fixture(&env, source);
        assert_eq!(env.run(source, born, None).verdict_deferred, 1);
        record_opening_verdict(&env, source, &path, born + time::Duration::hours(1), true);
        let stats = env.run(source, born + time::Duration::days(1), None);
        assert_eq!(
            (stats.verdict_deferred, stats.files_read, stats.bytes_repair),
            (0, 1, 0)
        );
        assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
        assert_eq!(opening_tokens(&env.scope(source).agg), 0);
        env.cleanup();
    }
}

#[test]
fn missing_verdict_does_not_defer_later_bytes_of_a_fresh_file() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-verdict-opening-only-{source:?}"));
        let (path, born, _) = opening_verdict_fixture(&env, source);
        record_opening_verdict(&env, source, &path, born, true);
        assert_eq!(env.run(source, born, None).files_read, 1);
        fs::remove_file(env.state.join("composition-start-verdicts.jsonl")).unwrap();
        let mut extra = if source == Source::Claude {
            json!({"type":"user","sessionId":"s1","uuid":"later-prompt","cwd":env.cwd(),"message":{"content":"a later prompt"}})
        } else {
            json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"a later prompt"}]}})
        };
        extra["timestamp"] = json!(born
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap());
        append_records(&path, std::slice::from_ref(&extra));
        let stats = env.run(source, born + time::Duration::hours(1), None);
        assert_eq!(
            (stats.verdict_deferred, stats.files_read, stats.bytes_repair),
            (0, 1, 0)
        );
        assert_eq!(stats.bytes_new, body(&[extra]).len() as u64);
        assert_eq!(opening_tokens(&env.scope(source).agg), 0);
        env.cleanup();
    }
}

#[test]
fn deferred_opening_preserves_a_cached_deleted_folder_scope() {
    let env = Env::new("composition-verdict-gone-folder");
    let source = Source::Claude;
    write_records(
        &env.root.join("p/older.jsonl"),
        &claude_turn(&env.cwd(), base_now().date(), 1),
    );
    env.run(source, base_now(), None);
    // Same map used for a linked worktree removed before its first read.
    let old_index = read_index(&env.state, source);
    let scope_id = old_index.files["older.jsonl"].scope.clone().unwrap();
    assert_eq!(old_index.cwd_scopes.get(&env.cwd()), Some(&scope_id));
    fs::remove_dir_all(&env.workspace).unwrap();
    let (path, born, _) = opening_verdict_fixture(&env, source);
    let stats = env.run(source, born, None);
    assert_eq!(stats.verdict_deferred, 1);
    let index = read_index(&env.state, source);
    assert_eq!(index.cwd_scopes.get(&env.cwd()), Some(&scope_id));
    assert!(!index.files.contains_key("s1.jsonl"));
    let stats = env.run(source, born + time::Duration::days(1), None);
    assert_eq!(
        (stats.verdict_deferred, stats.unscoped, stats.files_read),
        (0, 0, 1)
    );
    assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
    let index = read_index(&env.state, source);
    assert_eq!(index.files["s1.jsonl"].scope.as_ref(), Some(&scope_id));
    assert_eq!(index.scope_info.len(), 1);
    assert!(
        !index.cwd_scopes.contains_key(&env.cwd()),
        "mapping pruned once no opening waits"
    );
    env.cleanup();
}

#[test]
fn deferred_opening_caches_an_unseen_workspace_before_removal() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-verdict-unseen-workspace-{source:?}"));
        let (path, born, _) = opening_verdict_fixture(&env, source);
        let stats = env.run(source, born, None);
        assert_eq!((stats.verdict_deferred, stats.files_read), (1, 0));
        let index = read_index(&env.state, source);
        assert!(index.files.is_empty(), "no file pin for a deferred opening");
        assert!(
            index.scope_generations.is_empty(),
            "no checkpoint committed"
        );
        let scope_id = index.cwd_scopes.get(&env.cwd()).unwrap().clone();
        assert_eq!(index.scope_info.len(), 1);
        fs::remove_dir_all(&env.workspace).unwrap();
        let stats = env.run_with(
            source,
            born + time::Duration::days(1),
            None,
            0,
            &mut FolderResolver::default(),
        );
        assert_eq!(
            (
                stats.verdict_deferred,
                stats.files_read,
                stats.unscoped,
                stats.scan_errors
            ),
            (0, 1, 0, 0)
        );
        assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
        let index = read_index(&env.state, source);
        assert_eq!(
            index.files.values().next().unwrap().scope.as_ref(),
            Some(&scope_id)
        );
        assert!(opening_tokens(&env.scope(source).agg) > 0);
        env.cleanup();
    }
}

#[test]
fn opening_verdict_probe_respects_expired_deadline_and_keeps_new_bytes() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-verdict-deadline-{source:?}"));
        let (path, born, _) = opening_verdict_fixture(&env, source);
        let deadline = Instant::now() - Duration::from_secs(1);
        // Deadline check precedes opening even a nonexistent path.
        assert_eq!(
            super::file::new_parse_state_before(source, &path.with_extension("missing"), deadline)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        let mut resolver = FolderResolver::default();
        let mut run = Run {
            state_dir: env.state.clone(),
            now: born,
            deadline,
            resolver: &mut resolver,
            repair_left: 0,
            start_verdicts: Default::default(),
        };
        let stats = run_source(&mut run, source, std::slice::from_ref(&env.root), None);
        assert!(stats.cut);
        assert_eq!(
            (
                stats.verdict_deferred,
                stats.files_read,
                stats.bytes_head,
                stats.bytes_new,
                stats.bytes_repair
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(resolver.calls, 0);
        let index = read_index(&env.state, source);
        assert!(index.files.is_empty());
        assert_eq!(index.last_scan_started, Some(born.unix_timestamp()));
        let stats = env.run_with(
            source,
            born + time::Duration::days(1),
            None,
            0,
            &mut FolderResolver::default(),
        );
        assert_eq!(
            (stats.verdict_deferred, stats.files_read, stats.bytes_repair),
            (0, 1, 0)
        );
        assert_eq!(stats.bytes_new, fs::metadata(&path).unwrap().len());
        env.cleanup();
    }
}

#[test]
fn later_opening_verdict_transitions_do_not_reread_counted_bytes() {
    let env = Env::new("composition-verdict-forward-only");
    let source = Source::Claude;
    env.run(
        source,
        OffsetDateTime::now_utc() - time::Duration::minutes(1),
        None,
    );
    let (path, born, _) = opening_verdict_fixture(&env, source);
    env.run(source, born + time::Duration::hours(7), None);
    let before = env.scope(source).agg;
    assert!(opening_tokens(&before) > 0);
    for (day, measured) in [(1, true), (2, false)] {
        let now = born + time::Duration::days(day);
        record_opening_verdict(&env, source, &path, now, measured);
        let stats = env.run(source, now, None);
        assert_eq!(
            (
                stats.verdict_deferred,
                stats.files_read,
                stats.bytes_new,
                stats.bytes_repair
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(env.scope(source).agg, before);
    }
    env.cleanup();
}

#[test]
fn first_run_is_forward_only_even_for_live_files() {
    let env = Env::uninstalled("composition-v2-first-run");
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
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.files_read),
        (0, 0, 0)
    );
    assert_eq!((stats.install_forward_only, stats.dormant_found), (2, 2));

    // Each file only counts what is appended after install.
    let appended = claude_turn(&cwd, day, 3);
    for path in [&live, &old] {
        append_records(path, &appended);
    }
    let stats = env.run(Source::Claude, now + time::Duration::hours(1), None);
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair),
        (2 * body(&appended).len() as u64, 0)
    );
    let first = total_tokens(&env.scope(Source::Claude).agg);
    assert!(first > 0);
    append_records(&old, &claude_turn(&cwd, day, 4));
    env.run(Source::Claude, now + time::Duration::hours(2), None);
    let second = total_tokens(&env.scope(Source::Claude).agg);
    assert_eq!(second * 2, first * 3);

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

/// A transcript of `source` in `env`, written now.
fn write_session(env: &Env, source: Source, name: &str, day: Date) -> (PathBuf, Vec<Value>) {
    let (claude, codex) = every_family(&env.cwd(), day);
    let (path, records) = match source {
        Source::Claude => (env.root.join(format!("p/{name}.jsonl")), claude),
        Source::Codex => (
            env.root
                .join(format!("2026/rollout-2026-10-22T00-00-00-{name}.jsonl")),
            codex,
        ),
    };
    write_records(&path, &records);
    (path, records)
}

/// An unrelated line every reader skips, dated `day`.
fn later_line(day: Date, n: u32) -> Value {
    json!({"type":"unused","timestamp":ts(day, n)})
}

#[test]
fn install_reads_nothing_from_files_still_being_written() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::uninstalled(&format!("composition-install-in-flight-{source:?}"));
        let now = OffsetDateTime::now_utc();
        // Sessions still being written when the app is installed.
        let (a, _) = write_session(&env, source, "a", now.date());
        let (b, _) = write_session(&env, source, "b", now.date());
        let stats = env.run(source, now, None);
        assert_eq!(
            (
                stats.bytes_new,
                stats.bytes_repair,
                stats.bytes_head,
                stats.files_read,
                stats.lines.lines
            ),
            (0, 0, 0, 0, 0),
            "{source:?}"
        );
        assert_eq!(
            (
                stats.install_forward_only,
                stats.dormant_found,
                stats.checkpoint_restarts,
                stats.full_read_waiting_files,
                stats.full_read_backlog_bytes
            ),
            (2, 2, 0, 0, 0)
        );
        let index = read_index(&env.state, source);
        for path in [&a, &b] {
            let pin = index
                .files
                .values()
                .find(|pin| Path::new(&pin.path) == path.as_path())
                .unwrap();
            let size = fs::metadata(path).unwrap().len();
            assert_eq!((pin.start, pin.waiting), (size, false));
        }
        assert!(index.scope_generations.is_empty(), "nothing counted");

        // The next day reads only what the sessions wrote since, even with
        // the whole repair budget free.
        let next = now + time::Duration::days(1);
        let line = later_line(next.date(), 1);
        append_records(&a, std::slice::from_ref(&line));
        let stats = env.run(source, next, None);
        assert_eq!(
            (stats.bytes_new, stats.bytes_repair, stats.lines.lines),
            (body(std::slice::from_ref(&line)).len() as u64, 0, 1)
        );
        assert_eq!(
            (stats.full_read_waiting_files, stats.install_forward_only),
            (0, 0)
        );
        env.cleanup();
    }
}

#[test]
fn file_created_after_install_is_read_from_its_start() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::uninstalled(&format!("composition-install-then-new-{source:?}"));
        let now = OffsetDateTime::now_utc();
        let (live, _) = write_session(&env, source, "a", now.date());
        assert_eq!(env.run(source, now, None).install_forward_only, 1);
        // Born after the install record's cutoff: new bytes from zero.
        let (born, records) = write_session(&env, source, "b", now.date());
        let size = fs::metadata(&born).unwrap().len();
        let stats = env.run(source, now + time::Duration::days(1), None);
        assert_eq!(
            (
                stats.bytes_new,
                stats.bytes_repair,
                stats.new_files,
                stats.install_forward_only,
                stats.lines.lines
            ),
            (size, 0, 1, 0, records.len() as u64),
            "{source:?}"
        );
        let scope = env.scope(source);
        let checkpoint = |path: &Path| {
            scope
                .files
                .values()
                .find(|checkpoint| Path::new(&checkpoint.path) == path)
                .cloned()
        };
        let read = checkpoint(&born).unwrap();
        assert_eq!(read.offset, size);
        assert!(checkpoint(&live).is_none(), "unchanged since install");
        env.cleanup();
    }
}

#[test]
fn earlier_build_install_backlog_keeps_draining() {
    let env = Env::uninstalled("composition-earlier-install-backlog");
    let now = base_now();
    let cwd = env.cwd();
    let older = env.root.join("p/older.jsonl");
    write_records(&older, &claude_turn(&cwd, now.date(), 1));
    File::options()
        .write(true)
        .open(&older)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
    let newer = env.root.join("p/newer.jsonl");
    write_records(&newer, &claude_turn(&cwd, now.date(), 2));
    env.run(Source::Claude, now - time::Duration::days(1), None);
    earlier_build_install_backlog(&env, Source::Claude, &[&older, &newer]);
    let older_size = fs::metadata(&older).unwrap().len();
    let newer_size = fs::metadata(&newer).unwrap().len();
    let run = |day: i64, budget: u64| {
        env.run_with(
            Source::Claude,
            now + time::Duration::days(day),
            None,
            budget,
            &mut FolderResolver::default(),
        )
    };

    // Budget for one file: the newest is read whole, the other waits.
    let stats = run(0, newer_size);
    assert_eq!(
        (stats.bytes_repair, stats.bytes_new, stats.files_read),
        (newer_size, 0, 1)
    );
    assert_eq!(
        (stats.full_read_waiting_files, stats.full_read_backlog_bytes),
        (1, older_size)
    );
    // No budget: still waiting, never dropped.
    let stats = run(1, 0);
    assert_eq!((stats.bytes_repair, stats.files_read), (0, 0));
    assert_eq!(
        (stats.full_read_waiting_files, stats.full_read_backlog_bytes),
        (1, older_size)
    );
    // Budget again: the rest drains, whole and from its start.
    let stats = run(2, REPAIR_BYTES_PER_DAY);
    assert_eq!((stats.bytes_repair, stats.files_read), (older_size, 1));
    assert_eq!(
        (stats.full_read_waiting_files, stats.full_read_backlog_bytes),
        (0, 0)
    );
    let scope = env.scope(Source::Claude);
    for path in [&older, &newer] {
        let checkpoint = scope
            .files
            .values()
            .find(|c| Path::new(&c.path) == path)
            .unwrap();
        assert_eq!(checkpoint.offset, fs::metadata(path).unwrap().len());
    }
    assert_eq!(v2_rows(&scope.agg), whole_rows_of(&[&older, &newer]));
    env.cleanup();
}

#[test]
fn agent_reset_starts_files_still_being_written_at_their_end() {
    let env = Env::new("composition-reset-in-flight");
    let now = base_now();
    let cwd = env.cwd();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&cwd, now.date(), 1));
    env.run(Source::Claude, now, None);
    // Still being written when the index is lost.
    append_records(&path, &claude_turn(&cwd, now.date(), 2));
    fs::remove_file(harvest::index_path(&env.state, Source::Claude)).unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(
        (
            stats.agent_resets,
            stats.install_forward_only,
            stats.bytes_new + stats.bytes_repair
        ),
        (1, 1, 0)
    );
    // The set-aside scope's reset commits the next day, still reading nothing.
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(
        (stats.scopes_committed, stats.bytes_new + stats.bytes_repair),
        (1, 0)
    );
    let line = later_line(now.date(), 3);
    append_records(&path, std::slice::from_ref(&line));
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.install_forward_only
        ),
        (body(std::slice::from_ref(&line)).len() as u64, 0, 0)
    );
    let checkpoint = &env.scope(Source::Claude).files["a.jsonl"];
    assert_eq!(checkpoint.offset, fs::metadata(&path).unwrap().len());
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
    let same_shard = (0..10_000)
        .map(|n| format!("other{n}.jsonl"))
        .find(|key| super::scope::shard_id(key) == super::scope::shard_id("idle.jsonl"))
        .unwrap();
    let other = env.root.join("p").join(same_shard);
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
fn codex_archive_never_read_while_plain_is_counted_unpinned() {
    let env = Env::new("composition-v2-archive-unpinned");
    let now = base_now();
    // Not zstd, so a decode would fail; the zero read and failure counts
    // show no counted read touched it.
    let compressed = env
        .root
        .join("archived_sessions/rollout-2026-10-01T00-00-00-zzz.jsonl.zst");
    fs::create_dir_all(compressed.parent().unwrap()).unwrap();
    fs::write(&compressed, b"not zstd").unwrap();
    let stats = env.run(Source::Codex, now, None);
    assert_eq!(
        (
            stats.archived,
            stats.archived_unpinned,
            stats.bytes_new + stats.bytes_repair + stats.bytes_head,
            stats.files_failed
        ),
        (0, 1, 0, 0)
    );
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
        (
            stats.archived,
            stats.archived_unpinned,
            stats.bytes_new + stats.bytes_repair
        ),
        (1, 0, 0)
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
    assert!(read_index(&env.state, Source::Codex).files[name].done);
    // An archive-only discovery does not read or rewrite its checkpoint shard.
    assert_eq!(scope.files[name].status, super::checkpoint::Status::Live);
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

fn whole_rows_of(paths: &[&Path]) -> Rows {
    let mut whole = Reading::default();
    for (n, path) in paths.iter().enumerate() {
        whole.read(Source::Claude, path, n as u32 + 1, &[]);
    }
    v2_rows(&whole.agg)
}

/// A second folder (its own scope under `FolderResolver`).
fn other_workspace(env: &Env) -> String {
    let dir = env.root.parent().unwrap().join("other");
    fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

fn manifest_of(env: &Env, cwd: &str) -> PathBuf {
    scope_path(&env.state, Source::Claude, &sha256_hex(&[cwd]))
}

/// Every state file of a scope, by name.
fn state_files(manifest: &Path) -> BTreeMap<String, Vec<u8>> {
    super::scope::scope_files(manifest)
        .into_iter()
        .map(|file| {
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&file).unwrap())
        })
        .collect()
}

fn sha_of(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

/// Damage a scope's newest committed state as named.
fn damage_scope_state(manifest: &Path, damage: &str) {
    let mut stored: Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    let generation = stored["generation"].as_u64().unwrap();
    let totals = manifest.with_extension(format!("totals.{generation}.zst"));
    match damage {
        "bad_manifest" => fs::write(manifest, b"{not json").unwrap(),
        "missing_manifest" => fs::remove_file(manifest).unwrap(),
        "totals_sha" => fs::write(&totals, b"not the committed totals").unwrap(),
        "missing_totals" => fs::remove_file(&totals).unwrap(),
        "malformed_totals" => {
            fs::write(&totals, b"{not json").unwrap();
            stored["totals"]["sha"] = json!(sha_of(&totals));
            fs::write(manifest, serde_json::to_vec(&stored).unwrap()).unwrap();
        }
        "unknown_totals_id" => {
            // A kind id this build does not know, with a matching hash.
            fn rename_one_kind(value: &mut Value) -> bool {
                match value {
                    Value::String(text) if kind_from_str(text).is_some() => {
                        *text = "future_id".to_string();
                        true
                    }
                    Value::Array(items) => items.iter_mut().any(rename_one_kind),
                    Value::Object(fields) => fields.values_mut().any(rename_one_kind),
                    _ => false,
                }
            }
            let mut value: Value = super::checkpoint::read_json(&totals).unwrap().unwrap();
            assert!(rename_one_kind(&mut value));
            super::checkpoint::write_packed(&totals, &value).unwrap();
            stored["totals"]["sha"] = json!(sha_of(&totals));
            fs::write(manifest, serde_json::to_vec(&stored).unwrap()).unwrap();
        }
        other => panic!("unknown damage {other}"),
    }
}

#[test]
fn reset_scope_uploads_again_and_then_reads_new_files_forward_only() {
    let env = Env::new("composition-v2-reset-upload");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    // A session started after install is read from its start.
    let later = day + time::Duration::days(1);
    let s2 = env.root.join("p/s2.jsonl");
    write_records(&s2, &claude_turn(&cwd, later, 2));
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(1),
        Some(&mut capture),
    );
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.checkpoint_restarts
        ),
        (fs::metadata(&s2).unwrap().len(), 0, 0)
    );
    assert_eq!(capture.payloads.len(), 2);
    assert_eq!(
        v2_rows(&env.scope(Source::Claude).agg),
        whole_rows_of(&[&path, &s2])
    );

    // Damaged state: quarantined (no upload that day), then reset at the
    // files' current ends. The acknowledged upload is sent again, marked
    // with the reset date, and no history is read again.
    let scope_id = sha256_hex(&[cwd.as_str()]);
    fs::write(scope_path(&env.state, Source::Claude, &scope_id), b"{}").unwrap();
    append_records(&path, &claude_turn(&cwd, day, 3));
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(2),
        Some(&mut capture),
    );
    assert_eq!(stats.scopes_quarantined, 1);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(capture.payloads.len(), 2);
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(3),
        Some(&mut capture),
    );
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(capture.payloads.len(), 3);
    let ymd = |date: Date| super::super::measure::date_ymd(date);
    let reset_at = ymd((now + time::Duration::days(2)).date());
    assert_eq!(capture.payloads[2]["history_reset_at"], reset_at);

    // After the reset a new session is read in full again, and only its
    // day is sent.
    let next = day + time::Duration::days(4);
    let s3 = env.root.join("p/s3.jsonl");
    write_records(&s3, &claude_turn(&cwd, next, 4));
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(4),
        Some(&mut capture),
    );
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.checkpoint_restarts
        ),
        (fs::metadata(&s3).unwrap().len(), 0, 0)
    );
    assert_eq!(capture.payloads.len(), 4);
    assert_eq!(capture.payloads[3]["history_reset_at"], reset_at);
    let dates: BTreeSet<String> = capture.payloads[3]["daily_aggregates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["date"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(dates, BTreeSet::from([ymd(next)]));
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&s3));
    env.cleanup();
}

#[test]
fn file_created_after_install_is_read_in_full_and_once_after_a_crash() {
    let env = Env::new("composition-v2-new-after-install");
    let now = base_now();
    let cwd = env.cwd();
    let a = env.root.join("p/a.jsonl");
    write_records(&a, &claude_turn(&cwd, now.date(), 1));
    env.run(Source::Claude, now, None);

    let day2 = now + time::Duration::days(1);
    let b = env.root.join("p/b.jsonl");
    write_records(&b, &claude_turn(&cwd, day2.date(), 2));
    let stats = env.run(Source::Claude, day2, None);
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.checkpoint_restarts,
            stats.dormant_found
        ),
        (fs::metadata(&b).unwrap().len(), 0, 0, 0)
    );
    assert_eq!(
        v2_rows(&env.scope(Source::Claude).agg),
        whole_rows_of(&[&a, &b])
    );

    // The run that first reads a new file commits its scope, then stops
    // before saving its pins.
    let day3 = now + time::Duration::days(2);
    let c = env.root.join("p/c.jsonl");
    write_records(&c, &claude_turn(&cwd, day3.date(), 3));
    harvest::tests::set_crash_after(Some(1));
    let stats = env.run(Source::Claude, day3, None);
    harvest::tests::set_crash_after(None);
    assert_eq!(stats.scopes_committed, 1);
    assert_eq!(stats.bytes_new, fs::metadata(&c).unwrap().len());
    let counted = v2_rows(&env.scope(Source::Claude).agg);
    assert_eq!(counted, whole_rows_of(&[&a, &b, &c]));
    // The committed checkpoint wins over the missing pin: nothing is read
    // twice, and nothing restarts.
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.checkpoint_restarts
        ),
        (0, 0, 0)
    );
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), counted);
    let more = claude_turn(&cwd, (now + time::Duration::days(4)).date(), 4);
    append_records(&c, &more);
    let stats = env.run(Source::Claude, now + time::Duration::days(4), None);
    assert_eq!(
        (
            stats.bytes_new,
            stats.bytes_repair,
            stats.checkpoint_restarts
        ),
        (body(&more).len() as u64, 0, 0)
    );
    assert_eq!(
        v2_rows(&env.scope(Source::Claude).agg),
        whole_rows_of(&[&a, &b, &c])
    );
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
    let run = |now: OffsetDateTime, resolver: &mut dyn ScopeResolver| {
        let mut run = Run {
            start_verdicts: Default::default(),
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
    // Installed before the session starts, so its transcript is new bytes.
    fs::create_dir_all(&env_root).unwrap();
    run(
        now - time::Duration::days(1),
        &mut super::scope::GitScopeResolver,
    );
    write_records(
        &path,
        &claude_turn(&worktree.to_string_lossy(), now.date(), 1),
    );
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
    let index: Index = super::checkpoint::read_json(&state.join("index-claude-code.json"))
        .unwrap()
        .unwrap();
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
    let stored = serde_json::to_string(&super::aggregate::StoredAggregate::from_aggregate(
        &scope.agg,
    ))
    .unwrap();
    assert!(!stored.contains(&in_worktree("src")));
    fs::remove_dir_all(base).unwrap();
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
fn totals_are_written_as_stored_without_a_copy() {
    let dir = scratch("composition-v2-aggregate-ref");
    let (claude, codex) = every_family("/w", fallback_date());
    for (source, records) in [(Source::Claude, claude), (Source::Codex, codex)] {
        let path = dir.join(format!("{}.jsonl", source.label()));
        write_records(&path, &records);
        let mut agg = read_whole(source, &[&path]).agg;
        agg.day_generation.insert(day_of(fallback_date()), 3);
        let copied = super::aggregate::StoredAggregate::from_aggregate(&agg);
        let written = |generations| {
            serde_json::to_string(&super::aggregate::AggregateRef {
                agg: &agg,
                generations,
            })
            .unwrap()
        };
        assert_eq!(written(true), serde_json::to_string(&copied).unwrap());
        // Without generations: the same rows, no generations.
        let mut copied = copied;
        let mut value = serde_json::to_value(&copied).unwrap();
        value["day_generation"] = json!([]);
        assert_eq!(
            serde_json::from_str::<Value>(&written(false)).unwrap(),
            value
        );
        // And it loads back as the same totals.
        copied = serde_json::from_str(&written(true)).unwrap();
        let back = copied.into_aggregate();
        assert_eq!(v2_rows(&back), v2_rows(&agg));
    }
    // A stored kind or part id this build does not know is bad state.
    assert!(serde_json::from_str::<super::aggregate::Id<Kind>>("\"files_read\"").is_ok());
    assert!(serde_json::from_str::<super::aggregate::Id<Kind>>("\"no_such_kind\"").is_err());
    fs::remove_dir_all(dir).unwrap();
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
    let (mut claude, mut codex) = every_family("/w", fallback_date());
    let reloads: Vec<_> = claude
        .iter()
        .filter(|row| row["type"] == "attachment" || row["message"]["content"].is_string())
        .cloned()
        .collect();
    claude.extend(reloads);
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

    codex.push(codex[1].clone());
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
    assert_eq!(
        developer,
        BTreeSet::from(["environment", "other", "start_not_measured"])
    );
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

/// `records` as another session's.
fn as_session(records: Vec<Value>, session: &str) -> Vec<Value> {
    records
        .into_iter()
        .map(|mut record| {
            record["sessionId"] = json!(session);
            record["uuid"] = json!(format!("{session}-{}", record["uuid"].as_str().unwrap()));
            record
        })
        .collect()
}

#[test]
fn idle_checkpoints_go_cold_and_a_cold_rewrite_restarts_at_its_end() {
    let env = Env::new("composition-v2-cold");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let file = format!("{cwd}/src/shared.rs");
    let idle = env.root.join("p/idle.jsonl");
    let mut records = claude_turn(&cwd, day, 1);
    records.extend(claude_read_turn(&cwd, day, 2, &file));
    write_records(&idle, &records);
    env.run(Source::Claude, now, None);
    let first = env.scope(Source::Claude);
    assert!(first
        .files
        .values()
        .all(|checkpoint| checkpoint.cold.is_none()));
    let day_tokens = |agg: &Aggregate| -> u64 {
        agg.days
            .iter()
            .filter(|((row_day, _), _)| *row_day == day_of(day))
            .map(|(_, bucket)| bucket.tokens)
            .sum()
    };

    // Days later another session reads the same file. The idle file (its
    // file unchanged for over two days) goes cold: its totals stay, its
    // share is dropped, and it still counts as a session that read the file.
    let later = now + time::Duration::days(13);
    let same_shard = (0..10_000)
        .map(|n| format!("other{n}.jsonl"))
        .find(|key| super::scope::shard_id(key) == super::scope::shard_id("idle.jsonl"))
        .unwrap();
    let other = env.root.join("p").join(same_shard);
    write_records(
        &other,
        &as_session(claude_read_turn(&cwd, later.date(), 3, &file), "s2"),
    );
    let mut capture = Capture::default();
    let stats = env.run(Source::Claude, later, Some(&mut capture));
    assert_eq!(stats.cold_compacted, 1);
    let scope = env.scope(Source::Claude);
    let cold = |scope: &super::scope::Scope| {
        scope
            .files
            .values()
            .find(|checkpoint| checkpoint.path.ends_with("idle.jsonl"))
            .cloned()
            .unwrap()
    };
    let checkpoint = cold(&scope);
    assert!(checkpoint.cold.is_some());
    assert_eq!(checkpoint.contribution.file_days().count(), 0);
    assert_eq!(checkpoint.contribution.session(), Some("s1"));
    assert_eq!(day_tokens(&scope.agg), day_tokens(&first.agg));
    let row = capture.payloads[0]["top_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["relative_path_or_name"] == "src/shared.rs")
        .cloned()
        .unwrap();
    assert_eq!(
        (&row["session_count"], &row["session_count_30d"]),
        (&json!(2), &json!(2))
    );
    let totals = total_tokens(&scope.agg);

    // A cold file rewritten is never read again: it restarts at its end,
    // counted, and nothing changes.
    let replacement = env.root.join("p/idle.tmp");
    write_records(&replacement, &claude_turn(&cwd, day, 7));
    fs::rename(&replacement, &idle).unwrap();
    let stats = env.run(Source::Claude, later + time::Duration::days(1), None);
    assert_eq!(
        (stats.cold_restarted, stats.bytes_repair, stats.bytes_new),
        (1, 0, 0)
    );
    let scope = env.scope(Source::Claude);
    assert_eq!(total_tokens(&scope.agg), totals);
    assert!(cold(&scope).cold.is_some());

    // Lines appended to it later count as new lines.
    let more = claude_turn(&cwd, later.date(), 8);
    append_records(&idle, &more);
    let stats = env.run(Source::Claude, later + time::Duration::days(2), None);
    assert_eq!(stats.bytes_new as usize, body(&more).len());
    assert!(total_tokens(&env.scope(Source::Claude).agg) > totals);
    env.cleanup();
}

#[test]
fn compaction_keeps_open_tokens_per_day_and_kind() {
    use crate::composition_kinds::Part;
    let mut state = ParseState {
        session: "s".into(),
        ..Default::default()
    };
    state.add_open(1, &Slot::plain(Kind::CommandOutput, Part::Git), 10);
    state.add_open(1, &Slot::plain(Kind::CommandOutput, Part::Search), 30);
    state.add_open(1, &Slot::plain(Kind::FilesRead, Part::FileTool), 5);
    state.add_open(2, &Slot::plain(Kind::CommandOutput, Part::Git), 7);
    let mut checkpoint = Checkpoint {
        path: String::new(),
        dev: 0,
        ino: 0,
        created: 0,
        offset: 0,
        skipping: false,
        head: Default::default(),
        tail: Default::default(),
        size: 0,
        mtime: (0, 0),
        parser_version: String::new(),
        status: Status::Live,
        parse: StoredParse::from_state(&state),
        contribution: Default::default(),
        last_seen: 0,
        cold: None,
    };
    assert!(checkpoint.compact());
    let open: BTreeSet<(Day, Kind, Part, u64)> = checkpoint
        .parse
        .clone()
        .into_state()
        .unwrap()
        .open
        .into_iter()
        .map(|(day, slot, tokens)| (day, slot.kind, slot.part, tokens))
        .collect();
    // Each day and kind keeps its tokens, on its largest part.
    assert_eq!(
        open,
        BTreeSet::from([
            (1, Kind::CommandOutput, Part::Search, 40),
            (1, Kind::FilesRead, Part::FileTool, 5),
            (2, Kind::CommandOutput, Part::Git, 7),
        ])
    );
    // Compacting again changes nothing; the cold form round-trips.
    assert!(!checkpoint.compact());
    let json = serde_json::to_string(&checkpoint).unwrap();
    let back: Checkpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cold, checkpoint.cold);
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
    super::checkpoint::read_json(&harvest::index_path(state, source))
        .unwrap()
        .unwrap()
}

/// Turn install pins (each at its file's end) into the backlog an earlier
/// build's install left for files live at install: unscoped, from offset
/// zero, waiting for a full read within the repair budget.
fn earlier_build_install_backlog(env: &Env, source: Source, paths: &[&Path]) {
    let mut index = read_index(&env.state, source);
    for path in paths {
        let pin = index
            .files
            .values_mut()
            .find(|pin| Path::new(&pin.path) == *path)
            .unwrap();
        assert!(pin.scope.is_none() && pin.start == pin.size && !pin.waiting);
        pin.start = 0;
        pin.waiting = true;
    }
    super::checkpoint::write_json(&harvest::index_path(&env.state, source), &index).unwrap();
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
    let run = |now: OffsetDateTime| {
        let mut resolver = super::scope::GitScopeResolver;
        let mut run = Run {
            start_verdicts: Default::default(),
            state_dir: state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver: &mut resolver,
            repair_left: REPAIR_BYTES_PER_DAY,
        };
        run_source(&mut run, Source::Claude, std::slice::from_ref(&root), None)
    };
    // Installed before the main checkout's session starts (new bytes).
    fs::create_dir_all(&root).unwrap();
    run(now - time::Duration::days(1));
    write_records(
        &root.join("p/main.jsonl"),
        &claude_turn(&main.to_string_lossy(), now.date(), 1),
    );
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
    // The subprocess round trip preserves witnesses and known folders.
    cache = serde_json::from_slice(&serde_json::to_vec(&cache).unwrap()).unwrap();
    // A second wake with nothing new reads no pins and adds nothing.
    let io = super::checkpoint::IO_BYTES.with(|io| io.get());
    assert_eq!(harvest::map_worktrees(&state, today, &mut cache), 0);
    assert_eq!(super::checkpoint::IO_BYTES.with(|io| io.get()), io);
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
    let mut scope = scope;
    scope
        .load_all_shards(&scope_path(&state, Source::Claude, &scope_id))
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
    // The first run is the install: the old file starts at its end.
    let env = Env::uninstalled("composition-v2-dormant-resume");
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
fn upload_labels_need_a_fetched_hint_that_allows_them() {
    use super::aggregate::Bucket;
    use super::scope::{SavedIdentity, Scope};
    use crate::snapshot_client::{decode_activity_hint, workspace_labels_allowed};
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
                workspace_kind: Some("repository_root".into()),
                workspace_label: Some("repo".into()),
            },
            common_dir: None,
        },
    );
    let bucket = Bucket {
        events: 1,
        tokens: 10,
        residency: 10,
        images: 0,
    };
    scope.agg.days.insert((today, Kind::FilesRead), bucket);
    scope.agg.day_generation.insert(today, 1);
    let payload = |labels_enabled: bool| {
        let mut capture = Capture::default();
        let target = UploadTarget {
            uploader: &mut capture,
            machine_id: "machine-test",
            destination: "device|machine|api",
            labels_enabled,
            details_enabled: false,
        };
        let (request, _) =
            super::upload::build_request(&scope, Source::Claude, &target, now, window, 0);
        serde_json::to_value(&request).unwrap()
    };
    let hint = |labels: bool| {
        decode_activity_hint(json!({
            "source": "claude-code", "server_time": "2026-10-25T10:00:00Z",
            "record_count_15m": 0, "record_count_24h": 0,
            "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
            "workspace_labels_enabled": labels,
            "recommended_scan_after": "2026-10-25T10:05:00Z",
        }))
        .unwrap()
    };

    // Policy ON keeps today's labelled payload.
    let on = payload(workspace_labels_allowed(Some(&hint(true))));
    assert_eq!(on, payload(true));
    assert_eq!(on["workspace_label"], "repo");
    assert_eq!(on["repository_label"], "repo");
    // Policy OFF and a failed hint fetch both withhold every label.
    let withheld = payload(false);
    assert_eq!(
        payload(workspace_labels_allowed(Some(&hint(false)))),
        withheld
    );
    assert_eq!(payload(workspace_labels_allowed(None)), withheld);
    for field in [
        "workspace_label",
        "workspace_label_source",
        "repository_label",
        "repository_label_source",
    ] {
        assert!(withheld[field].is_null(), "{field} must be withheld");
    }
    assert_eq!(withheld["repository_hash"], on["repository_hash"]);
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
        totals.days.push((today, vec![(kind, 10 + n)]));
    }
    let mut capture = Capture::default();
    let target = UploadTarget {
        uploader: &mut capture,
        machine_id: "machine-test",
        destination: "device|machine|api",
        labels_enabled: true,
        details_enabled: false,
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

mod scale;

#[test]
fn incremental_scope_totals_equal_full_recompute_after_appends() {
    let env = Env::new("composition-incremental-recompute");
    let now = base_now();
    let cwd = env.cwd();
    let paths: Vec<_> = (0..12)
        .map(|n| env.root.join(format!("p/s{n}.jsonl")))
        .collect();
    for (n, path) in paths.iter().enumerate() {
        write_records(
            path,
            &as_session(
                claude_read_turn(&cwd, now.date(), 1, &format!("{cwd}/src/f{}.rs", n % 3)),
                &format!("session{n}"),
            ),
        );
    }
    env.run(Source::Claude, now, None);
    for (n, path) in paths.iter().enumerate().filter(|(n, _)| n % 2 == 0) {
        append_records(
            path,
            &as_session(
                claude_read_turn(
                    &cwd,
                    now.date(),
                    2,
                    &format!("{cwd}/src/f{}.rs", (n + 1) % 3),
                ),
                &format!("session{n}"),
            ),
        );
    }
    env.run(Source::Claude, now + time::Duration::days(1), None);
    let mut full = Reading::in_workspace(&env.workspace);
    for path in &paths {
        full.read(Source::Claude, path, 1, &[]);
    }
    let scope = env.scope(Source::Claude);
    assert_same_totals(&scope.agg, &full.agg);
    let mut recomputed: Vec<_> = scope
        .files
        .values()
        .flat_map(super::scope::checkpoint_members)
        .collect();
    recomputed.sort_unstable();
    assert_eq!(scope.file_sessions, recomputed);
    env.cleanup();
}

#[test]
fn shard_write_before_manifest_commit_keeps_old_checkpoint_recoverable() {
    let env = Env::new("composition-shard-crash");
    let now = base_now();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let mut scope = env.scope(Source::Claude);
    let manifest = scope_path(&env.state, Source::Claude, &scope.scope_id);
    let old_offset = scope.files["s.jsonl"].offset;
    scope.files.get_mut("s.jsonl").unwrap().offset += 123;
    scope
        .save_shard(
            &manifest,
            super::scope::shard_id("s.jsonl"),
            scope.generation + 1,
        )
        .unwrap();
    // Simulate exit after the immutable shard write, before the manifest.
    let recovered = env.scope(Source::Claude);
    assert_eq!(recovered.files["s.jsonl"].offset, old_offset);
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bad_state, 0);
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));
    env.cleanup();
}

#[test]
fn unknown_checkpoint_id_restarts_only_that_checkpoint_without_reading_history() {
    for field in [
        "open_kind",
        "open_part",
        "call_share",
        "contribution_part",
        "contribution_file",
        "contribution_session",
    ] {
        let env = Env::new(&format!("composition-unknown-id-{field}"));
        let now = base_now();
        let path = env.root.join("p/a.jsonl");
        let other = env.root.join("p/b.jsonl");
        for path in [&path, &other] {
            let mut records = claude_turn(&env.cwd(), now.date(), 1);
            records.extend(claude_read_turn(
                &env.cwd(),
                now.date(),
                2,
                &format!("{}/src/lib.rs", env.cwd()),
            ));
            write_records(path, &records);
        }
        env.run(Source::Claude, now, None);
        let mut scope = env.scope(Source::Claude);
        let manifest = scope_path(&env.state, Source::Claude, &scope.scope_id);
        let checkpoint = scope.files.get_mut("a.jsonl").unwrap();
        let mut encoded = serde_json::to_value(&*checkpoint).unwrap();
        let part_row = encoded["contribution"]["parts"][0].clone();
        match field {
            "open_kind" => encoded["parse"]["open"][0][1] = json!("future_id"),
            "open_part" => encoded["parse"]["open"][0][2] = json!("future_id"),
            "call_share" => {
                encoded["parse"]["open_calls"] = json!([{
                    "id": "call-open", "kind": part_row[1], "part": part_row[2],
                    "tool": "Read", "file": null,
                    "shares": [["future_id", part_row[2], 1, null, null]],
                    "items": [], "seq": 0
                }])
            }
            "contribution_part" => encoded["contribution"]["parts"][0][2] = json!("future_id"),
            "contribution_file" => encoded["contribution"]["files"][0][2] = json!("future_id"),
            "contribution_session" => {
                encoded["contribution"]["sessions"][0][1] = json!("future_id")
            }
            _ => unreachable!(),
        }
        *checkpoint = serde_json::from_value(encoded).unwrap();
        assert!(!checkpoint.ids_known(), "{field}");
        let id = super::scope::shard_id("a.jsonl");
        scope
            .files
            .retain(|key, _| super::scope::shard_id(key) == id);
        scope.generation += 1;
        scope.save_shard(&manifest, id, scope.generation).unwrap();
        super::scope::save_scope(&manifest, Source::Claude, &scope).unwrap();
        let members = env.scope(Source::Claude).file_sessions;
        append_records(&path, &claude_turn(&env.cwd(), now.date(), 3));
        let more = claude_turn(&env.cwd(), now.date(), 4);
        append_records(&other, &more);
        let before = total_tokens(&env.scope(Source::Claude).agg);
        let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
        assert_eq!(
            (
                stats.checkpoint_restarts,
                stats.bad_state,
                stats.bytes_repair
            ),
            (1, 0, 0),
            "{field}"
        );
        assert_eq!(stats.bytes_new, body(&more).len() as u64, "{field}");
        let after = env.scope(Source::Claude);
        assert_eq!(
            total_tokens(&after.agg),
            before + tokens_of(&[&other], &more),
            "{field}"
        );
        assert_eq!(
            after.files["a.jsonl"].offset,
            fs::metadata(&path).unwrap().len()
        );
        assert!(after.files["a.jsonl"].ids_known());
        // Its counted files keep their session counts.
        assert!(members.iter().all(|row| after.file_sessions.contains(row)));

        // Its history can never be replaced, so a rewrite never adds it twice.
        let mut rewritten = claude_turn(&env.cwd(), now.date(), 5);
        rewritten.extend(claude_turn(&env.cwd(), now.date(), 6));
        write_records(&path, &rewritten);
        let before = total_tokens(&after.agg);
        let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
        assert_eq!(
            (stats.cold_restarted, stats.bytes_repair),
            (1, 0),
            "{field}"
        );
        assert_eq!(total_tokens(&env.scope(Source::Claude).agg), before);
        env.cleanup();
    }
}

/// Tokens `records` add when appended to the files at `paths`, as one read.
fn tokens_of(paths: &[&Path], records: &[Value]) -> u64 {
    let read = |with: bool| {
        let dir = scratch("composition-tokens-of");
        let mut reading = Reading::default();
        for (n, path) in paths.iter().enumerate() {
            let copy = dir.join(format!("{n}.jsonl"));
            let mut text = fs::read(path).unwrap();
            if !with {
                text.truncate(text.len() - body(records).len());
            }
            fs::write(&copy, text).unwrap();
            reading.read(Source::Claude, &copy, n as u32 + 1, &[]);
        }
        fs::remove_dir_all(dir).unwrap();
        total_tokens(&reading.agg)
    };
    read(true) - read(false)
}

#[test]
fn unmodified_shard_is_not_rewritten() {
    let env = Env::new("composition-untouched-shard");
    let now = base_now();
    let a = env.root.join("p/a.jsonl");
    let b = env.root.join("p/b.jsonl");
    assert_ne!(
        super::scope::shard_id("a.jsonl"),
        super::scope::shard_id("b.jsonl")
    );
    for path in [&a, &b] {
        write_records(path, &claude_turn(&env.cwd(), now.date(), 1));
    }
    env.run(Source::Claude, now, None);
    let scope = env.scope(Source::Claude);
    let manifest = scope_path(&env.state, Source::Claude, &scope.scope_id);
    let id = super::scope::shard_id("a.jsonl");
    let shard = manifest.with_extension(format!("s{id:03}.{}.zst", scope.generation));
    let saved = fs::read(&shard).unwrap();
    let modified = fs::metadata(&shard).unwrap().modified().unwrap();
    append_records(&b, &claude_turn(&env.cwd(), now.date(), 2));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bad_state, 0);
    assert_eq!(fs::read(&shard).unwrap(), saved);
    assert_eq!(fs::metadata(&shard).unwrap().modified().unwrap(), modified);
    env.cleanup();
}

/// Only the shards a run reads are checked. Damage in an untouched shard
/// is found when a read first loads it, before anything is read.
#[test]
fn damaged_untouched_shard_is_found_when_first_loaded() {
    let env = Env::new("composition-untouched-shard-damage");
    let now = base_now();
    let a = env.root.join("p/a.jsonl");
    let b = env.root.join("p/b.jsonl");
    assert_ne!(
        super::scope::shard_id("a.jsonl"),
        super::scope::shard_id("b.jsonl")
    );
    for path in [&a, &b] {
        write_records(path, &claude_turn(&env.cwd(), now.date(), 1));
    }
    env.run(Source::Claude, now, None);
    let manifest = manifest_of(&env, &env.cwd());
    damage_shard(&manifest, "a.jsonl", "truncated");
    let more = claude_turn(&env.cwd(), now.date(), 2);
    append_records(&b, &more);
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bad_state, 0);
    assert_eq!(stats.bytes_new, body(&more).len() as u64);
    append_records(&a, &claude_turn(&env.cwd(), now.date(), 3));
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(
        (
            stats.bad_state,
            stats.scopes_quarantined,
            stats.files_quarantined
        ),
        (1, 1, 2)
    );
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    env.cleanup();
}

#[test]
fn request_one_is_unmeasured_until_the_first_model_response_including_splits() {
    for source in [Source::Claude, Source::Codex] {
        let dir = scratch("composition-request-one");
        let path = dir.join("s.jsonl");
        let (claude, codex) = every_family("/w", fallback_date());
        let records = match source {
            Source::Claude => claude,
            Source::Codex => codex,
        };
        let first_response = match source {
            Source::Claude => 5,
            Source::Codex => 3,
        };
        write_records(&path, &records[..first_response]);
        let reading = read_whole(source, &[&path]);
        assert!(!reading.agg.all_parts.is_empty());
        assert!(reading
            .agg
            .all_parts
            .keys()
            .all(|slot| slot.kind == Kind::AutomaticAdditions
                && slot.part == crate::composition_kinds::Part::StartNotMeasured));
        write_records(&path, &records);
        assert_split_parity(Reading::default, source, &[&path]);
        let reading = read_whole(source, &[&path]);
        assert!(reading
            .agg
            .all_parts
            .keys()
            .any(|slot| slot.kind == Kind::FilesRead));
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn local_open_call_paths_never_appear_in_uploads() {
    let env = Env::new("composition-open-path-privacy");
    let now = base_now();
    let secret_path = format!("{}/private-scratch/src/example.rs", env.cwd());
    let records = claude_read_turn(&env.cwd(), now.date(), 1, &secret_path);
    let path = env.root.join("p/s.jsonl");
    // Persist a call whose result has not arrived yet.
    write_records(&path, &records[..1]);
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    let scope = env.scope(Source::Claude);
    let stored = serde_json::to_string(&scope.files["s.jsonl"]).unwrap();
    assert!(stored.contains(&secret_path));
    assert!(!serde_json::to_string(&capture.payloads)
        .unwrap()
        .contains(&env.cwd()));
    append_records(&path, &records[1..]);
    env.run(
        Source::Claude,
        now + time::Duration::days(1),
        Some(&mut capture),
    );
    let wire = serde_json::to_string(&capture.payloads).unwrap();
    assert!(!wire.contains(&secret_path));
    assert!(!wire.contains(&env.cwd()));
    assert!(wire.contains("example.rs"));
    env.cleanup();
}

#[test]
fn shared_max_fixture_contains_per_file_session_counts() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/context-composition/kinds_v2_max.json"
    ))
    .unwrap();
    assert_eq!(fixture["kinds_version"], 2);
    for row in fixture["top_files"].as_array().unwrap() {
        assert!(
            row["session_count"].as_u64().unwrap() >= row["session_count_30d"].as_u64().unwrap()
        );
    }
}

#[test]
fn committed_manifest_recovers_a_crash_before_the_single_pins_write() {
    let env = Env::new("composition-manifest-pins-crash");
    let now = base_now();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let index = harvest::index_path(&env.state, Source::Claude);
    let old = fs::read(&index).unwrap();
    let modified = fs::metadata(&index).unwrap().modified().unwrap();
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    env.run(Source::Claude, now + time::Duration::days(1), None);
    let expected = env.scope(Source::Claude).agg;
    // Keep the scope commit, restore the pre-run pins and their timestamp.
    fs::write(&index, old).unwrap();
    File::options()
        .write(true)
        .open(&index)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.bad_state),
        (0, 0, 0)
    );
    assert_eq!(stats.pins_rebuilt, 1);
    assert_eq!(env.scope(Source::Claude).agg, expected);
    env.cleanup();
}

#[test]
fn manifest_generation_recovers_pins_even_with_older_manifest_timestamp() {
    let env = Env::new("composition-generation-recovery");
    let now = base_now();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let pins = harvest::index_path(&env.state, Source::Claude);
    let old = fs::read(&pins).unwrap();
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    env.run(Source::Claude, now + time::Duration::days(1), None);
    let expected = env.scope(Source::Claude).agg;
    // Timestamp-based recovery would skip the completed scope here.
    fs::write(&pins, old).unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.pins_rebuilt),
        (0, 0, 1)
    );
    assert_eq!(env.scope(Source::Claude).agg, expected);
    env.cleanup();
}

#[test]
fn codex_agent_message_closes_request_one_across_checkpoints() {
    let env = Env::new("composition-codex-response-boundary");
    let now = base_now();
    let path = env.root.join("rollout-test.jsonl");
    write_records(
        &path,
        &[
            json!({"timestamp":ts(now.date(),1),"type":"session_meta","payload":{"id":"s","cwd":env.cwd()}}),
            json!({"timestamp":ts(now.date(),2),"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"first request"}]}}),
            json!({"timestamp":ts(now.date(),3),"type":"response_item","payload":{"type":"agent_message","content":[]}}),
        ],
    );
    env.run(Source::Codex, now, None);
    append_records(
        &path,
        &[
            json!({"timestamp":ts(now.date(),4),"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"next request"}]}}),
            json!({"timestamp":ts(now.date(),5),"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"later rules"}]}}),
        ],
    );
    env.run(Source::Codex, now + time::Duration::days(1), None);
    let scope = env.scope(Source::Codex);
    let tokens = |part| {
        scope
            .agg
            .all_parts
            .iter()
            .filter(|(slot, _)| slot.part == part)
            .map(|(_, bucket)| bucket.tokens)
            .sum::<u64>()
    };
    use crate::composition_kinds::Part;
    assert_eq!(tokens(Part::StartNotMeasured), tokens_for("first request"));
    assert!(tokens(Part::ByYou) > 0);
    assert!(tokens(Part::Other) > 0);
    env.cleanup();
}

#[test]
fn identity_and_scope_probes_do_not_prefetch_large_tool_output() {
    let env = Env::new("composition-bounded-head-prefetch");
    let path = env.root.join("p/s.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"user","sessionId":"s","isSidechain":false,"cwd":env.cwd(),"message":{"content":"start"}}),
            json!({"type":"user","message":{"content":"x".repeat(2 * 1024 * 1024)}}),
        ],
    );
    super::checkpoint::IO_BYTES.with(|io| io.set((0, 0)));
    let (cwds, _) = super::file::head_cwds(&path, Instant::now() + Duration::from_secs(5)).unwrap();
    assert_eq!(cwds, vec![env.cwd()]);
    let (state, _) = new_parse_state(Source::Claude, &path, 0);
    assert_eq!(&*state.session, "s");
    let read = super::checkpoint::IO_BYTES.with(|io| io.get().0);
    assert!(read <= 2 * 8192, "head probes read {read} bytes");
    env.cleanup();
}

#[test]
fn request_one_boundary_does_not_allocate_large_skipped_prelude_text() {
    let large = "x".repeat(8 * 1024 * 1024);
    for row in [
        json!({"type":"world_state","payload":{"text":large}}),
        json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":large}]}}),
    ] {
        let bytes = serde_json::to_vec(&row).unwrap();
        let (closed, stats) =
            crate::retry_allocation_probe::measure(|| super::codex::request1_input_closed(&bytes));
        assert!(!closed);
        assert!(
            stats.requested_peak < 128 * 1024,
            "prelude boundary allocated {} bytes",
            stats.requested_peak
        );
    }
}

#[test]
#[ignore = "private subprocess fixture"]
fn composition_worker_process_fixture() {
    if std::env::var_os("COMPOSITION_WORKER_FIXTURE").is_none() {
        return;
    }
    let input: Vec<String> = serde_json::from_reader(std::io::stdin().lock()).unwrap();
    if input.is_empty() {
        std::process::exit(7);
    }
    let scratch = vec![42u8; 8 * 1024 * 1024];
    std::hint::black_box(&scratch);
    harvest::write_worker_reply(&(std::process::id(), input)).unwrap();
}

#[test]
fn worker_process_waits_for_exit_and_preserves_hourly_metadata() {
    let command = || {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "context_composition::v2::tests::composition_worker_process_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("COMPOSITION_WORKER_FIXTURE", "1");
        cmd
    };
    let input = vec!["workspace-key".to_string()];
    let (pid, output): (u32, Vec<String>) =
        harvest::run_worker_process(&mut command(), &input).unwrap();
    assert_ne!(pid, std::process::id());
    assert_eq!(output, input);
    // wait_with_output reaps the worker, including when it exits unsuccessfully.
    let failed: anyhow::Result<(u32, Vec<String>)> =
        harvest::run_worker_process(&mut command(), &Vec::<String>::new());
    assert!(failed.is_err());
}

/// `count` transcript names sharing the checkpoint shard of `a.jsonl`.
fn same_shard_names(count: usize) -> Vec<String> {
    let id = super::scope::shard_id("a.jsonl");
    (0..)
        .map(|n| format!("b{n}.jsonl"))
        .filter(|name| super::scope::shard_id(name) == id)
        .take(count)
        .collect()
}

/// Remove or cut short the committed shard file holding `key`.
fn damage_shard(manifest: &Path, key: &str, damage: &str) {
    let stored: Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    let id = super::scope::shard_id(key);
    let generation = stored["shards"][id.to_string()]["generation"]
        .as_u64()
        .unwrap();
    let file = manifest.with_extension(format!("s{id:03}.{generation}.zst"));
    match damage {
        "missing" => fs::remove_file(&file).unwrap(),
        "truncated" => {
            let bytes = fs::read(&file).unwrap();
            fs::write(&file, &bytes[..bytes.len() / 2]).unwrap();
        }
        other => panic!("unknown damage {other}"),
    }
}

#[test]
fn full_reads_stop_at_their_granted_end() {
    let env = Env::uninstalled("composition-v2-repair-end");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let path = env.root.join("p/s.jsonl");
    write_records(&path, &claude_turn(&cwd, day, 1));
    // A full read waiting from an earlier build's install.
    env.run(Source::Claude, now - time::Duration::days(1), None);
    earlier_build_install_backlog(&env, Source::Claude, &[&path]);
    let granted = fs::metadata(&path).unwrap().len();
    // The file grows between discovery and its open; the budget holds only
    // its size at discovery.
    let more = claude_turn(&cwd, day, 2);
    harvest::tests::set_grow_before_open(&path, body(&more).into_bytes());
    let stats = env.run_with(
        Source::Claude,
        now,
        None,
        granted,
        &mut FolderResolver::default(),
    );
    assert_eq!(
        (stats.bytes_repair, stats.bytes_new, stats.repair_waiting),
        (granted, 0, 0)
    );
    // The appended bytes are read forward by the next run.
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(
        (stats.bytes_repair, stats.bytes_new),
        (0, body(&more).len() as u64)
    );
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));
    env.cleanup();
}

#[test]
fn new_state_folders_are_flushed_into_their_parents() {
    let root = scratch("composition-v2-durable-dirs");
    let file = root.join("a/b/state.json");
    super::checkpoint::SYNCED_DIRS.with(|dirs| dirs.borrow_mut().clear());
    super::checkpoint::write_json(&file, &json!({"x": 1})).unwrap();
    let synced = super::checkpoint::SYNCED_DIRS.with(|dirs| dirs.take());
    // Each new folder's entry is flushed before anything inside it commits.
    assert_eq!(synced, vec![root.clone(), root.join("a"), root.join("a/b")]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn each_shard_is_hashed_once_however_many_files_change() {
    let env = Env::new("composition-v2-verify-once");
    let now = base_now();
    let names = same_shard_names(2);
    for name in ["a.jsonl", names[0].as_str(), names[1].as_str()] {
        write_records(
            &env.root.join("p").join(name),
            &claude_turn(&env.cwd(), now.date(), 1),
        );
    }
    env.run(Source::Claude, now, None);
    let manifest = manifest_of(&env, &env.cwd());
    let mut scope = load_scope(
        &manifest,
        Source::Claude,
        &sha256_hex(&[env.cwd().as_str()]),
    )
    .unwrap()
    .unwrap();
    let id = super::scope::shard_id("a.jsonl");
    let shard = fs::read_dir(manifest.parent().unwrap())
        .unwrap()
        .flatten()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains(&format!(".s{id:03}."))
        })
        .unwrap()
        .path();
    super::checkpoint::IO_BYTES.with(|io| io.set((0, 0)));
    assert!(scope.verify_shards(&manifest, [id, id, id]).is_empty());
    assert!(scope.verify_shards(&manifest, [id]).is_empty());
    let read = super::checkpoint::IO_BYTES.with(|io| io.get().0);
    assert_eq!(read, fs::metadata(&shard).unwrap().len());
    env.cleanup();
}

#[test]
fn uncommitted_first_scope_shards_remain_pending() {
    let env = Env::new("composition-v2-uncommitted-first-shards");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    harvest::tests::set_fail_scope_commit(true);
    let stats = env.run(Source::Claude, now, None);
    harvest::tests::set_fail_scope_commit(false);
    assert_eq!(stats.scopes_committed, 0);
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!((stats.scopes_quarantined, stats.scopes_committed), (0, 1));
    // Born after the install: read again from its start as new bytes.
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair),
        (fs::metadata(&path).unwrap().len(), 0)
    );
    assert_eq!(v2_rows(&env.scope(Source::Claude).agg), whole_rows(&path));
    env.cleanup();
}

/// Damage in any part of a scope stops that scope, including unchanged
/// siblings. A later run pins every file at its then-current end.
#[test]
fn bad_scope_state_quarantines_and_resumes_forward_only() {
    for damage in [
        "bad_manifest",
        "missing_manifest",
        "totals_sha",
        "missing_totals",
        "malformed_totals",
        "unknown_totals_id",
        "missing_shard",
        "truncated_shard",
    ] {
        let env = Env::new(&format!("composition-forward-reset-{damage}"));
        let now = base_now();
        let cwd = env.cwd();
        let other_cwd = other_workspace(&env);
        let a = env.root.join("p/a.jsonl");
        let b = env.root.join("p").join(same_shard_names(1).remove(0));
        let other = env.root.join("q/other.jsonl");
        for (path, scope) in [(&a, &cwd), (&b, &cwd), (&other, &other_cwd)] {
            write_records(path, &claude_turn(scope, now.date(), 1));
        }
        let mut capture = Capture::default();
        env.run(Source::Claude, now, Some(&mut capture));
        append_records(&a, &claude_turn(&cwd, now.date(), 2));
        env.run(
            Source::Claude,
            now + time::Duration::days(1),
            Some(&mut capture),
        );
        let manifest = manifest_of(&env, &cwd);
        assert!(!manifest.with_extension("prev.json").exists());
        let before = state_files(&manifest_of(&env, &other_cwd));
        match damage {
            "missing_shard" => damage_shard(&manifest, "a.jsonl", "missing"),
            "truncated_shard" => damage_shard(&manifest, "a.jsonl", "truncated"),
            _ => damage_scope_state(&manifest, damage),
        }
        append_records(&a, &claude_turn(&cwd, now.date(), 3));
        let stats = env.run(
            Source::Claude,
            now + time::Duration::days(2),
            Some(&mut capture),
        );
        assert_eq!(
            (
                stats.scopes_quarantined,
                stats.files_quarantined,
                stats.bad_state
            ),
            (1, 2, 1),
            "{damage}"
        );
        assert_eq!(stats.bytes_new + stats.bytes_repair, 0, "{damage}");
        assert!(super::scope::scope_files(&manifest).is_empty());
        assert_eq!(state_files(&manifest_of(&env, &other_cwd)), before);
        append_records(&a, &claude_turn(&cwd, now.date(), 4));
        append_records(&b, &claude_turn(&cwd, now.date(), 5));
        let stats = env.run(
            Source::Claude,
            now + time::Duration::days(3),
            Some(&mut capture),
        );
        assert_eq!(stats.bytes_new + stats.bytes_repair, 0, "{damage}");
        let scope_id = sha256_hex(&[cwd.as_str()]);
        let mut scope = load_scope(&manifest, Source::Claude, &scope_id)
            .unwrap()
            .unwrap();
        scope.load_all_shards(&manifest).unwrap();
        for (key, path) in [
            ("a.jsonl", &a),
            (b.file_name().unwrap().to_str().unwrap(), &b),
        ] {
            assert_eq!(scope.files[key].offset, fs::metadata(path).unwrap().len());
        }
        assert_eq!(total_tokens(&scope.agg), 0);
        assert_eq!(
            capture.payloads.last().unwrap()["history_reset_at"],
            super::super::measure::date_ymd((now + time::Duration::days(2)).date())
        );
        let tail = claude_turn(&cwd, (now + time::Duration::days(4)).date(), 6);
        append_records(&a, &tail);
        let stats = env.run(
            Source::Claude,
            now + time::Duration::days(4),
            Some(&mut capture),
        );
        assert_eq!(stats.bytes_new, body(&tail).len() as u64);
        assert_eq!(stats.bytes_repair, 0);
        let counted = total_tokens(
            &load_scope(&manifest, Source::Claude, &scope_id)
                .unwrap()
                .unwrap()
                .agg,
        );
        assert!(counted > 0);
        let stats = env.run(Source::Claude, now + time::Duration::days(5), None);
        assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
        assert_eq!(
            total_tokens(
                &load_scope(&manifest, Source::Claude, &scope_id)
                    .unwrap()
                    .unwrap()
                    .agg
            ),
            counted
        );
        assert_eq!(state_files(&manifest_of(&env, &other_cwd)), before);
        env.cleanup();
    }
}

#[test]
fn bad_unchanged_scope_on_due_upload_is_quarantined_and_counted() {
    for damage in [
        "bad_manifest",
        "missing_manifest",
        "totals_sha",
        "missing_totals",
        "malformed_totals",
        "unknown_totals_id",
    ] {
        let env = Env::new(&format!("composition-upload-reset-{damage}"));
        let now = base_now();
        let path = env.root.join("p/a.jsonl");
        write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
        let mut capture = Capture::default();
        env.run(Source::Claude, now, Some(&mut capture));
        let manifest = manifest_of(&env, &env.cwd());
        damage_scope_state(&manifest, damage);
        let stats = env.run(
            Source::Claude,
            now + time::Duration::days(8),
            Some(&mut capture),
        );
        assert_eq!(
            (
                stats.bad_state,
                stats.scopes_quarantined,
                stats.files_quarantined
            ),
            (1, 1, 1),
            "{damage}"
        );
        assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
        assert_eq!(capture.payloads.len(), 1);
        env.cleanup();
    }
}

/// A due upload is built from the totals alone (their hash is checked); a
/// damaged shard is found and counted when a read first loads it.
#[test]
fn due_upload_sends_verified_totals_and_shard_damage_waits_for_a_read() {
    let env = Env::new("composition-upload-shard-damage");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    let manifest = manifest_of(&env, &env.cwd());
    damage_shard(&manifest, "a.jsonl", "missing");
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(8),
        Some(&mut capture),
    );
    assert_eq!((stats.bad_state, stats.uploaded), (0, 1));
    assert_eq!(capture.payloads.len(), 2);
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    let stats = env.run(
        Source::Claude,
        now + time::Duration::days(9),
        Some(&mut capture),
    );
    assert_eq!(
        (
            stats.bad_state,
            stats.scopes_quarantined,
            stats.files_quarantined
        ),
        (1, 1, 1)
    );
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    env.cleanup();
}

#[test]
fn reset_scope_whose_files_are_gone_commits_empty() {
    let env = Env::new("composition-reset-gone");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let manifest = manifest_of(&env, &env.cwd());
    damage_scope_state(&manifest, "bad_manifest");
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.scopes_quarantined, 1);
    fs::remove_file(&path).unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.scopes_committed, 1);
    let index = read_index(&env.state, Source::Claude);
    assert!(index.quarantined_scopes.is_empty());
    let scope = env.scope(Source::Claude);
    assert_eq!(
        scope.history_reset_at,
        Some(day_of((now + time::Duration::days(1)).date()))
    );
    assert_eq!(total_tokens(&scope.agg), 0);
    // Applied: later runs neither count nor commit the reset again.
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!((stats.scopes_quarantined, stats.scopes_committed), (0, 0));
    env.cleanup();
}

#[test]
fn lost_or_bad_index_resets_the_agent_even_with_a_damaged_scope() {
    for index_damage in ["missing", "bad"] {
        for state_damage in ["healthy", "missing_shard", "bad_manifest"] {
            let env = Env::new(&format!(
                "composition-agent-reset-{index_damage}-{state_damage}"
            ));
            let now = base_now();
            let a = env.root.join("p/a.jsonl");
            let b = env.root.join("q/b.jsonl");
            let other = other_workspace(&env);
            write_records(&a, &claude_turn(&env.cwd(), now.date(), 1));
            write_records(&b, &claude_turn(&other, now.date(), 2));
            env.run(Source::Claude, now, None);
            let manifest = manifest_of(&env, &env.cwd());
            match state_damage {
                "missing_shard" => damage_shard(&manifest, "a.jsonl", "missing"),
                "bad_manifest" => damage_scope_state(&manifest, "bad_manifest"),
                _ => {}
            }
            let index = harvest::index_path(&env.state, Source::Claude);
            if index_damage == "missing" {
                fs::remove_file(index).unwrap();
            } else {
                fs::write(index, b"[]").unwrap();
            }
            let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
            assert_eq!(
                (
                    stats.agent_resets,
                    stats.scopes_quarantined,
                    stats.files_quarantined
                ),
                (1, 2, 2)
            );
            assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
            append_records(&a, &claude_turn(&env.cwd(), now.date(), 3));
            let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
            assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
            assert_eq!(stats.scopes_committed, 2);
            for path in [&a, &b] {
                let pins = read_index(&env.state, Source::Claude);
                let key = path.file_name().unwrap().to_str().unwrap();
                assert_eq!(pins.files[key].start, fs::metadata(path).unwrap().len());
            }
            env.cleanup();
        }
    }
}

/// Pins lost from a valid index, for files that existed when its last scan
/// started. Test runs use clocks days behind the files' real birth times,
/// so the scan start is moved past them.
fn lose_pins_of_files_seen_by_the_last_scan(index: &mut Index) {
    index.files.clear();
    index.last_scan_started = Some(OffsetDateTime::now_utc().unix_timestamp() + 1);
}

#[test]
fn missing_pin_never_authorizes_history_reads() {
    let env = Env::new("composition-missing-pin");
    let now = base_now();
    let a = env.root.join("p/a.jsonl");
    write_records(&a, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let path = harvest::index_path(&env.state, Source::Claude);
    let mut index = read_index(&env.state, Source::Claude);
    append_records(&a, &claude_turn(&env.cwd(), now.date(), 2));
    let before = total_tokens(&env.scope(Source::Claude).agg);
    lose_pins_of_files_seen_by_the_last_scan(&mut index);
    super::checkpoint::write_json(&path, &index).unwrap();
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(stats.checkpoint_restarts, 1);
    append_records(&a, &claude_turn(&env.cwd(), now.date(), 3));
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(total_tokens(&env.scope(Source::Claude).agg), before);
    let tail = claude_turn(&env.cwd(), (now + time::Duration::days(3)).date(), 4);
    append_records(&a, &tail);
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(stats.bytes_new, body(&tail).len() as u64);
    let counted = total_tokens(&env.scope(Source::Claude).agg);
    assert!(counted > before);
    // A later rewrite cannot turn the saved EOF boundary into a full read.
    write_records(&a, &claude_turn(&env.cwd(), now.date(), 5));
    let stats = env.run(Source::Claude, now + time::Duration::days(4), None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(total_tokens(&env.scope(Source::Claude).agg), counted);
    env.cleanup();
}

#[test]
fn worker_timeout_covers_blocked_stdin_and_work_and_reaps() {
    for phase in ["input", "work", "protocol", "crash", "locked"] {
        let dir = scratch(&format!("composition-worker-{phase}"));
        let pid_file = dir.join("pid");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(match phase {
                "input" => "echo $$ > \"$1\"; exec sleep 60",
                "work" => "echo $$ > \"$1\"; cat >/dev/null; exec sleep 60",
                "protocol" => "echo $$ > \"$1\"; cat >/dev/null; echo malformed",
                // Lock busy: exits before reading its input, so the large
                // write fails; the exit status still decides.
                "locked" => "echo $$ > \"$1\"; exit 75",
                _ => "echo $$ > \"$1\"; exit 7",
            })
            .arg("fixture")
            .arg(&pid_file);
        let result: anyhow::Result<Value> = harvest::run_worker_process_timeout(
            &mut command,
            &"x".repeat(1024 * 1024),
            Duration::from_millis(250),
        );
        let expected = match phase {
            "input" | "work" => harvest::WorkerError::Timeout,
            "locked" => harvest::WorkerError::Locked,
            _ => harvest::WorkerError::Failed,
        };
        assert_eq!(
            result.unwrap_err().downcast_ref::<harvest::WorkerError>(),
            Some(&expected)
        );
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The worker is reaped by its own thread, never by the caller:
        // once gone, it is not left as a zombie.
        let deadline = Instant::now() + Duration::from_secs(10);
        // SAFETY: kill with signal 0 only probes the fixture pid.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(Instant::now() < deadline, "{phase}: worker not reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut status = 0;
        // SAFETY: waitpid and kill receive a fixture pid and a valid status pointer.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
#[ignore = "private subprocess lock fixture"]
fn composition_lock_fixture() {
    let Some(dir) = std::env::var_os("COMPOSITION_LOCK_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    if let Some(parent_ready) = std::env::var_os("COMPOSITION_LOCK_PARENT") {
        // This parent is killed on purpose: its orphaned child is the
        // worker under test. If it survives, it reaps the child below.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "context_composition::v2::tests::composition_lock_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_remove("COMPOSITION_LOCK_PARENT")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        fs::write(parent_ready, child.id().to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(60));
        // The parent-death test kills this process before this point. If it
        // survives, reap its child rather than leave fixture cleanup to init.
        child.wait().unwrap();
        return;
    }
    let Some(_lock) = harvest::lock_state(&dir).unwrap() else {
        std::process::exit(75);
    };
    if let Some(ms) = std::env::var_os("COMPOSITION_LOCK_WATCHDOG_MS") {
        let ms = ms.to_str().unwrap().parse().unwrap();
        harvest::start_watchdog(Duration::from_millis(ms));
    }
    fs::write(dir.join("held"), std::process::id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn worker_lock_excludes_a_second_process_and_survives_parent_death() {
    let dir = scratch("composition-worker-lock");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "context_composition::v2::tests::composition_lock_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("COMPOSITION_LOCK_DIR", &dir);
    let mut parent = command
        .env("COMPOSITION_LOCK_PARENT", dir.join("parent-ready"))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !dir.join("held").exists() || !dir.join("parent-ready").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let worker: i32 = fs::read_to_string(dir.join("parent-ready"))
        .unwrap()
        .parse()
        .unwrap();
    command.env_remove("COMPOSITION_LOCK_PARENT");
    assert_eq!(command.status().unwrap().code(), Some(75));
    parent.kill().unwrap();
    parent.wait().unwrap();
    // The scheduler died, but its orphaned worker still owns the lease.
    assert_eq!(command.status().unwrap().code(), Some(75));
    assert!(harvest::lock_state(&dir).unwrap().is_none());
    // SAFETY: this is the pid of our private fixture worker.
    unsafe {
        libc::kill(worker, libc::SIGKILL);
    }
    loop {
        if harvest::lock_state(&dir).unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hung_orphaned_worker_exits_at_its_cap_and_frees_the_lock() {
    let dir = scratch("composition-worker-watchdog");
    let started = Instant::now();
    let mut worker = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "context_composition::v2::tests::composition_lock_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("COMPOSITION_LOCK_DIR", &dir)
        .env("COMPOSITION_LOCK_WATCHDOG_MS", "2000")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !dir.join("held").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(harvest::lock_state(&dir).unwrap().is_none());
    // The fixture would sleep for a minute; its watchdog stops it first.
    let status = worker.wait().unwrap();
    assert_eq!(status.code(), Some(harvest::WORKER_WATCHDOG_EXIT));
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(harvest::lock_state(&dir).unwrap().is_some());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interrupted_install_with_lost_index_resets_all_scopes_without_replay() {
    let env = Env::new("composition-install-reset");
    let now = base_now();
    let a = env.root.join("p/a.jsonl");
    let b = env.root.join("q/b.jsonl");
    let other = other_workspace(&env);
    write_records(&a, &claude_turn(&env.cwd(), now.date(), 1));
    write_records(&b, &claude_turn(&other, now.date(), 2));
    // An install by an earlier build read files live at install, committed
    // a scope and stopped before saving its index. This build's install
    // reads nothing, so that state is made from a crashed run whose index
    // is then lost.
    harvest::tests::set_crash_after(Some(1));
    env.run(Source::Claude, now, None);
    harvest::tests::set_crash_after(None);
    fs::remove_file(harvest::index_path(&env.state, Source::Claude)).unwrap();
    assert!(install_path(&env.state, Source::Claude.label()).exists());
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(
        (
            stats.agent_resets,
            stats.scopes_quarantined,
            stats.files_quarantined
        ),
        (1, 2, 2)
    );
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.scopes_committed, 2);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    env.cleanup();
}

#[test]
fn crash_during_install_before_index_save_resets_without_replay() {
    let env = Env::uninstalled("composition-install-crash");
    let now = base_now();
    let day = now.date();
    let cwd = env.cwd();
    let a = env.root.join("p/a.jsonl");
    let b = env.root.join("p/b.jsonl");
    write_records(&a, &claude_turn(&cwd, day, 1));
    write_records(&b, &claude_turn(&cwd, day, 2));
    // This build's install writes its record, then stops before saving
    // its index: the record stays, the index is lost.
    let stats = env.run(Source::Claude, now, None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    fs::remove_file(harvest::index_path(&env.state, Source::Claude)).unwrap();
    assert!(install_path(&env.state, Source::Claude.label()).exists());
    let at_reset = [&a, &b].map(|path| fs::metadata(path).unwrap().len());

    // The next run is a reset, not a second install: every file is pinned
    // at its end and nothing is read.
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(
        (
            stats.agent_resets,
            stats.install_forward_only,
            stats.bytes_new,
            stats.bytes_repair,
            stats.files_read
        ),
        (1, 2, 0, 0, 0)
    );
    // The reset commits the next day, still reading nothing.
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(
        (stats.scopes_committed, stats.bytes_new + stats.bytes_repair),
        (1, 0)
    );

    // Only what is appended after the reset is read.
    let appended = claude_turn(&cwd, day, 3);
    for path in [&a, &b] {
        append_records(path, &appended);
    }
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.agent_resets),
        (2 * body(&appended).len() as u64, 0, 0)
    );
    let scope = env.scope(Source::Claude);
    for (name, size) in ["a.jsonl", "b.jsonl"].iter().zip(at_reset) {
        assert_eq!(
            scope.files[*name].offset,
            size + body(&appended).len() as u64
        );
    }
    env.cleanup();
}

#[test]
fn reset_marker_survives_a_crash_before_scope_state_moves() {
    let env = Env::new("composition-marker-reset");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    env.run(Source::Claude, now, None);
    let scope_id = sha256_hex(&[env.cwd().as_str()]);
    let marker = env
        .state
        .join("quarantined-scopes")
        .join(format!("{}-{scope_id}.json", Source::Claude.label()));
    super::checkpoint::write_json(&marker, &day_of(now.date())).unwrap();
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert_eq!(total_tokens(&env.scope(Source::Claude).agg), 0);
    assert_eq!(
        env.scope(Source::Claude).files["a.jsonl"].offset,
        fs::metadata(&path).unwrap().len()
    );
    env.cleanup();
}

#[test]
fn incomplete_resets_keep_absent_and_failed_files_pending_across_scope_commit() {
    for failure in ["absent", "read_failed", "crash_before_index"] {
        let env = Env::new(&format!("composition-partial-reset-{failure}"));
        let now = base_now();
        let cwd = env.cwd();
        let a = env.root.join("p/a.jsonl");
        let b = env.root.join("p/b.jsonl");
        for path in [&a, &b] {
            write_records(path, &claude_turn(&cwd, now.date(), 1));
        }
        env.run(Source::Claude, now, None);
        damage_scope_state(&manifest_of(&env, &cwd), "bad_manifest");
        append_records(&a, &claude_turn(&cwd, now.date(), 2));
        let stats = env.run(Source::Claude, now + time::Duration::days(1), None);
        assert_eq!(stats.scopes_quarantined, 1);
        let hidden = env.workspace.join("hidden.jsonl");
        if failure != "read_failed" {
            fs::rename(&b, &hidden).unwrap();
        } else {
            harvest::tests::set_fail_read(Some(&b));
        }
        if failure == "crash_before_index" {
            harvest::tests::set_crash_after(Some(1));
        }
        let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
        harvest::tests::set_crash_after(None);
        harvest::tests::set_fail_read(None);
        assert_eq!(stats.scopes_committed, 1, "{failure}");
        assert!(read_index(&env.state, Source::Claude).files["b.jsonl"].restart_at_end);
        if failure != "read_failed" {
            fs::rename(&hidden, &b).unwrap();
        }
        append_records(&b, &claude_turn(&cwd, now.date(), 3));
        let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
        assert_eq!(stats.bytes_new + stats.bytes_repair, 0, "{failure}");
        assert_eq!(total_tokens(&env.scope(Source::Claude).agg), 0);
        assert!(!read_index(&env.state, Source::Claude).files["b.jsonl"].restart_at_end);
        let tail = claude_turn(&cwd, (now + time::Duration::days(4)).date(), 4);
        append_records(&b, &tail);
        let stats = env.run(Source::Claude, now + time::Duration::days(4), None);
        assert_eq!(stats.bytes_new, body(&tail).len() as u64, "{failure}");
        env.cleanup();
    }
}

#[test]
fn committed_scope_reconciliation_restores_attribution_before_folder_disappears() {
    let env = Env::new("composition-restore-attribution");
    let now = base_now();
    let cwd = env.cwd();
    let a = env.root.join("p/a.jsonl");
    write_records(&a, &claude_turn(&cwd, now.date(), 1));
    let mut flaky = FlakyResolver {
        fail: true,
        ..Default::default()
    };
    env.run_with(Source::Claude, now, None, REPAIR_BYTES_PER_DAY, &mut flaky);
    let index_path = harvest::index_path(&env.state, Source::Claude);
    let old = fs::read(&index_path).unwrap();
    assert!(read_index(&env.state, Source::Claude).files["a.jsonl"]
        .scope
        .is_none());
    env.run(Source::Claude, now + time::Duration::days(1), None);
    fs::write(&index_path, old).unwrap();
    fs::remove_dir_all(&env.workspace).unwrap();
    let tail = claude_turn(&cwd, (now + time::Duration::days(2)).date(), 2);
    append_records(&a, &tail);
    let stats = env.run(Source::Claude, now + time::Duration::days(2), None);
    assert_eq!(stats.bytes_new, body(&tail).len() as u64);
    assert_eq!(stats.unscoped, 0);
    let index = read_index(&env.state, Source::Claude);
    let scope = sha256_hex(&[cwd.as_str()]);
    assert_eq!(
        index.files["a.jsonl"].scope.as_deref(),
        Some(scope.as_str())
    );
    assert_eq!(index.scope_info[&scope].workspace_path, cwd);
    env.cleanup();
}

#[test]
fn failed_missing_pin_reset_with_equal_offset_stays_pending_after_crash() {
    let env = Env::new("composition-pending-equal-offset");
    let now = base_now();
    let cwd = env.cwd();
    let path = env.root.join("p/a.jsonl");
    write_records(&path, &claude_turn(&cwd, now.date(), 1));
    env.run(Source::Claude, now, None);
    let before = total_tokens(&env.scope(Source::Claude).agg);
    let mut index = read_index(&env.state, Source::Claude);
    lose_pins_of_files_seen_by_the_last_scan(&mut index);
    super::checkpoint::write_json(&harvest::index_path(&env.state, Source::Claude), &index)
        .unwrap();
    env.run(Source::Claude, now + time::Duration::days(1), None);
    append_records(&path, &claude_turn(&cwd, now.date(), 2));
    harvest::tests::set_fail_read(Some(&path));
    harvest::tests::set_crash_after(Some(1));
    env.run(Source::Claude, now + time::Duration::days(2), None);
    harvest::tests::set_fail_read(None);
    harvest::tests::set_crash_after(None);
    assert!(read_index(&env.state, Source::Claude).files["a.jsonl"].restart_at_end);
    append_records(&path, &claude_turn(&cwd, now.date(), 3));
    let stats = env.run(Source::Claude, now + time::Duration::days(3), None);
    assert_eq!(stats.bytes_new + stats.bytes_repair, 0);
    assert!(stats.checkpoint_restarts > 0);
    assert_eq!(total_tokens(&env.scope(Source::Claude).agg), before);
    env.cleanup();
}

#[path = "tests/a34.rs"]
mod a34;

#[path = "tests/a2.rs"]
mod a2;

mod details;
