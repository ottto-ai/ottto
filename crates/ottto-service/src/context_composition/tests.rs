//! Golden-fixture tests for the context-composition collector.
//!
//! Every expected number is HAND-COMPUTED (mirrored from the Python reference
//! `test_context_composition_audit.py`) so the token math can be audited by eye.
//! Token rule under test: tokens = ceil(chars/4); images = 1300 nominal each;
//! residency(L) = number of assistant turns in `(L, next_compaction)`.

use super::*;
use serde_json::json;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use time::Month;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(name: &str) -> PathBuf {
    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ottto-context-composition-{name}-{}-{counter}.jsonl",
        std::process::id()
    ))
}

fn write_jsonl(name: &str, records: &[Value]) -> PathBuf {
    let path = temp_path(name);
    let mut file = fs::File::create(&path).unwrap();
    for record in records {
        writeln!(file, "{}", serde_json::to_string(record).unwrap()).unwrap();
    }
    path
}

/// A window wide enough that fixture events (bucketed on the file mtime) are
/// never filtered by the capture window.
fn wide_window() -> DateWindow {
    DateWindow {
        floor: Date::from_calendar_date(2000, Month::January, 1).unwrap(),
        today: Date::from_calendar_date(2100, Month::January, 1).unwrap(),
    }
}

#[test]
fn content_block_shapes_preserve_text_order_and_image_semantics() {
    let cases = [
        (Value::Null, "", 0),
        (json!("שלום🙂"), "שלום🙂", 0),
        (json!(17), "17", 0),
        (json!(true), "true", 0),
        (json!([]), "", 0),
        (json!({"type":"text","text":"one"}), "one", 0),
        (json!({"type":"text","text":17}), "", 0),
        (json!({"type":"image","data":"ignored"}), "", 1),
        (
            json!(["a", null, 2, {"type":"input_text","text":"b"},
            {"type":"input_image"}, {"type":"output_image"},
            {"type":"output_text","text":"c"}, {"unknown":[1,2]}]),
            "a\nnull\n2\nb\nc\n{\"unknown\": [1, 2]}",
            2,
        ),
    ];
    assert_eq!(extract_blocks_text_and_images(None), (String::new(), 0));
    for (input, text, images) in cases {
        assert_eq!(
            extract_blocks_text_and_images(Some(&input)),
            (text.into(), images)
        );
    }
}

#[test]
fn image_body_size_does_not_enter_composition_tokens() {
    for size in [0, 8, 1024 * 1024] {
        let image = json!({"type":"image","source":{"data":"x".repeat(size)}});
        for content in [image.clone(), json!([image])] {
            assert_eq!(
                extract_blocks_text_and_images(Some(&content)),
                (String::new(), 1)
            );
        }
    }
}

// -------------------------------------------------------------------------
// Session A: images. assistant ordinals [1,3,5,7]; no compaction.
//   r1 Read /proj/app/main.py -> "ABCDEFGH"(8=2) code_reads @ord2 res{3,5,7}=3
//   b1 Bash -> "file1\nfile2"(11=3) shell_output @ord4 res{5,7}=2
//   br1 browser -> "shot"(4=1)+1 image(1300) browser_and_images @ord6 res{7}=1
// -------------------------------------------------------------------------
pub(super) fn sess_a() -> Vec<Value> {
    vec![
        json!({"type":"user","sessionId":"sessA","message":{"role":"user","content":"hi"}}),
        json!({"type":"assistant","sessionId":"sessA","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"/proj/app/main.py"}}]}}),
        json!({"type":"user","sessionId":"sessA","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"r1","content":"ABCDEFGH"}]}}),
        json!({"type":"assistant","sessionId":"sessA","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"b1","name":"Bash","input":{"command":"ls"}}]}}),
        json!({"type":"user","sessionId":"sessA","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"b1","content":"file1\nfile2"}]}}),
        json!({"type":"assistant","sessionId":"sessA","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"br1","name":"mcp__Claude_Browser__computer","input":{}}]}}),
        json!({"type":"user","sessionId":"sessA","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"br1","content":[
                {"type":"text","text":"shot"},
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":"xxxx"}}]}]}}),
        json!({"type":"assistant","sessionId":"sessA","message":{"role":"assistant","content":[{"type":"text","text":"done"}]}}),
    ]
}

// -------------------------------------------------------------------------
// Session B: compaction + memory read + memory write + attachment.
// assistant ordinals [2,4,7,9]; compaction @ord6 (type summary).
//   att task_reminder "REMEMBER"(8=2) harness @ord1 res(1,6){2,4}=2
//   m1 Read MEMORY.md -> "MEMDATA!"(8=2) memory_notes @ord3 res(3,6){4}=1
//   w1 Write /x/memory/note.md content "WRITTENCONTENT"(14=4) -> memory WRITE (separate, dropped)
//   w1 result "OK"(2=1) other_tools @ord5 res(5,6){}=0
//   g1 Grep -> "match1"(6=2) other_tools @ord8 res(8,inf){9}=1
// -------------------------------------------------------------------------
pub(super) fn sess_b() -> Vec<Value> {
    vec![
        json!({"type":"user","sessionId":"sessB","message":{"role":"user","content":"go"}}),
        json!({"type":"attachment","sessionId":"sessB","attachment":{"type":"task_reminder","content":"REMEMBER","itemCount":1}}),
        json!({"type":"assistant","sessionId":"sessB","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"m1","name":"Read","input":{"file_path":"/Users/x/.claude/projects/-p/memory/MEMORY.md"}}]}}),
        json!({"type":"user","sessionId":"sessB","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"m1","content":"MEMDATA!"}]}}),
        json!({"type":"assistant","sessionId":"sessB","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"w1","name":"Write","input":{"file_path":"/x/memory/note.md","content":"WRITTENCONTENT"}}]}}),
        json!({"type":"user","sessionId":"sessB","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"w1","content":"OK"}]}}),
        json!({"type":"summary","sessionId":"sessB","summary":"compacted"}),
        json!({"type":"assistant","sessionId":"sessB","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"g1","name":"Grep","input":{"pattern":"foo"}}]}}),
        json!({"type":"user","sessionId":"sessB","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"g1","content":"match1"}]}}),
        json!({"type":"assistant","sessionId":"sessB","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]}}),
    ]
}

// -------------------------------------------------------------------------
// Session C: memory via attachment injection + doc reads + html + orphan.
// assistant ordinals [3,5,8]; no compaction.
//   att edited_text_file /x/memory/recall.md snippet "MEMSNIP12"(9=3) memory_notes @ord1 res{3,5,8}=3
//   att edited_text_file /proj/app/code.py snippet "CODESNIP"(8=2) harness @ord2 res{3,5,8}=3
//   d1 Read /proj/docs/readme.md -> "DOCTEXT!"(8=2) doc_reads_md @ord4 res{5,8}=2
//   h1 Read /proj/efforts.html -> "HTMLDATA"(8=2) doc_reads_html @ord6 res{8}=1
//   orphan result (unknown id) "ORPHAN12"(8=2) other_tools @ord7 res{8}=1
// -------------------------------------------------------------------------
pub(super) fn sess_c() -> Vec<Value> {
    vec![
        json!({"type":"user","sessionId":"sessC","message":{"role":"user","content":"c"}}),
        json!({"type":"attachment","sessionId":"sessC","attachment":{"type":"edited_text_file","filename":"/x/memory/recall.md","snippet":"MEMSNIP12"}}),
        json!({"type":"attachment","sessionId":"sessC","attachment":{"type":"edited_text_file","filename":"/proj/app/code.py","snippet":"CODESNIP"}}),
        json!({"type":"assistant","sessionId":"sessC","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"d1","name":"Read","input":{"file_path":"/proj/docs/readme.md"}}]}}),
        json!({"type":"user","sessionId":"sessC","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"d1","content":"DOCTEXT!"}]}}),
        json!({"type":"assistant","sessionId":"sessC","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"h1","name":"Read","input":{"file_path":"/proj/efforts.html"}}]}}),
        json!({"type":"user","sessionId":"sessC","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"h1","content":"HTMLDATA"}]}}),
        json!({"type":"user","sessionId":"sessC","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"UNKNOWN","content":"ORPHAN12"}]}}),
        json!({"type":"assistant","sessionId":"sessC","message":{"role":"assistant","content":[{"type":"text","text":"fin"}]}}),
    ]
}

fn build_claude_report() -> WorkspaceReport {
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    for (name, recs) in [("a", sess_a()), ("b", sess_b()), ("c", sess_c())] {
        let path = write_jsonl(name, &recs);
        parse_claude_session(&path, &mut report, fallback, false).unwrap();
        let _ = fs::remove_file(&path);
    }
    report
}

// (events, tokens, residency, images).
type CatTotals = (u64, u64, u64, u64);

// Summed across A+B+C.
const EXPECTED_CLAUDE: &[(Category, CatTotals)] = &[
    (Category::HarnessAttachments, (2, 4, 10, 0)),
    (Category::ShellOutput, (1, 3, 6, 0)),
    (Category::CodeReads, (1, 2, 6, 0)),
    (Category::DocReadsMd, (1, 2, 4, 0)),
    (Category::DocReadsHtml, (1, 2, 2, 0)),
    (Category::MemoryNotes, (2, 5, 11, 0)),
    (Category::BrowserAndImages, (2, 1301, 1301, 1)),
    (Category::WebFetchSearch, (0, 0, 0, 0)),
    (Category::AgentResults, (0, 0, 0, 0)),
    (Category::OtherTools, (3, 5, 4, 0)),
];

#[test]
fn claude_categories_exact() {
    let report = build_claude_report();
    for (cat, expected) in EXPECTED_CLAUDE {
        assert_eq!(report.category_totals(*cat), *expected, "category {cat:?}");
    }
    // Total tokens 1324, residency 1344, images 1.
    let total_tokens: u64 = report.daily.values().map(|b| b.tokens).sum();
    let total_res: u64 = report.daily.values().map(|b| b.residency).sum();
    let total_img: u64 = report.daily.values().map(|b| b.images).sum();
    assert_eq!((total_tokens, total_res, total_img), (1324, 1344, 1));
    assert_eq!(report.sessions.len(), 3);
}

#[test]
fn claude_per_file_attribution() {
    let report = build_claude_report();
    assert_eq!(report.files["/proj/app/main.py"].tokens, 2);
    assert_eq!(
        report.files["/proj/app/main.py"].category,
        Category::CodeReads
    );
    assert_eq!(
        report.files["/x/memory/recall.md"].category,
        Category::MemoryNotes
    );
    assert_eq!(
        report.files["/proj/docs/readme.md"].category,
        Category::DocReadsMd
    );
    assert_eq!(
        report.files["/proj/app/code.py"].category,
        Category::HarnessAttachments
    );
}

// -------------------------------------------------------------------------
// Streaming-fragment dedup: one model response spans several adjacent assistant
// records sharing message.id -> counts as ONE turn for residency.
// deduped assistant turns [1,4,7]; r1 result @ord3 res{4,7}=2; b1 @ord6 res{7}=1.
// -------------------------------------------------------------------------
#[test]
fn streaming_fragments_collapse_by_message_id() {
    let recs = vec![
        json!({"type":"user","sessionId":"sX","message":{"role":"user","content":"hi"}}),
        json!({"type":"assistant","sessionId":"sX","message":{"role":"assistant","id":"A","content":[{"type":"thinking","thinking":"t"}]}}),
        json!({"type":"assistant","sessionId":"sX","message":{"role":"assistant","id":"A","content":[
            {"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"/x.py"}}]}}),
        json!({"type":"user","sessionId":"sX","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"r1","content":"AB"}]}}),
        json!({"type":"assistant","sessionId":"sX","message":{"role":"assistant","id":"B","content":[{"type":"text","text":"x"}]}}),
        json!({"type":"assistant","sessionId":"sX","message":{"role":"assistant","id":"B","content":[
            {"type":"tool_use","id":"b1","name":"Bash","input":{"command":"ls"}}]}}),
        json!({"type":"user","sessionId":"sX","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"b1","content":"CD"}]}}),
        json!({"type":"assistant","sessionId":"sX","message":{"role":"assistant","id":"C","content":[{"type":"text","text":"done"}]}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("stream", &recs);
    parse_claude_session(&path, &mut report, fallback, false).unwrap();
    let _ = fs::remove_file(&path);
    let code = report.category_totals(Category::CodeReads);
    let shell = report.category_totals(Category::ShellOutput);
    assert_eq!((code.1, code.2), (1, 2));
    assert_eq!((shell.1, shell.2), (1, 1));
}

#[test]
fn subagent_transcripts_stay_distinct() {
    let sub = vec![
        json!({"type":"user","isSidechain":true,"sessionId":"parent","message":{"role":"user","content":"go"}}),
        json!({"type":"assistant","isSidechain":true,"sessionId":"parent","message":{"role":"assistant","id":"z","content":[
            {"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}),
        json!({"type":"user","isSidechain":true,"sessionId":"parent","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"t","content":"AB"}]}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let p1 = write_jsonl("sub1", &sub);
    let p2 = write_jsonl("sub2", &sub);
    parse_claude_session(&p1, &mut report, fallback, true).unwrap();
    parse_claude_session(&p2, &mut report, fallback, true).unwrap();
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    assert_eq!(report.sessions.len(), 2);
}

// -------------------------------------------------------------------------
// Codex fixture. assistant ordinals [2,4,7,9]; compaction @ord6.
//   dev msg "DEVINSTRUCT"(11=3) harness @ord1 res(1,6){2,4}=2
//   c1 exec "SHELLOUT!"(9=3) shell_output @ord3 res(3,6){4}=1
//   c2 web output "WEBRESULT"(9=3) web_fetch_search @ord5 res(5,6){}=0
//   c3 exec "AFTER123"(8=2) shell_output @ord8 res(8,inf){9}=1
// -------------------------------------------------------------------------
pub(super) fn codex_sess() -> Vec<Value> {
    vec![
        json!({"type":"session_meta","payload":{"id":"codexS"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"DEVINSTRUCT"}]}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"c1","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"SHELLOUT!"}}),
        json!({"type":"response_item","payload":{"type":"custom_tool_call","name":"web_search","call_id":"c2","input":"q"}}),
        json!({"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"c2","output":[{"type":"input_text","text":"WEBRESULT"}]}}),
        json!({"type":"response_item","payload":{"type":"context_compacted"}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"c3","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c3","output":"AFTER123"}}),
        json!({"type":"response_item","payload":{"type":"agent_message","content":[{"type":"output_text","text":"final"}]}}),
    ]
}

#[test]
fn codex_categories_exact() {
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("codex", &codex_sess());
    parse_codex_session(&path, &mut report, fallback).unwrap();
    let _ = fs::remove_file(&path);
    assert_eq!(
        report.category_totals(Category::HarnessAttachments),
        (1, 3, 6, 0)
    );
    assert_eq!(report.category_totals(Category::ShellOutput), (2, 5, 5, 0));
    assert_eq!(
        report.category_totals(Category::WebFetchSearch),
        (1, 3, 0, 0)
    );
    let total: u64 = report.daily.values().map(|b| b.tokens).sum();
    assert_eq!(total, 11);
}

// -------------------------------------------------------------------------
// Codex MCP: mcp_tool_call_end carries the RESULT (not invocation args).
//   ord1 chrome_devtools/take_snapshot "DOMDATA!!"(9=3) browser_and_images res(1,inf){2}=1
//   k1 exec "SH"(2=1) shell_output @ord3 res{}=0
//   ord4 node_repl/js "CODE"(4=1) shell_output res{}=0
// -------------------------------------------------------------------------
#[test]
fn codex_mcp_categorization() {
    let recs = vec![
        json!({"type":"session_meta","payload":{"id":"cmcp"}}),
        json!({"type":"response_item","payload":{"type":"mcp_tool_call_end",
            "invocation":{"server":"chrome_devtools","tool":"take_snapshot"},
            "result":{"Ok":{"content":[{"type":"text","text":"DOMDATA!!"}]}}}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"k1","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"k1","output":"SH"}}),
        json!({"type":"response_item","payload":{"type":"mcp_tool_call_end",
            "invocation":{"server":"node_repl","tool":"js"},
            "result":{"Ok":{"content":[{"type":"text","text":"CODE"}]}}}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("codexmcp", &recs);
    parse_codex_session(&path, &mut report, fallback).unwrap();
    let _ = fs::remove_file(&path);
    let browser = report.category_totals(Category::BrowserAndImages);
    let shell = report.category_totals(Category::ShellOutput);
    assert_eq!((browser.0, browser.1, browser.2), (1, 3, 3));
    assert_eq!((shell.0, shell.1, shell.2), (2, 2, 0));
    assert_eq!(report.category_totals(Category::OtherTools).0, 0);
}

// -------------------------------------------------------------------------
// Codex user-message image: user TEXT skipped, input_image billed.
//   image @ord1 res{2}=1; c1 exec "OUT"(3=1) shell res=0.
// -------------------------------------------------------------------------
#[test]
fn codex_user_message_image_counted_text_skipped() {
    let recs = vec![
        json!({"type":"session_meta","payload":{"id":"cimg"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","content":[
            {"type":"input_text","text":"look at this screenshot"},
            {"type":"input_image","image_url":"data:x"}]}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"c1","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"OUT"}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("codeximg", &recs);
    parse_codex_session(&path, &mut report, fallback).unwrap();
    let _ = fs::remove_file(&path);
    let browser = report.category_totals(Category::BrowserAndImages);
    assert_eq!(browser, (1, 1300, 1300, 1));
    let shell = report.category_totals(Category::ShellOutput);
    assert_eq!((shell.1, shell.2), (1, 0));
    assert_eq!(report.category_totals(Category::HarnessAttachments).1, 0);
}

// -------------------------------------------------------------------------
// Codex injects AGENTS.md and environment context as USER-role messages.
// Labeled non-`user.*` blocks are harness; typed `user.text` stays skipped
// even when it looks like an injected block.
//   ord1 agents_md + ord2 environment harness @res{4}=1; ord3 typed skipped.
// -------------------------------------------------------------------------
const CODEX_AGENTS_MD: &str =
    "# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nRULES\n</INSTRUCTIONS>";
const CODEX_ENVIRONMENT: &str = "<environment_context>\n  <cwd>/repo</cwd>\n</environment_context>";

#[test]
fn codex_labeled_injected_user_blocks_are_harness() {
    let recs = vec![
        json!({"type":"session_meta","payload":{"id":"cinj"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user",
            "content":[{"type":"input_text","text":CODEX_AGENTS_MD}],
            "internal_chat_message_metadata_passthrough":{"content_item_kinds":["agents_md.instructions"]}}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user",
            "content":[{"type":"input_text","text":CODEX_ENVIRONMENT}],
            "internal_chat_message_metadata_passthrough":{"content_item_kinds":["environments.environment_context"]}}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user",
            "content":[{"type":"input_text","text":"# AGENTS.md instructions typed by the person"}],
            "internal_chat_message_metadata_passthrough":{"content_item_kinds":["user.text"]}}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"c1","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"OUT"}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("codexinj", &recs);
    parse_codex_session(&path, &mut report, fallback).unwrap();
    let _ = fs::remove_file(&path);
    let expected = estimate_text_tokens(CODEX_AGENTS_MD) + estimate_text_tokens(CODEX_ENVIRONMENT);
    assert_eq!(
        report.category_totals(Category::HarnessAttachments),
        (2, expected, expected, 0)
    );
}

// Unlabeled (older) rollouts fall back to the injected-block prefixes, per
// block, so typed text in the same message is still skipped.
#[test]
fn codex_unlabeled_injected_user_blocks_use_prefixes() {
    let recs = vec![
        json!({"type":"session_meta","payload":{"id":"cleg"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","content":[
            {"type":"input_text","text":CODEX_AGENTS_MD},
            {"type":"input_text","text":"please fix the bug"}]}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec","call_id":"c1","arguments":"{}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"OUT"}}),
    ];
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::July, 19).unwrap();
    let path = write_jsonl("codexleg", &recs);
    parse_codex_session(&path, &mut report, fallback).unwrap();
    let _ = fs::remove_file(&path);
    let expected = estimate_text_tokens(CODEX_AGENTS_MD);
    assert_eq!(
        report.category_totals(Category::HarnessAttachments),
        (1, expected, expected, 0)
    );
}

// -------------------------------------------------------------------------
// Incremental watermark.
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Copied history: fork/resume records count once as entered context, and
// only stay resident for the copying session's own requests.
// -------------------------------------------------------------------------

fn codex_dev(ordinal: u64, text: &str) -> Value {
    json!({"type":"response_item","ordinal":ordinal,"payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":text}]}})
}

fn codex_turn(ordinal: u64) -> Value {
    json!({"type":"response_item","ordinal":ordinal,"payload":{"type":"agent_message","content":[{"type":"output_text","text":"ok"}]}})
}

fn parse_codex_records(name: &str, records: &[Value]) -> WorkspaceReport {
    let mut report = WorkspaceReport::new(wide_window());
    let fallback = Date::from_calendar_date(2026, Month::October, 18).unwrap();
    let path = write_jsonl(name, records);
    parse_codex_session(&path, &mut report, fallback).unwrap();
    fs::remove_file(path).unwrap();
    report
}

#[test]
fn codex_ordinal_fork_counts_copied_history_once() {
    // Ordinals 0-3 are the copied parent: its header, instructions and turn.
    let report = parse_codex_records(
        "codex-ordinal-fork",
        &[
            json!({"type":"session_meta","ordinal":0,"payload":{"id":"child","forked_from_id":"parent","thread_source":"subagent","subagent_history_start_ordinal":4}}),
            json!({"type":"session_meta","ordinal":1,"payload":{"id":"parent"}}),
            codex_dev(2, "COPIEDDV"),
            codex_turn(3),
            codex_dev(4, "OWNDEVXX"),
            json!({"type":"response_item","ordinal":5,"payload":{"type":"function_call","name":"exec","call_id":"c1","arguments":"{}"}}),
            json!({"type":"response_item","ordinal":6,"payload":{"type":"function_call_output","call_id":"c1","output":"SHELL123"}}),
            codex_turn(7),
        ],
    );
    // Entered once (own block, 2 tokens). Residency: own block and the copied
    // block each stay for the child's two own requests; the parent's turn
    // is not one of them.
    assert_eq!(
        report.category_totals(Category::HarnessAttachments),
        (1, 2, 8, 0)
    );
    assert_eq!(report.copied_history_sessions, 1);
    assert_eq!(report.excluded_not_fresh, 0);
    assert_eq!(report.sessions["child"].total, 4);
}

#[test]
fn codex_legacy_subagent_fork_starts_at_trigger_turn() {
    let header = json!({"type":"session_meta","payload":{"id":"child","forked_from_id":"parent","thread_source":"subagent"}});
    let trigger =
        json!({"type":"inter_agent_communication_metadata","payload":{"trigger_turn":true}});
    let report = parse_codex_records(
        "codex-legacy-subagent",
        &[
            header.clone(),
            codex_dev(1, "COPIEDDV"),
            codex_turn(2),
            trigger,
            codex_dev(4, "OWNDEVXX"),
            codex_turn(5),
        ],
    );
    assert_eq!(
        report.category_totals(Category::HarnessAttachments),
        (1, 2, 4, 0)
    );
    assert_eq!(report.copied_history_sessions, 1);

    // Without the trigger the copied part has no boundary: skip the session.
    let report = parse_codex_records(
        "codex-legacy-subagent-no-trigger",
        &[header, codex_dev(1, "COPIEDDV"), codex_turn(2)],
    );
    assert!(report.daily.is_empty() && report.sessions.is_empty());
    assert_eq!(report.excluded_not_fresh, 1);
}

#[test]
fn codex_fork_without_boundary_is_excluded_and_paginated_fork_is_local() {
    let records = |header: Value| vec![header, codex_dev(1, "OWNDEVXX"), codex_turn(2)];
    let legacy = parse_codex_records(
        "codex-legacy-user-fork",
        &records(
            json!({"type":"session_meta","payload":{"id":"child","forked_from_id":"parent","thread_source":"user"}}),
        ),
    );
    assert!(legacy.daily.is_empty() && legacy.sessions.is_empty());
    assert_eq!(legacy.excluded_not_fresh, 1);

    for header in [
        json!({"type":"session_meta","payload":{"id":"child","forked_from_id":"parent","history_base":{"cursor":"x"},"thread_source":"user"}}),
        json!({"type":"session_meta","payload":{"id":"child","thread_source":"agent_created_thread","history_base":{"cursor":"x"}}}),
        json!({"type":"session_meta","payload":{"id":"child","thread_source":"user"}}),
    ] {
        let report = parse_codex_records("codex-local-history", &records(header));
        assert_eq!(
            report.category_totals(Category::HarnessAttachments),
            (1, 2, 2, 0)
        );
        assert_eq!(report.copied_history_sessions, 0);
        assert_eq!(report.excluded_not_fresh, 0);
    }
}

#[test]
fn claude_resumed_transcript_counts_copied_records_once_in_any_order() {
    let attachment = |uuid: &str, session: &str| json!({"type":"attachment","uuid":uuid,"sessionId":session,"attachment":{"content":"same harness text"}});
    let turn = |uuid: &str, session: &str, id: &str| json!({"type":"assistant","uuid":uuid,"sessionId":session,"message":{"id":id,"content":[]}});
    let original = write_jsonl(
        "claude-original",
        &[attachment("u1", "A"), turn("u2", "A", "m1")],
    );
    // The resumed transcript repeats u1/u2 under its own session id.
    let resumed = write_jsonl(
        "claude-resumed",
        &[
            attachment("u1", "B"),
            turn("u2", "B", "m1"),
            attachment("u3", "B"),
            turn("u4", "B", "m2"),
        ],
    );
    let fallback = Date::from_calendar_date(2026, Month::October, 18).unwrap();
    let parse = |order: [&PathBuf; 2]| {
        let mut report = WorkspaceReport::new(wide_window());
        for path in order {
            parse_claude_session(path, &mut report, fallback, true).unwrap();
        }
        report
    };
    let forward = parse([&original, &resumed]);
    let reverse = parse([&resumed, &original]);
    let (events, tokens, residency, _) = forward.category_totals(Category::HarnessAttachments);
    // Two distinct records entered; u1 stays for both sessions' requests
    // (2 turns), u3 for one.
    assert_eq!(events, 2);
    assert_eq!(residency, tokens / 2 * 3);
    assert_eq!(
        reverse.category_totals(Category::HarnessAttachments),
        forward.category_totals(Category::HarnessAttachments)
    );
    assert_eq!(
        (forward.copied_history_sessions, forward.excluded_not_fresh),
        (1, 0)
    );
    // Parsed second, the original holds only already-counted records.
    assert_eq!(
        (reverse.copied_history_sessions, reverse.excluded_not_fresh),
        (0, 1)
    );
    fs::remove_file(original).unwrap();
    fs::remove_file(resumed).unwrap();
}
