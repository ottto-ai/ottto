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
