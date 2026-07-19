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

// -------------------------------------------------------------------------
// Session A: images. assistant ordinals [1,3,5,7]; no compaction.
//   r1 Read /proj/app/main.py -> "ABCDEFGH"(8=2) code_reads @ord2 res{3,5,7}=3
//   b1 Bash -> "file1\nfile2"(11=3) shell_output @ord4 res{5,7}=2
//   br1 browser -> "shot"(4=1)+1 image(1300) browser_and_images @ord6 res{7}=1
// -------------------------------------------------------------------------
fn sess_a() -> Vec<Value> {
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
fn sess_b() -> Vec<Value> {
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
fn sess_c() -> Vec<Value> {
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
        parse_claude_session(&path, &mut report, fallback, false);
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
    parse_claude_session(&path, &mut report, fallback, false);
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
    parse_claude_session(&p1, &mut report, fallback, true);
    parse_claude_session(&p2, &mut report, fallback, true);
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
fn codex_sess() -> Vec<Value> {
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
    parse_codex_session(&path, &mut report, fallback);
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
    parse_codex_session(&path, &mut report, fallback);
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
    parse_codex_session(&path, &mut report, fallback);
    let _ = fs::remove_file(&path);
    let browser = report.category_totals(Category::BrowserAndImages);
    assert_eq!(browser, (1, 1300, 1300, 1));
    let shell = report.category_totals(Category::ShellOutput);
    assert_eq!((shell.1, shell.2), (1, 0));
    assert_eq!(report.category_totals(Category::HarnessAttachments).1, 0);
}

// -------------------------------------------------------------------------
// Primitives.
// -------------------------------------------------------------------------
#[test]
fn estimate_text_tokens_matches_reference() {
    assert_eq!(estimate_text_tokens(""), 0);
    assert_eq!(estimate_text_tokens("a"), 1);
    assert_eq!(estimate_text_tokens("abcd"), 1);
    assert_eq!(estimate_text_tokens("abcde"), 2);
    // Unicode codepoint count (not bytes): "é" is one char, one token.
    assert_eq!(estimate_text_tokens("é"), 1);
}

#[test]
fn is_memory_path_matches_reference() {
    assert!(is_memory_path("/a/b/MEMORY.md"));
    assert!(is_memory_path("/a/memory/x.md"));
    assert!(is_memory_path("/a/AutoMem/x.md"));
    assert!(!is_memory_path("/a/docs/readme.md"));
    assert!(!is_memory_path(""));
}

#[test]
fn classify_by_read_path_matches_reference() {
    assert_eq!(classify_by_read_path("/a/x.py"), Category::CodeReads);
    assert_eq!(classify_by_read_path("/a/x.md"), Category::DocReadsMd);
    assert_eq!(classify_by_read_path("/a/x.html"), Category::DocReadsHtml);
    assert_eq!(
        classify_by_read_path("/a/memory/x.md"),
        Category::MemoryNotes
    );
}

#[test]
fn codex_tool_and_mcp_categories() {
    assert_eq!(codex_tool_category("wait"), Category::ShellOutput);
    assert_eq!(codex_tool_category("write_stdin"), Category::ShellOutput);
    assert_eq!(codex_tool_category("read_file"), Category::CodeReads);
    assert_eq!(
        codex_mcp_category(Some(&json!({"server":"chrome","tool":"snapshot"}))),
        Category::BrowserAndImages
    );
    assert_eq!(
        codex_mcp_category(Some(&json!({"server":"web","tool":"search"}))),
        Category::WebFetchSearch
    );
    assert_eq!(
        codex_mcp_category(Some(&json!({"server":"node_repl","tool":"js"}))),
        Category::ShellOutput
    );
    assert_eq!(
        codex_mcp_category(Some(&json!({"server":"acme","tool":"thing"}))),
        Category::OtherTools
    );
}

// -------------------------------------------------------------------------
// Incremental watermark.
// -------------------------------------------------------------------------
#[test]
fn incremental_watermark_reparses_only_on_change() {
    let files = vec![
        (
            PathBuf::from("/w/a.jsonl"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(100),
        ),
        (
            PathBuf::from("/w/b.jsonl"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(200),
        ),
    ];
    let sig = workspace_files_signature(&files);
    let now = OffsetDateTime::now_utc();

    // No cache -> must rescan.
    assert!(should_rescan(None, "id", "claude-code", &sig, now));

    // Cache with matching signature and fresh post -> skip.
    let fresh = CompositionCacheEntry {
        identity: "id".to_string(),
        agent_source: "claude-code".to_string(),
        files: sig.clone(),
        payload_sha256: "abc".to_string(),
        posted_at: now.format(&Rfc3339).unwrap(),
    };
    assert!(!should_rescan(Some(&fresh), "id", "claude-code", &sig, now));

    // A changed mtime -> signature differs -> rescan.
    let mut changed_files = files.clone();
    changed_files[0].1 = SystemTime::UNIX_EPOCH + Duration::from_secs(999);
    let changed_sig = workspace_files_signature(&changed_files);
    assert!(should_rescan(
        Some(&fresh),
        "id",
        "claude-code",
        &changed_sig,
        now
    ));

    // A different destination identity -> rescan.
    assert!(should_rescan(
        Some(&fresh),
        "other",
        "claude-code",
        &sig,
        now
    ));

    // Stale post -> rescan even when unchanged.
    let stale = CompositionCacheEntry {
        posted_at: (now - time::Duration::seconds(CONTEXT_MAX_STALENESS_SECS))
            .format(&Rfc3339)
            .unwrap(),
        ..fresh.clone()
    };
    assert!(should_rescan(Some(&stale), "id", "claude-code", &sig, now));
}

// -------------------------------------------------------------------------
// Payload serialization against the ingest contract.
// -------------------------------------------------------------------------
#[test]
fn payload_matches_contract() {
    let mut report = WorkspaceReport::new(DateWindow::current());
    let fallback = OffsetDateTime::now_utc().date();
    let path = write_jsonl("payload", &sess_c());
    parse_claude_session(&path, &mut report, fallback, false);
    let _ = fs::remove_file(&path);

    let workspace = Path::new("/proj");
    let request =
        build_request(&report, workspace, "machine-a", "claude-code", true).expect("request");
    let value = serde_json::to_value(&request).unwrap();
    let obj = value.as_object().unwrap();

    // Only contract-allowed top-level keys are present (extra fields 422).
    let allowed = [
        "agent_source",
        "machine_id",
        "workspace_hash",
        "workspace_label",
        "workspace_label_source",
        "repository_hash",
        "repository_label",
        "repository_label_source",
        "repository_identity_source",
        "workspace_kind",
        "config_hash",
        "captured_at",
        "window_start",
        "window_end",
        "bucket_timezone",
        "collector_version",
        "counter_source",
        "daily_aggregates",
        "top_files",
        "sessions",
    ];
    for key in obj.keys() {
        assert!(allowed.contains(&key.as_str()), "unexpected key {key}");
    }

    assert_eq!(obj["agent_source"], json!("claude-code"));
    assert_eq!(obj["collector_version"], json!(COLLECTOR_VERSION));
    assert_eq!(obj["counter_source"], json!(COUNTER_SOURCE));
    assert_eq!(obj["bucket_timezone"], json!("UTC"));
    // Hashes are 64-hex, >= backend min length 16.
    assert_eq!(obj["workspace_hash"].as_str().unwrap().len(), 64);
    assert_eq!(obj["config_hash"].as_str().unwrap().len(), 64);

    // daily_aggregates rows carry exactly the six contract fields, dates in
    // window, and category from the closed enum.
    let daily = obj["daily_aggregates"].as_array().unwrap();
    assert!(!daily.is_empty());
    for row in daily {
        let row = row.as_object().unwrap();
        let keys: std::collections::BTreeSet<&str> = row.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "date",
                "category",
                "events",
                "tokens_entered_est",
                "residency_weighted_tokens_est",
                "image_count"
            ]
            .into_iter()
            .collect()
        );
        assert!(Category::ALL
            .iter()
            .any(|c| c.as_str() == row["category"].as_str().unwrap()));
    }

    // top_files are repo-relative or bare names, never absolute or path-leaking.
    let files = obj["top_files"].as_array().unwrap();
    let names: Vec<&str> = files
        .iter()
        .map(|f| f["relative_path_or_name"].as_str().unwrap())
        .collect();
    for name in &names {
        assert!(!name.starts_with('/'), "absolute path leaked: {name}");
        assert!(!name.contains(".."), "parent traversal: {name}");
        assert!(!name.to_ascii_lowercase().contains("/users/"));
    }
    assert!(names.contains(&"docs/readme.md"));
    assert!(names.contains(&"efforts.html"));
    assert!(names.contains(&"recall.md")); // /x/memory/recall.md -> basename
    assert!(names.contains(&"app/code.py"));

    // sessions hashed with sha256 prefix, top_category from the enum.
    let sessions = obj["sessions"].as_array().unwrap();
    assert!(!sessions.is_empty());
    for session in sessions {
        let hash = session["session_id_hash"].as_str().unwrap();
        assert!(hash.starts_with("sha256:"), "session hash {hash}");
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(Category::ALL
            .iter()
            .any(|c| c.as_str() == session["top_category"].as_str().unwrap()));
    }

    // window bounds are valid YYYY-MM-DD and within the capture cap.
    let start = Date::parse(
        obj["window_start"].as_str().unwrap(),
        &time::format_description::well_known::Iso8601::DATE,
    )
    .unwrap();
    let end = Date::parse(
        obj["window_end"].as_str().unwrap(),
        &time::format_description::well_known::Iso8601::DATE,
    )
    .unwrap();
    assert!(end >= start);
    // Inclusive window span (whole_days + 1) must not exceed the cap.
    assert!((end - start).whole_days() < MAX_WINDOW_DAYS);
}

/// Diagnostic parity dump against the Python reference. Point `OTTTO_CCA_DIR` at
/// a real Claude Code project dir and run:
///   cargo test -p ottto-service real_workspace_parity_dump -- --ignored --nocapture
/// then compare to:
///   python3 context_composition_audit.py --claude-dir <dir> --include-subagents --json
/// The per-category (events, tokens, residency, images) must match exactly.
#[test]
#[ignore]
fn real_workspace_parity_dump() {
    let Ok(dir) = std::env::var("OTTTO_CCA_DIR") else {
        eprintln!("set OTTTO_CCA_DIR to a Claude project dir");
        return;
    };
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                out.push(path);
            }
        }
    }
    let codex = std::env::var("OTTTO_CCA_AGENT").as_deref() == Ok("codex");
    let mut files = Vec::new();
    walk(Path::new(&dir), &mut files);
    files.sort();

    let parse = |file: &Path, report: &mut WorkspaceReport, d: Date| {
        if codex {
            parse_codex_session(file, report, d);
        } else {
            parse_claude_session(file, report, d, true);
        }
    };

    if std::env::var("OTTTO_CCA_PERFILE").is_ok() {
        for file in &files {
            let mtime = fs::metadata(file)
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let mut r = WorkspaceReport::new(wide_window());
            let lines = read_jsonl(file).len();
            parse(file, &mut r, file_date(mtime));
            let shell = r.category_totals(Category::ShellOutput);
            let harness = r.category_totals(Category::HarnessAttachments);
            let other = r.category_totals(Category::OtherTools);
            let code = r.category_totals(Category::CodeReads);
            eprintln!(
                "PERFILE\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                file.file_name().unwrap().to_string_lossy(),
                lines,
                shell.0,
                harness.0,
                other.0,
                shell.1,
                code.2
            );
        }
        return;
    }

    let mut report = WorkspaceReport::new(wide_window());
    for file in &files {
        let mtime = fs::metadata(file)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        parse(file, &mut report, file_date(mtime));
    }
    let mut total = 0u64;
    let mut total_res = 0u64;
    let mut total_img = 0u64;
    eprintln!("files={} sessions={}", files.len(), report.sessions.len());
    for cat in Category::ALL {
        let (events, tokens, res, img) = report.category_totals(cat);
        total += tokens;
        total_res += res;
        total_img += img;
        eprintln!(
            "{:22} events={:6} tokens={:9} res={:11} img={}",
            cat.as_str(),
            events,
            tokens,
            res,
            img
        );
    }
    eprintln!("total_tokens={total} residency={total_res} images={total_img}");
}

#[test]
fn config_hash_is_stable_and_source_specific() {
    let a = composition_config_hash("claude-code");
    let b = composition_config_hash("claude-code");
    let c = composition_config_hash("codex");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 64);
}
