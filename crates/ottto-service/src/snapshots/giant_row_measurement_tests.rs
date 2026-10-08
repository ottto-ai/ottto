// Explicit-run synthetic allocation observations, never a safety bound or CI budget.
use super::*;
use crate::retry_allocation_probe::{measure, measure_process, stats, Stats};
use std::io::Write;

struct Fixture {
    path: PathBuf,
    lines: usize,
    bytes: u64,
    row_bytes: usize,
    family: &'static str,
    n: usize,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn parent() -> Vec<Value> {
    vec![
        json!({"timestamp":"2026-08-02T08:00:00Z","type":"session_meta","payload":{"id":"legacy-parent","thread_source":"user"}}),
        json!({"timestamp":"2026-08-02T08:00:01Z","type":"turn_context","payload":{"turn_id":"parent-turn-1","model":"gpt-5.6-sol"}}),
        codex_test_token_line(
            "2026-08-02T08:00:02Z",
            None,
            (100, 80, 10, 2),
            Some((100, 80, 10, 2)),
        ),
        json!({"timestamp":"2026-08-02T08:10:01Z","type":"turn_context","payload":{"turn_id":"parent-late-turn","model":"gpt-5.6-sol"}}),
        codex_test_token_line(
            "2026-08-02T08:10:02Z",
            None,
            (160, 120, 18, 4),
            Some((60, 40, 8, 2)),
        ),
    ]
}
fn write_value(file: &mut File, value: &Value, lines: &mut usize) {
    serde_json::to_writer(&mut *file, value).unwrap();
    file.write_all(b"\n").unwrap();
    *lines += 1;
}
fn fixture(family: &'static str, row_bytes: usize, n: usize) -> Fixture {
    let path = temp_file("m1-giant-row");
    let mut file = File::create(&path).unwrap();
    let mut lines = 0;
    if family.starts_with("claude_") {
        write_value(
            &mut file,
            &json!({"type":"user","sessionId":"legacy-child","timestamp":"2026-08-02T08:20:00Z","message":{"role":"user","content":"Synthetic initial prompt"}}),
            &mut lines,
        );
    } else if family == "prefix" {
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:00Z","type":"session_meta","payload":{"id":"legacy-child","forked_from_id":"legacy-parent","thread_source":"user","source":"cli"}}),
            &mut lines,
        );
        for value in parent().iter().take(3) {
            write_value(&mut file, value, &mut lines);
        }
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:01Z","type":"event_msg","payload":{"type":"task_started"}}),
            &mut lines,
        );
    } else if family == "trigger" {
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:00Z","type":"session_meta","payload":{"id":"legacy-child","forked_from_id":"legacy-parent","thread_source":"subagent","source":{"subagent":{"thread_spawn":{"parent_thread_id":"legacy-parent"}}}}}),
            &mut lines,
        );
        write_value(
            &mut file,
            &codex_test_token_line(
                "2026-08-02T08:00:02Z",
                None,
                (100, 80, 10, 2),
                Some((100, 80, 10, 2)),
            ),
            &mut lines,
        );
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:01Z","type":"event_msg","payload":{"type":"task_started"}}),
            &mut lines,
        );
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:02Z","type":"turn_context","payload":{"turn_id":"child-first-turn","model":"gpt-5.6-sol","effort":"high"}}),
            &mut lines,
        );
    } else {
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:00Z","type":"session_meta","payload":{"id":"legacy-child"}}),
            &mut lines,
        );
    }
    let (start, end, atom) = match family {
        "claude_image" => (
            r#"{"type":"user","sessionId":"legacy-child","timestamp":"2026-08-02T08:20:01Z","message":{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":""#,
            r#""}}]}}"#,
            "A",
        ),
        "claude_tool_output" => (
            r#"{"type":"user","sessionId":"legacy-child","timestamp":"2026-08-02T08:20:01Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"synthetic","content":""#,
            r#""}]}}"#,
            "a",
        ),
        "image" => (
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,"#,
            r#""}]}}"#,
            "A",
        ),
        "escaped_text" => (
            r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"synthetic","output":""#,
            r#""}}"#,
            "\\n",
        ),
        "compaction" => (
            r#"{"type":"compacted","payload":{"replacement_history":[{"type":"message","role":"user","content":[{"type":"input_text","text":""#,
            r#""}]}]}}"#,
            "a",
        ),
        "first_prompt" => (
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":""#,
            r#""}]}}"#,
            "a",
        ),
        "turn_context" => (
            r#"{"type":"turn_context","payload":{"turn_id":"child-first-turn","model":"gpt-5.6-sol","synthetic_metadata":""#,
            r#""}}"#,
            "a",
        ),
        "dense_int_stress" => (
            r#"{"type":"response_item","payload":{"type":"function_call_output","synthetic_stress":["#,
            "0]}}",
            "0,",
        ),
        "dense_object_stress" => (
            r#"{"type":"response_item","payload":{"type":"function_call_output","synthetic_stress":["#,
            "{}]}}",
            "{\"k\":0},",
        ),
        _ => (
            r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"synthetic","output":""#,
            r#""}}"#,
            "a",
        ),
    };
    let start = if family.starts_with("claude_") {
        start.to_string()
    } else {
        start.replacen("{", r#"{"timestamp":"2026-08-02T08:20:01Z","#, 1)
    };
    assert!(row_bytes > start.len() + end.len());
    let available = row_bytes - start.len() - end.len();
    let repeats = available / atom.len();
    // Write in <=8 KiB chunks, never build decoded dense fixture Values.
    let chunk = atom.repeat((8192 / atom.len()).max(1));
    for _ in 0..n {
        file.write_all(start.as_bytes()).unwrap();
        let mut remaining = repeats * atom.len();
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            file.write_all(&chunk.as_bytes()[..take]).unwrap();
            remaining -= take;
        }
        file.write_all(end.as_bytes()).unwrap();
        // Pad outside the JSON so the exact physical row length is the target.
        file.write_all(&vec![b' '; available % atom.len()]).unwrap();
        file.write_all(b"\n").unwrap();
        lines += 1;
    }
    if family == "prefix" {
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:02Z","type":"turn_context","payload":{"turn_id":"child-first-turn","model":"gpt-5.6-sol"}}),
            &mut lines,
        );
    } else if family == "trigger" {
        write_value(
            &mut file,
            &json!({"timestamp":"2026-08-02T08:20:03Z","type":"inter_agent_communication_metadata","payload":{"trigger_turn":true}}),
            &mut lines,
        );
    }
    let (total, last) = if matches!(family, "prefix" | "trigger") {
        ((130, 100, 15, 3), (30, 20, 5, 1))
    } else {
        ((30, 20, 5, 1), (30, 20, 5, 1))
    };
    if family.starts_with("claude_") {
        write_value(
            &mut file,
            &json!({"type":"assistant","sessionId":"legacy-child","timestamp":"2026-08-02T08:20:04Z","requestId":"synthetic-request","message":{"id":"synthetic-response","model":"claude-sonnet-4-6","usage":{"input_tokens":30,"cache_read_input_tokens":20,"output_tokens":5}}}),
            &mut lines,
        );
    } else {
        write_value(
            &mut file,
            &codex_test_token_line("2026-08-02T08:20:04Z", None, total, Some(last)),
            &mut lines,
        );
    }
    let bytes = file.metadata().unwrap().len();
    drop(file);
    Fixture {
        path,
        lines,
        bytes,
        row_bytes,
        family,
        n,
    }
}
#[derive(Clone, Copy, Default)]
struct Observation {
    retained_after_row: isize,
    retained_in_window: isize,
    window_rows: usize,
    first_prompt_material_bytes: usize,
}
fn parse(f: &Fixture) -> Observation {
    // Only borrow fixture bytes/path. All parser state and outputs die in scope.
    // No cache, attribution, cwd/workspace, printing or worker thread here.
    let path = f.path.to_path_buf();
    let mut file = File::open(&path).unwrap();
    let source = if f.family.starts_with("claude_") {
        SnapshotSource::ClaudeCode
    } else {
        SnapshotSource::Codex
    };
    let identity = opened_object_identity(source, &mut file).unwrap();
    let ledgers = if f.family == "prefix" {
        let signatures = parent()
            .iter()
            .filter_map(codex_ownership_signature)
            .collect();
        Some(Arc::new(Mutex::new(BTreeMap::from([(
            "legacy-parent".to_string(),
            CodexParentOwnershipLedger {
                signatures,
                scan_complete: true,
                opened_object_identity: String::new(),
            },
        )]))))
    } else {
        None
    };
    let mut parser = OwnedJsonlParser::new(
        file,
        &path,
        source,
        if source == SnapshotSource::Codex {
            apply_codex_line
        } else {
            apply_claude_code_line
        },
        None,
        None,
        ledgers,
        true,
        true,
    )
    .unwrap();
    let mut observed = Observation::default();
    while !parser.step().unwrap() {
        observed.retained_after_row = observed.retained_after_row.max(stats().requested_live);
        let window_rows = parser.accumulator.codex_legacy_bootstrap_buffer.len();
        if window_rows > observed.window_rows {
            observed.window_rows = window_rows;
            observed.retained_in_window = stats().requested_live;
        }
    }
    observed.first_prompt_material_bytes = parser
        .accumulator
        .first_prompt_material
        .as_ref()
        .map_or(0, String::len);
    if f.family == "first_prompt" {
        // The existing prompt extractor normalizes to 255 characters before
        // first_prompt_material receives it; a near-cap ROW is still decoded.
        assert_eq!(observed.first_prompt_material_bytes, 255);
    }
    if f.family == "turn_context" {
        assert!(parser.accumulator.cache_configuration_witness.is_some());
    }
    let inherited = parser.accumulator.codex_inherited_usage_records_skipped;
    let parsed = parser
        .finish(
            &identity,
            &path,
            "2026-08-02T09:00:00Z",
            "fp".to_string(),
            None,
            None,
            None,
        )
        .unwrap();
    assert!(parsed.complete());
    assert_eq!(parsed.report.physical_line_count, f.lines);
    assert_eq!(parsed.report.parsed_json_line_count, f.lines);
    assert_eq!(parsed.report.malformed_json_line_count, 0);
    assert_eq!(parsed.report.invalid_utf8_line_count, 0);
    assert_eq!(parsed.report.over_line_cap_count, 0);
    assert_eq!(parsed.snapshots.len(), 1);
    let item = &parsed.snapshots[0];
    // Handwritten expected totals from the existing fork oracle, not a full reader.
    assert_eq!(
        (
            item.input_tokens,
            item.cache_read_tokens,
            item.output_tokens,
            item.reasoning_output_tokens,
            item.request_count
        ),
        if source == SnapshotSource::Codex {
            (30, 20, 5, 1, 1)
        } else {
            (30, 20, 5, 0, 1)
        }
    );
    if matches!(f.family, "prefix" | "trigger") {
        assert_eq!(inherited, 1);
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
        assert_eq!(item.model_usage[0].model, "gpt-5.6-sol");
        assert_eq!(
            observed.window_rows,
            f.n + if f.family == "prefix" { 1 } else { 2 }
        );
        if f.family == "trigger" {
            assert_eq!(
                item.model_usage[0].reasoning_effort.as_deref(),
                Some("high")
            );
        }
    }
    drop(parsed);
    observed
}
fn balanced(s: Stats) {
    assert_eq!(s.requested_live, 0);
    assert_eq!(s.usable_live, 0);
    assert_eq!(s.allocations, s.deallocations);
    // Necessary checks only: offsetting external frees/leaks can pass these.
}
#[test]
#[ignore = "explicit serial native measurement; no bound claimed"]
fn m1_giant_row_allocation_receipts() {
    assert!(cfg!(all(target_os = "macos", target_pointer_width = "64")));
    assert!(env!("OTTTO_SCAN_LAYOUT_RUSTC").starts_with("rustc 1.95.0 "));
    let commit = std::env::var("OTTTO_M1_COMMIT").expect("source commit receipt required");
    let machine = std::env::var("OTTTO_M1_MACHINE").expect("machine receipt required");
    let families = [
        "claude_image",
        "claude_tool_output",
        "image",
        "escaped_text",
        "compaction",
        "tool_output",
        "first_prompt",
        "turn_context",
        "dense_int_stress",
        "dense_object_stress",
        "prefix",
        "trigger",
    ];
    for family in families {
        // Each small instance independently compared. No dense/large process audit.
        let small = fixture(family, 4096, 1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                parse(&small); // Warm up outside counting on the same thread.
                let ((_, thread), process) = measure_process(|| measure(|| parse(&small)));
                balanced(thread);
                assert_eq!(thread.allocations,process.allocations);
                assert_eq!(thread.deallocations,process.deallocations);
                assert_eq!(thread.requested_peak_with_overlap,process.requested_peak);
                assert_eq!(thread.usable_peak_with_overlap,process.usable_peak);
                assert_eq!(process.requested_live,0);
                println!("\n{}",json!({"kind":"instance_comparison","family":family,"row_bytes":4096,"n":1,"agreement":true,"thread_requested_peak_with_overlap":thread.requested_peak_with_overlap,"process_requested_peak":process.requested_peak,"thread_usable_peak_with_overlap":thread.usable_peak_with_overlap,"process_usable_peak":process.usable_peak,"thread_allocations":thread.allocations,"process_allocations":process.allocations,"thread_deallocations":thread.deallocations,"process_deallocations":process.deallocations,"commit":commit,"rustc":env!("OTTTO_SCAN_LAYOUT_RUSTC"),"machine":machine,"scope":"this instance only; A1-A3 assumed; uncompensated violations detected","claim":"no bound claimed"}));
            }).join().unwrap();
        });
        drop(small);
        let sizes: &[usize] = if family.contains("stress") {
            &[1 << 20, 4 << 20]
        } else {
            &[1 << 20, 4 << 20, (16 << 20) - 1024]
        };
        let ns: &[usize] = if matches!(family, "prefix" | "trigger") {
            &[1, 4]
        } else {
            &[1]
        };
        for &size in sizes {
            for &n in ns {
                let f = fixture(family, size, n); // Files/buffers built before counting.
                std::thread::scope(|scope| {
                    scope.spawn(|| {
                    let warm = fixture(family,4096,1);
                    parse(&warm);
                    drop(warm);
                    let (observed, s) = measure(|| parse(&f));
                    balanced(s);
                    println!("\n{}",json!({"kind":"measurement","family":family,"synthetic_stress":family.contains("stress"),"row_bytes":f.row_bytes,"file_bytes":f.bytes,"physical_lines":f.lines,"n":n,"requested_peak":s.requested_peak,"requested_peak_with_overlap":s.requested_peak_with_overlap,"usable_peak":s.usable_peak,"usable_peak_with_overlap":s.usable_peak_with_overlap,"requested_live_end":s.requested_live,"retained_after_row":observed.retained_after_row,"retained_in_window":observed.retained_in_window,"window_rows":observed.window_rows,"first_prompt_material_bytes":observed.first_prompt_material_bytes,"retained_meaning":"whole parser scope live bytes after a step, includes reader buffer; not bootstrap-only","allocations":s.allocations,"deallocations":s.deallocations,"expected_tokens":[30,20,5,if family.starts_with("claude_") {0} else {1}],"expected_requests":1,"commit":commit,"rustc":env!("OTTTO_SCAN_LAYOUT_RUSTC"),"machine":machine,"scope":"A1-A3 assumed; uncompensated violations detected; small comparison validates only its instance","claim":"requested allocation observations, not RSS/process footprint; no bound claimed"}));
                }).join().unwrap();
                });
            }
        }
    }
}
