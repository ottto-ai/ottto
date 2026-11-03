//! Claude usage stated only in `usage.iterations[]` (one entry per API call).
//!
//! Real transcripts carry part of a response's usage only in its iterations,
//! and the top level never exceeds their sum. Each billed kind counts the
//! larger of the two, never both. Fixtures are synthetic usage blocks only.
use super::*;
use serde_json::json;

const SESSION_EQUAL: &str = "1d164000-0000-4000-8000-00000000000a";
const SESSION_PARTIAL: &str = "1d164000-0000-4000-8000-00000000000b";

/// Billed kinds in order: input, output, cache read, cache write 5m and 1h.
type Billed = [u64; 5];

fn billed(input: u64, output: u64, read: u64, write_5m: u64, write_1h: u64) -> Value {
    json!({"input_tokens": input, "output_tokens": output, "cache_read_input_tokens": read,
        "cache_creation_input_tokens": write_5m + write_1h,
        "cache_creation": {"ephemeral_5m_input_tokens": write_5m, "ephemeral_1h_input_tokens": write_1h}})
}

fn counted(usage: &UsageTotals) -> Billed {
    [
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_5m_tokens,
        usage.cache_creation_1h_tokens,
    ]
}

/// Each observed class: (name, top level, iterations, counted usage).
fn classes() -> Vec<(&'static str, Value, Vec<Value>, Billed)> {
    let last = billed(3, 90, 70_000, 2_000, 0);
    let last_1h = billed(1, 10, 600, 0, 100);
    vec![
        (
            "top level equals the sum",
            billed(3, 50, 1_000, 200, 0),
            vec![billed(3, 50, 1_000, 200, 0)],
            [3, 50, 1_000, 200, 0],
        ),
        (
            // Flat fields all zero; the nested write restates the iteration's.
            "only the iteration carries usage",
            json!({"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 1_684}}),
            vec![billed(2, 312, 894_911, 0, 1_684)],
            [2, 312, 894_911, 0, 1_684],
        ),
        (
            "top level restates the last of two calls",
            last.clone(),
            vec![billed(5, 120, 80_000, 4_000, 0), last],
            [8, 210, 150_000, 6_000, 0],
        ),
        (
            "1h writes, top level restates the last call",
            last_1h.clone(),
            vec![billed(1, 10, 500, 0, 300), last_1h],
            [2, 20, 1_100, 0, 400],
        ),
    ]
}

fn response(session: &str, n: usize, top: &Value, iterations: &[Value], at: &str) -> Value {
    let mut usage = top.clone();
    usage["iterations"] = json!(iterations);
    json!({"type": "assistant", "sessionId": session, "uuid": format!("u{n}"), "cwd": "/synthetic",
        "timestamp": at, "requestId": format!("req_{n}"), "message": {"id": format!("msg_{n}"),
        "model": "claude-opus-4-8", "role": "assistant", "usage": usage}})
}

/// [regress] A response whose usage sits only in `iterations[]`, in full or
/// beyond the top level's last call, is counted once per kind, and passes the
/// positive-usage check; a top level equal to the sum is not double counted.
#[test]
fn claude_usage_takes_the_larger_of_top_level_and_iterations_per_kind() {
    for (class, top, iterations, expected) in classes() {
        let line = response(
            SESSION_PARTIAL,
            0,
            &top,
            &iterations,
            "2026-11-02T10:00:00Z",
        );
        let usage = claude_code_delta_usage(&line).expect(class);
        assert_eq!(counted(&usage), expected, "{class}");
        assert!(
            recognized_positive_usage_shape(SnapshotSource::ClaudeCode, &line),
            "{class}"
        );
    }
}

/// [regress] A refusal fallback's declined first attempt, a call naming
/// another model than the line, is counted by `usage_iteration_model_differs`;
/// a call on the line's model, or naming none, is not.
#[test]
fn claude_iteration_on_another_model_is_counted() {
    let count = |line: &Value| {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
        let ((), counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            apply_claude_code_line(line, &mut accumulator)
        });
        counts.usage_iteration_model_differs
    };
    let on = |model: &str, mut usage: Value| {
        usage["model"] = json!(model);
        usage
    };
    let at = "2026-11-02T10:00:00Z";
    let served = billed(2, 60, 50_500, 500, 0);
    let calls = [
        on("claude-sonnet-4-5", billed(4, 30, 50_000, 1_000, 0)),
        on("claude-opus-4-8", served.clone()),
    ];
    assert_eq!(count(&response(SESSION_PARTIAL, 0, &served, &calls, at)), 1);
    let same = [on("claude-opus-4-8", served.clone())];
    assert_eq!(count(&response(SESSION_PARTIAL, 0, &served, &same, at)), 0);
    for (class, top, iterations, _) in classes() {
        let line = response(SESSION_PARTIAL, 0, &top, &iterations, at);
        assert_eq!(count(&line), 0, "{class}");
    }
}

/// [money] Emitted money and placement equal a transcript whose top level
/// already states every call, so the fold adds exactly the iterations-only
/// usage.
/// A session with only top-level-equals-sum lines emits the top-level totals,
/// as before the fold.
#[test]
fn claude_iterations_fold_matches_a_complete_top_level() {
    let dir = crate::test_scratch::ScratchDir::canonical("claude-usage-iterations");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let scan = |name: &str, complete: bool| {
        let root = dir.join(name);
        fs::create_dir_all(&root).unwrap();
        let equal = (0..3)
            .map(|n| {
                let usage = billed(3 + n as u64, 50, 1_000, 200, 0);
                let iterations = std::slice::from_ref(&usage);
                response(SESSION_EQUAL, 10 + n, &usage, iterations, &now).to_string() + "\n"
            })
            .collect::<String>();
        let partial = classes()
            .into_iter()
            .enumerate()
            .map(|(n, (_, top, iterations, [i, o, r, w5, w1]))| {
                let top = if complete {
                    billed(i, o, r, w5, w1)
                } else {
                    top
                };
                response(SESSION_PARTIAL, n, &top, &iterations, &now).to_string() + "\n"
            })
            .collect::<String>();
        fs::write(root.join(format!("{SESSION_EQUAL}.jsonl")), equal).unwrap();
        fs::write(root.join(format!("{SESSION_PARTIAL}.jsonl")), partial).unwrap();
        let (index, result) =
            super::source_erasure_tests::cold_full(&root, &now, ScanIndex::default());
        let route = sampled_scan::transition_fixture::scan_money(
            SnapshotSource::ClaudeCode,
            &index,
            &result,
        );
        (route, result)
    };
    let (complete, _) = scan("complete", true);
    let (as_written, result) = scan("as-written", false);
    // The oracle's money fields and placement, not the whole body: a top level
    // stating the sum of two calls also states a larger single prompt, so the
    // context watermarks rightly differ.
    use sampled_scan::transition_fixture::money_oracle::{
        assert_placement_equivalent, diff, FIELDS,
    };
    assert_eq!(complete.snapshots.len(), 2);
    assert_placement_equivalent(&complete, &as_written);
    let mut differences = Vec::new();
    for (entity, body) in &complete.snapshots {
        for field in FIELDS {
            let other = &as_written.snapshots[entity][*field];
            diff(
                &format!("{entity}/{field}"),
                &body[*field],
                other,
                &mut differences,
            );
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));

    let emitted = |session: &str| {
        let item = result
            .snapshots
            .iter()
            .find(|item| item.source_session_id == session)
            .expect(session);
        [
            item.input_tokens,
            item.output_tokens,
            item.cache_read_tokens,
            item.cache_creation_5m_tokens,
            item.cache_creation_1h_tokens,
        ]
    };
    assert_eq!(emitted(SESSION_EQUAL), [12, 150, 3_000, 600, 0]);
    // Top-level totals [7, 150, 71_600, 2_200, 1_784] plus the
    // iterations-only remainder [8, 442, 975_411, 4_000, 300].
    assert_eq!(emitted(SESSION_PARTIAL), [15, 592, 1_047_011, 6_200, 2_084]);
}
