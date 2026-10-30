//! Prefix differential against the actual pre-extraction publishing algorithm.
use super::*;
use crate::durable_tail_codec::{Durable, Enc};
use serde_json::json;

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const CUTOVER: i64 = 1_793_016_000_000;
const TIME: &str = "2026-10-27T01:00:01Z";

fn t(k: u64) -> Value {
    json!({"input_tokens":10*k,"cached_input_tokens":0,"cache_write_input_tokens":0,
        "output_tokens":2*k,"reasoning_output_tokens":0,"total_tokens":12*k})
}
fn h() -> Value {
    json!({"type":"session_meta","timestamp":"2026-10-27T00:00:00Z",
        "payload":{"id":SESSION,"timestamp":"2026-10-27T00:00:00Z"}})
}
fn event(kind: &str, id: Option<&str>) -> Value {
    let mut v =
        json!({"type":"event_msg","timestamp":"2026-10-27T01:00:00Z","payload":{"type":kind}});
    if let Some(id) = id {
        v["payload"]["turn_id"] = json!(id);
    }
    v
}
fn s(id: &str) -> Value {
    event("task_started", Some(id))
}
fn c(id: &str) -> Value {
    event("task_complete", Some(id))
}
fn u(j: u64, last: Option<u64>, total: u64) -> Value {
    let mut v = json!({"type":"event_msg","timestamp":TIME,"fixture_line":j,
        "payload":{"type":"token_count","info":{"model":"fixture-model","total_token_usage":t(total)}}});
    if let Some(last) = last {
        v["payload"]["info"]["last_token_usage"] = t(last);
    }
    v
}
fn n(response: &str, turn: Option<&str>, usage: u64, after: u64) -> Value {
    let mut v = json!({"type":"token_usage_record","timestamp":"2026-10-27T01:00:02Z",
        "payload":{"thread_id":SESSION,"response_id":response,"model":"fixture-model",
        "usage":t(usage),"thread_token_usage":t(after)}});
    if let Some(turn) = turn {
        v["payload"]["turn_id"] = json!(turn);
    }
    v
}
fn seed() -> SnapshotAccumulator {
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
    acc.source_session_id = Some(SESSION.into());
    acc.codex_ownership_boundary = CodexOwnershipBoundary::AllLocal;
    acc.codex_counting = Some(Box::new(CodexCounting::new(
        AckEvidence::None,
        Some(CUTOVER),
    )));
    acc
}
fn bytes<T: Durable>(value: &T) -> Vec<u8> {
    let mut e = Enc::full_bytes(512 * 1024);
    value
        .put(&mut e)
        .expect("complete deterministic fixture state");
    e.into_bytes()
}
fn assert_same(label: &str, prefix: usize, real: &SnapshotAccumulator, old: &SnapshotAccumulator) {
    // Full durable bytes include X content recursively, every accounting and
    // reducer field, six-dimensional tuples, Some(0), staged activity/selectors
    // and counters. I pointers and empty-only fields are never normalized.
    assert_eq!(
        bytes(real),
        bytes(old),
        "{label} prefix {prefix}: internal bytes"
    );
    // Supplement X fields omitted by the byte codec. These fixture lines carry
    // no instructions/prelude; session-start counters are in the codec/output.
    assert_eq!(
        (
            &real.title,
            &real.first_prompt_title,
            &real.first_prompt_material,
            &real.workspace_path,
            &real.codex_agent_label
        ),
        (
            &old.title,
            &old.first_prompt_title,
            &old.first_prompt_material,
            &old.workspace_path,
            &old.codex_agent_label
        ),
        "{label} prefix {prefix}: content"
    );
    let finish = |acc: &SnapshotAccumulator| {
        serde_json::to_vec(&acc.clone().into_items(
            Path::new("/fixture/codex.jsonl"),
            "2026-10-27T02:00:00Z",
            "fixture-fingerprint".into(),
            None,
        ))
        .unwrap()
    };
    assert_eq!(
        finish(real),
        finish(old),
        "{label} prefix {prefix}: snapshot bytes"
    );
    let receipts = |acc: &SnapshotAccumulator| {
        let mut folded = CountingV2Receipts::default();
        if let Some(counting) = &acc.codex_counting {
            counting.fold_receipts(&mut folded);
        }
        serde_json::to_vec(&folded).unwrap()
    };
    assert_eq!(
        receipts(real),
        receipts(old),
        "{label} prefix {prefix}: receipts"
    );
    assert_eq!(
        real.codex_counting.as_ref().and_then(|c| c.counters()),
        old.codex_counting.as_ref().and_then(|c| c.counters())
    );
}
fn run(label: &str, initial: SnapshotAccumulator, lines: &[Value]) -> SnapshotAccumulator {
    let mut real = initial.clone();
    let mut old = initial;
    assert_same(label, 0, &real, &old);
    for (i, line) in lines.iter().enumerate() {
        // The complete owned caller is void. Probe its admission methods on
        // independent copies as well, so equal output cannot hide Some vs None.
        let mut rp = real.clone();
        let mut op = old.clone();
        let selector = codex_selector_from_line(line);
        let timestamp = string_at(line, &["timestamp"]);
        rp.observe_codex_counting_line(line, timestamp.as_deref(), &selector);
        op.observe_codex_counting_line_pre_refactor(line, timestamp.as_deref(), &selector);
        if let Some(total) = codex_total_usage(line) {
            let last = codex_last_usage(line);
            let id = codex_usage_event_identity(line);
            let implicit = (!codex_total_usage_has_request_count(line)).then_some(1);
            let model = string_at(line, &["payload", "info", "model"]);
            let a = rp.set_cumulative_usage_with_selector(
                model.clone(),
                total.clone(),
                last.clone(),
                id.clone(),
                selector.clone(),
                timestamp.as_deref(),
                implicit,
                None,
            );
            let b = op.set_cumulative_usage_with_selector_pre_refactor(
                model,
                total,
                last,
                id,
                selector,
                timestamp.as_deref(),
                implicit,
                None,
            );
            assert_eq!(a, b, "{label} prefix {}: admission", i + 1);
        }
        assert_same(label, i + 1, &rp, &op);
        apply_codex_owned_line(line, &mut real);
        pre_refactor::apply_codex_owned_line_pre_refactor(line, &mut old);
        assert_same(label, i + 1, &real, &old);
    }
    real
}
fn core_cases() -> Vec<(&'static str, Vec<Value>)> {
    let mut cases = vec![
        (
            "ordinary",
            vec![
                h(),
                s("a"),
                u(1, Some(1), 1),
                u(2, Some(1), 1),
                u(2, Some(1), 1),
                n("r1", Some("a"), 1, 1),
                n("r1", Some("a"), 1, 1),
                u(3, Some(1), 2),
                c("a"),
                n("r1", Some("a"), 1, 1),
            ],
        ),
        (
            "ui-only-mismatch-reopen",
            vec![
                h(),
                s("a"),
                u(1, Some(1), 1),
                s("b"),
                u(2, Some(1), 2),
                c("x"),
                event("turn_aborted", Some("x")),
                s("a"),
                u(3, Some(1), 2),
                n("r1", Some("a"), 1, 1),
            ],
        ),
        (
            "unbound",
            vec![h(), u(1, Some(1), 1), u(2, Some(1), 1), u(2, Some(1), 1)],
        ),
        (
            "native-between-ui",
            vec![
                h(),
                s("a"),
                u(1, Some(1), 1),
                n("r1", Some("a"), 1, 1),
                u(2, Some(1), 1),
                u(3, Some(1), 1),
                c("a"),
            ],
        ),
        (
            "base-reset-zero",
            vec![
                h(),
                s("a"),
                u(1, None, 5),
                u(2, None, 7),
                u(3, None, 2),
                u(4, Some(0), 2),
                u(5, Some(1), 3),
                u(5, Some(1), 3),
                c("a"),
            ],
        ),
        (
            "legacy-prefix",
            vec![
                json!({"type":"event_msg","payload":{"type":"notice"}}),
                h(),
                s("a"),
                n("r1", Some("a"), 1, 1),
                u(1, Some(1), 1),
                c("a"),
            ],
        ),
        (
            "native-prefix",
            vec![
                n("r1", Some("a"), 1, 1),
                h(),
                s("a"),
                u(1, Some(1), 1),
                c("a"),
            ],
        ),
        (
            "coverage",
            vec![
                h(),
                s("a"),
                n("r1", Some("a"), 1, 1),
                n("r1", Some("a"), 1, 1),
                n("r2", Some("a"), 1, 3),
                n("r3", Some("a"), 2, 4),
                n("r3", Some("a"), 1, 5),
                n("r4", Some("a"), 1, 1),
                c("a"),
            ],
        ),
        (
            "outside-closed-missing",
            vec![
                h(),
                n("r1", Some("a"), 1, 1),
                c("a"),
                n("r2", Some("a"), 1, 2),
                s("b"),
                n("r3", None, 1, 3),
                c("b"),
            ],
        ),
    ];
    for close in [
        c("a"),
        event("turn_aborted", Some("a")),
        event("task_complete", None),
    ] {
        cases.push(("explicit-close", vec![h(), s("a"), u(1, Some(1), 1), close]));
    }
    for close in ["task_complete", "turn_aborted"] {
        let mut start = n("r1", Some("b"), 1, 1);
        start["payload"]["type"] = json!("task_started");
        let mut end = n("r2", Some("b"), 1, 2);
        end["payload"]["type"] = json!(close);
        cases.push((
            "native-lifecycle",
            vec![h(), s("a"), u(1, Some(1), 1), start, u(2, Some(1), 2), end],
        ));
    }
    for id in [String::new(), "x".repeat(129)] {
        cases.push((
            "invalid-close-id",
            vec![h(), s("a"), u(1, Some(1), 1), c(&id), c("a")],
        ));
        cases.push((
            "invalid-start-id",
            vec![h(), s(&id), u(1, Some(1), 1), c(&id)],
        ));
    }
    let mut invalid = vec![h(), s("a")];
    for j in 0..4 {
        let mut v = n(&format!("r{j}"), Some("a"), 1, 1);
        match j {
            0 => v["payload"]["thread_id"] = json!("foreign"),
            1 => {
                v["payload"].as_object_mut().unwrap().remove("response_id");
            }
            2 => {
                v["payload"]["usage"]
                    .as_object_mut()
                    .unwrap()
                    .remove("output_tokens");
            }
            _ => v["payload"]["usage"] = t(2),
        }
        invalid.push(v);
    }
    invalid.extend([n("ok", Some("a"), 1, 1), c("a")]);
    cases.push(("invalid-authority", invalid));
    let mut ring = vec![h()];
    ring.extend((1..=65).map(|i| c(&format!("a{i:02}"))));
    ring.extend([s("a01"), n("r1", Some("a01"), 1, 1)]);
    cases.push(("closed-filter", ring));
    let mut overflow = vec![h(), s("a")];
    overflow.extend((1..=65).map(|j| {
        let mut v = u(j, Some(1), j);
        v["payload"]["info"]["model"] = json!(format!("fixture-model-{j}"));
        v
    }));
    overflow.extend([n("r1", Some("a"), 1, 1), u(66, Some(1), 66), c("a")]);
    cases.push(("overflow", overflow));
    cases
}

#[test]
fn codex_pre_post_publishing_prefixes_are_byte_identical() {
    for (name, lines) in core_cases() {
        let result = run(name, seed(), &lines);
        let c = result.codex_counting.as_ref().and_then(|c| c.counters());
        match name {
            "ordinary" => {
                let c = c.unwrap();
                assert_eq!(c.native_counted, 1);
                assert_eq!(c.ui_equal_total_repeat, 1);
                assert_eq!(result.codex_duplicate_usage_records_skipped, 1);
            }
            "invalid-authority" => {
                let c = c.unwrap();
                assert_eq!(c.native_not_authority, 4);
                assert_eq!(c.native_counted, 1);
            }
            "ui-only-mismatch-reopen" => {
                let c = c.unwrap();
                assert_eq!(c.turn_closure_mismatch, 1);
                assert_eq!(c.turn_reopened, 1);
            }
            "overflow" => assert_eq!(c.unwrap().pending_overflow_flushes, 1),
            "closed-filter" => {
                let r = result
                    .codex_counting
                    .as_ref()
                    .unwrap()
                    .reducer
                    .as_ref()
                    .unwrap();
                assert_eq!(r.closed_turns.len(), 64);
                assert!(!r.closed_turns.iter().any(|id| id == "a01"));
                assert!(r.closed_filter.as_ref().unwrap().contains("a01"));
            }
            _ => {}
        }
        // Repeat every delta case with all cache/reasoning dimensions present.
        let mut dimensions = lines.clone();
        for line in &mut dimensions {
            for path in [
                "/payload/info/last_token_usage",
                "/payload/info/total_token_usage",
                "/payload/usage",
                "/payload/thread_token_usage",
            ] {
                if let Some(t) = line.pointer_mut(path) {
                    let k = t["input_tokens"].as_u64().unwrap() / 10;
                    t["cached_input_tokens"] = json!(2 * k);
                    t["cache_write_input_tokens"] = json!(k);
                    t["reasoning_output_tokens"] = json!(k);
                }
            }
        }
        run(name, seed(), &dimensions);
        // Explicit request-count variants, retaining physical duplicate Values.
        let mut explicit = lines.clone();
        for line in &mut explicit {
            for (path, last) in [
                ("/payload/info/last_token_usage", true),
                ("/payload/info/total_token_usage", false),
            ] {
                if let Some(t) = line.pointer_mut(path) {
                    let count = if last {
                        1
                    } else {
                        t["input_tokens"].as_u64().unwrap() / 10
                    };
                    t["request_count"] = json!(count);
                }
            }
        }
        run(name, seed(), &explicit);
    }
}

#[test]
fn codex_pre_post_version_and_reducer_guard_matrix() {
    let standard = vec![
        h(),
        s("a"),
        n("r1", Some("a"), 1, 1),
        u(1, Some(1), 1),
        c("a"),
    ];
    let mut absent = seed();
    absent.codex_counting = None;
    run("no counting", absent, &standard);
    for (version, reducer) in [
        (Some(CountingVersion::Legacy), false),
        (Some(CountingVersion::V2), false),
        (Some(CountingVersion::Legacy), true),
        (None, true),
    ] {
        let mut initial = seed();
        let counting = initial.codex_counting.as_mut().unwrap();
        counting.version = version;
        counting.reducer = reducer.then(Box::default);
        run("injected guard", initial.clone(), &standard);
        let mut native_first = standard.clone();
        native_first.swap(0, 2);
        run("injected native first", initial, &native_first);
    }
    for evidence in [
        AckEvidence::None,
        AckEvidence::LegacyAcked,
        AckEvidence::V2Marked,
    ] {
        for cutover in [None, Some(CUTOVER)] {
            for variant in 0..5 {
                let mut initial = seed();
                initial.codex_counting = Some(Box::new(CodexCounting::new(evidence, cutover)));
                let mut lines = standard.clone();
                match variant {
                    1 => lines[0]["payload"]["timestamp"] = json!("2020-01-01T00:00:00Z"),
                    2 => {
                        lines[0]["payload"]
                            .as_object_mut()
                            .unwrap()
                            .remove("timestamp");
                    }
                    3 => lines[0]["payload"]["timestamp"] = json!("invalid"),
                    4 => lines[0]["payload"]["history_base"] = json!({}),
                    _ => {}
                }
                run("version decision", initial, &lines);
            }
        }
    }
}

#[test]
fn codex_pre_post_direct_admission_return_order_and_publication_failures() {
    for bound in [false, true] {
        for implicit in [None, Some(0), Some(1)] {
            let mut real = seed();
            real.observe_codex_counting_line(&h(), Some(TIME), &SelectorCapture::default());
            if bound {
                real.observe_codex_counting_line(&s("a"), Some(TIME), &SelectorCapture::default());
            }
            let mut old = real.clone();
            for (id, model, last) in [
                ("first", Some("fixture-model"), 1),
                ("first", Some("changed-on-duplicate"), 1),
                ("zero", None, 0),
                ("next", None, 1),
            ] {
                let line = u(1, Some(last), 1);
                let total = codex_total_usage(&line).unwrap();
                let last = codex_last_usage(&line);
                real.codex_occurrence().unwrap().line_ui = Some(([1; 6], [2; 6]));
                old.codex_occurrence().unwrap().line_ui = Some(([1; 6], [2; 6]));
                let a = real.set_cumulative_usage_with_selector(
                    model.map(str::to_owned),
                    total.clone(),
                    last.clone(),
                    Some(sha256_hex(&["fixture-physical-identity", id])),
                    SelectorCapture::default(),
                    Some(TIME),
                    implicit,
                    None,
                );
                let b = old.set_cumulative_usage_with_selector_pre_refactor(
                    model.map(str::to_owned),
                    total,
                    last,
                    Some(sha256_hex(&["fixture-physical-identity", id])),
                    SelectorCapture::default(),
                    Some(TIME),
                    implicit,
                    None,
                );
                assert_eq!(a, b);
                assert_same("direct", 0, &real, &old);
                if id == "first" && model == Some("changed-on-duplicate")
                    || id == "zero" && implicit == Some(0)
                {
                    assert_eq!(
                        real.codex_occurrence().unwrap().line_ui,
                        Some(([1; 6], [2; 6]))
                    );
                }
            }
        }
    }
    for overflow in [false, true] {
        for native in [false, true] {
            let mut initial = seed();
            if overflow {
                initial.accepted_usage_totals.input_tokens = u64::MAX - 1;
            }
            let mut lines = vec![
                h(),
                s("a"),
                if native {
                    n("r1", Some("a"), 1, 1)
                } else {
                    u(1, Some(1), 1)
                },
                c("a"),
            ];
            if !overflow {
                for line in &mut lines {
                    line.as_object_mut().unwrap().remove("timestamp");
                }
            }
            run("publication refusal", initial, &lines);
        }
    }
}

#[test]
fn codex_content_scratch_and_real_fence_adoption_leave_publishing_state_isolated() {
    use crate::snapshots::sampled_jsonl::durable;
    for (name, mut lines) in core_cases()
        .into_iter()
        .filter(|(name, _)| matches!(*name, "ui-only-mismatch-reopen" | "overflow"))
    {
        lines.push(json!({"type":"event_msg","timestamp":TIME,"payload":{"type":"user_message","message":"synthetic fixture prompt"}}));
        let root = crate::test_scratch::ScratchDir::new("codex-pre-post-isolation");
        let path = root.join("fixture.jsonl");
        let text = lines
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>();
        std::fs::write(&path, &text).unwrap();
        let mut real = seed();
        let mut old = real.clone();
        let mut offset = 0;
        for line in &lines {
            let length = (line.to_string().len() + 1) as u64;
            crate::durable_tail_codec::with_line(Some((offset, length)), || {
                // Native envelope work precedes the copied owned caller. Both
                // branches receive the same header/prelude initialization.
                if string_eq_at(line, &["type"], "session_meta") {
                    real.session_start.note_codex_session_meta(line);
                    old.session_start.note_codex_session_meta(line);
                }
                apply_codex_owned_line(line, &mut real);
                pre_refactor::apply_codex_owned_line_pre_refactor(line, &mut old);
            });
            offset += length;
        }
        assert_same(name, lines.len(), &real, &old);
        assert!(real.first_prompt_material.is_some());
        let before = bytes(&real);
        let mut scratch = durable::test_codex_content_scratch(&real);
        for line in &lines {
            scratch.observe_codex_content_counting(line);
            if let Some(total) = codex_total_usage(line) {
                scratch.decide_codex_usage(
                    None,
                    total,
                    codex_last_usage(line),
                    codex_usage_event_identity(line),
                    Some(1),
                );
            }
            assert!(scratch.usage_buckets.is_empty());
            assert_eq!(scratch.accepted_usage_totals, UsageTotals::default());
            if let Some(turn) = scratch.codex_occurrence().and_then(|r| r.turn.as_ref()) {
                assert!(turn.pending.is_empty());
                assert_eq!(turn.staged_events, 0);
            }
            assert_eq!(
                bytes(&real),
                before,
                "scratch prefix cannot mutate retained accounting"
            );
        }
        assert!(matches!(
            durable::test_rederive_codex_accumulator(
                &real,
                &std::fs::File::open(&path).unwrap(),
                true
            ),
            Err(crate::durable_tail_codec::Refuse::NotRederivable(
                "content_fence"
            ))
        ));
        assert_eq!(
            bytes(&real),
            before,
            "failed fence preserves retained owner"
        );
        let mut adopted = durable::test_rederive_codex_accumulator(
            &real,
            &std::fs::File::open(&path).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(bytes(&real), before);
        assert_same("after adoption", 0, &adopted, &old);
        for (i, line) in [
            s("b"),
            u(90, Some(1), 90),
            n("suffix", Some("b"), 1, 90),
            c("x"),
            s("fresh"),
            u(91, Some(1), 91),
            c("fresh"),
        ]
        .iter()
        .enumerate()
        {
            apply_codex_owned_line(line, &mut adopted);
            pre_refactor::apply_codex_owned_line_pre_refactor(line, &mut old);
            assert_same("suffix after adoption", i + 1, &adopted, &old);
        }
    }
}
