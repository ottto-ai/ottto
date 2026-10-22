use super::*;
use crate::composition_kinds::Part;
use crate::snapshots::{
    self, SnapshotBatchRequest, SnapshotSessionStart, SnapshotSource, StartVerdict,
};

#[test]
fn composition_ids_match_snapshot_wire_for_roots_task_workflow_and_codex() {
    let root = scratch("composition-id-wire-parity");
    for (source, path, first, expected) in [
        (Source::Claude, "root.jsonl", "ROOT", "ROOT"),
        (
            Source::Claude,
            "PARENT/subagents/agent-task.jsonl",
            "COPIED",
            "PARENT_agent-task",
        ),
        (
            Source::Claude,
            "PARENT/subagents/workflows/wf-test/inner/agent-nested.jsonl",
            "COPIED",
            "PARENT_agent-nested",
        ),
        (
            Source::Codex,
            "rollout.jsonl",
            "01A03E99-49CF-7460-9FD7-F7DBFD2F05E4",
            "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4",
        ),
    ] {
        let path = root.join(path);
        let records = match source {
            Source::Claude => vec![
                json!({"type":"user","sessionId":first,"timestamp":"2026-08-02T06:00:00Z","message":{"content":"first"}}),
                json!({"type":"assistant","sessionId":"LATER","timestamp":"2026-08-02T06:01:00Z","message":{"id":"m","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":2}}}),
            ],
            Source::Codex => vec![
                json!({"type":"session_meta","timestamp":"2026-08-02T06:00:00Z","payload":{"id":first}}),
                json!({"type":"event_msg","timestamp":"2026-08-02T06:01:00Z","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":2}}}}),
            ],
        };
        write_records(&path, &records);
        let parse = match source {
            Source::Claude => snapshots::parse_claude_code_jsonl_file,
            Source::Codex => snapshots::parse_codex_jsonl_file,
        };
        let items = parse(&path, "2026-08-02T06:02:00Z", "fp".into()).unwrap();
        assert_eq!(items.len(), 1);
        let state = new_parse_state(source, &path, 0).0;
        assert_eq!(&*state.session, expected);
        assert_eq!(&*state.session, items[0].source_session_id);
        let round = StoredParse::from_state(&state).into_state().unwrap();
        assert_eq!(round.session, state.session);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn session_rows_send_plain_ids_and_exact_top_kind_tokens() {
    let env = Env::new("composition-session-top-kind-tokens");
    let now = base_now();
    let (claude, _) = every_family(&env.cwd(), now.date());
    write_records(&env.root.join("p/s.jsonl"), &claude);
    let mut capture = Capture::default();
    env.run(Source::Claude, now, Some(&mut capture));
    let scope = env.scope(Source::Claude);
    assert!(!capture.payloads[0]["sessions"]
        .as_array()
        .unwrap()
        .is_empty());
    for row in capture.payloads[0]["sessions"].as_array().unwrap() {
        let id = row["source_session_id"].as_str().unwrap();
        assert_eq!(
            row["session_id_hash"],
            format!("sha256:{}", sha256_hex(&[id]))
        );
        let tokens = row["top_kind_tokens_entered_est"].as_u64().unwrap();
        assert!(tokens <= row["total_tokens_entered_est"].as_u64().unwrap());
        let kind = kind_from_str(row["top_kind"].as_str().unwrap()).unwrap();
        let expected: u64 = scope.agg.sessions[id]
            .days
            .iter()
            .flat_map(|(_, kinds)| kinds)
            .filter(|(k, _)| *k == kind)
            .map(|(_, tokens)| tokens)
            .sum();
        assert_eq!(tokens, expected);
    }
    env.cleanup();
}

fn verdict_request(source: Source, path: &Path, measured: bool) -> SnapshotBatchRequest {
    let (parse, snapshot_source) = match source {
        Source::Claude => (
            snapshots::parse_claude_code_jsonl_file
                as fn(&Path, &str, String) -> anyhow::Result<Vec<snapshots::SnapshotItem>>,
            SnapshotSource::ClaudeCode,
        ),
        Source::Codex => (
            snapshots::parse_codex_jsonl_file
                as fn(&Path, &str, String) -> anyhow::Result<Vec<snapshots::SnapshotItem>>,
            SnapshotSource::Codex,
        ),
    };
    let mut item = parse(path, "2026-08-02T06:02:00Z", "fp".into())
        .unwrap()
        .remove(0);
    item.session_start = Some(Box::new(SnapshotSessionStart {
        client_version: Some("test".into()),
        user_turn_count: measured.then_some(1),
        ..Default::default()
    }));
    SnapshotBatchRequest {
        schema_version: snapshots::SNAPSHOT_SCHEMA_VERSION,
        source: snapshot_source.api_slug().into(),
        machine_id: "synthetic-machine".into(),
        collector_version: None,
        snapshots: vec![item],
        upload_policy: Default::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}

fn record_request(
    support: &Path,
    request: &SnapshotBatchRequest,
    now: i64,
) -> std::io::Result<u64> {
    snapshots::start_verdict_store::record(
        support,
        "synthetic-destination",
        &request.source,
        &request.snapshots,
        now,
    )
}

#[test]
fn final_verdict_bridge_both_ways_missing_and_expired_are_unmeasured() {
    let env = Env::new("composition-final-verdict-bridge");
    let now = base_now();
    let path = env.root.join("p/s.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"user","sessionId":"s","isSidechain":false,"cwd":env.cwd(),"timestamp":ts(now.date(),1),"message":{"content":"opening prompt"}}),
            json!({"type":"assistant","sessionId":"s","timestamp":ts(now.date(),2),"message":{"id":"m","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":2}}}),
        ],
    );
    let request = verdict_request(Source::Claude, &path, true);
    let source = "claude-code";
    let id = &request.snapshots[0].source_session_id;
    let get = |when| {
        snapshots::start_verdict_store::load(&env.root, "synthetic-destination", when)
            .get(source, id, when)
    };
    assert_eq!(get(now.unix_timestamp()), StartVerdict::NotMeasured);
    let bytes = record_request(&env.root, &request, now.unix_timestamp()).unwrap();
    assert!(bytes > 0);
    assert_eq!(get(now.unix_timestamp()), StartVerdict::Measured);
    assert_eq!(
        record_request(&env.root, &request, now.unix_timestamp()).unwrap(),
        0
    );
    let unmeasured = verdict_request(Source::Claude, &path, false);
    assert!(record_request(&env.root, &unmeasured, now.unix_timestamp() + 1).unwrap() > 0);
    assert_eq!(get(now.unix_timestamp() + 1), StartVerdict::NotMeasured);
    assert!(record_request(&env.root, &request, now.unix_timestamp() + 2).unwrap() > 0);
    assert_eq!(get(now.unix_timestamp() + 2), StartVerdict::Measured);
    assert_eq!(
        get(now.unix_timestamp() + 93 * 86_400),
        StartVerdict::NotMeasured
    );
    assert_eq!(
        snapshots::start_verdict_store::load(
            &env.root,
            "synthetic-destination",
            now.unix_timestamp() + 2
        )
        .get(source, "missing", now.unix_timestamp() + 2),
        StartVerdict::NotMeasured
    );
    eprintln!("verdict fixture: first_record_bytes={bytes}; unchanged_record_bytes=0");
    env.cleanup();
}

#[test]
fn measured_starts_skip_opening_and_unmeasured_or_missing_count_it() {
    for source in [Source::Claude, Source::Codex] {
        for (name, verdict) in [
            ("measured", Some(true)),
            ("not-measured", Some(false)),
            ("missing", None),
        ] {
            let env = Env::new(name);
            let now = base_now();
            let path = env.root.join(match source {
                Source::Claude => "p/s/subagents/agent-test.jsonl",
                Source::Codex => "p/rollout.jsonl",
            });
            let records = match source {
                Source::Claude => vec![
                    json!({"type":"user","sessionId":"s","isSidechain":true,"agentId":"test","cwd":env.cwd(),"timestamp":ts(now.date(),1),"message":{"content":"opening prompt"}}),
                    json!({"type":"assistant","sessionId":"s","timestamp":ts(now.date(),2),"message":{"id":"m","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":2}}}),
                    json!({"type":"user","sessionId":"s","timestamp":ts(now.date(),3),"message":{"content":"later prompt"}}),
                ],
                Source::Codex => vec![
                    json!({"type":"session_meta","timestamp":ts(now.date(),0),"payload":{"id":"s","cwd":env.cwd()}}),
                    json!({"type":"response_item","timestamp":ts(now.date(),1),"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"opening prompt"}]}}),
                    json!({"type":"response_item","timestamp":ts(now.date(),2),"payload":{"type":"agent_message","content":[]}}),
                    json!({"type":"event_msg","timestamp":ts(now.date(),2),"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":2}}}}),
                    json!({"type":"response_item","timestamp":ts(now.date(),3),"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"later prompt"}]}}),
                ],
            };
            write_records(&path, &records);
            if let Some(measured) = verdict {
                let request = verdict_request(source, &path, measured);
                record_request(&env.root, &request, now.unix_timestamp()).unwrap();
            }
            env.run(source, now, None);
            let agg = env.scope(source).agg;
            let opening: u64 = agg
                .all_parts
                .iter()
                .filter(|(slot, _)| slot.part == Part::StartNotMeasured)
                .map(|(_, b)| b.tokens)
                .sum();
            assert_eq!(
                opening,
                if verdict == Some(true) {
                    0
                } else {
                    tokens_for("opening prompt")
                },
                "{source:?} {name}"
            );
            let prompt_part = if source == Source::Claude {
                Part::ByAgent
            } else {
                Part::ByYou
            };
            assert!(agg
                .all_parts
                .iter()
                .any(|(slot, b)| slot.part == prompt_part && b.tokens > 0));
            env.cleanup();
        }
    }
}

#[test]
fn far_apart_compaction_pair_clears_residency_once_across_checkpoint() {
    let mut state = ParseState {
        session: "s".into(),
        request1_closed: true,
        ..Default::default()
    };
    let base = Aggregate::default();
    let mut agg = Aggregate::default();
    let mut contribution = Contribution::default();
    let mut stats = LineStats::default();
    let mut out = LineSink {
        sink: Sink {
            base: &base,
            agg: &mut agg,
            contribution: &mut contribution,
            window: wide(),
            generation: 1,
        },
        copied_before: None,
        fallback_day: day_of(fallback_date()),
        stats: &mut stats,
        kinds: KindsVersion::V2,
        names: Names::Raw,
    };
    let slot = Slot::plain(Kind::YourPrompts, Part::ByYou);
    state.add_open(day_of(fallback_date()), &slot, 100);
    super::super::claude::handle_line(&mut out, &mut state, br#"{"type":"system","subtype":"compact_boundary","uuid":"boundary","timestamp":"2026-07-19T10:00:00Z"}"#);
    assert!(state.open.is_empty());
    state.add_open(day_of(fallback_date()), &slot, 73);
    super::super::claude::handle_line(
        &mut out,
        &mut state,
        br#"{"type":"attachment","uuid":"attachment","parentUuid":"boundary"}"#,
    );
    state = serde_json::from_slice::<StoredParse>(
        &serde_json::to_vec(&StoredParse::from_state(&state)).unwrap(),
    )
    .unwrap()
    .into_state()
    .unwrap();
    super::super::claude::handle_line(&mut out, &mut state, br#"{"type":"user","isCompactSummary":true,"uuid":"legacy","parentUuid":"attachment","timestamp":"2026-07-19T11:00:00Z","message":{"content":"summary"}}"#);
    assert!(state.open.iter().any(|(_, s, t)| s == &slot && *t >= 73));
    // A summary linked elsewhere is a separate compaction.
    super::super::claude::handle_line(&mut out, &mut state, br#"{"type":"user","isCompactSummary":true,"parentUuid":"unrelated","timestamp":"2026-07-19T11:00:01Z"}"#);
    assert!(state.open.is_empty());
}

#[test]
fn workflow_journals_are_excluded_before_resolving_composition_ids() {
    let env = Env::new("composition-workflow-journal");
    let now = base_now();
    let path = env
        .root
        .join("p/s/subagents/workflows/wf-test/journal.jsonl");
    write_records(&path, &claude_turn(&env.cwd(), now.date(), 1));
    let mut capture = Capture::default();
    let stats = env.run(Source::Claude, now, Some(&mut capture));
    assert_eq!(stats.files_read, 0);
    assert!(capture.payloads.is_empty());
    env.cleanup();
}

#[test]
fn measured_start_does_not_suppress_prompts_after_a_dormant_prefix() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new("composition-dormant-measured-start");
        let now = base_now();
        let path = env.root.join(match source {
            Source::Claude => "p/s.jsonl",
            Source::Codex => "p/rollout.jsonl",
        });
        let records = match source {
            Source::Claude => vec![
                json!({"type":"user","sessionId":"s","cwd":env.cwd(),"timestamp":ts(now.date(),1),"message":{"content":"old opening"}}),
                json!({"type":"assistant","sessionId":"s","timestamp":ts(now.date(),2),"message":{"id":"m","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":2}}}),
            ],
            Source::Codex => vec![
                json!({"type":"session_meta","timestamp":ts(now.date(),0),"payload":{"id":"s","cwd":env.cwd()}}),
                json!({"type":"response_item","timestamp":ts(now.date(),1),"payload":{"type":"agent_message","content":[]}}),
                json!({"type":"event_msg","timestamp":ts(now.date(),2),"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":2}}}}),
            ],
        };
        write_records(&path, &records);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600))
            .unwrap();
        let request = verdict_request(source, &path, true);
        record_request(&env.root, &request, now.unix_timestamp()).unwrap();
        let first = env.run(source, now, None);
        assert_eq!(first.files_read, 0);
        let later = "later prompt must count";
        let row = match source {
            Source::Claude => {
                json!({"type":"user","sessionId":"s","cwd":env.cwd(),"timestamp":ts(now.date(),3),"message":{"content":later}})
            }
            Source::Codex => {
                json!({"type":"response_item","timestamp":ts(now.date(),3),"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":later}]}})
            }
        };
        append_records(&path, &[row]);
        let second = env.run(source, now + time::Duration::hours(1), None);
        assert!(second.bytes_new > 0);
        let scope = env.scope(source);
        let prompts: u64 = scope
            .agg
            .all_parts
            .iter()
            .filter(|(slot, _)| slot.part == Part::ByYou)
            .map(|(_, bucket)| bucket.tokens)
            .sum();
        assert_eq!(prompts, tokens_for(later), "{source:?}");
        assert!(scope
            .agg
            .all_parts
            .keys()
            .all(|slot| slot.part != Part::StartNotMeasured));
        env.cleanup();
    }
}
