//! Additive detail contract at the real reader -> stored totals -> upload boundary.
use super::*;
use crate::context_composition::v2::aggregate::{AggregateRef, StoredAggregate};
use crate::context_composition::v2::scope::Scope;
use crate::context_composition::v2::upload::{build_request, details_enabled, DETAILS_CONTRACT};

fn payload(scope: &Scope, enabled: bool, labels: bool) -> Value {
    let mut capture = Capture::default();
    let target = UploadTarget {
        uploader: &mut capture,
        machine_id: "machine-test",
        destination: "test-destination",
        labels_enabled: labels,
        details_enabled: enabled,
    };
    let now = base_now();
    let (request, _) = build_request(
        scope,
        Source::Claude,
        &target,
        now,
        Window::ending(day_of(now.date())),
        0,
    );
    // Exercise exactly the serialization boundary used by upload_scope.
    serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap()
}

fn scope() -> Scope {
    Scope::new(
        "scope",
        ScopeInfo {
            workspace_hash: "f".repeat(64),
            workspace_path: "/synthetic/repository".into(),
            identity: Default::default(),
            common_dir: None,
        },
    )
}

fn add(
    agg: &mut Aggregate,
    base: &Aggregate,
    day: Day,
    id: &str,
    tool: &str,
    tokens: u64,
) -> Contribution {
    let mut contribution = Contribution::default();
    let mut sink = Sink {
        base,
        agg,
        contribution: &mut contribution,
        window: Window::ending(day_of(base_now().date())),
        generation: 1,
    };
    sink.entered(&super::super::aggregate::Entered {
        day,
        slot: Slot::plain(
            Kind::CommandOutput,
            crate::composition_kinds::Part::OtherCommands,
        ),
        tokens,
        images: 0,
        file: None,
        session: id,
        ts: None,
    });
    sink.tool(day, tool, Kind::CommandOutput, id, tokens, true);
    contribution
}

#[test]
fn capability_is_exact_and_absent_null_unknown_are_legacy() {
    use crate::snapshot_client::decode_activity_hint;
    let mut hint = json!({"source":"claude-code", "server_time":"2026-10-25T10:00:00Z",
        "record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
        "backfill_window_days":92,"recommended_scan_after":"2026-10-25T10:05:00Z"});
    for token in [
        None,
        Some(Value::Null),
        Some(json!("future-contract")),
        Some(json!(DETAILS_CONTRACT)),
    ] {
        hint.as_object_mut()
            .unwrap()
            .remove("context_composition_details_contract");
        if let Some(token) = token {
            hint["context_composition_details_contract"] = token;
        }
        let decoded = decode_activity_hint(hint.clone()).unwrap();
        assert_eq!(
            details_enabled(decoded.context_composition_details_contract.as_deref()),
            hint["context_composition_details_contract"] == DETAILS_CONTRACT
        );
    }
    let legacy = payload(&scope(), false, true);
    for field in ["top_files_7d", "sessions_7d", "session_count_7d"] {
        assert!(legacy.get(field).is_none());
    }
    check_server_rules(&legacy).unwrap();
}

#[test]
fn session_tools_merge_roundtrip_subtract_prune_and_old_state() {
    let day = day_of(base_now().date());
    let mut agg = Aggregate::default();
    let share = add(&mut agg, &Aggregate::default(), day - 1, "s", "Read", 90);
    let mut delta = Aggregate::default();
    add(&mut delta, &agg, day, "s", "Read", 30);
    agg.merge(delta);
    let encoded = serde_json::to_value(AggregateRef {
        agg: &agg,
        generations: true,
    })
    .unwrap();
    let restored: StoredAggregate = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(restored.into_aggregate(), agg);
    assert_eq!(
        agg.sessions["s"]
            .tools
            .as_ref()
            .unwrap()
            .values()
            .map(|(_, t)| t)
            .sum::<u64>(),
        120
    );
    agg.subtract(&share, 2);
    assert_eq!(
        agg.sessions["s"]
            .tools
            .as_ref()
            .unwrap()
            .values()
            .map(|(_, t)| t)
            .sum::<u64>(),
        30
    );
    agg.prune(Window {
        floor: day + 1,
        period_floor: day + 1,
        today: day + 1,
    });
    assert!(agg.sessions.is_empty());
    let mut old = encoded;
    old.as_object_mut().unwrap().remove("session_tools");
    let old: StoredAggregate = serde_json::from_value(old).unwrap();
    let mut old = old.into_aggregate();
    let mut delta = Aggregate::default();
    add(&mut delta, &old, day, "s", "Read", 10);
    old.merge(delta);
    assert!(
        old.sessions["s"].tools.is_none(),
        "old session history must never look complete"
    );
}

#[test]
fn attribution_bounds_omit_incomplete_sessions() {
    let day = day_of(base_now().date());
    let mut agg = Aggregate::default();
    let base = Aggregate::default();
    for n in 0..129 {
        add(&mut agg, &base, day, "s", &format!("tool{n}"), 1);
    }
    assert!(agg.sessions["s"].tools.is_none());
    for n in 0..300 {
        add(&mut agg, &base, day, &format!("s{n}"), "Read", 1);
    }
    assert!(agg.sessions.values().filter(|t| t.tools.is_some()).count() <= 256);
}

#[test]
fn seven_day_lists_have_actual_window_totals_and_rankings() {
    use super::super::aggregate::{FileKey, FileTotals};
    let today = day_of(base_now().date());
    let base = Aggregate::default();
    let mut scope = scope();
    add(&mut scope.agg, &base, today - 7, "old", "old", 9000);
    add(&mut scope.agg, &base, today - 6, "recent", "mcp/read", 100);
    add(&mut scope.agg, &base, today, "recent", "mcp/read", 200);
    add(&mut scope.agg, &base, today + 1, "future", "future", 9000);
    for (day, name, tokens) in [
        (today - 7, "old.rs", 9000),
        (today - 6, "recent.rs", 100),
        (today, "recent.rs", 200),
    ] {
        let key = FileKey {
            path: name.into(),
            kind: Kind::FilesRead,
            part: crate::composition_kinds::Part::FileTool,
        };
        scope.agg.day_files.insert(
            (day, key.clone()),
            FileTotals {
                events: 1,
                tokens,
                last: Some(base_now().unix_timestamp()),
            },
        );
        scope.agg.all_files.insert(
            key,
            FileTotals {
                events: 1,
                tokens,
                last: None,
            },
        );
    }
    let enabled = payload(&scope, true, true);
    let tools: Vec<_> = enabled["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["window"] == "7d")
        .collect();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["tokens_entered_est"], 300);
    assert_eq!(tools[0]["distinct_sessions"], 1);
    let files = enabled["top_files_7d"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["relative_path_or_name"], "recent.rs");
    assert_eq!(files[0]["tokens_entered_est"], 300);
    let sessions = enabled["sessions_7d"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["source_session_id"], "recent");
    assert_eq!(sessions[0]["total_tokens_entered_est"], 300);
    assert_eq!(
        sessions[0]["top_tool"],
        json!({"label":"mcp/read","server_label":"mcp","kind":"command_output","tokens_entered_est":300})
    );
    assert_eq!(enabled["session_count_7d"], 1);
    let withheld = payload(&scope, true, false);
    assert!(withheld["tools"].as_array().unwrap().is_empty());
    assert!(withheld["sessions_7d"][0].get("top_tool").is_none());
    let legacy = payload(&scope, false, true);
    check_server_rules(&legacy).unwrap();
    assert!(legacy["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s.get("top_tool").is_none()));
}

#[test]
fn unsafe_winner_is_omitted_instead_of_replaced() {
    let day = day_of(base_now().date());
    let mut scope = scope();
    let base = Aggregate::default();
    add(&mut scope.agg, &base, day, "s", "safe", 10);
    add(&mut scope.agg, &base, day, "s", "bearer secret", 100);
    let wire = payload(&scope, true, true);
    assert!(wire["sessions"][0].get("top_tool").is_none());
    assert!(wire["sessions_7d"][0].get("top_tool").is_none());
    assert!(!serde_json::to_string(&wire).unwrap().contains("secret"));
}

#[test]
fn actual_reader_stored_state_and_wire_agree_on_session_winner() {
    let dir = scratch("detail-wire");
    let path = dir.join("session.jsonl");
    let cwd = "/synthetic/repository";
    // Existing real Claude fixture includes tool_use/tool_result classification.
    write_records(
        &path,
        &claude_read_turn(cwd, base_now().date(), 1, "src/lib.rs"),
    );
    let reading = read_whole(Source::Claude, &[&path]);
    assert!(!reading.agg.sessions.is_empty());
    let bytes = serde_json::to_vec(&AggregateRef {
        agg: &reading.agg,
        generations: true,
    })
    .unwrap();
    let stored: StoredAggregate = serde_json::from_slice(&bytes).unwrap();
    let mut scope = scope();
    scope.agg = stored.into_aggregate();
    let mut capture = Capture::default();
    let mut target = UploadTarget {
        uploader: &mut capture,
        machine_id: "machine-test",
        destination: "test-destination",
        labels_enabled: true,
        details_enabled: true,
    };
    let now = base_now();
    let result = super::super::upload::upload_scope(
        &dir.join("state"),
        Source::Claude,
        &scope,
        &mut target,
        now,
        Window::ending(day_of(now.date())),
    );
    assert_eq!(
        result.outcome,
        super::super::upload::UploadOutcome::Uploaded
    );
    let row = &capture.payloads[0]["sessions_7d"][0];
    assert_eq!(row["top_tool"]["label"], "Read");
    assert!(row["top_tool"]["tokens_entered_est"].as_u64().unwrap() > 0);
    assert!(
        row["top_tool"]["tokens_entered_est"].as_u64().unwrap()
            <= row["total_tokens_entered_est"].as_u64().unwrap()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn capability_change_refreshes_acked_scope_without_transcript_changes() {
    use super::super::upload::{upload_scope, UploadOutcome};
    let dir = scratch("detail-capability-ack");
    let now = base_now();
    let window = Window::ending(day_of(now.date()));
    let scope = scope();
    let mut capture = Capture::default();
    for (enabled, expected) in [
        (false, UploadOutcome::Uploaded),
        (false, UploadOutcome::Unchanged),
        (true, UploadOutcome::Uploaded),
        (false, UploadOutcome::Uploaded),
    ] {
        let mut target = UploadTarget {
            uploader: &mut capture,
            machine_id: "machine-test",
            destination: "test-destination",
            labels_enabled: true,
            details_enabled: enabled,
        };
        assert_eq!(
            upload_scope(&dir, Source::Claude, &scope, &mut target, now, window).outcome,
            expected
        );
    }
    assert_eq!(capture.payloads.len(), 3);
    assert!(capture.payloads[0].get("sessions_7d").is_none());
    assert!(capture.payloads[1].get("sessions_7d").is_some());
    assert!(capture.payloads[2].get("sessions_7d").is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn scope_attribution_budget_stays_bounded_across_merge_and_roundtrip() {
    let day = day_of(base_now().date());
    let base = Aggregate::default();
    let mut agg = Aggregate::default();
    for s in 0..65 {
        for t in 0..128 {
            add(&mut agg, &base, day, &format!("s{s}"), &format!("t{t}"), 1);
        }
    }
    assert_eq!(agg.tracked_tool_rows, 8192);
    assert!(agg.sessions["s64"].tools.is_none());
    let bytes = serde_json::to_vec(&AggregateRef {
        agg: &agg,
        generations: true,
    })
    .unwrap();
    let restored: StoredAggregate = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.into_aggregate(), agg);
    let mut delta = Aggregate::default();
    add(&mut delta, &agg, day, "s0", "new", 1);
    agg.merge(delta);
    assert!(agg.tracked_tool_rows <= 8192);
    assert!(agg.sessions["s0"].tools.is_none());
}
