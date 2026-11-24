//! Tests for the machine-local active session list: which sessions enter it,
//! how rows are built and cached, and tracking confirmation.

use super::*;
use crate::snapshots::SnapshotUploadPolicy;
use ottto_protocol::{
    AgentAccountStatus, AgentStatusCollectionMethod, AgentStatusPlanObservation,
    AgentStatusState,
};

fn usage_row(model: &str, effort: Option<&str>, tokens: u64) -> SnapshotModelUsage {
    SnapshotModelUsage {
        evidence_ref: None,
        identity_parts: None,
        copy_unproven: false,
        model: model.to_string(),
        input_tokens: 0,
        output_tokens: tokens,
        cache_read_tokens: 0,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        reasoning_effort: effort.map(str::to_string),
        unattributed_total_tokens: 0,
        request_count: 1,
        selector_context: BTreeMap::new(),
        selector_sources: BTreeMap::new(),
        auth_mode: None,
        billing_channel: None,
        billing_provider: None,
        gateway_provider: None,
        model_provider: None,
        subscription_product: None,
        account_identifier_hash: None,
        cost_usd: None,
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
    }
}

fn bucket(
    bucket_start: &str,
    last_activity_at: &str,
    rows: Vec<SnapshotModelUsage>,
) -> crate::snapshots::SnapshotUsageBucket {
    crate::snapshots::SnapshotUsageBucket {
        bucket_start: bucket_start.to_string(),
        model_usage: rows,
        first_activity_at: Some(last_activity_at.to_string()),
        last_activity_at: Some(last_activity_at.to_string()),
    }
}

#[test]
fn active_window_follows_the_effective_cadence() {
    let dir = temp_dir("battery-window");
    for (interval, window) in [(300, 15), (900, 20), (1800, 35)] {
        assert_eq!(
            active_activity_window(std::time::Duration::from_secs(interval)),
            Duration::minutes(window)
        );
        let reconciled = reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            &[],
            None,
            None,
            "2026-07-19T10:00:00Z",
            std::time::Duration::from_secs(interval),
        )
        .unwrap();
        let value = serde_json::to_value(reconciled).unwrap();
        assert_eq!(
            value["active_window_seconds"].as_u64(),
            Some(window as u64 * 60)
        );
    }
    let snapshot = test_snapshot("battery-active", "2026-07-19T10:00:00Z");
    let at = |now| {
        reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            None,
            now,
            std::time::Duration::from_secs(900),
        )
        .unwrap()
    };
    assert_eq!(at("2026-07-19T10:18:00Z").sessions.len(), 1);
    assert!(at("2026-07-19T10:21:00Z").sessions.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reconciled_session_carries_latest_model_and_effort() {
    let dir = temp_dir("latest-identity");
    let mut snapshot = test_snapshot("s-wire", "2026-07-19T10:04:00Z");
    snapshot.usage_buckets = vec![bucket(
        "2026-07-19T10:00:00Z",
        "2026-07-19T10:04:00Z",
        vec![usage_row("claude-opus-5", Some("high"), 500)],
    )];

    let reconciliation = reconcile_active_sessions(
        &dir,
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("reconciliation");

    assert_eq!(
        reconciliation.sessions[0].latest_model.as_deref(),
        Some("claude-opus-5")
    );
    assert_eq!(
        reconciliation.sessions[0]
            .latest_reasoning_effort
            .as_deref(),
        Some("high")
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pi_session_carries_newest_row_provider_route_and_other_sources_none() {
    let mut older = usage_row("glm-5", None, 900);
    older.model_provider = Some("gcp_glm".to_string());
    let mut newest = usage_row("gemini-3-flash-preview", None, 10);
    newest.model_provider = Some("google_vertex".to_string());
    newest.gateway_provider = Some("google_vertex".to_string());
    let mut snapshot = test_snapshot("s-pi", "2026-07-19T11:04:00Z");
    snapshot.usage_buckets = vec![
        bucket("2026-07-19T10:00:00Z", "2026-07-19T10:30:00Z", vec![older]),
        bucket("2026-07-19T11:00:00Z", "2026-07-19T11:04:00Z", vec![newest]),
    ];
    let route = |snapshot: &SnapshotItem, source| {
        active_session_from_snapshot(source, snapshot, None).provider_route
    };

    assert_eq!(
        route(&snapshot, SnapshotSource::Pi).as_deref(),
        Some("google_vertex")
    );
    assert_eq!(route(&snapshot, SnapshotSource::ClaudeCode), None);

    snapshot.usage_buckets[1].model_usage[0].model_provider = Some(" ".to_string());
    assert_eq!(route(&snapshot, SnapshotSource::Pi), None);
}

#[test]
fn native_transcript_dates_remain_activity_span_across_timezone_and_resume() {
    let dir = temp_dir("registration-native-dates");
    let path = dir.join("registered-session.jsonl");
    std::fs::create_dir_all(&dir).unwrap();
    let rows = [
        serde_json::json!({"timestamp":"2026-07-18T12:00:00+03:00","sessionId":"registered-session","type":"user","message":{"role":"user","content":"Repair startup"}}),
        serde_json::json!({"timestamp":"2026-07-19T10:04:00Z","sessionId":"registered-session","type":"assistant","requestId":"fixture-request","message":{"id":"fixture-message","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":2}}}),
    ];
    std::fs::write(
        &path,
        rows.iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let snapshots = crate::snapshots::parse_claude_code_jsonl_file(
        &path,
        "2026-07-19T10:05:00Z",
        "fixture-fingerprint".into(),
    )
    .unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        snapshots[0].source_started_at.as_deref(),
        Some("2026-07-18T12:00:00+03:00")
    );
    assert_eq!(
        snapshots[0].source_last_activity_at.as_deref(),
        Some("2026-07-19T10:04:00Z")
    );
    assert!(snapshots[0].source_ended_at.is_none());
    let result = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        &snapshots,
        None,
        None,
        "2026-07-19T10:05:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        registrations,
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert_eq!(
        result.sessions[0].source_started_at,
        snapshots[0].source_started_at
    );
    assert_eq!(
        result.sessions[0].source_last_activity_at,
        "2026-07-19T10:04:00Z"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn registrations() -> crate::claude_session_registrations::Registrations {
    BTreeMap::from([(
        "registered-session".to_string(),
        crate::claude_session_registrations::Registration {
            name: Some("Repair process registration".to_string()),
            name_source: Some("user".to_string()),
            entrypoint: Some("claude-desktop".to_string()),
        },
    )])
}

#[test]
fn registrations_enrich_local_rows_without_changing_snapshots_dates_or_accounting() {
    let dir = temp_dir("registration-local");
    let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
    snapshot.session_display_name_source = Some("first_prompt".to_string());
    snapshot.origin = None;
    let original = serde_json::to_value(&snapshot).unwrap();
    let result = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        registrations,
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    let row = &result.sessions[0];
    assert_eq!(
        row.session_display_name.as_deref(),
        Some("Repair process registration")
    );
    assert_eq!(row.provider_surface.as_deref(), Some("claude_desktop"));
    assert_eq!(row.source_started_at, snapshot.source_started_at);
    assert_eq!(
        row.source_last_activity_at,
        snapshot.source_last_activity_at.clone().unwrap()
    );
    assert_eq!(row.input_tokens, Some(snapshot.input_tokens));
    assert_eq!(serde_json::to_value(&snapshot).unwrap(), original);
    let cache = read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode));
    assert_eq!(
        cache.registration_evidence["registered-session"]
            .name_source
            .as_deref(),
        Some("user")
    );
    assert!(serde_json::to_value(result)
        .unwrap()
        .get("registration_evidence")
        .is_none());
    // An incremental scan omits the unchanged transcript entirely.
    let unchanged = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        &[],
        None,
        None,
        "2026-07-19T10:10:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        || panic!("no registration acquisition without new activity"),
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert_eq!(unchanged.changed_session_count, 0);
    assert_eq!(
        unchanged.sessions[0].session_display_name.as_deref(),
        Some("Repair process registration"),
        "a carried row keeps its proven registration name"
    );
    assert_eq!(
        read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode))
            .registration_evidence["registered-session"]
            .name_source
            .as_deref(),
        Some("user"),
        "and the provenance of that name"
    );
    let expired = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        &[],
        None,
        None,
        "2026-07-19T10:30:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        || panic!("no registration acquisition without new activity"),
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert!(expired.sessions.is_empty());
    assert!(
        read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode))
            .registration_evidence
            .is_empty()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn duplicate_snapshots_use_the_selected_rows_title_provenance() {
    let dir = temp_dir("registration-selected-title");
    let mut older = test_snapshot("registered-session", "2026-07-19T10:03:00Z");
    older.session_display_name_source = Some("first_prompt".into());
    let mut newer = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
    newer.session_display_name = Some("Intentional native title".into());
    newer.session_display_name_source = Some("transcript_title".into());
    let result = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        &[older, newer],
        None,
        None,
        "2026-07-19T10:05:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        registrations,
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert_eq!(
        result.sessions[0].session_display_name.as_deref(),
        Some("Intentional native title")
    );
    assert_eq!(
        result.sessions[0].source_last_activity_at,
        "2026-07-19T10:04:00Z"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn registrations_preserve_intentional_names_policy_and_children() {
    for title_source in [
        Some("transcript_title"),
        Some("desktop_title"),
        Some("agent_label"),
        None,
    ] {
        let dir = temp_dir("registration-precedence");
        let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
        snapshot.session_display_name_source = title_source.map(str::to_string);
        if title_source.is_none() {
            snapshot.session_display_name = None;
        }
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            std::time::Duration::from_secs(300),
            registrations,
            None,
            WatermarkPrune::Floor(None),
        )
        .unwrap();
        assert_eq!(
            result.sessions[0].session_display_name,
            snapshot.session_display_name
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    let dir = temp_dir("registration-child");
    let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
    snapshot.session_display_name_source = Some("first_prompt".into());
    snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
        is_sidechain: Some(true),
        ..Default::default()
    });
    let result = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        registrations,
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert_eq!(
        result.sessions[0].session_display_name,
        snapshot.session_display_name
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// [regress] A headless Codex run's stored title is its whole first message,
/// which the title filter rejects, so the row had only its folder. The row
/// now shows the existing prompt-prefix label through the same filter.
/// Native names win, subagents and other sources stay unnamed, and the
/// snapshot (upload body and fingerprint) is untouched.
#[test]
fn unnamed_codex_rows_show_filtered_prompt_prefix_label_without_touching_upload() {
    use SnapshotSource::{ClaudeCode, Codex, Pi};
    let clean = "Fix the  flaky sync retry";
    let shown = Some("Fix the flaky sync retry");
    let cases = [
        (Codex, None, "exec", clean, shown),
        (Codex, None, "exec", "You are a release worker", None),
        (Codex, None, "exec", "Continue the same session", None),
        (Codex, None, "exec", "Read AGENTS.md instructions", None),
        (Codex, Some("Native"), "exec", clean, Some("Native")),
        (Codex, None, "subagent", clean, None),
        (ClaudeCode, None, "cli", clean, None),
        (Pi, None, "cli", clean, None),
    ];
    for (source, native, origin, label, expected) in cases {
        let dir = temp_dir("codex-prefix-title");
        let mut snapshot = test_snapshot("unnamed-session", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = native.map(str::to_string);
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            source: (origin != "subagent").then(|| origin.to_string()),
            thread_source: (origin == "subagent").then(|| origin.to_string()),
            ..Default::default()
        });
        let mut fact = direct_fact("template_group_id", "template-group");
        fact.display_label = Some(label.to_string());
        fact.display_label_source = Some("prompt_prefix".to_string());
        snapshot.attribution_facts = vec![fact];
        let upload_body = serde_json::to_vec(&snapshot).unwrap();
        let result = reconcile_with_registrations(
            &dir,
            source,
            std::slice::from_ref(&snapshot),
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            std::time::Duration::from_secs(300),
            BTreeMap::new,
            None,
            WatermarkPrune::Floor(None),
        )
        .unwrap();
        assert_eq!(result.sessions[0].session_display_name.as_deref(), expected);
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), upload_body);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn missing_registrations_preserve_transcript_fallback_and_never_create_active_rows() {
    let dir = temp_dir("registration-missing");
    let snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
    let result = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        BTreeMap::new,
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert_eq!(
        result.sessions[0].session_display_name,
        snapshot.session_display_name
    );
    let empty = reconcile_with_registrations(
        &dir,
        SnapshotSource::ClaudeCode,
        &[],
        None,
        None,
        "2026-07-19T10:30:00Z",
        Some("policy"),
        std::time::Duration::from_secs(300),
        || panic!("no registry scan for empty source"),
        None,
        WatermarkPrune::Floor(None),
    )
    .unwrap();
    assert!(empty.sessions.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

fn test_policy() -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
        session_artifacts_enabled: true,
        session_attribution_enabled: true,
        session_attribution_labels_enabled: true,
    }
}

fn temp_dir(name: &str) -> PathBuf {
    crate::test_scratch::private_dir(&format!("ottto-active-sessions-{name}"))
}

mod tracking_confirmation_tests {
    use super::*;

    #[test]
    fn parsed_pre_repair_session_can_confirm_below_a_future_watermark() {
        use crate::tracking_confirmation::parsed_activity_witness;
        let since = OffsetDateTime::parse("2026-11-15T10:00:00Z", &Rfc3339).ok();
        for source in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ] {
            let dir = temp_dir("confirmation-parsed");
            let future = test_snapshot("existing-session", "2026-11-16T10:00:00Z");
            reconcile_active_sessions(
                &dir,
                source,
                std::slice::from_ref(&future),
                None,
                None,
                "2026-11-15T09:59:00Z",
                std::time::Duration::from_secs(300),
            )
            .unwrap();
            let mut witness = None;
            reconcile_with_registrations(
                &dir,
                source,
                &[future],
                None,
                None,
                "2026-11-16T10:00:00Z",
                Some("local"),
                std::time::Duration::from_secs(300),
                crate::agent_status::claude_session_registrations,
                Some(&mut |new, prev, within_ceiling| {
                    witness =
                        witness.max(parsed_activity_witness(since, new, prev, within_ceiling))
                }),
                WatermarkPrune::Floor(None),
            )
            .unwrap();
            assert_eq!(witness, None, "unchanged future evidence never matures");
            let mut turn = test_snapshot("existing-session", "2026-11-15T10:01:00Z");
            turn.source_started_at = Some("2026-11-15T09:00:00Z".into());
            let mut witness = None;
            reconcile_with_registrations(
                &dir,
                source,
                &[turn],
                None,
                None,
                "2026-11-15T10:01:00Z",
                Some("local"),
                std::time::Duration::from_secs(300),
                crate::agent_status::claude_session_registrations,
                Some(&mut |new, prev, within_ceiling| {
                    witness =
                        witness.max(parsed_activity_witness(since, new, prev, within_ceiling))
                }),
                WatermarkPrune::Floor(None),
            )
            .unwrap();
            assert_eq!(
                witness.and_then(|at| at.format(&Rfc3339).ok()).as_deref(),
                Some("2026-11-15T10:01:00Z")
            );
            assert_eq!(
                read_cache(&active_session_cache_path(&dir, source)).watermarks
                    ["existing-session"],
                "2026-11-16T10:00:00Z"
            );
            let mut cache = read_cache(&active_session_cache_path(&dir, source));
            cache
                .watermarks
                .insert("cached-session".into(), "2026-11-15T10:01:00Z".into());
            write_cache(&active_session_cache_path(&dir, source), &cache).unwrap();
            let mut witness = None;
            reconcile_with_registrations(
                &dir,
                source,
                &[
                    test_snapshot("cached-session", "2026-11-16T10:00:00Z"),
                    test_snapshot("cached-session", "2026-11-15T10:01:00Z"),
                ],
                None,
                None,
                "2026-11-15T10:01:00Z",
                Some("local"),
                std::time::Duration::from_secs(300),
                crate::agent_status::claude_session_registrations,
                Some(&mut |new, prev, within_ceiling| {
                    witness =
                        witness.max(parsed_activity_witness(since, new, prev, within_ceiling))
                }),
                WatermarkPrune::Floor(None),
            )
            .unwrap();
            assert_eq!(
                witness, None,
                "a duplicate row must use the original baseline"
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn waiting_repair_keeps_watermarks_from_its_start() {
        use crate::tracking_confirmation::parsed_activity_witness;
        const NOW: &str = "2026-11-16T10:00:00Z";
        let since = OffsetDateTime::parse("2026-11-10T10:00:00Z", &Rfc3339).ok();
        for (keep_since, after_start_kept) in [(since, true), (None, false)] {
            let prune = WatermarkPrune::Floor(keep_since);
            let dir = temp_dir("confirmation-floor");
            let source = SnapshotSource::ClaudeCode;
            let path = active_session_cache_path(&dir, source);
            let mut cache = ActiveSessionCache::default();
            cache
                .watermarks
                .insert("after-start".into(), "2026-11-11T10:00:00Z".into());
            cache
                .watermarks
                .insert("before-start".into(), "2026-11-09T10:00:00Z".into());
            write_cache(&path, &cache).unwrap();
            reconcile_with_registrations(
                &dir,
                source,
                &[],
                None,
                None,
                NOW,
                Some("local"),
                std::time::Duration::from_secs(300),
                crate::agent_status::claude_session_registrations,
                None,
                prune,
            )
            .unwrap();
            let watermarks = read_cache(&path).watermarks;
            assert_eq!(
                watermarks.contains_key("after-start"),
                after_start_kept,
                "{keep_since:?}"
            );
            assert!(!watermarks.contains_key("before-start"));
            if keep_since.is_some() {
                // The unchanged session is re-read while the Repair waits.
                let mut witness = None;
                reconcile_with_registrations(
                    &dir,
                    source,
                    &[test_snapshot("after-start", "2026-11-11T10:00:00Z")],
                    None,
                    None,
                    NOW,
                    Some("local"),
                    std::time::Duration::from_secs(300),
                    crate::agent_status::claude_session_registrations,
                    Some(&mut |new, prev, within_ceiling| {
                        witness = witness.max(parsed_activity_witness(
                            since,
                            new,
                            prev,
                            within_ceiling,
                        ))
                    }),
                    prune,
                )
                .unwrap();
                assert_eq!(witness, None, "unchanged activity never confirms");
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn unreadable_tracking_state_skips_watermark_pruning() {
    let dir = temp_dir("watermark-prune-skip");
    let source = SnapshotSource::ClaudeCode;
    let path = active_session_cache_path(&dir, source);
    let mut cache = ActiveSessionCache::default();
    // Four days old, with a valid and an unparsable value.
    cache
        .watermarks
        .insert("old".into(), "2026-11-12T10:00:00Z".into());
    cache
        .watermarks
        .insert("invalid".into(), "not-a-time".into());
    write_cache(&path, &cache).unwrap();
    let reconcile = |prune| {
        reconcile_with_registrations(
            &dir,
            source,
            &[],
            None,
            None,
            "2026-11-16T10:00:00Z",
            Some("local"),
            std::time::Duration::from_secs(300),
            crate::agent_status::claude_session_registrations,
            None,
            prune,
        )
        .unwrap();
        read_cache(&path).watermarks.len()
    };
    assert_eq!(
        reconcile(WatermarkPrune::Skip),
        2,
        "unreadable state keeps all"
    );
    assert_eq!(
        reconcile(WatermarkPrune::Floor(None)),
        0,
        "next good pass prunes"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn status_read_reuses_reconciliation_until_cache_file_changes() {
    let dir = temp_dir("status-read-stamp");
    let source = SnapshotSource::ClaudeCode;
    let path = active_session_cache_path(&dir, source);
    assert_eq!(read_active_session_reconciliation(&dir, source), None);

    let first = reconcile_active_sessions(
        &dir,
        source,
        &[test_snapshot("s1", "2026-07-19T10:04:00Z")],
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(first.sessions.len(), 1);
    assert_eq!(
        read_active_session_reconciliation(&dir, source),
        Some(first.clone())
    );

    // Same object, length and mtime: the kept parse is returned, so the
    // garbled bytes are never read.
    let original = std::fs::metadata(&path).unwrap();
    let garbled = vec![b' '; original.len() as usize];
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    std::io::Write::write_all(&mut &file, &garbled).unwrap();
    file.set_modified(original.modified().unwrap()).unwrap();
    drop(file);
    assert_eq!(
        read_active_session_reconciliation(&dir, source),
        Some(first.clone())
    );

    // A reconcile replaces the file, so the next read parses it again.
    let mut cache = ActiveSessionCache::default();
    let mut second = first.clone();
    second.sessions.clear();
    second.changed_session_count = 0;
    cache.reconciliation = Some(second.clone());
    write_cache(&path, &cache).unwrap();
    assert_ne!(Some(second.clone()), Some(first));
    assert_eq!(
        read_active_session_reconciliation(&dir, source),
        Some(second)
    );

    std::fs::remove_file(&path).unwrap();
    assert_eq!(read_active_session_reconciliation(&dir, source), None);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn last_activity_cache_cases() {
    const PAST: &str = "2026-07-19T10:04:00Z";
    const FUTURE: &str = "2026-07-20T10:04:00Z";
    const NOW: &str = "2026-07-19T10:05:00Z";
    let legacy = serde_json::json!({
        "watermarks": {"real": PAST, "future": FUTURE, "invalid": "not-a-time"},
        "reconciliation": {"reconciled_at": NOW, "changed_session_count": 0, "sessions": []}
    });
    let mut carried = legacy.clone();
    carried["reconciliation"]["last_activity_at"] = PAST.into();
    carried["watermarks"] = serde_json::json!({});
    let empty = serde_json::json!({});
    let candidates = [FUTURE, PAST, "not-a-time"];
    let older = serde_json::json!({"reconciliation": legacy["reconciliation"]});
    for (name, cached, activity, expected) in [
        ("empty-scan-carry", carried, &[][..], Some(PAST)),
        ("ceiling-before-max", empty, &candidates, Some(PAST)),
        ("legacy-seed", legacy.clone(), &[][..], Some(PAST)),
        ("older-cache-decode", older, &[][..], None),
    ] {
        let dir = temp_dir(name);
        let source = SnapshotSource::Codex;
        let cache: ActiveSessionCache = serde_json::from_value(cached).unwrap();
        write_cache(&active_session_cache_path(&dir, source), &cache).unwrap();
        let snapshots = activity
            .iter()
            .enumerate()
            .map(|(i, at)| {
                let mut snapshot = test_snapshot(&format!("s{i}"), at);
                snapshot.model_usage.clear();
                snapshot.usage_buckets.clear();
                snapshot
            })
            .collect::<Vec<_>>();
        let observed = reconcile_active_sessions(
            &dir,
            source,
            &snapshots,
            None,
            None,
            NOW,
            std::time::Duration::from_secs(300),
        )
        .unwrap();
        assert_eq!(observed.last_activity_at.as_deref(), expected, "{name}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn watermarks_expire_by_age_only() {
    let dir = temp_dir("watermark-age");
    let path = active_session_cache_path(&dir, SnapshotSource::ClaudeCode);
    let mut cache = ActiveSessionCache::default();
    for index in 0..5_001 {
        cache.watermarks.insert(
            format!("recent-{index}"),
            "2026-07-16T10:41:00Z".to_string(),
        );
    }
    // Four days old, with no Repair waiting.
    cache
        .watermarks
        .insert("expired".to_string(), "2026-07-15T10:40:00Z".to_string());
    write_cache(&path, &cache).unwrap();
    reconcile_active_sessions(
        &dir,
        SnapshotSource::ClaudeCode,
        &[],
        None,
        None,
        "2026-07-19T10:40:00Z",
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    let cache = read_cache(&path);
    assert_eq!(cache.watermarks.len(), 5_001);
    assert!(!cache.watermarks.contains_key("expired"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn long_scan_keeps_activity_seen_after_scan_start_and_advances_watermark() {
    let dir = temp_dir("long-scan");
    let snapshot = test_snapshot("live", "2026-07-19T10:06:00Z");
    let result = reconcile_active_sessions(
        &dir,
        SnapshotSource::ClaudeCode,
        &[
            snapshot,
            test_snapshot("old", "2026-07-19T09:44:00Z"),
            test_snapshot("future", "2026-07-19T10:46:00Z"),
        ],
        None,
        Some("2026-07-19T10:00:00Z"),
        "2026-07-19T10:40:00Z",
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(result.changed_session_count, 1);
    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.sessions[0].source_session_id, "live");
    let cache = read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode));
    assert_eq!(cache.watermarks["live"], "2026-07-19T10:06:00Z");
    assert_eq!(cache.reconciliation, Some(result.clone()));
    assert_eq!(
        result.scan_started_at.as_deref(),
        Some("2026-07-19T10:00:00Z")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn requires_advanced_recent_activity_and_preserves_compaction_times() {
    let dir = temp_dir("advanced");
    let mut snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
    snapshot.last_turn_context_tokens = Some(59_000);
    snapshot.compaction_events = vec![crate::snapshots::SnapshotCompactionEvent {
        at: "2026-07-19T09:59:00Z".to_string(),
        before: Some(100),
        after: Some(59_000),
        trigger: None,
    }];
    snapshot.local_context_points = vec![
        LocalContextPoint {
            at_unix_seconds: 1_784_454_600, // 2026-07-19T09:50:00Z
            prompt_tokens: 90,
        },
        LocalContextPoint {
            at_unix_seconds: 1_784_455_440, // 2026-07-19T10:04:00Z
            prompt_tokens: 59_000,
        },
    ];
    let first = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");
    assert_eq!(first.changed_session_count, 1);
    assert_eq!(
        first.sessions[0].compaction_timestamps,
        vec!["2026-07-19T09:59:00Z"]
    );
    let session = &first.sessions[0];
    assert_eq!(
        session.compaction_events,
        [ActiveSessionCompaction {
            at: "2026-07-19T09:59:00Z".to_string(),
            before_tokens: Some(100),
            after_tokens: Some(59_000),
            trigger: None,
        }]
    );
    assert_eq!(session.first_turn_context_tokens, Some(90));
    assert_eq!(session.last_turn_context_tokens, Some(59_000));
    assert_eq!(
        session.context_points,
        [(1_784_454_600, 90), (1_784_455_440, 59_000),]
    );
    // The list file is compact JSON, and a quiet scan carries the row
    // with its points and sizes unchanged.
    let written = std::fs::read(active_session_cache_path(&dir, SnapshotSource::Codex))
        .expect("read list file");
    assert!(!written.contains(&b'\n'));
    let quiet = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        None,
        None,
        "2026-07-19T10:06:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("quiet reconciliation");
    assert_eq!(quiet.sessions, first.sessions);

    let unchanged = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:10:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("unchanged reconciliation");
    assert_eq!(unchanged.changed_session_count, 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn keeps_recent_sessions_listed_until_their_activity_leaves_the_window() {
    let dir = temp_dir("carried");
    let busy = test_snapshot("busy", "2026-07-19T10:04:00Z");
    let first = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&busy),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");
    assert_eq!(first.sessions.len(), 1);

    // An incremental scan that re-selected nothing still lists the session.
    let quiet = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        None,
        None,
        "2026-07-19T10:15:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("quiet reconciliation");
    assert_eq!(quiet.changed_session_count, 0);
    assert_eq!(quiet.sessions, first.sessions);

    // A newly advanced session joins; the carried one stays, newest first.
    let other = test_snapshot("other", "2026-07-19T10:16:00Z");
    let mixed = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[busy.clone(), other],
        None,
        None,
        "2026-07-19T10:17:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("mixed reconciliation");
    assert_eq!(mixed.changed_session_count, 1);
    let ids = mixed
        .sessions
        .iter()
        .map(|session| session.source_session_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["other", "busy"]);

    // Fifteen minutes after its last activity the carried session expires.
    let later = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        None,
        None,
        "2026-07-19T10:20:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("later reconciliation");
    let ids = later
        .sessions
        .iter()
        .map(|session| session.source_session_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["other"]);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rebuilds_a_listed_session_re_read_without_new_activity() {
    let dir = temp_dir("rebuilt");
    let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
    let first = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");
    assert!(first.sessions[0].session_display_name.is_some());

    // The workspace disabled titles; the re-read snapshot carries none.
    let mut stripped = snapshot.clone();
    stripped.session_display_name = None;
    let rebuilt = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[stripped],
        None,
        None,
        "2026-07-19T10:08:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("rebuilt reconciliation");
    assert_eq!(rebuilt.changed_session_count, 0);
    assert_eq!(rebuilt.sessions.len(), 1);
    assert!(rebuilt.sessions[0].session_display_name.is_none());

    let _ = std::fs::remove_dir_all(dir);
}

/// [regress] local labels survive upload settings and quiet scans.
#[test]
fn local_labels_survive_disabled_uploads_and_quiet_policy_changes() {
    let dir = temp_dir("policy-change");
    let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
    let local = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");
    assert_eq!(
        local.sessions[0].session_display_name,
        snapshot.session_display_name
    );
    let mut uploaded = vec![snapshot.clone()];
    crate::snapshots::apply_upload_policy(
        SnapshotSource::Codex,
        &mut uploaded,
        SnapshotUploadPolicy {
            session_titles_enabled: false,
            ..test_policy()
        },
    );
    assert!(uploaded[0].session_display_name.is_none());
    let changed = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        None,
        None,
        "2026-07-19T10:08:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("policy-change reconciliation");
    assert_eq!(changed.sessions.len(), 1);
    assert_eq!(
        changed.sessions[0].session_display_name,
        local.sessions[0].session_display_name
    );
    assert_eq!(
        changed.sessions[0].workspace_display_label,
        local.sessions[0].workspace_display_label
    );

    let _ = std::fs::remove_dir_all(dir);
}

fn account_display(account: &str) -> crate::snapshots::claude_request_identity::AccountDisplay {
    crate::snapshots::claude_request_identity::AccountDisplay {
        current: ActiveSessionCurrentAccount {
            status: "known".into(),
            account_identifier_hash: Some(account.into()),
            organization_identifier_hash: Some("workspace".into()),
            subscription_product: Some("max".into()),
            latest_request_at: Some("2026-07-19T10:04:00Z".into()),
            unknown_reason: None,
        },
        history: vec![ActiveSessionAccountUse {
            account_identifier_hash: Some(account.into()),
            organization_identifier_hash: Some("workspace".into()),
            subscription_product: Some("max".into()),
            request_count: 1,
            input_tokens: 100,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            output_tokens: 0,
            last_used_at: Some("2026-07-19T10:04:00Z".into()),
            current: true,
        }],
    }
}

#[test]
fn current_account_and_history_come_only_from_this_reads_own_requests() {
    let dir = temp_dir("session-accounts");
    let reconcile = |snapshot: &SnapshotItem, source, at: &str| {
        reconcile_active_sessions(
            &dir,
            source,
            std::slice::from_ref(snapshot),
            None,
            None,
            at,
            std::time::Duration::from_secs(300),
        )
        .expect("reconciliation")
        .sessions
    };
    let mut tagged = test_snapshot("s-claude", "2026-07-19T10:04:00Z");
    tagged.claude_account_display = Some(Box::new(account_display("account-a")));
    let listed = reconcile(&tagged, SnapshotSource::ClaudeCode, "2026-07-19T10:05:00Z");
    let display = account_display("account-a");
    assert_eq!(listed[0].current_account.as_ref(), Some(&display.current));
    assert_eq!(listed[0].account_history, display.history);
    // Legacy cumulative attribution is untouched by the new fields.
    assert_eq!(listed[0].account_identifier_hash, None);

    // Not re-read: the carried row keeps what its own requests proved.
    let quiet = reconcile_active_sessions(
        &dir,
        SnapshotSource::ClaudeCode,
        &[],
        None,
        None,
        "2026-07-19T10:06:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("quiet")
    .sessions;
    assert_eq!(quiet[0].current_account.as_ref(), Some(&display.current));

    // Any re-read rebuilds from its own evidence. The same last activity
    // does not prove the same requests (a second request in that same
    // instant, or a corrected body), so a re-read this cycle could not
    // tag clears the listed facts rather than lend them to new usage.
    let mut untagged = tagged.clone();
    untagged.claude_account_display = None;
    untagged.input_tokens += 7;
    untagged.request_count += 1;
    let reread = reconcile(
        &untagged,
        SnapshotSource::ClaudeCode,
        "2026-07-19T10:07:00Z",
    );
    assert_eq!(reread[0].current_account, None);
    assert!(reread[0].account_history.is_empty());
    // Even a byte-identical re-read without an identity pass clears them.
    let mut same = tagged.clone();
    same.claude_account_display = None;
    let unchanged = reconcile(&same, SnapshotSource::ClaudeCode, "2026-07-19T10:07:15Z");
    assert_eq!(unchanged[0].current_account, None);
    // A rebuilt answer for the same activity replaces the listed one.
    let mut retagged = tagged.clone();
    retagged.claude_account_display = Some(Box::new(account_display("account-b")));
    let replaced = reconcile(
        &retagged,
        SnapshotSource::ClaudeCode,
        "2026-07-19T10:07:30Z",
    );
    assert_eq!(
        replaced[0].current_account,
        Some(account_display("account-b").current)
    );
    // Newer activity without per-request identity: absent too.
    let mut newer = untagged.clone();
    newer.source_last_activity_at = Some("2026-07-19T10:08:00Z".into());
    let advanced = reconcile(&newer, SnapshotSource::ClaudeCode, "2026-07-19T10:09:00Z");
    assert_eq!(advanced[0].current_account, None);

    // Other sources never show it, whatever the item carries.
    let mut codex = test_snapshot("s-codex", "2026-07-19T10:04:00Z");
    codex.claude_account_display = Some(Box::new(account_display("account-a")));
    let codex_dir = temp_dir("session-accounts-codex");
    let codex_sessions = reconcile_active_sessions(
        &codex_dir,
        SnapshotSource::Codex,
        &[codex],
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("codex")
    .sessions;
    assert_eq!(codex_sessions[0].current_account, None);
    assert!(codex_sessions[0].account_history.is_empty());

    // A cache written by an older daemon decodes with both fields absent.
    let path = active_session_cache_path(&dir, SnapshotSource::ClaudeCode);
    std::fs::write(
        &path,
        r#"{"reconciliation":{"reconciled_at":"2026-07-19T10:05:00Z","changed_session_count":1,"sessions":[{"source_session_id":"old","source_last_activity_at":"2026-07-19T10:04:00Z","account_identifier_hash":"legacy"}]}}"#,
    )
    .unwrap();
    let old = read_active_session_reconciliation(&dir, SnapshotSource::ClaudeCode).unwrap();
    assert_eq!(old.sessions[0].current_account, None);
    assert!(old.sessions[0].account_history.is_empty());
    assert_eq!(
        old.sessions[0].account_identifier_hash.as_deref(),
        Some("legacy")
    );

    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(codex_dir);
}

#[test]
fn withholds_carried_attribution_that_current_evidence_contradicts() {
    let dir = temp_dir("carried-attribution");
    let mut snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
    snapshot.model_usage[0].account_identifier_hash = Some("account-a".into());
    snapshot.usage_buckets[0].model_usage[0].account_identifier_hash = Some("account-a".into());
    let status = test_status();
    let first = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        Some(&status),
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");
    assert_eq!(
        first.sessions[0].account_identifier_hash.as_deref(),
        Some("account-a")
    );

    let agreeing = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        Some(&status),
        None,
        "2026-07-19T10:06:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("agreeing reconciliation");
    assert_eq!(
        agreeing.sessions[0].account_identifier_hash.as_deref(),
        Some("account-a")
    );

    let mut conflicting = test_status();
    conflicting.plan_observations.push(test_plan_observation(
        "s1",
        "account-b",
        AgentStatusConfidence::High,
    ));
    let withheld = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        Some(&conflicting),
        None,
        "2026-07-19T10:07:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("conflicting reconciliation");
    assert_eq!(withheld.sessions.len(), 1);
    assert!(withheld.sessions[0].account_identifier_hash.is_none());
    assert!(withheld.sessions[0].organization_identifier_hash.is_none());
    assert!(withheld.sessions[0].account_attribution_source.is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn withholds_carried_login_fallback_after_a_workspace_switch() {
    let mut session = active_session_from_snapshot(
        SnapshotSource::Codex,
        &test_snapshot("s1", "2026-07-19T10:04:00Z"),
        None,
    );
    session.account_identifier_hash = Some("account-a".into());
    session.organization_identifier_hash = Some("workspace-x".into());
    session.account_attribution_source = Some("current_login_at_reconciliation".into());
    let mut status = test_status();
    let mut account = test_current_account("account-a");
    account.organization_identifier_hash = Some("workspace-x".into());
    status.account = Some(account.clone());

    let mut same = session.clone();
    withhold_contradicted_attribution(&mut same, &status);
    assert_eq!(
        same.organization_identifier_hash.as_deref(),
        Some("workspace-x")
    );

    account.organization_identifier_hash = Some("workspace-y".into());
    status.account = Some(account);
    withhold_contradicted_attribution(&mut session, &status);
    assert!(session.account_identifier_hash.is_none());
    assert!(session.organization_identifier_hash.is_none());
}

#[test]
fn clearing_a_withdrawn_source_does_not_carry_recent_sessions() {
    let dir = temp_dir("cleared");
    let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
    reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        std::slice::from_ref(&snapshot),
        None,
        None,
        "2026-07-19T10:05:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("first reconciliation");

    let cleared = clear_active_sessions(&dir, SnapshotSource::Codex, "2026-07-19T10:06:00Z")
        .expect("cleared reconciliation");
    assert!(cleared.sessions.is_empty());
    assert_eq!(
        cleared.last_activity_at.as_deref(),
        Some("2026-07-19T10:04:00Z")
    );
    let after = reconcile_active_sessions(
        &dir,
        SnapshotSource::Codex,
        &[],
        None,
        None,
        "2026-07-19T10:07:00Z",
        std::time::Duration::from_secs(300),
    )
    .expect("next reconciliation");
    assert!(after.sessions.is_empty());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn attributes_current_login_only_with_matching_provider_and_plan() {
    let mut status = AgentStatusSnapshot {
        source: ottto_protocol::SourceKind::Codex,
        status: AgentStatusState::Available,
        collection_method: AgentStatusCollectionMethod::CliJson,
        captured_at: "2026-07-19T10:05:00Z".to_string(),
        expires_at: "2026-07-19T10:15:00Z".to_string(),
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    };
    status.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: Some("plus".to_string()),
        subscription_product: Some("chatgpt_plus".to_string()),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: Some("acct_hash".to_string()),
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: Some("account_identifier".to_string()),
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    });
    let active = active_session_from_snapshot(
        SnapshotSource::Codex,
        &test_snapshot("s1", "2026-07-19T10:04:00Z"),
        Some(&status),
    );
    assert_eq!(active.account_identifier_hash.as_deref(), Some("acct_hash"));
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("current_login_at_reconciliation")
    );
    assert_eq!(
        active.source_started_at.as_deref(),
        Some("2026-07-19T09:50:00Z")
    );
    assert_eq!(active.input_tokens, Some(100));
    assert_eq!(active.cache_read_tokens, Some(80));
    assert_eq!(active.output_tokens, Some(20));
    assert_eq!(
        active.input_token_scope.as_deref(),
        Some("inclusive_cached")
    );
}

#[test]
fn explains_withheld_accounts_without_widening_attribution() {
    let mut status = test_status();
    status.account = Some(test_current_account("current_login_hash"));
    status.plan_observations.push(test_plan_observation(
        "parent",
        "parent_hash",
        AgentStatusConfidence::High,
    ));

    // Several accounts on the session's own requests: neither the parent's
    // nor the current login's single account may stand in for them.
    let mut mixed = test_snapshot("mixed", "2026-07-19T10:04:00Z");
    mixed
        .attribution_facts
        .push(direct_fact("parent_session_ref", "parent"));
    mixed.claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &mixed, Some(&status));
    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
    assert_eq!(
        active.account_withheld_reason.as_deref(),
        Some("multiple_accounts")
    );

    // Incomplete evidence only explains; the existing fallbacks are
    // unchanged, and an attributed card never carries a reason.
    let mut incomplete = test_snapshot("incomplete", "2026-07-19T10:04:00Z");
    incomplete.claude_account_withheld_reason =
        Some(crate::snapshots::CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE);
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &incomplete, Some(&status));
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("current_login_at_reconciliation")
    );
    assert_eq!(active.account_withheld_reason, None);
    let active = active_session_from_snapshot(SnapshotSource::ClaudeCode, &incomplete, None);
    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(
        active.account_withheld_reason.as_deref(),
        Some("incomplete_request_evidence")
    );

    // A reason no longer describes rows a later pass attributed.
    let mut attributed = mixed.clone();
    for row in &mut attributed.model_usage {
        row.account_identifier_hash = Some("family_hash".to_string());
    }
    for bucket in &mut attributed.usage_buckets {
        for row in &mut bucket.model_usage {
            row.account_identifier_hash = Some("family_hash".to_string());
        }
    }
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &attributed, Some(&status));
    assert_eq!(
        active.account_identifier_hash.as_deref(),
        Some("family_hash")
    );
    assert_eq!(active.account_withheld_reason, None);

    // Contract-5 rows: each bucket row carries its own request login and the
    // lifetime row splits into exact parts. Two accounts explain themselves
    // with no stored reason, and still name nothing.
    let part = |hash: &str| crate::snapshots::SnapshotIdentityPart {
        account_identifier_hash: Some(hash.to_string()),
        evidence_ref: Some(0),
        input_tokens: 50,
        output_tokens: 10,
        cache_read_tokens: 40,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        unattributed_total_tokens: 0,
        request_count: 1,
        cost_usd: None,
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
    };
    let mut tagged = test_snapshot("tagged", "2026-07-19T10:04:00Z");
    tagged.provenance.collector =
        crate::snapshots::claude_request_identity::COLLECTOR.to_string();
    tagged
        .attribution_facts
        .push(direct_fact("parent_session_ref", "parent"));
    tagged.request_evidence = vec![crate::snapshots::SnapshotRequestEvidence {
        identity_basis: "telemetry".to_string(),
        provider_workspace_hash: Some("organization_hash".to_string()),
        account_source: None,
    }];
    let mut later = tagged.usage_buckets[0].clone();
    later.bucket_start = "2026-07-19T11:00:00Z".to_string();
    tagged.usage_buckets.push(later);
    tagged.model_usage[0].identity_parts = Some(vec![part("login_a"), part("login_b")]);
    for (bucket, login) in tagged.usage_buckets.iter_mut().zip(["login_a", "login_b"]) {
        bucket.model_usage[0].account_identifier_hash = Some(login.to_string());
        bucket.model_usage[0].evidence_ref = Some(0);
    }
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &tagged, Some(&status));
    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
    assert_eq!(
        active.account_withheld_reason.as_deref(),
        Some("multiple_accounts")
    );

    // A login under the retired sole-login basis (never emitted, still
    // parsed) is not the request's own telemetry.
    let mut census = tagged.clone();
    census.request_evidence[0].identity_basis = "transcript_sole_login".to_string();
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &census, Some(&status));
    assert_eq!(active.account_attribution_source, None);
    assert_eq!(active.account_withheld_reason, None);

    // One account beside untagged usage is not several accounts.
    let mut one_and_untagged = tagged.clone();
    one_and_untagged.model_usage[0].identity_parts = Some(vec![
        part("login_a"),
        crate::snapshots::SnapshotIdentityPart {
            account_identifier_hash: None,
            evidence_ref: None,
            ..part("login_a")
        },
    ]);
    let untagged = &mut one_and_untagged.usage_buckets[1].model_usage[0];
    untagged.account_identifier_hash = None;
    untagged.evidence_ref = None;
    let active = active_session_from_snapshot(
        SnapshotSource::ClaudeCode,
        &one_and_untagged,
        Some(&status),
    );
    assert_eq!(active.account_attribution_source, None);
    assert_eq!(active.account_withheld_reason, None);

    // Every request on one account stays named, as today.
    let mut single = tagged.clone();
    single.model_usage[0].identity_parts = None;
    single.model_usage[0].account_identifier_hash = Some("login_a".to_string());
    single.model_usage[0].evidence_ref = Some(0);
    single.usage_buckets[1].model_usage[0].account_identifier_hash =
        Some("login_a".to_string());
    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &single, Some(&status));
    assert_eq!(active.account_identifier_hash.as_deref(), Some("login_a"));
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("snapshot_account_identity")
    );
    assert_eq!(active.account_withheld_reason, None);
}

#[test]
fn classifies_headless_codex_run_from_its_own_session_header() {
    // The dominant `codex exec` shape on disk: the provider names the binary
    // in `originator` and the non-interactive entry point in `source`, while
    // `thread_source` stays `user` because a person may have typed it.
    let mut snapshot = test_snapshot("headless", "2026-07-19T10:04:00Z");
    snapshot.session_display_name = None;
    snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
        originator: Some("codex_exec".to_string()),
        source: Some("exec".to_string()),
        thread_source: Some("user".to_string()),
        ..Default::default()
    });

    let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

    assert_eq!(active.session_kind.as_deref(), Some("headless"));
}

#[test]
fn keeps_subagent_role_for_a_headless_subagent_run() {
    // Codex spawns subagents through `codex exec`, so both signals appear.
    // The more specific role wins; headless never overwrites it.
    let mut snapshot = test_snapshot("headless-subagent", "2026-07-19T10:04:00Z");
    snapshot.session_display_name = None;
    snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
        originator: Some("codex_exec".to_string()),
        thread_source: Some("subagent".to_string()),
        source_subagent: Some(true),
        ..Default::default()
    });

    let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

    assert_eq!(active.session_kind.as_deref(), Some("subagent"));
}

#[test]
fn carries_provider_surface_when_upload_policy_strips_attribution_facts() {
    let mut snapshot = test_snapshot("desktop", "2026-07-19T10:04:00Z");
    snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
        originator: Some("codex_work_desktop".to_string()),
        source: Some("vscode".to_string()),
        ..Default::default()
    });
    snapshot.attribution_facts.clear();

    let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

    assert_eq!(active.provider_surface.as_deref(), Some("codex_desktop"));
}

#[test]
fn attributes_from_exact_snapshot_account_identity() {
    let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
    snapshot.model_usage[0].account_identifier_hash = Some("desktop_hash".to_string());
    snapshot.usage_buckets[0].model_usage[0].account_identifier_hash =
        Some("desktop_hash".to_string());
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "parent",
        "desktop_hash",
        AgentStatusConfidence::High,
    ));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(
        active.account_identifier_hash.as_deref(),
        Some("desktop_hash")
    );
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("snapshot_account_identity")
    );
}

#[test]
fn codex_bound_sessions_complete_their_local_account_workspace_key() {
    let account = |id| ottto_core::billing_identity_hash("openai", "account", id).unwrap();
    let workspace = |id| ottto_core::billing_identity_hash("openai", "workspace", id).unwrap();
    let default_account = account("default-login");
    let slot_account = account("slot-login");
    let default_workspace = workspace("default-workspace");
    let slot_workspace = workspace("slot-workspace");
    let mut status = test_status();
    status.source = ottto_protocol::SourceKind::Codex;
    let mut observation = test_plan_observation(
        "default-status",
        &default_account,
        AgentStatusConfidence::High,
    );
    observation.organization_identifier_hash = Some(default_workspace.clone());
    status.plan_observations.push(observation);

    for (name, bound_account, creator_account, creator_workspace, disposition, expected_org) in [
        (
            "other-slot",
            &slot_account,
            &slot_account,
            Some(&slot_workspace),
            None,
            Some(&slot_workspace),
        ),
        (
            "default-observation-wins",
            &default_account,
            &default_account,
            Some(&slot_workspace),
            None,
            Some(&default_workspace),
        ),
        (
            "mismatched-creator",
            &slot_account,
            &default_account,
            Some(&default_workspace),
            None,
            None,
        ),
        (
            "missing-workspace",
            &slot_account,
            &slot_account,
            None,
            None,
            None,
        ),
        (
            "conflicting-creator",
            &slot_account,
            &slot_account,
            Some(&slot_workspace),
            Some("conflict"),
            None,
        ),
    ] {
        let dir = temp_dir(name);
        let mut snapshot = test_snapshot(name, "2026-07-19T10:04:00Z");
        snapshot.model_usage[0].account_identifier_hash = Some(bound_account.clone());
        snapshot.usage_buckets[0].model_usage[0].account_identifier_hash =
            Some(bound_account.clone());
        snapshot.session_account_evidence = Some(crate::snapshots::SessionAccountEvidence {
            provider: "openai",
            account_identifier_hash: Some(creator_account.clone()),
            provider_workspace_hash: creator_workspace.cloned(),
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "codex_creator_header:v1",
            identity_disposition: disposition,
            source_created_at: None,
        });

        let result = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[snapshot],
            Some(&status),
            None,
            "2026-07-19T10:05:00Z",
            std::time::Duration::from_secs(300),
        )
        .unwrap();
        assert_eq!(result.sessions.len(), 1, "{name}");
        let active = &result.sessions[0];
        // Companion cards require both account and workspace hashes exactly;
        // creator workspace hashes already use the card's workspace namespace.
        assert_eq!(
            active.account_identifier_hash.as_ref(),
            Some(bound_account),
            "{name}"
        );
        assert_eq!(
            active.organization_identifier_hash.as_ref(),
            expected_org,
            "{name}"
        );
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("snapshot_account_identity"),
            "{name}"
        );
        assert_eq!(
            read_active_session_reconciliation(&dir, SnapshotSource::Codex)
                .unwrap()
                .sessions,
            result.sessions,
            "{name}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn changed_login_keeps_proven_session_account_and_withholds_only_fallback() {
    let mut status = test_status();
    status.source = ottto_protocol::SourceKind::Codex;
    status.account = Some(test_current_account("old-login"));
    let retained = crate::agent_status_refresh::status_for_reconciliation(&status, &[], true);
    assert!(retained.account.is_none());
    let mut proven = test_snapshot("proven", "2026-07-19T10:04:00Z");
    proven.model_usage[0].account_identifier_hash = Some("session-owner".into());
    proven.usage_buckets[0].model_usage[0].account_identifier_hash =
        Some("session-owner".into());
    let active = active_session_from_snapshot(SnapshotSource::Codex, &proven, Some(&retained));
    assert_eq!(
        active.account_identifier_hash.as_deref(),
        Some("session-owner")
    );
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("snapshot_account_identity")
    );
    let unbound = test_snapshot("unbound", "2026-07-19T10:04:00Z");
    let unsafe_fallback =
        active_session_from_snapshot(SnapshotSource::Codex, &unbound, Some(&status));
    assert_eq!(
        unsafe_fallback.account_identifier_hash.as_deref(),
        Some("old-login")
    );
    let withheld =
        active_session_from_snapshot(SnapshotSource::Codex, &unbound, Some(&retained));
    assert!(withheld.account_identifier_hash.is_none());
    let stable_home = crate::agent_status::CodexHomeBinding {
        home: std::path::PathBuf::from("/synthetic/stable-home"),
        account_identifier_hash: "old-login".into(),
        workspace_identifier_hash: "workspace".into(),
        auth_modified_at: std::time::UNIX_EPOCH,
    };
    status
        .account
        .as_mut()
        .unwrap()
        .organization_identifier_hash = Some("workspace".into());
    let still_current =
        crate::agent_status_refresh::status_for_reconciliation(&status, &[stable_home], true);
    assert_eq!(
        still_current.account, status.account,
        "an unchanged home retains its current-login metadata"
    );
}

#[test]
fn inherits_high_confidence_account_from_direct_root_lineage() {
    let mut snapshot = test_snapshot("parent_agent-child", "2026-07-19T10:04:00Z");
    snapshot
        .attribution_facts
        .push(direct_fact("parent_session_ref", "parent"));
    snapshot
        .attribution_facts
        .push(direct_fact("root_session_ref", "parent"));
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "parent",
        "desktop_hash",
        AgentStatusConfidence::High,
    ));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(
        active.account_identifier_hash.as_deref(),
        Some("desktop_hash")
    );
    assert_eq!(
        active.account_attribution_source.as_deref(),
        Some("lineage_plan_observation")
    );
}

#[test]
fn refuses_conflicting_direct_lineage_accounts() {
    let mut snapshot = test_snapshot("root_agent-child", "2026-07-19T10:04:00Z");
    snapshot
        .attribution_facts
        .push(direct_fact("parent_session_ref", "parent"));
    snapshot
        .attribution_facts
        .push(direct_fact("root_session_ref", "root"));
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "parent",
        "first_hash",
        AgentStatusConfidence::High,
    ));
    status.plan_observations.push(test_plan_observation(
        "root",
        "second_hash",
        AgentStatusConfidence::High,
    ));
    status.account = Some(test_current_account("second_hash"));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

#[test]
fn launched_session_never_borrows_its_starters_account() {
    let attribution = |facts: &[(&str, &str)], own_hash: Option<&str>| {
        let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        for (field, source_version) in facts {
            let mut fact = direct_fact(field, "parent");
            fact.evidence.source_version = source_version.to_string();
            snapshot.attribution_facts.push(fact);
        }
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "parent",
            "parent_hash",
            AgentStatusConfidence::High,
        ));
        if let Some(own_hash) = own_hash {
            status.plan_observations.push(test_plan_observation(
                "child",
                own_hash,
                AgentStatusConfidence::High,
            ));
        }
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));
        (
            active.account_identifier_hash,
            active.account_attribution_source,
        )
    };
    let borrowed = (
        Some("parent_hash".to_string()),
        Some("lineage_plan_observation".to_string()),
    );

    // Launched by a launcher or by the desktop app, on either lineage field:
    // the starter's account stays the starter's.
    let launched: [&[(&str, &str)]; 3] = [
        &[("parent_session_ref", "launcher_event:v1")],
        &[("parent_session_ref", "claude_desktop_spawn:v1")],
        &[("root_session_ref", "claude_desktop_spawn:v1")],
    ];
    for facts in launched {
        assert_eq!(attribution(facts, None), (None, None), "{facts:?}");
        assert_eq!(
            attribution(facts, Some("child_hash")),
            (
                Some("child_hash".to_string()),
                Some("session_plan_observation".to_string())
            ),
            "{facts:?}"
        );
    }
    // Nested work, unknown or look-alike parsers, and a non-launched fact
    // beside a launched one keep the lineage fallback.
    let not_launched: [&[(&str, &str)]; 6] = [
        &[("parent_session_ref", "claude_code_jsonl:v40")],
        &[("parent_session_ref", "test:v1")],
        &[("root_session_ref", "")],
        &[("parent_session_ref", "launcher_events:v1")],
        &[("parent_session_ref", "claude_desktop_spawner:v1")],
        &[
            ("parent_session_ref", "launcher_event:v1"),
            ("root_session_ref", "claude_code_jsonl:v40"),
        ],
    ];
    for facts in not_launched {
        assert_eq!(attribution(facts, None), borrowed, "{facts:?}");
    }
}

#[test]
fn refuses_conflict_between_exact_observation_and_snapshot_identity() {
    let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
    snapshot.model_usage[0].account_identifier_hash = Some("snapshot_hash".to_string());
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "child",
        "observation_hash",
        AgentStatusConfidence::High,
    ));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

#[test]
fn refuses_conflicting_exact_session_observations() {
    let snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "child",
        "first_hash",
        AgentStatusConfidence::High,
    ));
    status.plan_observations.push(test_plan_observation(
        "child",
        "second_hash",
        AgentStatusConfidence::High,
    ));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

#[test]
fn refuses_partial_snapshot_account_identity() {
    let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
    let mut second_row = snapshot.model_usage[0].clone();
    snapshot.model_usage[0].account_identifier_hash = Some("desktop_hash".to_string());
    second_row.account_identifier_hash = None;
    snapshot.model_usage.push(second_row);

    let active = active_session_from_snapshot(
        SnapshotSource::ClaudeCode,
        &snapshot,
        Some(&test_status()),
    );

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

#[test]
fn refuses_conflicting_bucket_snapshot_account_identity() {
    let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
    snapshot.model_usage[0].account_identifier_hash = Some("aggregate_hash".to_string());
    snapshot.usage_buckets[0].model_usage[0].account_identifier_hash =
        Some("bucket_hash".to_string());
    let mut status = test_status();
    status.account = Some(test_current_account("bucket_hash"));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

#[test]
fn own_request_parts_gate_account_fallbacks() {
    // Contract-5 transcript/reported classification; `e2` allocates final grains before tagging.

    use crate::claude_local_otel::{
        ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipEvidence,
        ClaudeTraceOwnershipLoadReport,
    };
    use crate::snapshots::claude_request_identity as identity;
    use sha2::{Digest, Sha256};

    // A subagent's two requests in one hour on one model, read by the
    // parser and tagged by contract 5 from each request's own telemetry.
    let parent = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let agent = "a4d1585d310070d0f";
    let dir = temp_dir("own-request-parts");
    let transcript = dir
        .join(parent)
        .join("subagents")
        .join(format!("agent-{agent}.jsonl"));
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let line = |n: u64| {
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:0{n}Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"req_{n}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
        )
    };
    std::fs::write(&transcript, line(1) + &line(2)).unwrap();
    let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
    // `None` leaves that request without telemetry, so it stays untagged.
    let tagged = |logins: [Option<&str>; 2]| {
        let mut api = ClaudeLocalOtelLoadReport::default();
        let mut trace = ClaudeTraceOwnershipLoadReport::default();
        for (n, login) in (1_u64..).zip(logins) {
            let Some(login) = login else { continue };
            let mut row = ClaudeLocalOtelEvidence {
                capture_revision: "claude_api_request:v2".into(),
                session_id: parent.into(),
                request_id: format!("req_{n}"),
                client_request_id: format!("client-req_{n}"),
                observed_at: format!("2026-08-02T07:00:0{n}Z"),
                model: "claude-haiku-4-5".into(),
                effort: "high".into(),
                query_source: "user".into(),
                speed: "fast".into(),
                cost_usd_micros: Some(100),
                event_sequence: Some(n),
                app_version: "2.1.226".into(),
                input_tokens: 10,
                output_tokens: 10,
                request_count: 1,
                account_identity_checked: true,
                account_identifier_hash: Some(login.into()),
                ..Default::default()
            };
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            let mut owner = ClaudeTraceOwnershipEvidence {
                capture_revision: "claude_llm_request_ownership:v1".into(),
                session_id: parent.into(),
                request_id: format!("req_{n}"),
                client_request_id: format!("client-req_{n}"),
                agent_id: agent.to_string(),
                observed_at: "2026-08-02T07:00:30Z".to_string(),
                ..Default::default()
            };
            owner.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&owner).unwrap())
            );
            api.evidence
                .entry(parent.to_string())
                .or_default()
                .push(row);
            trace
                .evidence
                .entry(parent.to_string())
                .or_default()
                .push(owner);
        }
        let mut items = crate::snapshots::e2_pipeline_scan_fixture::parse_ordinary(
            &transcript,
            "2026-08-02T07:01:00Z",
            "child-fp".to_string(),
        )
        .unwrap();
        let evidence = identity::ScanEvidence::new(&api, &trace, BTreeSet::new());
        assert_eq!(
            identity::apply_scan(&mut items, &evidence, BTreeMap::new()).sent,
            1
        );
        let item = items.remove(0);
        assert_eq!(item.source_session_id, format!("{parent}_agent-{agent}"));
        // Every row splits into parts: no row carries a hash.
        assert!(item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage)
            )
            .all(|row| row.account_identifier_hash.is_none()
                && row
                    .identity_parts
                    .as_ref()
                    .is_some_and(|parts| parts.len() == 2)));
        item
    };
    let lineage = |account_hash: &str| {
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            parent,
            account_hash,
            AgentStatusConfidence::High,
        ));
        status
    };
    let attribution = |item: &SnapshotItem, status: &AgentStatusSnapshot| {
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, item, Some(status));
        (
            active.account_identifier_hash,
            active.account_attribution_source,
        )
    };

    // Two own logins: neither the parent's account nor an observation of
    // either login stands in for them.
    let mixed = tagged([Some(a.as_str()), Some(b.as_str())]);
    assert_eq!(attribution(&mixed, &lineage(c.as_str())), (None, None));
    assert_eq!(attribution(&mixed, &lineage(a.as_str())), (None, None));
    // A stored mixed-account reason still explains the withheld account.
    let mut mixed = mixed;
    mixed.claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
    for status in [lineage(c.as_str()), lineage(a.as_str())] {
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &mixed, Some(&status));
        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
        assert_eq!(
            active.account_withheld_reason.as_deref(),
            Some("multiple_accounts")
        );
    }

    // One own login beside an untagged request: lineage, an exact
    // observation or the current login naming another account is refused;
    // the same account keeps its source.
    let one = tagged([Some(a.as_str()), None]);
    assert_eq!(attribution(&one, &lineage(b.as_str())), (None, None));
    assert_eq!(
        attribution(&one, &lineage(a.as_str())),
        (
            Some(a.clone()),
            Some("lineage_plan_observation".to_string())
        )
    );
    let session = one.source_session_id.clone();
    let exact = |account_hash: &str| {
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            &session,
            account_hash,
            AgentStatusConfidence::High,
        ));
        status
    };
    assert_eq!(attribution(&one, &exact(b.as_str())), (None, None));
    assert_eq!(
        attribution(&one, &exact(a.as_str())),
        (
            Some(a.clone()),
            Some("session_plan_observation".to_string())
        )
    );
    let mut one = one;
    one.model_usage[0].model_provider = Some("anthropic".to_string());
    one.model_usage[0].subscription_product = Some("claude_max".to_string());
    let login = |account_hash: &str| {
        let mut status = test_status();
        let mut account = test_current_account(account_hash);
        account.provider = Some("anthropic".to_string());
        account.plan_type = None;
        account.subscription_product = Some("claude_max".to_string());
        status.account = Some(account);
        status
    };
    assert_eq!(attribution(&one, &login(b.as_str())), (None, None));
    assert_eq!(
        attribution(&one, &login(a.as_str())),
        (
            Some(a.clone()),
            Some("current_login_at_reconciliation".to_string())
        )
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn refuses_indirect_or_low_confidence_lineage() {
    let mut snapshot = test_snapshot("parent_agent-child", "2026-07-19T10:04:00Z");
    let mut fact = direct_fact("root_session_ref", "parent");
    fact.evidence.strength = "inferred".to_string();
    snapshot.attribution_facts.push(fact);
    let mut status = test_status();
    status.plan_observations.push(test_plan_observation(
        "parent",
        "desktop_hash",
        AgentStatusConfidence::Low,
    ));

    let active =
        active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

    assert_eq!(active.account_identifier_hash, None);
    assert_eq!(active.account_attribution_source, None);
}

fn test_status() -> AgentStatusSnapshot {
    AgentStatusSnapshot {
        source: ottto_protocol::SourceKind::ClaudeCode,
        status: AgentStatusState::Available,
        collection_method: AgentStatusCollectionMethod::CliJson,
        captured_at: "2026-07-19T10:05:00Z".to_string(),
        expires_at: "2026-07-19T10:15:00Z".to_string(),
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    }
}

fn test_plan_observation(
    session_id: &str,
    account_hash: &str,
    confidence: AgentStatusConfidence,
) -> AgentStatusPlanObservation {
    AgentStatusPlanObservation {
        desktop_recent_at: None,
        observed_at: Some("2026-07-19T10:04:00Z".to_string()),
        evidence_method: Some("claude_desktop_session_bucket".to_string()),
        source_session_id: Some(session_id.to_string()),
        provider: Some("anthropic".to_string()),
        billing_provider: Some("anthropic".to_string()),
        model_provider: Some("anthropic".to_string()),
        billing_channel: Some("subscription".to_string()),
        auth_mode: Some("claude_desktop".to_string()),
        gateway_provider: None,
        subscription_product: Some("claude_subscription".to_string()),
        plan_type: Some("subscription".to_string()),
        account_label: None,
        account_id: None,
        organization_label: None,
        organization_id: None,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some("organization_hash".to_string()),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: Some("provider_account_id".to_string()),
        billing_identity_confidence: confidence.clone(),
        confidence,
        is_current: Some(true),
    }
}

fn test_current_account(account_hash: &str) -> AgentAccountStatus {
    AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: Some("plus".to_string()),
        subscription_product: Some("chatgpt_plus".to_string()),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: Some("account_identifier".to_string()),
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    }
}

fn direct_fact(field: &str, value: &str) -> crate::session_attribution::SessionAttributionFact {
    crate::session_attribution::SessionAttributionFact {
        field: field.to_string(),
        value: value.to_string(),
        display_label: None,
        display_label_source: None,
        evidence: crate::session_attribution::SessionFieldEvidence {
            kind: "provider_metadata".to_string(),
            strength: "direct".to_string(),
            observed_at: "2026-07-19T10:04:00Z".to_string(),
            source_version: "test:v1".to_string(),
            evidence_ref: format!("sha256:{}", "a".repeat(64)),
        },
    }
}

fn test_snapshot(session_id: &str, last_activity: &str) -> SnapshotItem {
    let model_usage = SnapshotModelUsage {
        evidence_ref: None,
        identity_parts: None,
        copy_unproven: false,
        model: "gpt-5.6-codex".to_string(),
        input_tokens: 100,
        output_tokens: 20,
        cache_read_tokens: 80,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        reasoning_effort: None,
        unattributed_total_tokens: 0,
        request_count: 1,
        selector_context: BTreeMap::from([(
            "subscription_product".to_string(),
            "chatgpt_plus".to_string(),
        )]),
        selector_sources: BTreeMap::new(),
        auth_mode: Some("oauth".to_string()),
        billing_channel: Some("subscription".to_string()),
        billing_provider: Some("openai".to_string()),
        gateway_provider: Some("openai".to_string()),
        model_provider: Some("openai".to_string()),
        subscription_product: Some("chatgpt_plus".to_string()),
        account_identifier_hash: None,
        cost_usd: None,
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
    };
    SnapshotItem {
        evidence_basis: None,
        request_evidence: Vec::new(),
        request_identity_refusals: 0,
        claude_org_markers: None,
        claude_account_withheld_reason: None,
        claude_account_display: None,
        source_session_id: session_id.to_string(),
        snapshot_fingerprint: format!("fp-{session_id}"),
        status: "active".to_string(),
        input_tokens: 100,
        output_tokens: 20,
        cache_read_tokens: 80,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        unattributed_total_tokens: 0,
        request_count: 1,
        usage_accounting_contract: None,
        removed_request_count: None,
        removed_usage: None,
        telemetry_owned_complete: None,
        resolver_conflict_count: None,
        copy_unproven_counts: None,
        claude_money: None,
        session_account_evidence: None,
        claude_usage_request_ids: std::collections::BTreeSet::new(),
        claude_usage_occurrences: std::collections::BTreeMap::new(),
        request_contributions: Box::new([]),
        cache_observations: None,
        cache_observations_state: None,
        cache_base_head_etag: None,
        cache_conflict_answer: None,
        cache_requests: Vec::new(),
        cache_requests_complete: true,
        avg_duration_ms: None,
        avg_time_to_first_token_ms: None,
        max_duration_ms: None,
        max_time_to_first_token_ms: None,
        peak_context_fill_tokens: Some(100),
        last_turn_context_tokens: None,
        first_turn_context_window_tokens: None,
        peak_context_fill_window_tokens: None,
        last_turn_context_window_tokens: None,
        first_turn_context_tokens: Some(90),
        compaction_count: Some(1),
        compaction_timestamps: vec!["2026-07-19T09:59:00Z".to_string()],
        compaction_events: Vec::new(),
        first_own_request_at: None,
        local_context_points: Vec::new(),
        compaction_total_pre_tokens: None,
        compaction_total_post_tokens: None,
        compaction_total_cumulative_dropped_tokens: None,
        compaction_total_duration_ms: None,
        context_curve: None,
        claude_context_curve_boundaries: Vec::new(),
        claude_context_curve_identity_complete: false,
        claude_context_curve_request_index_complete: false,
        claude_context_curve_owned_start_proven: false,
        claude_file_birth: Default::default(),
        claude_file_birth_verdict: None,
        activity_summary: None,
        tool_usage: None,
        tool_usage_truncated: false,
        session_start: None,
        model_usage: vec![model_usage.clone()],
        usage_buckets: vec![crate::snapshots::SnapshotUsageBucket {
            bucket_start: "2026-07-19T10:00:00Z".to_string(),
            model_usage: vec![model_usage],
            first_activity_at: Some(last_activity.to_string()),
            last_activity_at: Some(last_activity.to_string()),
        }],
        cost: None,
        session_display_name: Some("Test active session".to_string()),
        session_display_name_source: Some("test".to_string()),
        source_started_at: Some("2026-07-19T09:50:00Z".to_string()),
        source_ended_at: None,
        source_last_activity_at: Some(last_activity.to_string()),
        collected_at: "2026-07-19T10:05:00Z".to_string(),
        workspace_hash: Some("workspace".to_string()),
        workspace_display_label: Some("workspace".to_string()),
        workspace_label_source: Some("test".to_string()),
        repository_hash: Some("repository".to_string()),
        repository_label: Some("repository".to_string()),
        repository_label_source: Some("test".to_string()),
        repository_identity_source: Some("test".to_string()),
        workspace_kind: Some("repository_root".to_string()),
        source_file_fingerprint: Some("source-fp".to_string()),
        session_artifacts: Vec::new(),
        provenance: crate::snapshots::SnapshotProvenance {
            collector: "test".to_string(),
            source_file_count: 1,
            input_token_scope: Some("inclusive_cached".to_string()),
            state_total_tokens: None,
            state_archived: None,
        },
        origin: None,
        originator: None,
        attribution_facts: Vec::new(),
    }
}
