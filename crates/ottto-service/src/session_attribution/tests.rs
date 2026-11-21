//! Tests for session attribution: origin classification, labels and the
//! wire fixture.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

const SESSION_ATTRIBUTION_SCHEMA_VERSION: &str = "session_attribution.v1";

fn origin() -> SnapshotOrigin {
    SnapshotOrigin::default()
}

#[test]
fn codex_provider_automation_is_direct_scheduled_origin() {
    let mut origin = origin();
    origin.thread_source = Some("automation".to_string());
    origin.originator = Some("Codex Desktop".to_string());
    let facts = direct_provider_facts(
        SnapshotSource::Codex,
        Some(&origin),
        "session-1",
        "2026-07-19T00:00:00Z",
        "codex_jsonl:v21",
    );
    assert!(facts.iter().any(|fact| {
        fact.field == "origin_kind"
            && fact.value == "provider_scheduled_task"
            && fact.evidence.strength == "direct"
    }));
    assert!(facts
        .iter()
        .any(|fact| fact.field == "scheduler_kind" && fact.value == "codex_scheduled"));
    assert!(facts
        .iter()
        .any(|fact| fact.field == "provider_surface" && fact.value == "codex_desktop"));
}

#[test]
fn desktop_originator_outranks_an_exec_source() {
    // Real shape: ChatGPT Work desktop rollouts write `source: "exec"` while
    // naming a desktop client in `originator`. The signals disagree, the
    // client wins, and the session stays unlabelled rather than being
    // called headless on the weaker signal.
    for surface in ["codex_work_desktop", "Codex Desktop", "codex_desktop"] {
        let mut origin = origin();
        origin.originator = Some(surface.to_string());
        origin.source = Some("exec".to_string());

        assert_eq!(
            execution_mode(SnapshotSource::Codex, &origin),
            None,
            "{surface} must not be reported as headless"
        );

        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-work-desktop",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(
            !facts.iter().any(|fact| fact.field == "execution_mode"),
            "{surface} must not emit an execution mode"
        );
        assert!(facts
            .iter()
            .any(|fact| fact.field == "provider_surface" && fact.value == "codex_desktop"));
    }
}

#[test]
fn direct_fact_payload_is_bounded_and_content_free() {
    let mut origin = origin();
    origin.thread_source = Some("automation".to_string());
    origin.originator = Some("Codex Desktop".to_string());
    origin.parent_session_ref = Some("019f-parent".to_string());
    let facts = direct_provider_facts(
        SnapshotSource::Codex,
        Some(&origin),
        "session-5",
        "2026-07-19T00:00:00Z",
        "codex_jsonl:v21",
    );
    let payload = serde_json::to_vec(&facts).expect("serialize facts");
    assert!(payload.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
    let text = String::from_utf8(payload).expect("json");
    for forbidden in [
        "prompt_text",
        "transcript_text",
        "filesystem_path",
        "working_directory",
        "remote_url",
        "process_argv",
        "process_environment",
        "scheduler_definition",
        "raw_log",
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn hint_context_fails_closed_for_unknown_or_invalid_keys() {
    let home = Path::new("/nonexistent");
    assert!(SessionAttributionContext::from_activity_hint(
        SnapshotSource::Codex,
        home,
        false,
        None,
        None,
    )
    .is_none());
    assert!(SessionAttributionContext::from_activity_hint(
        SnapshotSource::Codex,
        home,
        true,
        Some("not-base64"),
        Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .is_none());
    let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    assert!(SessionAttributionContext::from_activity_hint(
        SnapshotSource::Codex,
        home,
        true,
        Some(&encoded),
        Some("hmac-sha256:v2"),
    )
    .is_none());
}

#[test]
fn checkpoint_namespace_changes_only_with_key_epoch() {
    let context = SessionAttributionContext {
        key: Zeroizing::new(vec![1_u8; 32]),
        provider_schedules: ProviderScheduleInventory::default(),
        external_schedulers:
            crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        launch_events: crate::launch_events::LaunchEventInventory::default(),
    };
    let rotated = SessionAttributionContext {
        key: Zeroizing::new(vec![2_u8; 32]),
        provider_schedules: ProviderScheduleInventory::default(),
        external_schedulers:
            crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        launch_events: crate::launch_events::LaunchEventInventory::default(),
    };
    let changed_inventory = SessionAttributionContext {
        key: Zeroizing::new(vec![1_u8; 32]),
        provider_schedules: ProviderScheduleInventory {
            definitions: vec![ProviderScheduleDefinition {
                opaque_id: "hmac-sha256:v1:opaque".to_string(),
                prompt_signature: "private schedule prompt material".to_string(),
            }],
        },
        external_schedulers:
            crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        launch_events: crate::launch_events::LaunchEventInventory::default(),
    };

    let namespace = context.checkpoint_namespace();
    assert_eq!(namespace.len(), 16);
    assert_ne!(namespace, rotated.checkpoint_namespace());
    assert_eq!(namespace, changed_inventory.checkpoint_namespace());
}

fn launch_context(events: Vec<crate::launch_events::LaunchEvent>) -> SessionAttributionContext {
    SessionAttributionContext {
        key: Zeroizing::new(vec![7_u8; 32]),
        provider_schedules: ProviderScheduleInventory::default(),
        external_schedulers:
            crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        launch_events: crate::launch_events::LaunchEventInventory::from_events(events),
    }
}

fn launch_event() -> crate::launch_events::LaunchEvent {
    crate::launch_events::LaunchEvent {
        controller_session_ref: "a9789dcf-1e4a-4a6e-8abd-f30094efb269".to_string(),
        worker_session_ref: "019f6822-403f-7652-a308-b0c12142e337".to_string(),
        workflow_ref: Some("402d846d-c13c-4743-8326-580e4ca70e30".to_string()),
        agent_kind: "pr-fixer",
    }
}

#[test]
fn claude_desktop_spawn_facts_state_the_starting_session_as_provider_artifact() {
    let facts = claude_desktop_spawn_facts(
        "94bd328b-f2a9-4c31-bbfe-e174d41b4310",
        "da1dc804-1c50-4401-8c3c-0898b126772f",
        "2026-10-18T10:20:00Z",
    );

    // A launched top-level session: no Task/Workflow family root or depth.
    assert_eq!(
        facts
            .iter()
            .map(|fact| (fact.field.as_str(), fact.value.as_str()))
            .collect::<Vec<_>>(),
        [
            ("parent_session_ref", "94bd328b-f2a9-4c31-bbfe-e174d41b4310"),
            ("origin_kind", "agent_spawn"),
            ("agent_kind", "claude_desktop_session"),
        ]
    );
    for fact in &facts {
        assert_eq!(fact.evidence.kind, "provider_artifact");
        assert_eq!(fact.evidence.strength, "direct");
        assert_eq!(fact.evidence.source_version, "claude_desktop_spawn:v1");
    }
    validate_fact_limits(&facts).expect("facts fit the wire contract");
}

#[test]
fn claude_desktop_spawn_facts_refuse_a_non_uuid_starting_session() {
    for parent in [
        "/Users/example/project",
        "~/project/94bd328b-f2a9-4c31-bbfe-e174d41b4310",
        "94BD328B-F2A9-4C31-BBFE-E174D41B4310",
        " 94bd328b-f2a9-4c31-bbfe-e174d41b4310",
        "94bd328b-f2a9-4c31-bbfe-e174d41b4310_agent-a1b2c3d4e5f6a7b8c",
        "local_parent",
        "",
    ] {
        assert!(
            claude_desktop_spawn_facts(
                parent,
                "da1dc804-1c50-4401-8c3c-0898b126772f",
                "2026-10-18T10:20:00Z",
            )
            .is_empty(),
            "{parent:?}"
        );
    }
}

#[test]
fn launch_event_facts_state_the_controller_edge_as_direct_evidence() {
    let event = launch_event();
    let context = launch_context(vec![event.clone()]);

    let facts = context.launch_event_facts(&event.worker_session_ref, "2026-08-09T15:20:00Z");

    let by_field: BTreeMap<&str, &SessionAttributionFact> = facts
        .iter()
        .map(|fact| (fact.field.as_str(), fact))
        .collect();
    assert_eq!(
        by_field["parent_session_ref"].value,
        event.controller_session_ref
    );
    assert_eq!(
        by_field["workflow_ref"].value,
        event.workflow_ref.expect("repair event workflow")
    );
    assert_eq!(by_field["origin_kind"].value, "agent_spawn");
    assert_eq!(by_field["agent_kind"].value, "pr-fixer");
    // Ordering is load-bearing: `enforce_fact_limits` trims from the tail,
    // so the edge itself must never be the first thing dropped.
    assert_eq!(facts[0].field, "parent_session_ref");
    for fact in &facts {
        assert_eq!(fact.evidence.strength, "direct");
        assert_eq!(fact.evidence.kind, "launcher_event");
        // The backend hard-rejects a source_version outside this shape, and
        // a raise there 422s the whole batch rather than one fact.
        assert_eq!(fact.evidence.source_version, "launcher_event:v1");
        assert!(fact.evidence.evidence_ref.starts_with("sha256:"));
        assert!(fact.display_label.is_none());
        assert!(fact.display_label_source.is_none());
    }
    validate_fact_limits(&facts).expect("launch facts fit the wire contract");
}

#[test]
fn grouping_facts_keep_opaque_ids_and_bounded_private_labels_separate() {
    let key = Zeroizing::new(vec![9_u8; 32]);
    let scheduled_prompt =
        "Inspect the landing queue, verify every required check, and report only safe results.";
    let normalized_schedule =
        normalize_template_material(scheduled_prompt).expect("normalized schedule");
    let schedule_id =
        opaque_hmac_id(&key, "schedule_definition", "schedule-1").expect("schedule id");
    let context = SessionAttributionContext {
        key,
        provider_schedules: ProviderScheduleInventory {
            definitions: vec![ProviderScheduleDefinition {
                opaque_id: schedule_id.clone(),
                prompt_signature: normalized_schedule
                    .chars()
                    .take(MAX_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS)
                    .collect(),
            }],
        },
        external_schedulers:
            crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        launch_events: crate::launch_events::LaunchEventInventory::default(),
    };
    let origin = SnapshotOrigin {
        thread_source: Some("automation".to_string()),
        ..SnapshotOrigin::default()
    };
    let mut skills = BTreeSet::new();
    skills.insert("landing-lander".to_string());
    let first_prompt =
        format!("An automation named Landing has fired. Its prompt is: {scheduled_prompt}");

    let facts = context.grouping_facts(SessionAttributionGroupingInput {
        source: SnapshotSource::Codex,
        origin: Some(&origin),
        source_session_id: "session-opaque",
        observed_at: "2026-07-19T00:00:00Z",
        source_version: "codex_jsonl:v21",
        first_prompt: Some(&first_prompt),
        provider_skills: &skills,
        activity_skills: &BTreeSet::new(),
        repository_hash: None,
        source_started_at: None,
        transcript_path: Path::new("/missing"),
    });

    assert!(facts.iter().any(|fact| fact.field == "template_group_id"));
    assert!(facts.iter().any(|fact| {
        fact.field == "schedule_definition_id"
            && fact.value == schedule_id
            && fact.evidence.strength == "corroborated"
    }));
    assert!(facts.iter().any(|fact| {
        fact.field == "template_group_id"
            && fact.display_label.as_deref() == Some(scheduled_prompt)
            && fact.display_label_source.as_deref() == Some("prompt_prefix")
    }));
    assert!(facts.iter().any(|fact| {
        fact.field == "skill_id"
            && fact.display_label.as_deref() == Some("landing-lander")
            && fact.display_label_source.as_deref() == Some("skill_name")
    }));
    assert!(facts.iter().all(|fact| {
        fact.value.starts_with("hmac-sha256:v1:")
            || !matches!(
                fact.field.as_str(),
                "template_group_id" | "schedule_definition_id" | "skill_id"
            )
    }));
    let wire = serde_json::to_string(&facts).expect("facts");
    assert!(wire.contains("landing-lander"));
    assert!(wire.contains("Inspect the landing queue"));
    assert!(wire.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
}

#[test]
fn prompt_prefix_label_is_bounded_single_line_and_redacts_paths() {
    let label = prompt_prefix_display_label(
        "An automation named Review has fired. Its prompt is:\nInspect /Users/alice/secret/repo, C:\\work\\private, and src/internal/config.rs then report a concise result that keeps going beyond the display limit until it is truncated.",
    )
    .expect("display label");

    assert!(label.starts_with("Inspect [path] [path] and [path]"));
    assert!(!label.contains("alice"));
    assert!(!label.contains("private"));
    assert!(!label.contains('\n'));
    assert!(label.len() <= MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES);
}

/// Mirror of the backend's display-label path check: a plain,
/// case-insensitive substring match over the whole label.
fn backend_rejects_label(label: &str) -> bool {
    let lowered = label.to_ascii_lowercase();
    ["/users/", "\\users\\", "/home/", "\\home\\"]
        .iter()
        .chain(ATTRIBUTION_FORBIDDEN_FRAGMENTS.iter())
        .any(|fragment| lowered.contains(fragment))
}

#[test]
fn prompt_prefix_label_redacts_slashless_tokens_the_backend_treats_as_paths() {
    // Real Codex exec first prompt shape (2026-09-27): a dotted identifier
    // containing `.claude` has no slash, yet the backend's substring check
    // rejected the whole snapshot batch with HTTP 422.
    let label = prompt_prefix_display_label(
        "Fix `subscriptions.claude_account_coverage` then read .codex config and the workspace_path and transcript_path fields",
    )
    .expect("display label");

    assert_eq!(
        label,
        "Fix [path] then read [path] config and the [path] and [path] fields"
    );
    assert!(!backend_rejects_label(&label));
}

#[test]
fn codex_schedule_inventory_reads_only_bounded_definition_fields() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "ottto-session-attribution-{}-{unique}",
        std::process::id()
    ));
    let schedule_dir = home.join(".codex/automations/schedule-1");
    fs::create_dir_all(&schedule_dir).expect("schedule dir");
    fs::write(
        schedule_dir.join("automation.toml"),
        r#"
id = "schedule-1"
name = "Private local name"
prompt = "Inspect the landing queue, verify required checks, and report safe results."
rrule = "FREQ=HOURLY"
status = "ACTIVE"
"#,
    )
    .expect("schedule");

    let inventory = load_codex_schedule_inventory(&home, &[3_u8; 32]);

    assert_eq!(inventory.definitions.len(), 1);
    assert!(inventory.definitions[0]
        .opaque_id
        .starts_with("hmac-sha256:v1:"));
    assert!(!inventory.definitions[0].opaque_id.contains("schedule-1"));
    fs::remove_dir_all(home).expect("cleanup");
}

fn budget_fact(field: &str) -> SessionAttributionFact {
    SessionAttributionFact {
        field: field.to_string(),
        value: "b".repeat(32),
        display_label: None,
        display_label_source: None,
        evidence: SessionFieldEvidence {
            kind: "provider_native".to_string(),
            strength: "direct".to_string(),
            observed_at: "2026-07-26T07:20:49Z".to_string(),
            source_version: "claude_code_jsonl:v19".to_string(),
            evidence_ref: format!("sha256:{}", "a".repeat(64)),
        },
    }
}

/// A fact whose value sits exactly on the per-value ceiling.
///
/// At 8 KiB an ordinary `budget_fact` can no longer reach the byte budget
/// before the 24-fact count cap does — that ordering is the point of the
/// raise. Probing the byte budget therefore needs the widest fact the
/// contract still accepts, which is the only shape that can still exhaust
/// the payload budget inside the count cap.
fn wide_budget_fact(field: &str) -> SessionAttributionFact {
    SessionAttributionFact {
        value: "w".repeat(MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES),
        ..budget_fact(field)
    }
}

fn fits_wire_budget(facts: &[SessionAttributionFact]) -> bool {
    serde_json::to_vec(facts).expect("serialize").len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES
}

#[test]
fn enforce_fact_limits_drops_trailing_grouping_facts_over_the_byte_budget() {
    // When the byte budget does bind, facts are dropped from the tail, so a
    // skill-heavy session loses the grouping evidence appended after its
    // direct provider facts. At 8 KiB only values at the per-value ceiling
    // can reach the byte budget inside the 24-fact cap, so the list is built
    // from `wide_budget_fact`. It grows to the first over-budget length
    // rather than a hardcoded count so the test keeps testing the byte
    // budget when it next moves.
    let mut facts = vec![
        wide_budget_fact("origin_kind"),
        wide_budget_fact("provider_surface"),
        wide_budget_fact("execution_mode"),
        wide_budget_fact("template_group_id"),
    ];
    while fits_wire_budget(&facts) && facts.len() < MAX_SESSION_ATTRIBUTION_FACTS {
        facts.push(wide_budget_fact("skill_id"));
    }
    let skills_before = facts.iter().filter(|fact| fact.field == "skill_id").count();
    let before = facts.len();
    assert!(
        before < MAX_SESSION_ATTRIBUTION_FACTS,
        "the byte budget must bind before the {MAX_SESSION_ATTRIBUTION_FACTS}-fact cap"
    );
    assert!(!fits_wire_budget(&facts));

    enforce_fact_limits(&mut facts);

    assert!(facts.len() < before);
    assert!(fits_wire_budget(&facts));
    // Truncation is tail-first, so the leading direct provider facts survive
    // intact while the trailing skill evidence is what actually gets lost.
    assert_eq!(facts[0].field, "origin_kind");
    assert_eq!(facts[1].field, "provider_surface");
    assert_eq!(facts[2].field, "execution_mode");
    assert_eq!(facts[3].field, "template_group_id");
    let surviving_skills = facts.iter().filter(|fact| fact.field == "skill_id").count();
    assert!(
        surviving_skills < skills_before,
        "expected skill evidence to be dropped"
    );
}

/// The near-limit attribution case of the two-language fixture corpus.
///
/// This is the exact shape that produced the 422 at the old 2 KiB budget, so
/// it is the one case both implementations must agree on byte-for-byte: the
/// daemon must emit it and the backend must accept it. The facts are carried
/// verbatim (synthetic values only) so the other language can replay the
/// payload instead of reconstructing a guess at it.
#[test]
fn attribution_budget_corpus_pins_the_near_limit_payload() {
    const RETIRED_PAYLOAD_BUDGET_BYTES: usize = 2_048;
    const PREVIOUS_PAYLOAD_BUDGET_BYTES: usize = 4_096;
    fn case(facts: &[SessionAttributionFact]) -> serde_json::Value {
        let payload = serde_json::to_vec(facts).expect("serialize");
        let mut digest = Sha256::new();
        digest.update(&payload);
        serde_json::json!({
            "fact_count": facts.len(),
            "payload_bytes": payload.len(),
            "payload_sha256": format!("{:x}", digest.finalize()),
            "accepted_by_retired_budget":
                payload.len() <= RETIRED_PAYLOAD_BUDGET_BYTES,
            "accepted_by_previous_budget":
                payload.len() <= PREVIOUS_PAYLOAD_BUDGET_BYTES,
            "accepted_by_current_budget":
                payload.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
            "facts": facts,
        })
    }

    let mut facts = vec![
        budget_fact("origin_kind"),
        budget_fact("provider_surface"),
        budget_fact("execution_mode"),
        budget_fact("template_group_id"),
    ];
    // First list that the retired 2 KiB budget refused: the original
    // regression, and still accepted today.
    while serde_json::to_vec(&facts).expect("serialize").len() <= RETIRED_PAYLOAD_BUDGET_BYTES {
        facts.push(budget_fact("skill_id"));
    }
    let over_retired = facts.clone();
    // First list the superseded 4 KiB budget refused: the band this raise
    // newly admits, and the one the deployed backend already accepts.
    while serde_json::to_vec(&facts).expect("serialize").len() <= PREVIOUS_PAYLOAD_BUDGET_BYTES {
        facts.push(budget_fact("skill_id"));
    }
    let over_previous = facts.clone();
    // Largest list the current budget still accepts: the acceptance
    // boundary. One more fact must 422, and that is the whole value of the
    // case — a budget nobody probes at its edge is a budget nobody agrees
    // on. Ordinary facts can no longer reach that edge inside the 24-fact
    // cap, so the boundary cases carry values at the per-value ceiling.
    let mut near_limit = vec![
        wide_budget_fact("origin_kind"),
        wide_budget_fact("provider_surface"),
        wide_budget_fact("execution_mode"),
        wide_budget_fact("template_group_id"),
    ];
    loop {
        let mut candidate = near_limit.clone();
        candidate.push(wide_budget_fact("skill_id"));
        if serde_json::to_vec(&candidate).expect("serialize").len()
            > MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES
        {
            break;
        }
        near_limit = candidate;
    }
    let mut over_current = near_limit.clone();
    over_current.push(wide_budget_fact("skill_id"));

    let actual = serde_json::json!({
        "schema_version": "attribution_budget_golden:v2",
        "attribution_schema_version": SESSION_ATTRIBUTION_SCHEMA_VERSION,
        "max_payload_bytes": MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
        "previous_max_payload_bytes": PREVIOUS_PAYLOAD_BUDGET_BYTES,
        "retired_max_payload_bytes": RETIRED_PAYLOAD_BUDGET_BYTES,
        "max_facts": MAX_SESSION_ATTRIBUTION_FACTS,
        "max_fact_value_bytes": MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES,
        "over_retired_budget_case": case(&over_retired),
        "over_previous_budget_case": case(&over_previous),
        "near_limit_case": case(&near_limit),
        "over_current_budget_case": case(&over_current),
    });
    if std::env::var_os("UPDATE_ATTRIBUTION_BUDGET_GOLDEN").is_some() {
        fs::write(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/snapshot-audit/attribution-budget-golden.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&actual).expect("serialize golden")
            ),
        )
        .expect("write attribution budget golden");
    }
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/snapshot-audit/attribution-budget-golden.json"
    ))
    .expect("parse attribution budget golden");
    assert_eq!(actual, expected);
    assert!(over_previous.len() > over_retired.len());
    assert!(near_limit.len() <= MAX_SESSION_ATTRIBUTION_FACTS);
    validate_fact_limits(&over_retired).expect("over-retired payload is valid now");
    validate_fact_limits(&over_previous).expect("over-previous payload is valid now");
    validate_fact_limits(&near_limit).expect("near-limit payload is valid");
    // The refusal must come from the byte budget, not the count cap, or the
    // corpus would stop describing the budget it claims to pin.
    assert!(
        over_current.len() <= MAX_SESSION_ATTRIBUTION_FACTS,
        "the over-budget case must stay inside the fact-count cap"
    );
    let refusal =
        validate_fact_limits(&over_current).expect_err("one fact past the budget must fail");
    assert!(
        refusal.contains(&MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES.to_string()),
        "expected a byte-budget refusal, got: {refusal}"
    );
}
