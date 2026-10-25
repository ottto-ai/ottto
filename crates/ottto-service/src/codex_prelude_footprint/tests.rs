use super::*;
use crate::test_scratch::ScratchDir;
use serde_json::json;

fn rollout(records: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        out.extend_from_slice(serde_json::to_string(record).unwrap().as_bytes());
        out.push(b'\n');
    }
    out
}

fn parse(records: &[Value]) -> CodexPrelude {
    parse_prelude(std::io::Cursor::new(rollout(records))).unwrap()
}

fn meta(extra: Value) -> Value {
    let mut payload = json!({
        "id": "s1",
        "cwd": "/repo",
        "context_window": 258400,
        "base_instructions": {"text": "BASE-INSTRUCTIONS"},
    });
    for (key, value) in extra.as_object().unwrap() {
        payload[key] = value.clone();
    }
    json!({"type": "session_meta", "payload": payload})
}

fn message(role: &str, kind: Option<&str>, text: &str) -> Value {
    let mut payload = json!({
        "type": "message",
        "role": role,
        "content": [{"type": "input_text", "text": text}],
    });
    if let Some(kind) = kind {
        payload["internal_chat_message_metadata_passthrough"] =
            json!({"content_item_kinds": [kind]});
    }
    json!({"type": "response_item", "payload": payload})
}

fn usage(input: u64) -> Value {
    json!({"type": "token_usage_record", "payload": {"usage": {"input_tokens": input}}})
}

const SKILLS_BODY: &str = "## Skills\nA skill is...\n### Skill roots\n- `r0` = `/home/u/.codex/skills/.system`\n- `r1` = `/repo/.agents/skills`\n- `r2` = `/home/u/.codex/plugins/cache/x/skills`\n### Available skills\n- imagegen: Make images. (file: r0/imagegen/SKILL.md)\n- deploy: Ship it. (file: r1/deploy/SKILL.md)\n- sheets: Spreadsheets. (file: r2/sheets/SKILL.md)\n";

#[test]
fn prelude_reads_world_state_and_stops_at_first_request() {
    let prelude = parse(&[
        meta(json!({})),
        json!({"type": "turn_context", "payload": {"model": "gpt-6.1-sol"}}),
        json!({"type": "world_state", "payload": {"full": true, "state": {
            "agents_md": {"directory": "/repo", "text": "GLOBAL"},
            "host_skills": {"body": SKILLS_BODY},
        }}}),
        message("developer", Some("permissions.instructions"), "PERMS"),
        message(
            "developer",
            Some("host_skills.instructions"),
            "<skills_instructions>\nX\n</skills_instructions>",
        ),
        message("developer", Some("hooks.additional_context"), "HOOK"),
        message(
            "user",
            Some("agents_md.instructions"),
            "# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nGLOBAL\n</INSTRUCTIONS>",
        ),
        message(
            "user",
            Some("environments.environment_context"),
            "<environment_context>E</environment_context>",
        ),
        message(
            "user",
            Some("user.text"),
            "typed prompt that is never counted",
        ),
        usage(25_000),
        // After the first request: never read.
        json!({"type": "world_state", "payload": {"state": {"agents_md": {"text": "LATER"}}}}),
    ]);
    assert!(prelude.complete);
    assert!(prelude.is_owned_fresh_start());
    assert_eq!(prelude.cwd.as_deref(), Some("/repo"));
    assert_eq!(prelude.model.as_deref(), Some("gpt-6.1-sol"));
    assert_eq!(prelude.context_window, Some(258_400));
    assert_eq!(prelude.first_input_tokens, Some(25_000));
    assert_eq!(
        prelude.base_instructions_chars,
        "BASE-INSTRUCTIONS".len() as u64
    );
    assert_eq!(prelude.hook_chars, 4);
    let environment = "<environment_context>E</environment_context>".len() as u64;
    assert_eq!(prelude.other_harness_chars, 5 + environment);
    let agents = prelude.agents_md.unwrap();
    assert_eq!(agents.text, "GLOBAL");
    assert_eq!(agents.directory.as_deref(), Some("/repo"));
    assert_eq!(prelude.skills_body.as_deref(), Some(SKILLS_BODY));
}

#[test]
fn rows_fed_one_by_one_match_the_reader_and_need_world_state() {
    let records = [
        meta(json!({})),
        // Without world_state (cli < 0.159) nothing is taken from messages.
        message(
            "user",
            Some("agents_md.instructions"),
            "# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nRULES\n</INSTRUCTIONS>",
        ),
        message("user", None, "unlabeled text is not counted"),
        usage(100),
        json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
            "last_token_usage": {"input_tokens": 100}, "model_context_window": 1000}}}),
        json!({"type": "event_msg", "payload": {"type": "never_read"}}),
    ];
    let mut parser = CodexPreludeParser::default();
    let fed = records
        .iter()
        .take_while(|row| parser.observe(row) == PreludeStep::More);
    assert_eq!(fed.count(), 3);
    let prelude = parser.finish();
    assert_eq!(prelude, parse(&records));
    assert!(prelude.complete);
    assert_eq!(prelude.agents_md, None);
    assert_eq!(prelude.other_harness_chars, 0);
}

#[test]
fn incomplete_prelude_is_not_final() {
    let prelude = parse(&[meta(json!({})), message("user", Some("user.text"), "hi")]);
    assert!(!prelude.complete);
    assert!(!prelude.is_owned_fresh_start());
}

#[test]
fn forks_and_copied_parents_are_not_fresh_starts() {
    for extra in [
        json!({"forked_from_id": "parent"}),
        json!({"history_base": {"thread_id": "parent", "end_ordinal_exclusive": 4}}),
        json!({"subagent_history_start_ordinal": 3}),
        json!({"thread_source": "agent_created_thread"}),
    ] {
        let prelude = parse(&[meta(extra.clone()), usage(1)]);
        assert!(prelude.is_fork, "{extra}");
        assert!(!prelude.is_owned_fresh_start());
    }
    let copied = parse(&[
        meta(json!({})),
        json!({"type": "session_meta", "payload": {"id": "parent"}}),
        usage(1),
    ]);
    assert!(copied.is_fork);
    let plain = parse(&[meta(json!({"forked_from_id": null})), usage(1)]);
    assert!(!plain.is_fork);
}

#[test]
fn token_count_event_also_closes_the_prelude() {
    let prelude = parse(&[
        meta(json!({"context_window": null})),
        json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
            "last_token_usage": {"input_tokens": 777}, "model_context_window": 400000}}}),
    ]);
    assert!(prelude.complete);
    assert_eq!(prelude.first_input_tokens, Some(777));
    assert_eq!(prelude.context_window, Some(400_000));
}

#[test]
fn zero_context_estimates_do_not_end_the_prelude() {
    let estimate = |kind: &str| match kind {
        "record" => usage(0),
        _ => json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
            "last_token_usage": {"input_tokens": 0}, "total_token_usage": {"input_tokens": 0}}}}),
    };
    for kind in ["record", "event"] {
        let prelude = parse(&[
            meta(json!({})),
            estimate(kind),
            message("user", Some(AGENTS_MD_KIND), "RULES"),
            usage(5),
        ]);
        assert_eq!(prelude.first_input_tokens, Some(5), "{kind}");
        assert_eq!(prelude.chars(BlockKind::AgentsMd), 5, "{kind}");
    }
}

#[test]
fn model_output_closes_request_one_blocks() {
    let prelude = parse(&[
        meta(json!({})),
        message("developer", Some("permissions.instructions"), "PERMS"),
        message("user", Some("user.text"), "go"),
        json!({"type": "response_item", "payload": {"type": "reasoning"}}),
        // Injected after the model answered: request 2's input.
        message("developer", Some("hooks.additional_context"), "LATE"),
        usage(10),
    ]);
    assert!(prelude.input_closed && !prelude.blocks_incomplete);
    assert_eq!(prelude.chars(BlockKind::Environment), 5);
    assert_eq!(prelude.chars(BlockKind::Prompt), 2);
    assert_eq!(prelude.chars(BlockKind::Hooks), 0);
    // The footprint's totals keep their window: up to the first usage record.
    assert_eq!((prelude.hook_chars, prelude.other_harness_chars), (4, 5));
}

#[test]
fn unlabeled_or_image_blocks_mark_request_one_incomplete() {
    let mut malformed = message("user", None, "x");
    malformed["payload"]["internal_chat_message_metadata_passthrough"] =
        json!({"content_item_kinds": [7]});
    let image = json!({"type": "response_item", "payload": {"type": "message", "role": "user",
        "content": [{"type": "input_image", "image_url": "data:"}],
        "internal_chat_message_metadata_passthrough": {"content_item_kinds": ["user.image"]}}});
    for row in [message("user", None, "unlabeled"), malformed, image] {
        let prelude = parse(&[meta(json!({})), row, usage(1)]);
        assert!(prelude.blocks_incomplete);
        assert_eq!(prelude.block_chars, [0; BLOCK_KINDS]);
    }
}

#[test]
fn matching_only_caps_agents_md_and_skips_skills() {
    let mut parser = CodexPreludeParser::matching_only(4);
    parser.observe(&json!({"type": "world_state", "payload": {"state": {
        "agents_md": {"text": "abc\u{e9}def"}, "host_skills": {"body": SKILLS_BODY}}}}));
    let prelude = parser.prelude();
    assert_eq!(prelude.agents_md.as_ref().unwrap().text, "abc");
    assert!(prelude.agents_md_capped);
    assert_eq!(prelude.skills_body, None);
    parser.release_text();
    assert_eq!(parser.prelude().agents_md, None);
}

fn chain(files: &[(&str, &str, u64)]) -> Vec<ChainFile> {
    files
        .iter()
        .map(|(relative_path, name, size)| ChainFile {
            relative_path: relative_path.to_string(),
            name: name.to_string(),
            size: *size,
        })
        .collect()
}

fn items(
    text: &str,
    chain: &[ChainFile],
    user: Option<(&str, u64)>,
    limit: u64,
) -> Vec<ContextFootprintItemInput> {
    instruction_items(&InstructionInputs {
        text,
        chain,
        user_file: user,
        limit,
        salt: None,
    })
}

#[test]
fn user_and_project_chain_split_into_files() {
    let root = "root rules\n";
    let nested = "nested\nrules";
    let text = format!("global{PROJECT_DOC_SEPARATOR}{root}\n\n{nested}");
    let files = chain(&[
        ("AGENTS.md", "AGENTS.md", root.len() as u64),
        ("backend/AGENTS.md", "AGENTS.md", nested.len() as u64),
    ]);
    let out = items(&text, &files, Some(("AGENTS.md", 7)), 32_768);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].source.as_deref(), Some("User"));
    // Codex trims the user file: disk bytes, but no whole-file line count.
    assert_eq!(out[0].file_counts.file_bytes, Some(7));
    assert_eq!(out[0].file_counts.file_lines, None);
    assert_eq!(out[0].tokens, 6);
    assert_eq!(out[1].relative_path.as_deref(), Some("AGENTS.md"));
    assert_eq!(out[1].file_counts.file_bytes, Some(root.len() as u64));
    assert_eq!(out[1].file_counts.file_lines, Some(1));
    assert_eq!(out[2].relative_path.as_deref(), Some("backend/AGENTS.md"));
    assert_eq!(out[2].file_counts.file_lines, Some(2));
    assert_eq!(out[2].file_counts.file_chars, Some(12));
    assert_eq!(out[2].tokens, 12);
    assert!(out.iter().all(|item| item.kind == "memory_file"));
    assert!(out
        .iter()
        .all(|item| item.file_counts.truncated_by_limit == Some(false)));
}

#[test]
fn chain_over_limit_marks_the_cut_file() {
    let root = "a".repeat(30);
    let nested_loaded = "b".repeat(10);
    let text = format!("{root}\n\n{nested_loaded}");
    let files = chain(&[
        ("AGENTS.md", "AGENTS.md", 30),
        ("sub/AGENTS.md", "AGENTS.md", 25),
    ]);
    let out = items(&text, &files, None, 40);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].file_counts.truncated_by_limit, Some(false));
    assert_eq!(out[1].file_counts.file_bytes, Some(25));
    assert_eq!(out[1].file_counts.file_lines, None);
    assert_eq!(out[1].tokens, 10);
    assert_eq!(out[1].file_counts.truncated_by_limit, Some(true));
    // The same rule answers the per-session flag from the loaded text alone.
    assert!(agents_md_cut(&text, 40));
    assert!(!agents_md_cut(&text, 64));
    assert!(!agents_md_cut(
        &format!("{}{PROJECT_DOC_SEPARATOR}p", "u".repeat(99)),
        40
    ));
}

#[test]
fn over_cap_disk_size_is_omitted_but_the_cut_is_kept() {
    // A 2 MiB AGENTS.md whose loaded prefix fits the budget: admission
    // bounds file_bytes at 1 MiB, so the payload carries no disk size (BR4).
    let text = "x".repeat(40);
    let files = chain(&[("AGENTS.md", "AGENTS.md", 2 * 1024 * 1024)]);
    let out = items(&text, &files, None, 40);
    let wire = serde_json::to_value(&out[0]).unwrap();
    assert_eq!(
        wire,
        json!({"kind": "memory_file", "name": "AGENTS.md", "tokens": 40, "source": "Project",
            "relative_path": "AGENTS.md", "loading_mode": "always_on", "truncated_by_limit": true})
    );
}

#[test]
fn text_without_separator_is_project_or_user() {
    let files = chain(&[("AGENTS.md", "AGENTS.md", 5)]);
    let project = items("rules", &files, Some(("AGENTS.md", 99)), 32_768);
    assert_eq!(project.len(), 1);
    assert_eq!(project[0].source.as_deref(), Some("Project"));
    // Codex trims the user file; its size is a little larger than the text.
    let user = items("global rules", &[], Some(("AGENTS.md", 13)), 32_768);
    assert_eq!(user[0].source.as_deref(), Some("User"));
    assert_eq!(user[0].relative_path.as_deref(), Some("AGENTS.md"));
}

#[test]
fn changed_files_fall_back_without_guessing_boundaries() {
    let single = chain(&[("AGENTS.md", "AGENTS.md", 99)]);
    let out = items(
        &format!("g{PROJECT_DOC_SEPARATOR}{}", "x".repeat(50)),
        &single,
        None,
        50,
    );
    assert_eq!(out[1].relative_path.as_deref(), Some("AGENTS.md"));
    assert_eq!(out[1].file_counts.truncated_by_limit, Some(true));

    let two = chain(&[
        ("AGENTS.md", "AGENTS.md", 3),
        ("sub/AGENTS.md", "AGENTS.md", 3),
    ]);
    let out = items(
        &format!("g{PROJECT_DOC_SEPARATOR}aaaa\n\nbbbb"),
        &two,
        None,
        32_768,
    );
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].name, COMBINED_CHAIN_NAME);
    assert_eq!(out[1].relative_path, None);
    assert_eq!(out[1].file_counts.file_bytes, None);
    assert_eq!(out[1].tokens, 10);
}

#[test]
fn chain_walks_root_to_directory_override_first() {
    let root = ScratchDir::new("codex-session-start-chain");
    fs::create_dir(root.join(".git")).unwrap();
    fs::write(root.join("AGENTS.md"), "root").unwrap();
    let sub = root.join("backend");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("AGENTS.md"), "plain").unwrap();
    fs::write(sub.join("AGENTS.override.md"), "override!").unwrap();
    let deeper = sub.join("app");
    fs::create_dir(&deeper).unwrap();

    let found_root = project_root(&deeper).unwrap();
    assert_eq!(found_root, root.to_path_buf());
    let files = agents_md_chain(&deeper, Some(&found_root));
    assert_eq!(
        files,
        chain(&[
            ("AGENTS.md", "AGENTS.md", 4),
            ("backend/AGENTS.override.md", "AGENTS.override.md", 9),
        ])
    );
    // Without a project root only the directory itself is searched.
    assert_eq!(agents_md_chain(&sub, None).len(), 1);
}

#[test]
fn project_doc_limit_reads_top_level_key_only() {
    assert_eq!(
        project_doc_max_bytes(
            Path::new("/nonexistent-codex-home"),
            CodexHomeTrust::ProviderDefault
        ),
        DEFAULT_PROJECT_DOC_MAX_BYTES
    );
    assert_eq!(
        configured_project_doc_max_bytes(
            "model = \"x\"\nproject_doc_max_bytes = 65_536 # bigger\n[profiles.a]\nproject_doc_max_bytes = 1\n"
        ),
        Some(65_536)
    );
    assert_eq!(
        configured_project_doc_max_bytes("[profiles.a]\nproject_doc_max_bytes = 1\n"),
        None
    );
}

#[test]
fn skills_listing_becomes_sized_skill_items() {
    let context = SkillRootContext {
        project_root: Some(Path::new("/repo")),
        codex_home: Path::new("/home/u/.codex"),
        home: Path::new("/home/u"),
    };
    let out = skill_items(SKILLS_BODY, &context);
    let summary: Vec<(&str, &str)> = out
        .iter()
        .map(|item| (item.name.as_str(), item.source.as_deref().unwrap()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("imagegen", "System"),
            ("deploy", "Project"),
            ("sheets", "Plugin")
        ]
    );
    let line = "- deploy: Ship it. (file: r1/deploy/SKILL.md)";
    assert_eq!(out[1].tokens, line.len() as u64);
    assert!(out
        .iter()
        .all(|item| item.kind == "skill" && item.relative_path.is_none()));
}

#[test]
fn request_carries_sizes_and_no_text() {
    let workspace = ScratchDir::new("codex-session-start-request");
    fs::create_dir(workspace.join(".git")).unwrap();
    fs::write(workspace.join("AGENTS.md"), "SECRET-RULE-TEXT").unwrap();
    let codex_home = ScratchDir::new("codex-session-start-home");
    let directory = workspace.to_string_lossy().into_owned();
    let prelude = CodexPrelude {
        cwd: Some(directory.clone()),
        complete: true,
        model: Some("gpt-6.1-sol".to_string()),
        context_window: Some(200_000),
        first_input_tokens: Some(25_000),
        started_at: Some(1_792_310_400),
        base_instructions_chars: 4_000,
        other_harness_chars: 400,
        agents_md: Some(LoadedAgentsMd {
            directory: Some(directory),
            text: "SECRET-RULE-TEXT".to_string(),
        }),
        skills_body: Some(SKILLS_BODY.to_string()),
        ..CodexPrelude::default()
    };
    let request = build_request(RequestInputs {
        prelude: &prelude,
        workspace: &workspace,
        identity: RepositoryIdentity {
            repository_hash: Some("a".repeat(64)),
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: Some("git_common_dir".to_string()),
            workspace_kind: Some("repository_root".to_string()),
        },
        machine_id: "otm_test",
        labels_enabled: false,
        codex_home: &codex_home,
        home: Path::new("/home/u"),
        salt: Some(&[7; 32]),
    })
    .unwrap();
    assert_eq!(request.agent_source, "codex");
    assert_eq!(request.counter_source, COUNTER_SOURCE);
    assert_eq!(request.used_tokens, 25_000);
    assert_eq!(request.context_window_tokens, 200_000);
    assert_eq!(request.pct_context, 12.5);
    assert_eq!(request.memory_files.len(), 1);
    assert_eq!(
        request.memory_files[0].relative_path.as_deref(),
        Some("AGENTS.md")
    );
    assert_eq!(request.memory_files[0].file_counts.file_bytes, Some(16));
    assert_eq!(request.memory_files[0].file_counts.file_chars, Some(16));
    // A whole loaded file gets the shared device-salted hash recipe.
    assert_eq!(
        request.memory_files[0].file_counts.content_hash.as_deref(),
        Some(
            crate::context_file_counts::salted_content_hash(&[7; 32], b"SECRET-RULE-TEXT").as_str()
        )
    );
    assert_eq!(request.skills.len(), 3);
    let names: Vec<&str> = request.categories.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["System prompt", "Memory files", "Skills"]);
    // Characters, not tokens: the backend owns the ratio.
    assert_eq!(request.counter_source, "codex_rollout_prelude_chars_v1");
    assert_eq!(request.categories[0].tokens, 4_400);
    // Dated at the session start, not the upload.
    assert_eq!(request.captured_at, "2026-10-18T08:00:00Z");
    assert_eq!(request.workspace_label, None);
    let wire = serde_json::to_string(&request).unwrap();
    assert!(!wire.contains("SECRET-RULE-TEXT"));
    assert!(!wire.contains(&*workspace.to_string_lossy()));
}

#[test]
fn request_labels_need_a_fetched_hint_that_allows_them() {
    let workspace = ScratchDir::new("codex-session-start-label-policy");
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&*workspace)
        .args(["init", "-q"])
        .status()
        .unwrap();
    assert!(status.success());
    let codex_home = ScratchDir::new("codex-session-start-label-policy-home");
    let prelude = CodexPrelude {
        cwd: Some(workspace.to_string_lossy().into_owned()),
        complete: true,
        model: Some("gpt-6.1-sol".to_string()),
        context_window: Some(200_000),
        first_input_tokens: Some(25_000),
        started_at: Some(1_792_310_400),
        ..CodexPrelude::default()
    };
    let request = |labels_enabled: bool| {
        serde_json::to_value(
            build_request(RequestInputs {
                prelude: &prelude,
                workspace: &workspace,
                identity: resolve_repository_identity(&workspace, labels_enabled),
                machine_id: "otm_test",
                labels_enabled,
                codex_home: &codex_home,
                home: Path::new("/home/u"),
                salt: None,
            })
            .unwrap(),
        )
        .unwrap()
    };
    let hint = |labels: bool| {
        crate::snapshot_client::decode_activity_hint(json!({
            "source": "codex", "server_time": "2026-10-25T10:00:00Z",
            "record_count_15m": 0, "record_count_24h": 0,
            "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
            "workspace_labels_enabled": labels,
            "recommended_scan_after": "2026-10-25T10:05:00Z",
        }))
        .unwrap()
    };

    // Policy ON keeps today's labelled request.
    let on = request(workspace_labels_allowed(Some(&hint(true))));
    assert_eq!(on, request(true));
    assert!(on["workspace_label"].is_string());
    assert!(on["repository_label"].is_string());
    // Policy OFF and a failed hint fetch both withhold every label.
    let withheld = request(false);
    assert_eq!(
        request(workspace_labels_allowed(Some(&hint(false)))),
        withheld
    );
    assert_eq!(request(workspace_labels_allowed(None)), withheld);
    for field in [
        "workspace_label",
        "workspace_label_source",
        "repository_label",
        "repository_label_source",
    ] {
        assert!(withheld[field].is_null(), "{field} must be withheld");
    }
    assert_eq!(withheld["repository_hash"], on["repository_hash"]);
}

#[test]
fn request_needs_a_context_window() {
    let prelude = CodexPrelude {
        complete: true,
        ..CodexPrelude::default()
    };
    let request = build_request(RequestInputs {
        prelude: &prelude,
        workspace: Path::new("/nonexistent-codex-session-start"),
        identity: RepositoryIdentity {
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: Some("non_git".to_string()),
        },
        machine_id: "otm_test",
        labels_enabled: false,
        codex_home: Path::new("/nonexistent-codex-home"),
        home: Path::new("/home/u"),
        salt: None,
    });
    assert!(request.is_none());
}

#[test]
fn window_after_the_first_usage_record_is_still_read() {
    let prelude = parse(&[
        meta(json!({"context_window": null, "timestamp": "2026-10-18T08:00:00Z"})),
        message("user", Some("user.text"), "hi"),
        usage(321),
        json!({"type": "world_state", "payload": {"state": {"agents_md": {"text": "LATER"}}}}),
        json!({"type": "event_msg", "payload": {"type": "token_count", "info": {
            "last_token_usage": {"input_tokens": 999}, "model_context_window": 272000}}}),
    ]);
    assert!(prelude.complete);
    assert_eq!(prelude.first_input_tokens, Some(321));
    assert_eq!(prelude.context_window, Some(272_000));
    assert_eq!(prelude.agents_md, None);
    assert_eq!(prelude.started_at, Some(1_792_310_400));
}

fn write_rollout(dir: &Path, name: &str, records: &[Value]) {
    fs::write(dir.join(name), rollout(records)).unwrap();
}

#[test]
fn newest_session_start_wins_over_recent_activity() {
    let sessions = ScratchDir::new("codex-session-start-sessions");
    // A registered slot home's sessions folder is a second root.
    let slot_home = ScratchDir::new("codex-session-start-slot");
    let slot_sessions = slot_home.join("sessions");
    fs::create_dir(&slot_sessions).unwrap();
    let roots = [sessions.to_path_buf(), slot_sessions.clone()];
    let support = ScratchDir::new("codex-session-start-support");
    let workspace = ScratchDir::new("codex-session-start-workspace");
    let cwd = workspace.to_string_lossy().into_owned();
    let start = |id: &str, at: &str| {
        vec![
            json!({"type": "session_meta", "payload": {"id": id, "cwd": cwd, "timestamp": at, "context_window": 1000}}),
            usage(10),
        ]
    };
    write_rollout(
        &slot_sessions,
        "rollout-newer.jsonl",
        &start("newer", "2026-10-18T09:00:00Z"),
    );
    // Written last (newest mtime) but started earlier: a resumed old session.
    write_rollout(
        &sessions,
        "rollout-older.jsonl",
        &start("older", "2026-10-17T09:00:00Z"),
    );
    write_rollout(
        &sessions,
        "rollout-fork.jsonl",
        &[
            json!({"type": "session_meta", "payload": {"id": "fork", "cwd": cwd, "timestamp": "2026-10-18T10:00:00Z", "forked_from_id": "newer"}}),
            usage(10),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let chosen = select_candidates(&roots, &support, "dest", deadline);
    assert_eq!(chosen.len(), 1);
    assert!(chosen[0].0.ends_with("rollout-newer.jsonl"));
    // Read against the home that wrote it (its user file, skills, config).
    assert_eq!(chosen[0].2, slot_home.to_path_buf());
    // The index makes the next cycle read nothing new and choose the same.
    let index = read_index(&support);
    assert_eq!(index.files.len(), 3);
    assert_eq!(
        select_candidates(&roots, &support, "dest", deadline),
        chosen
    );
    // Once that start is sent it is one observation: a week later it is
    // still not replayed (BR3) and frees its slot for other repositories;
    // another destination still needs it.
    let week_ago = OffsetDateTime::now_utc() - time::Duration::days(8);
    write_json_atomic(
        &upload_cache_path(&support, &sha256_hex(&[cwd.as_str()])),
        &UploadCacheEntry {
            identity: "dest".to_string(),
            request_sha256: "h".to_string(),
            posted_at: week_ago.format(&Rfc3339).unwrap(),
            // 2026-10-18T09:00:00Z, the start of rollout-newer.
            started_at: Some(1_792_314_000),
        },
    );
    assert!(select_candidates(&roots, &support, "dest", deadline).is_empty());
    // An older session resuming later is no newer observation either.
    write_rollout(
        &sessions,
        "rollout-older.jsonl",
        &start("older", "2026-10-17T09:00:00Z"),
    );
    assert!(select_candidates(&roots, &support, "dest", deadline).is_empty());
    assert_eq!(
        select_candidates(&roots, &support, "other", deadline),
        chosen
    );
    // A genuinely newer start is a new observation.
    write_rollout(
        &sessions,
        "rollout-newest.jsonl",
        &start("newest", "2026-10-18T11:00:00Z"),
    );
    let newer = select_candidates(&roots, &support, "dest", deadline);
    assert_eq!(newer.len(), 1);
    assert!(newer[0].0.ends_with("rollout-newest.jsonl"));
}

#[test]
fn existing_footprint_disable_file_also_disables_codex() {
    let support = ScratchDir::new("codex-session-start-disable");
    assert!(!local_harvest_disabled(&support));
    fs::create_dir(support.join("context_footprint")).unwrap();
    fs::write(support.join("context_footprint").join("disabled"), "").unwrap();
    assert!(local_harvest_disabled(&support));
}
