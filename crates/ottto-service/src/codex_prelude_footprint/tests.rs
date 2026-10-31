use super::*;
use crate::snapshots::line_delivery::{
    DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want,
};
use crate::test_scratch::ScratchDir;
use crate::transcript_acquisition::FileObject;
use serde_json::json;
use std::sync::Arc;

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

fn write_rollout(
    feed: &Arc<CodexPreludeFeed>,
    roots: &[PathBuf],
    dir: &Path,
    name: &str,
    records: &[Value],
) {
    let path = dir.join(name);
    fs::write(&path, rollout(records)).unwrap();
    let mut view = fixture_view(&path, DeliveryMode::Full, 0);
    view.root = roots
        .iter()
        .position(|root| root == dir)
        .and_then(|i| u16::try_from(i).ok());
    deliver(feed, roots, view, records, DeliveryEnd::Complete);
}

#[test]
fn newest_session_start_wins_over_recent_activity() {
    let sessions = ScratchDir::new("codex-session-start-sessions");
    // A registered slot home's sessions folder is a second root.
    let slot_home = ScratchDir::new("codex-session-start-slot");
    let slot_sessions = slot_home.join("sessions");
    fs::create_dir(&slot_sessions).unwrap();
    let roots = [sessions.to_path_buf(), slot_sessions.clone()];
    let feed = Arc::new(CodexPreludeFeed::default());
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
        &feed,
        &roots,
        &slot_sessions,
        "rollout-newer.jsonl",
        &start("newer", "2026-10-18T09:00:00Z"),
    );
    // Written last (newest mtime) but started earlier: a resumed old session.
    write_rollout(
        &feed,
        &roots,
        &sessions,
        "rollout-older.jsonl",
        &start("older", "2026-10-17T09:00:00Z"),
    );
    write_rollout(
        &feed,
        &roots,
        &sessions,
        "rollout-fork.jsonl",
        &[
            json!({"type": "session_meta", "payload": {"id": "fork", "cwd": cwd, "timestamp": "2026-10-18T10:00:00Z", "forked_from_id": "newer", "context_window": 1000}}),
            usage(10),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let chosen = select_candidates(&feed, &roots, &support, "dest", deadline);
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].0.started_at, Some(1_792_314_000));
    // Read against the home that wrote it (its user file, skills, config).
    assert_eq!(chosen[0].2, slot_home.to_path_buf());
    // A second snapshot chooses the same observation with no reader.
    assert_eq!(feed.snapshot(SystemTime::now()).0.len(), 3);
    assert_eq!(
        select_candidates(&feed, &roots, &support, "dest", deadline),
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
    assert!(select_candidates(&feed, &roots, &support, "dest", deadline).is_empty());
    // An older session resuming later is no newer observation either.
    write_rollout(
        &feed,
        &roots,
        &sessions,
        "rollout-older.jsonl",
        &start("older", "2026-10-17T09:00:00Z"),
    );
    assert!(select_candidates(&feed, &roots, &support, "dest", deadline).is_empty());
    assert_eq!(
        select_candidates(&feed, &roots, &support, "other", deadline),
        chosen
    );
    // A genuinely newer start is a new observation.
    write_rollout(
        &feed,
        &roots,
        &sessions,
        "rollout-newest.jsonl",
        &start("newest", "2026-10-18T11:00:00Z"),
    );
    let newer = select_candidates(&feed, &roots, &support, "dest", deadline);
    assert_eq!(newer.len(), 1);
    assert_eq!(newer[0].0.started_at, Some(1_792_321_200));
}

#[test]
fn existing_footprint_disable_file_also_disables_codex() {
    let support = ScratchDir::new("codex-session-start-disable");
    assert!(!local_harvest_disabled(&support));
    fs::create_dir(support.join("context_footprint")).unwrap();
    fs::write(support.join("context_footprint").join("disabled"), "").unwrap();
    assert!(local_harvest_disabled(&support));
}

fn fixture_view(path: &Path, mode: DeliveryMode, start: u64) -> FileView {
    if !path.exists() {
        fs::write(path, b"").unwrap();
    }
    let (object, held) = FileObject::of(&fs::File::open(path).unwrap()).unwrap();
    FileView {
        source: SnapshotSource::Codex,
        object,
        mtime: held.modified().ok(),
        mode,
        root: Some(0),
        start,
    }
}
fn deliver(
    feed: &Arc<CodexPreludeFeed>,
    roots: &[PathBuf],
    view: FileView,
    rows: &[Value],
    end: DeliveryEnd,
) -> (Want, u64) {
    let mut observer = feed.observer(roots);
    let want = observer.begin(&view);
    let mut offset = view.start;
    if want == Want::Lines {
        for value in rows {
            offset += serde_json::to_vec(value).unwrap().len() as u64 + 1;
            observer.line(
                &view,
                &PhysicalLine {
                    end: offset,
                    value: Some(value),
                },
            );
        }
    }
    observer.end(&view, &end);
    (want, offset)
}
fn observed(rows: &[Value]) -> CodexPrelude {
    let dir = ScratchDir::new("prelude-oracle");
    let roots = [dir.join("sessions")];
    let feed = Arc::new(CodexPreludeFeed::default());
    let view = fixture_view(&dir.join("fixture"), DeliveryMode::Full, 0);
    deliver(&feed, &roots, view, rows, DeliveryEnd::Complete);
    // Oracle returns a partial at EOF; LD holds that partial until terminal.
    let mut done = feed.snapshot(SystemTime::now()).0;
    assert_eq!(done.len(), 1);
    done.remove(0).1
}
fn request_json(prelude: &CodexPrelude, home: &Path, workspace: &Path) -> Option<Vec<u8>> {
    build_request(RequestInputs {
        prelude,
        workspace,
        identity: RepositoryIdentity {
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: Some("non_git".into()),
        },
        machine_id: "otm_fixture",
        labels_enabled: false,
        codex_home: &home.join(".codex"),
        home,
        salt: None,
    })
    .map(|request| serde_json::to_vec(&request).unwrap())
}

#[test]
fn observer_oracle_requests_and_none_outcomes() {
    let home = ScratchDir::new("prelude-parity-home");
    let workspace = home.join("repo");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(workspace.join("AGENTS.md"), "project").unwrap();
    fs::write(home.join(".codex/AGENTS.md"), "user").unwrap();
    for text in ["project", "user", "user\n\n--- project-doc ---\n\nproject"] {
        for flags in [
            json!({}),
            json!({"context_window": 0}),
            json!({"timestamp": null}),
        ] {
            let mut m = meta(json!({"cwd": workspace, "timestamp": "2026-10-18T08:00:00Z"}));
            for (k, v) in flags.as_object().unwrap() {
                m["payload"][k] = v.clone();
            }
            let records = vec![
                m,
                json!({"type":"world_state","payload":{"state":{
                "agents_md":{"directory":workspace,"text":text},
                "host_skills":{"body":SKILLS_BODY}}}}),
                message("developer", Some("hooks.additional_context"), "hook"),
                usage(0),
                usage(123),
            ];
            let oracle = parse(&records);
            let actual = observed(&records);
            assert_eq!(actual, oracle);
            let actual_json = request_json(&actual, &home, &workspace);
            let oracle_json = request_json(&oracle, &home, &workspace);
            assert_eq!(actual_json, oracle_json);
            assert_eq!(actual_json.is_some(), flags == json!({}));
            assert_eq!(oracle_json.is_some(), flags == json!({}));
            assert_eq!(actual_json.is_none(), flags != json!({}));
            assert_eq!(
                !actual_json.unwrap_or_default().is_empty(),
                flags == json!({})
            );
        }
    }
}

#[test]
fn pending_continuity_unchanged_wrong_offsets_restart_and_incomplete() {
    let dir = ScratchDir::new("prelude-continuity");
    let roots = [dir.join("sessions")];
    for delta in [-1i64, 0, 1] {
        let feed = Arc::new(CodexPreludeFeed::default());
        let full = fixture_view(&dir.join("fixture"), DeliveryMode::Full, 0);
        let (_, next) = deliver(
            &feed,
            &roots,
            full,
            &[meta(json!({"context_window":null})), usage(7)],
            DeliveryEnd::Complete,
        );
        assert_eq!(metric(&feed, "pending"), 1);
        let unchanged = FileView {
            mode: DeliveryMode::Unchanged,
            start: next,
            ..full
        };
        assert_eq!(
            deliver(&feed, &roots, unchanged, &[], DeliveryEnd::Complete).0,
            Want::Skip
        );
        let tail = FileView {
            mode: DeliveryMode::Tail,
            start: (next as i64 + delta) as u64,
            ..full
        };
        let window = json!({"type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":99},"model_context_window":555}}});
        deliver(&feed, &roots, tail, &[window], DeliveryEnd::Incomplete);
        let done = feed.snapshot(SystemTime::now()).0;
        assert_eq!(done.len(), usize::from(delta == 0));
        assert_eq!(
            metric(&feed, "codex_prelude_gap_dropped"),
            usize::from(delta != 0)
        );
        // Restart with a warm acquisition prefix never manufactures a parser.
        let restarted = Arc::new(CodexPreludeFeed::default());
        for _ in 0..2 {
            deliver(&restarted, &roots, tail, &[], DeliveryEnd::Complete);
        }
        assert_eq!(metric(&restarted, "codex_prelude_unseen_prefix"), 1);
        // Full replaces Done as well as Pending, even when replacement fails.
        deliver(
            &feed,
            &roots,
            full,
            &[meta(json!({}))],
            DeliveryEnd::Incomplete,
        );
        assert!(feed.snapshot(SystemTime::now()).0.is_empty());
        deliver(
            &feed,
            &roots,
            full,
            &[meta(json!({})), usage(1)],
            DeliveryEnd::Incomplete,
        );
        assert_eq!(feed.snapshot(SystemTime::now()).0.len(), 1);
        assert_eq!(
            deliver(&feed, &roots, tail, &[], DeliveryEnd::Complete).0,
            Want::Skip
        );
    }
}

#[test]
fn root_snapshot_registration_filter_and_ties_precede_winner_selection() {
    let dir = ScratchDir::new("prelude-roots");
    let registered = dir.join("registered");
    let process = dir.join("process");
    let third = dir.join("third");
    let roots = [
        registered.join("sessions"),
        process.join("sessions"),
        third.join("archived_sessions"),
    ];
    let workspace = dir.join("repo");
    fs::create_dir(&workspace).unwrap();
    let support = dir.join("support");
    let feed = Arc::new(CodexPreludeFeed::default());
    let records = |at: &str| [meta(json!({"cwd":workspace,"timestamp":at})), usage(7)];
    for (i, at) in [
        "2026-10-18T08:00:00Z",
        "2026-10-18T09:00:00Z",
        "2026-10-18T08:00:00Z",
    ]
    .iter()
    .enumerate()
    {
        let mut view = fixture_view(&dir.join(format!("file{i}")), DeliveryMode::Full, 0);
        view.root = Some(i as u16);
        deliver(&feed, &roots, view, &records(at), DeliveryEnd::Complete);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let chosen = select_candidates(&feed, &[roots[0].clone()], &support, "dest", deadline);
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].2, registered);
    let all = feed.snapshot(SystemTime::now()).0;
    let expected = all
        .iter()
        .filter(|(_, _, h, _, _)| h != &process)
        .min_by_key(|r| r.0)
        .unwrap()
        .2
        .clone();
    let chosen = select_candidates(
        &feed,
        &[roots[2].clone(), roots[0].clone()],
        &support,
        "dest",
        deadline,
    );
    assert_eq!(chosen[0].2, expected);
    // The stored home survives process-root reorder/removal at upload.
    assert_eq!(feed.snapshot(SystemTime::now()).0.len(), 3);
    for ordinal in [None, Some(99)] {
        let mut view = fixture_view(&dir.join("missing"), DeliveryMode::Full, 0);
        view.root = ordinal;
        assert_eq!(
            deliver(
                &feed,
                &roots,
                view,
                &records("2026-10-18T08:00:00Z"),
                DeliveryEnd::Complete
            )
            .0,
            Want::Skip
        );
    }
    assert_eq!(metric(&feed, "root_missing"), 2);
}

#[test]
fn text_caps_are_utf8_safe_and_unuploadable_newest_still_suppresses_old() {
    let dir = ScratchDir::new("prelude-caps");
    let roots = [dir.join("sessions")];
    let workspace = dir.join("repo");
    fs::create_dir(&workspace).unwrap();
    let feed = Arc::new(CodexPreludeFeed::default());
    for (n, at) in ["2026-10-18T08:00:00Z", "2026-10-18T09:00:00Z"]
        .iter()
        .enumerate()
    {
        let full = fixture_view(&dir.join(format!("file{n}")), DeliveryMode::Full, 0);
        let text = if n == 0 {
            "ok".into()
        } else {
            "€".repeat(65536)
        };
        let rows = [
            meta(json!({"cwd":workspace,"timestamp":at})),
            json!({"type":"world_state","payload":{"state":{"agents_md":{"text":text},"host_skills":{"body":if n==0 { String::from("small") } else { "€".repeat(40000) }}}}}),
            usage(7),
        ];
        deliver(&feed, &roots, full, &rows, DeliveryEnd::Complete);
    }
    assert_eq!(metric(&feed, "text_capped"), 1);
    assert!(select_candidates(
        &feed,
        &roots,
        &dir.join("support"),
        "dest",
        Instant::now() + Duration::from_secs(60)
    )
    .is_empty());
    let old = Arc::new(CodexPreludeFeed::default());
    let full = fixture_view(&dir.join("expired"), DeliveryMode::Full, 0);
    deliver(
        &old,
        &roots,
        FileView {
            mtime: Some(SystemTime::UNIX_EPOCH),
            ..full
        },
        &[meta(json!({})), usage(2)],
        DeliveryEnd::Complete,
    );
    assert!(old.snapshot(SystemTime::now()).0.is_empty());
}

#[test]
fn dropped_byte_bound_and_newline_and_overlong_differences_are_explicit() {
    use std::io::Read;
    let rows = [
        meta(json!({})),
        json!({"padding":"x".repeat(2*1024*1024)}),
        usage(11),
    ];
    let oracle = parse_prelude(std::io::Cursor::new(rollout(&rows)).take(2 * 1024 * 1024)).unwrap();
    assert!(!oracle.complete);
    assert!(observed(&rows).complete);
    let mut bytes = rollout(&[meta(json!({})), usage(11)]);
    bytes.pop();
    assert!(
        parse_prelude(std::io::Cursor::new(&bytes))
            .unwrap()
            .complete
    );
    let dir = ScratchDir::new("prelude-differences");
    let roots = [dir.join("sessions")];
    let feed = Arc::new(CodexPreludeFeed::default());
    let view = fixture_view(&dir.join("fixture"), DeliveryMode::Full, 0);
    let (_, next) = deliver(
        &feed,
        &roots,
        view,
        &[meta(json!({}))],
        DeliveryEnd::Complete,
    );
    assert!(
        feed.snapshot(SystemTime::now()).0.is_empty(),
        "unterminated usage is not delivered"
    );
    deliver(
        &feed,
        &roots,
        FileView {
            start: next,
            mode: DeliveryMode::Tail,
            ..view
        },
        &[usage(11)],
        DeliveryEnd::Complete,
    );
    assert!(feed.snapshot(SystemTime::now()).0[0].1.complete);
    // LD delivers an overlong usage as Null; the unlimited oracle accepts it.
    let rows = [meta(json!({})), usage(11)];
    assert!(parse(&rows).complete);
    let fresh = Arc::new(CodexPreludeFeed::default());
    deliver(
        &fresh,
        &roots,
        view,
        &[rows[0].clone(), Value::Null],
        DeliveryEnd::Complete,
    );
    assert!(fresh.snapshot(SystemTime::now()).0.is_empty());
}

pub(crate) fn metric(feed: &CodexPreludeFeed, key: &str) -> usize {
    feed.metrics()
        .split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix(&format!("{key}="))
                .and_then(|s| s.parse().ok())
        })
        .unwrap()
}
#[test]
fn pending_eviction_capacity_and_repeated_unseen_streams_stay_bounded() {
    let dir = ScratchDir::new("prelude-heap");
    let roots = [dir.join("sessions")];
    let feed = Arc::new(CodexPreludeFeed::default());
    let rows = [
        meta(json!({})),
        json!({"type":"world_state","payload":{"state":{"agents_md":{"text":"a".repeat(128*1024)},"host_skills":{"body":"s".repeat(96*1024)}}}}),
    ];
    let first = fixture_view(&dir.join("file0"), DeliveryMode::Full, 0);
    let (_, next) = deliver(&feed, &roots, first, &rows, DeliveryEnd::Complete);
    for i in 1..40 {
        let view = fixture_view(&dir.join(format!("file{i}")), DeliveryMode::Full, 0);
        deliver(&feed, &roots, view, &rows, DeliveryEnd::Complete);
        assert!(metric(&feed, "feed_bytes") <= 4 * 1024 * 1024);
    }
    assert!(metric(&feed, "evicted") > 0);
    assert_eq!(
        deliver(
            &feed,
            &roots,
            FileView {
                mode: DeliveryMode::Tail,
                start: next,
                ..first
            },
            &[usage(5)],
            DeliveryEnd::Complete
        )
        .0,
        Want::Skip
    );
    assert!(metric(&feed, "codex_prelude_unseen_prefix") > 0);
    // Repeated insert/remove must not hide retained container slots.
    for i in 0..200 {
        let view = fixture_view(&dir.join(format!("unseen{i}")), DeliveryMode::Tail, 9);
        deliver(&feed, &roots, view, &[], DeliveryEnd::Complete);
        deliver(
            &feed,
            &roots,
            FileView {
                mode: DeliveryMode::Full,
                start: 0,
                ..view
            },
            &[usage(2)],
            DeliveryEnd::Complete,
        );
        assert!(metric(&feed, "feed_bytes") <= 4 * 1024 * 1024);
    }
}

#[test]
fn scope_dedup_cap_ties_and_missing_start_preserve_phase_two_order() {
    let dir = ScratchDir::new("prelude-ranking");
    let roots = [dir.join("sessions")];
    let support = dir.join("support");
    let feed = Arc::new(CodexPreludeFeed::default());
    for i in 0..15 {
        let workspace = dir.join(format!("repo{i}"));
        fs::create_dir(&workspace).unwrap();
        let view = fixture_view(&dir.join(format!("file{i}")), DeliveryMode::Full, 0);
        deliver(
            &feed,
            &roots,
            view,
            &[
                meta(json!({"cwd":workspace,"timestamp":"2026-10-18T08:00:00Z"})),
                usage(9),
            ],
            DeliveryEnd::Complete,
        );
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut starts = feed.snapshot(SystemTime::now()).0;
    starts.sort_by_key(|s| s.0);
    let chosen = select_candidates(&feed, &roots, &support, "dest", deadline);
    assert_eq!(chosen.len(), 12);
    assert_eq!(
        chosen.iter().map(|c| c.0.cwd.clone()).collect::<Vec<_>>(),
        starts[..12]
            .iter()
            .map(|c| c.1.cwd.clone())
            .collect::<Vec<_>>()
    );
    // One cached repository scope suppresses its later directories, even when
    // the newest directory's start has already been sent.
    feed.remember_scopes(
        starts
            .iter()
            .map(|s| (s.1.cwd.clone().unwrap(), "one-scope".into()))
            .collect(),
    );
    assert_eq!(
        select_candidates(&feed, &roots, &support, "dest", deadline).len(),
        1
    );
    let cwd = starts[0].1.cwd.as_ref().unwrap();
    write_json_atomic(
        &upload_cache_path(&support, &sha256_hex(&[cwd])),
        &UploadCacheEntry {
            identity: "dest".into(),
            request_sha256: "h".into(),
            posted_at: "2026-10-18T08:00:00Z".into(),
            started_at: starts[0].1.started_at,
        },
    );
    assert!(select_candidates(&feed, &roots, &support, "dest", deadline).is_empty());
    let missing = Arc::new(CodexPreludeFeed::default());
    let view = fixture_view(&dir.join("missing-start"), DeliveryMode::Full, 0);
    deliver(
        &missing,
        &roots,
        view,
        &[meta(json!({"cwd":cwd})), usage(9)],
        DeliveryEnd::Complete,
    );
    let chosen = select_candidates(&missing, &roots, &support, "other", deadline);
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].0.started_at, None);
    assert!(
        request_json(&chosen[0].0, &dir, Path::new(cwd)).is_none(),
        "mtime is ranking only"
    );
}

#[test]
fn callback_skip_mtime_scope_pruning_and_monotonic_end_guards() {
    let dir = ScratchDir::new("prelude-skips");
    let roots = [dir.join("sessions")];
    let feed = Arc::new(CodexPreludeFeed::default());
    let view = fixture_view(&dir.join("fixture"), DeliveryMode::Full, 0);
    let rows = [meta(json!({})), usage(9)];
    deliver(&feed, &roots, view, &rows, DeliveryEnd::Complete);
    let later = view.mtime.unwrap() + Duration::from_secs(1);
    let unchanged = FileView {
        mode: DeliveryMode::Unchanged,
        mtime: Some(later),
        ..view
    };
    assert_eq!(
        deliver(&feed, &roots, unchanged, &[], DeliveryEnd::Complete).0,
        Want::Skip
    );
    assert_eq!(feed.snapshot(SystemTime::now()).0[0].4, later);
    feed.remember_scopes(vec![("/absent".into(), "scope".into())]);
    assert!(feed.snapshot(SystemTime::now()).1.is_empty());
    let wrong_source = FileView {
        source: SnapshotSource::Pi,
        ..view
    };
    assert_eq!(
        deliver(&feed, &roots, wrong_source, &rows, DeliveryEnd::Complete).0,
        Want::Skip
    );
    let mut observer = feed.observer(&roots);
    assert_eq!(observer.begin(&view), Want::Lines);
    observer.line(
        &view,
        &PhysicalLine {
            end: 0,
            value: Some(&rows[0]),
        },
    );
    observer.end(&view, &DeliveryEnd::Complete);
    assert!(feed.snapshot(SystemTime::now()).0.is_empty());
    assert_eq!(metric(&feed, "codex_prelude_gap_dropped"), 1);
}

#[cfg(unix)]
#[test]
fn root_alias_snapshot_keeps_the_configured_codex_home() {
    let dir = ScratchDir::new("prelude-root-alias-home");
    let home = dir.join("home");
    let real = dir.join("elsewhere");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&real).unwrap();
    let root = home.join("sessions");
    std::os::unix::fs::symlink(&real, &root).unwrap();
    let feed = Arc::new(CodexPreludeFeed::default());
    let roots = [root.clone()];
    let mut observer = feed.observer(&roots);
    assert_eq!(
        observer.root_ordinal(&fs::canonicalize(&real).unwrap(), &roots),
        Some(0)
    );
    let view = fixture_view(&dir.join("fixture"), DeliveryMode::Full, 0);
    assert_eq!(observer.begin(&view), Want::Lines);
    let m = meta(json!({}));
    let u = usage(3);
    observer.line(
        &view,
        &PhysicalLine {
            end: 100,
            value: Some(&m),
        },
    );
    observer.line(
        &view,
        &PhysicalLine {
            end: 200,
            value: Some(&u),
        },
    );
    observer.end(&view, &DeliveryEnd::Complete);
    assert_eq!(feed.snapshot(SystemTime::now()).0[0].2, home);
    assert_eq!(metric(&feed, "root_missing"), 0);
}

#[test]
fn index_survives_swap_removal_and_replacement_order() {
    let dir = ScratchDir::new("prelude-index");
    let roots = [dir.join("sessions")];
    let feed = Arc::new(CodexPreludeFeed::default());
    let mut views = Vec::new();
    for i in 0..32 {
        let view = fixture_view(&dir.join(format!("file{i}")), DeliveryMode::Full, 0);
        deliver(
            &feed,
            &roots,
            view,
            &[meta(json!({"cwd":format!("/cwd/{i}")})), usage(i + 1)],
            DeliveryEnd::Complete,
        );
        views.push(view);
    }
    for i in (0..32).rev() {
        deliver(
            &feed,
            &roots,
            views[i],
            &[
                meta(json!({"cwd":format!("/new/{i}")})),
                usage(i as u64 + 100),
            ],
            DeliveryEnd::Complete,
        );
        assert_eq!(metric(&feed, "feed_files"), 32);
    }
    let done = feed.snapshot(SystemTime::now()).0;
    assert_eq!(done.len(), 32);
    for (i, view) in views.iter().enumerate().take(32) {
        let p = &done.iter().find(|s| s.0 == view.object).unwrap().1;
        assert_eq!(p.cwd, Some(format!("/new/{i}")));
        assert_eq!(p.first_input_tokens, Some(i as u64 + 100));
    }
}

/// The existing probe intercepts OwnedJsonlParser's first acquisition step,
/// not arbitrary File::open. Missing source files additionally make a former
/// uploader re-read unable to reproduce the nonempty selected request.
#[test]
fn uploader_selection_and_request_do_not_acquire_sources_after_eviction_or_feed_restart() {
    use crate::snapshots::{
        scan_source_roots, terminal_contract_retry::source_acquisitions, ScanIndex,
    };
    let dir = ScratchDir::new("prelude-uploader-no-acquisition");
    let sessions = dir.join("sessions");
    fs::create_dir(&sessions).unwrap();
    let roots = [sessions.clone()];
    let support = ScratchDir::new("prelude-no-acquisition-support");
    let path =
        sessions.join("rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl");
    let rows = [
        meta(
            json!({"id":"019fa111-2222-7333-8444-555555555555", "cwd":dir.to_path_buf(), "timestamp":"2026-10-07T10:00:00Z"}),
        ),
        usage(17),
    ];
    fs::write(&path, rollout(&rows)).unwrap();
    let mut full = fixture_view(&path, DeliveryMode::Full, 0);
    full.mtime = Some(SystemTime::now() - Duration::from_secs(3600));
    let feed = Arc::new(CodexPreludeFeed::default());
    assert_eq!(
        deliver(&feed, &roots, full, &rows, DeliveryEnd::Complete).0,
        Want::Lines
    );
    assert_eq!(feed.done_for_test().len(), 1);
    let (scan, acquisitions) = source_acquisitions(|| {
        scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut ScanIndex::default(),
            "2026-10-07T12:00:00Z",
            14,
        )
        .unwrap()
    });
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(acquisitions.get(&path), Some(&1), "probe positive control");
    let select = |feed: &CodexPreludeFeed| {
        source_acquisitions(|| {
            select_candidates(
                feed,
                &roots,
                &support,
                "dest",
                Instant::now() + Duration::from_secs(60),
            )
        })
    };
    let (chosen, acquired) = select(&feed);
    assert_eq!(chosen.len(), 1);
    assert!(acquired.is_empty());
    assert!(!request_json(&chosen[0].0, &dir, &dir).unwrap().is_empty());
    let pending = [
        meta(json!({})),
        json!({"type":"world_state","payload":{"state":{
        "agents_md":{"text":"a".repeat(128*1024)},"host_skills":{"body":"s".repeat(96*1024)}}}}),
    ];
    for i in 0..48 {
        let view = fixture_view(&dir.join(format!("pressure{i}")), DeliveryMode::Full, 0);
        deliver(&feed, &roots, view, &pending, DeliveryEnd::Complete);
    }
    assert!(metric(&feed, "evicted") > 0);
    assert!(feed.done_for_test().is_empty(), "original Done was evicted");
    let (chosen, acquired) = select(&feed);
    assert!(chosen.is_empty());
    assert!(acquired.is_empty());
    let restarted = CodexPreludeFeed::default(); // Feed-only warm-RAM reset.
    let (chosen, acquired) = select(&restarted);
    assert!(chosen.is_empty());
    assert!(acquired.is_empty());
    assert_eq!(
        deliver(&feed, &roots, full, &rows, DeliveryEnd::Complete).0,
        Want::Lines
    );
    fs::remove_file(&path).unwrap();
    assert!(!path.exists());
    let ((chosen, bytes), acquired) = source_acquisitions(|| {
        let chosen = select_candidates(
            &feed,
            &roots,
            &support,
            "dest",
            Instant::now() + Duration::from_secs(60),
        );
        assert_eq!(chosen.len(), 1);
        let bytes = request_json(&chosen[0].0, &dir, &dir).unwrap();
        (chosen, bytes)
    });
    assert_eq!(chosen[0].0.first_input_tokens, Some(17));
    assert!(!bytes.is_empty());
    assert!(acquired.is_empty());
}

#[test]
fn obsolete_index_cleanup_counts_once_and_never_sweeps_a_directory() {
    for (case, expected) in [
        ("removed", [1, 0, 0]),
        ("absent", [0, 1, 0]),
        ("failed", [0, 0, 1]),
    ] {
        let support = ScratchDir::new("prelude-index-cleanup");
        let state_dir = support.join(STATE_DIR);
        fs::create_dir(&state_dir).unwrap();
        fs::create_dir(support.join("context_footprint")).unwrap();
        fs::write(support.join("context_footprint/disabled"), b"").unwrap();
        let index = state_dir.join("index.json");
        let sibling = state_dir.join("upload-cache.json");
        fs::write(&sibling, b"preserve-upload-cache").unwrap();
        match case {
            "removed" => fs::write(&index, b"obsolete-not-decoded").unwrap(),
            "failed" => {
                fs::create_dir(&index).unwrap();
                fs::write(index.join("canary"), b"never-sweep").unwrap();
            }
            _ => {}
        }
        let feed = CodexPreludeFeed::default();
        assert_eq!(metric(&feed, "index_cleanup_removed"), 0);
        assert_eq!(metric(&feed, "index_cleanup_absent"), 0);
        assert_eq!(metric(&feed, "index_cleanup_failed"), 0);
        // The disabled gate keeps this real uploader entry point away from
        // credentials/network; cleanup runs before that gate.
        harvest_once(&support, &support, &feed).unwrap();
        assert_eq!(
            [
                metric(&feed, "index_cleanup_removed"),
                metric(&feed, "index_cleanup_absent"),
                metric(&feed, "index_cleanup_failed")
            ],
            expected
        );
        assert_eq!(index.exists(), case == "failed");
        assert_eq!(index.is_dir(), case == "failed");
        assert_eq!(
            fs::read(index.join("canary")).ok(),
            (case == "failed").then(|| b"never-sweep".to_vec())
        );
        assert_eq!(fs::read(&sibling).unwrap(), b"preserve-upload-cache");
        assert!(!feed.metrics().contains("index.json"));
        if case != "failed" {
            fs::write(&index, b"later-file-stays").unwrap();
        }
        harvest_once(&support, &support, &feed).unwrap();
        assert_eq!(
            [
                metric(&feed, "index_cleanup_removed"),
                metric(&feed, "index_cleanup_absent"),
                metric(&feed, "index_cleanup_failed")
            ],
            expected,
            "one attempt per daemon feed"
        );
        assert_eq!(
            fs::read(&index).ok(),
            (case != "failed").then(|| b"later-file-stays".to_vec())
        );
        assert_eq!(fs::read(&sibling).unwrap(), b"preserve-upload-cache");
        assert_eq!(
            fs::read(index.join("canary")).ok(),
            (case == "failed").then(|| b"never-sweep".to_vec())
        );
    }
}
