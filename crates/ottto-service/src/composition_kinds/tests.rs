//! Pins the kinds_version 1 classification through the kinds interface: every
//! function must give the same answer the collector's v1 classifiers give,
//! with no parts and no kinds_version 2 value.

use super::*;
use serde_json::json;

fn claude() -> LineCtx<'static> {
    LineCtx::v1()
}

fn codex() -> LineCtx<'static> {
    LineCtx::v1()
}

fn counted(verdict: Verdict) -> Option<&'static str> {
    match verdict {
        Verdict::Count { kind, part } => {
            assert_eq!(part, Part::Unsplit, "v1 has no parts");
            Some(kind.as_str())
        }
        Verdict::Skip(reason) => {
            assert_eq!(
                reason,
                SkipReason::NotMeasured,
                "v1 skips only unmeasured content"
            );
            None
        }
    }
}

#[test]
fn claude_tool_matches_v1_categories() {
    let cases = [
        ("Bash", None, "shell_output"),
        ("Read", Some("/w/src/main.rs"), "code_reads"),
        ("Read", Some("/w/docs/guide.md"), "doc_reads_md"),
        ("Read", Some("/w/docs/page.html"), "doc_reads_html"),
        ("Read", Some("/w/memory/notes.md"), "memory_notes"),
        ("Read", None, "code_reads"),
        ("NotebookRead", Some("/w/a.ipynb"), "code_reads"),
        ("Task", None, "agent_results"),
        ("Agent", None, "agent_results"),
        ("WebFetch", None, "web_fetch_search"),
        ("WebSearch", None, "web_fetch_search"),
        (
            "mcp__claude-in-chrome__navigate",
            None,
            "browser_and_images",
        ),
        ("mcp__computer-use__click", None, "browser_and_images"),
        ("preview_start", None, "browser_and_images"),
        ("take_screenshot", None, "browser_and_images"),
        ("Edit", Some("/w/src/main.rs"), "other_tools"),
        ("mcp__acme__thing", None, "other_tools"),
        ("", None, "other_tools"),
    ];
    for (name, file, expected) in cases {
        let input = match file {
            Some(file) => json!({"file_path": file}),
            None => json!({}),
        };
        let class = claude_tool(&claude(), name, &input);
        assert_eq!(class.kind.as_str(), expected, "{name} {file:?}");
        assert_eq!(class.kind, cc_tool_category(name, file.unwrap_or("")));
        assert_eq!(class.part, Part::Unsplit);
        assert_eq!(class.tool.as_str(), name);
        assert_eq!(class.file.as_deref(), file);
    }
    // No input, or a file path that is not a string: no file.
    for input in [Value::Null, json!({"file_path": 7}), json!(["x"])] {
        let class = claude_tool(&claude(), "Read", &input);
        assert_eq!(class.kind, Kind::CodeReads);
        assert_eq!(class.file, None);
    }
    let unmatched = CallClass::unmatched();
    assert_eq!(
        (unmatched.kind, unmatched.part, unmatched.file),
        (Kind::OtherTools, Part::Unsplit, None)
    );
}

#[test]
fn claude_attachment_and_text_match_v1() {
    let attachment = |att_type, filename, has_rendered| ClaudeAttachment {
        att_type,
        filename,
        file_type: None,
        has_rendered,
    };
    let cases = [
        (
            attachment("file", Some("/w/MEMORY.md"), true),
            "memory_notes",
        ),
        (
            attachment("file", Some("/w/AutoMem/x.md"), false),
            "memory_notes",
        ),
        (
            attachment("file", Some("/w/docs/x.md"), true),
            "harness_attachments",
        ),
        (
            attachment("instructions", None, true),
            "harness_attachments",
        ),
        // v1 counts every attachment type, rendered or not.
        (
            attachment("prompt_snapshot", None, false),
            "harness_attachments",
        ),
        (
            attachment("deferred_tools_record", None, false),
            "harness_attachments",
        ),
        (attachment("", None, false), "harness_attachments"),
    ];
    for (att, expected) in cases {
        assert_eq!(
            counted(claude_attachment(&claude(), &att)),
            Some(expected),
            "{att:?}"
        );
    }
    let user_line = json!({"type": "user", "message": {"content": "hi"}});
    assert_eq!(counted(claude_user_text(&claude(), &user_line)), None);
    let read = claude_tool(&claude(), "Read", &json!({"file_path": "/w/a.png"}));
    for call in [None, Some(&read)] {
        assert_eq!(counted(image(&claude(), call)), Some("browser_and_images"));
    }
}

#[test]
fn codex_calls_and_events_match_v1() {
    let cases = [
        (Some("exec"), "shell_output"),
        (Some("exec_command"), "shell_output"),
        (Some("shell"), "shell_output"),
        (Some("local_shell"), "shell_output"),
        (Some("write_stdin"), "shell_output"),
        (Some("wait"), "shell_output"),
        (Some("web_search"), "web_fetch_search"),
        (Some("fetch_url"), "web_fetch_search"),
        (Some("browser_open"), "browser_and_images"),
        (Some("spawn_agent"), "agent_results"),
        (Some("read_file"), "code_reads"),
        (Some("view"), "code_reads"),
        (Some("apply_patch"), "other_tools"),
        (None, "other_tools"),
    ];
    for (name, expected) in cases {
        let class = codex_call(&codex(), name, "tools.exec_command({})");
        assert_eq!(class.kind.as_str(), expected, "{name:?}");
        if let Some(name) = name {
            assert_eq!(class.kind, codex_tool_category(name));
            assert_eq!(class.tool.as_str(), name);
        }
        assert_eq!((class.part, class.file.as_deref()), (Part::Unsplit, None));

        // The whole output goes to the call's class, inner items or not.
        let parsed = [ParsedCommand {
            kind: "read",
            path: Some("a.md"),
        }];
        let items = [
            InnerItem::Command {
                cwd: Some("/w"),
                command: "cat a.md",
                parsed: &parsed,
                output_chars: 40,
            },
            InnerItem::Mcp {
                server: "chrome",
                tool: "snapshot",
                output_chars: 60,
            },
        ];
        for inner in [&items[..], &[]] {
            assert_eq!(
                codex_cell(&class, inner, 25),
                vec![CellShare {
                    kind: class.kind,
                    part: Part::Unsplit,
                    tokens: 25,
                    file: None,
                    tool: None,
                }]
            );
        }
    }

    let mcp = [
        (
            json!({"server": "chrome", "tool": "snapshot"}),
            "browser_and_images",
        ),
        (
            json!({"server": "playwright", "tool": "click"}),
            "browser_and_images",
        ),
        (
            json!({"server": "web", "tool": "search"}),
            "web_fetch_search",
        ),
        (json!({"server": "node_repl", "tool": "js"}), "shell_output"),
        (
            json!({"server": "helper", "tool": "agent_run"}),
            "agent_results",
        ),
        (json!({"server": "acme", "tool": "thing"}), "other_tools"),
        (json!("not an object"), "other_tools"),
    ];
    for (invocation, expected) in mcp {
        let class = codex_mcp(&codex(), Some(&invocation));
        assert_eq!(class.kind.as_str(), expected, "{invocation}");
        assert_eq!(class.kind, codex_mcp_category(Some(&invocation)));
        assert_eq!(class.part, Part::Unsplit);
    }
    let class = codex_mcp(
        &codex(),
        Some(&json!({"server": "chrome", "tool": "snapshot"})),
    );
    assert_eq!(class.tool.as_str(), "chrome/snapshot");
    assert_eq!(codex_mcp(&codex(), None).kind, Kind::OtherTools);

    assert_eq!(
        counted(codex_event(&codex(), "web_search_end")),
        Some("web_fetch_search")
    );
    for event in [
        "mcp_tool_call_end",
        "agent_message",
        "context_compacted",
        "",
    ] {
        assert_eq!(counted(codex_event(&codex(), event)), None, "{event}");
    }
}

#[test]
fn codex_message_matches_v1() {
    use ContentLabel::{Absent, Present};
    let harness = Some("harness_attachments");
    let cases = [
        ("developer", Absent, "", harness),
        ("developer", Present(Some("user.input")), "typed", harness),
        (
            "user",
            Present(Some("user.input")),
            "# AGENTS.md instructions",
            None,
        ),
        (
            "user",
            Present(Some("agents_md.instructions")),
            "typed",
            harness,
        ),
        (
            "user",
            Present(Some("environments.environment_context")),
            "",
            harness,
        ),
        // A label that is present but empty is not `user.*`.
        ("user", Present(Some("")), "typed", harness),
        // A label that is not a string is never harness.
        ("user", Present(None), "# AGENTS.md instructions", None),
        ("user", Absent, "# AGENTS.md instructions for /w", harness),
        ("user", Absent, "  <environment_context>", harness),
        ("user", Absent, "<user_instructions>", harness),
        ("user", Absent, "please fix the bug", None),
        ("assistant", Absent, "# AGENTS.md instructions", None),
        ("system", Present(Some("agents_md.instructions")), "", None),
    ];
    for (role, label, text, expected) in cases {
        assert_eq!(
            counted(codex_message(&codex(), role, label, text)),
            expected,
            "{role} {label:?} {text:?}"
        );
    }
}

#[test]
fn repo_relative_matches_v1_names() {
    let workspace = Path::new("/w/repo");
    let mut cache = GitRootCache::default();
    let cases = [
        ("/w/repo/src/main.rs", Some("src/main.rs")),
        ("/w/other/docs/guide.md", Some("guide.md")),
        ("/w/repo", Some("repo")),
        ("relative/notes.md", Some("notes.md")),
        ("/", None),
        ("", None),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            repo_relative(raw, workspace, Some("repohash"), &mut cache).as_deref(),
            expected,
            "{raw}"
        );
        assert_eq!(
            repo_relative(raw, workspace, None, &mut cache).as_deref(),
            expected,
            "{raw}"
        );
    }
}

#[test]
fn wire_ids_and_parts() {
    assert_eq!(
        Kind::ALL.map(Kind::as_str),
        [
            "harness_attachments",
            "shell_output",
            "code_reads",
            "doc_reads_md",
            "doc_reads_html",
            "memory_notes",
            "browser_and_images",
            "web_fetch_search",
            "agent_results",
            "other_tools",
        ]
    );
    assert_eq!(
        Kind::V2.map(Kind::as_str),
        [
            "files_read",
            "command_output",
            "computer_use",
            "web_and_browser",
            "other_tools",
            "automatic_additions",
            "your_prompts",
        ]
    );
    for (index, kind) in Kind::ALL.into_iter().enumerate() {
        assert_eq!(kind.index(), index);
    }
    // Row order inside a day follows declaration order; v1 order is unchanged.
    let mut sorted = Kind::ALL;
    sorted.sort();
    assert_eq!(sorted, Kind::ALL);

    let parts = [
        (Part::ShellRead, "shell_read", Kind::FilesRead),
        (Part::FileTool, "file_tool", Kind::FilesRead),
        (Part::SkillFile, "skill_file", Kind::FilesRead),
        (
            Part::InstructionsLater,
            "instructions_later",
            Kind::FilesRead,
        ),
        (Part::MemoryFile, "memory_file", Kind::FilesRead),
        (Part::Git, "git", Kind::CommandOutput),
        (Part::Search, "search", Kind::CommandOutput),
        (Part::TestsBuilds, "tests_builds", Kind::CommandOutput),
        (Part::OtherCommands, "other_commands", Kind::CommandOutput),
        (Part::AppControl, "app_control", Kind::ComputerUse),
        (Part::Screenshots, "screenshots", Kind::ComputerUse),
        (Part::Web, "web", Kind::WebAndBrowser),
        (Part::Browser, "browser", Kind::WebAndBrowser),
        (Part::Addon, "addon", Kind::OtherTools),
        (Part::AgentReports, "agent_reports", Kind::OtherTools),
        (
            Part::BackgroundReports,
            "background_reports",
            Kind::OtherTools,
        ),
        (Part::BuiltInOther, "built_in_other", Kind::OtherTools),
        (
            Part::StartNotMeasured,
            "start_not_measured",
            Kind::AutomaticAdditions,
        ),
        (
            Part::ToolDescriptionsLater,
            "tool_descriptions_later",
            Kind::AutomaticAdditions,
        ),
        (
            Part::ListsUpdated,
            "lists_updated",
            Kind::AutomaticAdditions,
        ),
        (
            Part::InstructionsReloaded,
            "instructions_reloaded",
            Kind::AutomaticAdditions,
        ),
        (
            Part::MemoryReloaded,
            "memory_reloaded",
            Kind::AutomaticAdditions,
        ),
        (
            Part::CompactionSummary,
            "compaction_summary",
            Kind::AutomaticAdditions,
        ),
        (Part::Reminders, "reminders", Kind::AutomaticAdditions),
        (Part::Environment, "environment", Kind::AutomaticAdditions),
        (Part::HookOutput, "hook_output", Kind::AutomaticAdditions),
        (
            Part::FilesMentioned,
            "files_mentioned",
            Kind::AutomaticAdditions,
        ),
        (
            Part::FilesChanged,
            "files_changed",
            Kind::AutomaticAdditions,
        ),
        (Part::Other, "other", Kind::AutomaticAdditions),
        (Part::ByYou, "by_you", Kind::YourPrompts),
        (Part::ByAgent, "by_agent", Kind::YourPrompts),
    ];
    for (part, id, kind) in parts {
        assert_eq!((part.as_str(), part.kind()), (id, Some(kind)));
        assert!(Kind::V2.contains(&kind));
    }
    assert_eq!(Part::Unsplit.kind(), None);

    // The kinds_version 1 reader tracks no request-1 phase.
    assert_eq!(claude().request_1, Request1::No);
    assert_eq!(codex().request_1, Request1::No);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "has no kinds_version 1 slot")]
fn v2_kind_has_no_v1_slot() {
    Kind::FilesRead.index();
}
