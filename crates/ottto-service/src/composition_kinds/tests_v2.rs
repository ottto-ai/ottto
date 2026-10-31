//! kinds_version 2 classification through the kinds interface: the seven
//! kinds and their parts, the never-counted records, request 1, the shell
//! command split, Codex inner items and checkout-relative file names. Every id
//! produced must be one the shared wire fixture allows.

use super::shell::{classify_shell, ShellClass, ShellSegment};
use super::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

const WORKSPACE: &str = "/w/repo";

fn ctx() -> LineCtx<'static> {
    LineCtx::v2(Request1::No, Some(Path::new(WORKSPACE)), true, Author::You)
}

fn claude() -> LineCtx<'static> {
    ctx()
}

fn codex() -> LineCtx<'static> {
    ctx()
}

fn with_request_1(mut ctx: LineCtx<'static>, request_1: Request1) -> LineCtx<'static> {
    ctx.request_1 = request_1;
    ctx
}

fn by_agent(mut ctx: LineCtx<'static>) -> LineCtx<'static> {
    ctx.author = Author::Agent;
    ctx
}

/// `kind/part` of a counted verdict, or `skip:<reason>`.
fn ids(verdict: Verdict) -> String {
    match verdict {
        Verdict::Count { kind, part } => {
            assert_eq!(part.kind(), Some(kind), "{part:?} belongs to its kind");
            format!("{}/{}", kind.as_str(), part.as_str())
        }
        Verdict::Skip(reason) => format!("skip:{reason:?}"),
    }
}

/// `kind/part tokens file` lines of a split result.
fn cells(shares: &[CellShare]) -> Vec<String> {
    shares
        .iter()
        .map(|share| {
            format!(
                "{}/{} {} {}",
                share.kind.as_str(),
                share.part.as_str(),
                share.tokens,
                share.file.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

fn split(call: &CallClass, tokens: u64) -> Vec<String> {
    cells(&codex_cell(call, &[], tokens))
}

type Segment = (ShellClass, Vec<String>);

fn segments(script: &str) -> Vec<Segment> {
    classify_shell(script, Some(Path::new(WORKSPACE)))
        .into_iter()
        .map(|ShellSegment { class, paths }| (class, paths))
        .collect()
}

fn paths(list: &[&str]) -> Vec<String> {
    list.iter().map(|path| path.to_string()).collect()
}

#[test]
fn shell_commands_split_into_output_segments() {
    use ShellClass::*;
    let cases: Vec<(&str, Vec<Segment>)> = vec![
        // `cd` changes the folder later relative paths join to.
        (
            "cd sub && cat a.rs",
            vec![(Read, paths(&["/w/repo/sub/a.rs"]))],
        ),
        (
            "cd .. && cat README.md",
            vec![(Read, paths(&["/w/README.md"]))],
        ),
        // An unknown folder keeps the path as written.
        ("cd ~ && cat notes.md", vec![(Read, paths(&["notes.md"]))]),
        ("cd \"$DIR\" && cat a.md", vec![(Read, paths(&["a.md"]))]),
        (
            "bash -lc 'cd /x && cat y.md'",
            vec![(Read, paths(&["/x/y.md"]))],
        ),
        // A command array joined by spaces.
        (
            "/bin/zsh -lc cat a.md b.md",
            vec![(Read, paths(&["/w/repo/a.md", "/w/repo/b.md"]))],
        ),
        ("git -C /other status", vec![(Git, vec![])]),
        // `rev:path` is relative to the checkout root, so it stays as
        // written; `rev:./path` is relative to the folder git runs in.
        (
            "git -C /other show HEAD:src/a.rs",
            vec![(Read, paths(&["src/a.rs"]))],
        ),
        (
            "cd sub && git show abc123:docs/x.md",
            vec![(Read, paths(&["docs/x.md"]))],
        ),
        (
            "cd sub && git show HEAD:./x.md HEAD:../y.md",
            vec![(Read, paths(&["/w/repo/sub/x.md", "/w/repo/y.md"]))],
        ),
        ("git show HEAD", vec![(Git, vec![])]),
        ("git grep -n foo", vec![(Search, vec![])]),
        ("gh pr view 12", vec![(Git, vec![])]),
        // Codex calls this one unknown; it is a read.
        (
            "nl -ba src/a.rs | sed -n '1,40p'",
            vec![(Read, paths(&["/w/repo/src/a.rs"]))],
        ),
        (
            "sed -n '1,40p' src/a.rs",
            vec![(Read, paths(&["/w/repo/src/a.rs"]))],
        ),
        (
            "head -n 5 a.rs b.rs",
            vec![(Read, paths(&["/w/repo/a.rs", "/w/repo/b.rs"]))],
        ),
        (
            "tail -50 log.txt",
            vec![(Read, paths(&["/w/repo/log.txt"]))],
        ),
        (
            "jq '.x' data.json",
            vec![(Read, paths(&["/w/repo/data.json"]))],
        ),
        (
            "awk '{print $1}' f.txt",
            vec![(Read, paths(&["/w/repo/f.txt"]))],
        ),
        (
            "cat < input.txt",
            vec![(Read, paths(&["/w/repo/input.txt"]))],
        ),
        (
            "sudo -u bob cat /etc/hosts",
            vec![(Read, paths(&["/etc/hosts"]))],
        ),
        (
            "cat a.md | grep foo",
            vec![(Read, paths(&["/w/repo/a.md"]))],
        ),
        // Writes are not reads and print nothing.
        ("cat > out.md", vec![]),
        ("cat a.rs > /dev/null", vec![]),
        ("sed -i 's/a/b/' f.rs", vec![]),
        ("perl -pi -e 's/a/b/' f.rs", vec![]),
        ("cat > out.txt <<'EOF'\ncat secret.md\nEOF", vec![]),
        ("echo hi | tee notes.md", vec![(Other, vec![])]),
        ("cat <<EOF\nhello\nEOF", vec![(Other, vec![])]),
        // A heredoc body is data; the command after it still counts.
        (
            "python3 - <<'EOF'\nprint(open('x').read())\nEOF\ncat a.md",
            vec![(Other, vec![]), (Read, paths(&["/w/repo/a.md"]))],
        ),
        // `2>&1` and `>&2` keep the output.
        ("cargo test 2>&1 | tail -20", vec![(TestsBuilds, vec![])]),
        ("echo oops >&2", vec![(Other, vec![])]),
        ("cargo build > build.log 2>&1", vec![]),
        ("rg foo src | head", vec![(Search, vec![])]),
        ("ls -la", vec![(Search, vec![])]),
        ("uv run pytest -q", vec![(TestsBuilds, vec![])]),
        ("npm test", vec![(TestsBuilds, vec![])]),
        ("python3 -m pytest tests", vec![(TestsBuilds, vec![])]),
        ("scripts/run_tests.sh", vec![(TestsBuilds, vec![])]),
        ("timeout 60 cargo check", vec![(TestsBuilds, vec![])]),
        ("echo done", vec![(Other, vec![])]),
        ("mkdir -p x && cd x", vec![]),
        // Tests and `read` print nothing.
        (
            "test -f a.md && cat a.md",
            vec![(Read, paths(&["/w/repo/a.md"]))],
        ),
        (
            "[ -f a.md ] && cat a.md",
            vec![(Read, paths(&["/w/repo/a.md"]))],
        ),
        (
            "[[ -n \"$X\" ]] && cat a.md",
            vec![(Read, paths(&["/w/repo/a.md"]))],
        ),
        (
            "while read l; do echo \"$l\"; done < list.txt",
            vec![(Other, vec![])],
        ),
        // `xargs -I{}`'s placeholder is not a file.
        (
            "xargs -I{} cat {} a.md < list.txt",
            vec![(Read, paths(&["/w/repo/a.md", "/w/repo/list.txt"]))],
        ),
        // Variables set earlier in the command; unknown ones and globs leave
        // the read without a file.
        (
            "F=src/a.rs; cat \"$F\"",
            vec![(Read, paths(&["/w/repo/src/a.rs"]))],
        ),
        (
            "export D=/x; cat ${D}/y.md",
            vec![(Read, paths(&["/x/y.md"]))],
        ),
        ("cat $UNKNOWN", vec![(Read, vec![])]),
        ("cat src/*.rs", vec![(Read, vec![])]),
        ("cat \"$(pwd)/a.md\"", vec![(Read, vec![])]),
        ("for f in a b; do cat $f; done", vec![(Read, vec![])]),
        ("# cat a.md\nls", vec![(Search, vec![])]),
        (
            "git status && cat a.md b.md || echo none",
            vec![
                (Git, vec![]),
                (Read, paths(&["/w/repo/a.md", "/w/repo/b.md"])),
                (Other, vec![]),
            ],
        ),
    ];
    for (script, expected) in cases {
        assert_eq!(segments(script), expected, "{script:?}");
    }
    // Without a session folder, relative paths stay as written.
    assert_eq!(
        classify_shell("cat ./a.md", None),
        vec![ShellSegment {
            class: Read,
            paths: paths(&["a.md"])
        }]
    );
    // Unbalanced quotes and huge commands still end.
    assert_eq!(segments("cat 'a.md").len(), 1);
    let long = "echo x && ".repeat(10_000);
    assert!(segments(&long).len() <= 64);
}

#[test]
fn claude_bash_output_splits_evenly_across_segments_and_files() {
    let call = claude_tool(
        &claude(),
        "Bash",
        &json!({"command": "git status && cat a.md b.md"}),
    );
    assert_eq!((call.kind, call.part), (Kind::CommandOutput, Part::Git));
    assert_eq!(call.tool.as_str(), "Bash");
    assert_eq!(
        split(&call, 100),
        [
            "command_output/git 50 -",
            "files_read/shell_read 25 /w/repo/a.md",
            "files_read/shell_read 25 /w/repo/b.md",
        ]
    );
    // Shares always sum to the output, and rounding never loses a token.
    for tokens in [0, 1, 2, 3, 7, 99, 1_000_003] {
        let total: u64 = codex_cell(&call, &[], tokens)
            .iter()
            .map(|share| share.tokens)
            .sum();
        assert_eq!(total, tokens);
    }
    assert_eq!(split(&call, 1), ["command_output/git 1 -"]);
    assert_eq!(split(&call, 0), ["command_output/git 0 -"]);

    // One share: no share list, the class is the whole result.
    let read = claude_tool(&claude(), "Bash", &json!({"command": "cat src/a.rs"}));
    assert!(read.shares.is_empty());
    assert_eq!(read.file.as_deref(), Some("/w/repo/src/a.rs"));
    assert_eq!(
        split(&read, 9),
        ["files_read/shell_read 9 /w/repo/src/a.rs"]
    );
    // Repeated parts merge.
    let git = claude_tool(
        &claude(),
        "Bash",
        &json!({"command": "git diff; git log -3"}),
    );
    assert!(git.shares.is_empty());
    assert_eq!(split(&git, 9), ["command_output/git 9 -"]);
    // Only writes: what it prints is errors.
    let write = claude_tool(
        &claude(),
        "Bash",
        &json!({"command": "cat > a.md <<EOF\nx\nEOF"}),
    );
    assert_eq!(split(&write, 4), ["command_output/other_commands 4 -"]);
    // Skill, memory and instruction files read through the shell.
    let special = claude_tool(
        &claude(),
        "Bash",
        &json!({"command": "cat .agents/skills/x/SKILL.md AGENTS.md memory/MEMORY.md"}),
    );
    assert_eq!(
        split(&special, 30),
        [
            "files_read/skill_file 10 /w/repo/.agents/skills/x/SKILL.md",
            "files_read/instructions_later 10 /w/repo/AGENTS.md",
            "files_read/memory_file 10 /w/repo/memory/MEMORY.md",
        ]
    );
}

#[test]
fn claude_tools_by_name_and_server() {
    let cases = [
        (
            "Read",
            json!({"file_path": "/w/repo/src/main.rs"}),
            "files_read/file_tool",
        ),
        (
            "Read",
            json!({"file_path": "/w/repo/.claude/skills/x/SKILL.md"}),
            "files_read/skill_file",
        ),
        (
            "Read",
            json!({"file_path": "/m/memory/MEMORY.md"}),
            "files_read/memory_file",
        ),
        (
            "Read",
            json!({"file_path": "/m/memory/user_notes.md"}),
            "files_read/memory_file",
        ),
        // A source folder named memory is code.
        (
            "Read",
            json!({"file_path": "/w/repo/src/memory/alloc.rs"}),
            "files_read/file_tool",
        ),
        (
            "Read",
            json!({"file_path": "/w/repo/sub/CLAUDE.md"}),
            "files_read/instructions_later",
        ),
        ("Read", json!({}), "files_read/file_tool"),
        (
            "NotebookRead",
            json!({"file_path": "/w/repo/a.ipynb"}),
            "files_read/file_tool",
        ),
        ("Skill", json!({"skill": "x"}), "files_read/skill_file"),
        ("Grep", json!({"pattern": "x"}), "command_output/search"),
        ("Glob", json!({"pattern": "*.rs"}), "command_output/search"),
        (
            "Bash",
            json!({"command": "cargo test"}),
            "command_output/tests_builds",
        ),
        ("Bash", json!({}), "command_output/other_commands"),
        ("BashOutput", json!({}), "command_output/other_commands"),
        ("Task", json!({}), "other_tools/agent_reports"),
        ("Agent", json!({}), "other_tools/agent_reports"),
        ("SendMessage", json!({}), "other_tools/agent_reports"),
        ("TaskOutput", json!({}), "other_tools/background_reports"),
        ("WebFetch", json!({}), "web_and_browser/web"),
        ("WebSearch", json!({}), "web_and_browser/web"),
        (
            "Edit",
            json!({"file_path": "/w/repo/a.rs"}),
            "other_tools/built_in_other",
        ),
        ("TodoWrite", json!({}), "other_tools/built_in_other"),
        ("", Value::Null, "other_tools/built_in_other"),
        // Browser servers have a tool called `computer`: the server decides.
        (
            "mcp__Claude_Browser__computer",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__claude-in-chrome__computer",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__Claude_in_Chrome__navigate",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__Control_Chrome__open_url",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__Claude_Preview__preview_screenshot",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__playwright__browser_click",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__plugin_chrome_claude-in-chrome__computer",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__claude_ai_Control_Chrome__open_url",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__chrome-devtools-mcp__take_snapshot",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__puppeteer__puppeteer_click",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__browser-use__open",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__browsermcp__browser_snapshot",
            json!({}),
            "web_and_browser/browser",
        ),
        (
            "mcp__computer-use__app_click",
            json!({}),
            "computer_use/app_control",
        ),
        (
            "mcp__computer-use__app_screenshot",
            json!({}),
            "computer_use/screenshots",
        ),
        (
            "mcp__computer-use__zoom",
            json!({}),
            "computer_use/screenshots",
        ),
        (
            "mcp__plugin_desktop_computer-use__app_type",
            json!({}),
            "computer_use/app_control",
        ),
        (
            "mcp__remote-devices__click",
            json!({}),
            "computer_use/app_control",
        ),
        (
            "mcp__plugin_fleet_remote-devices__screenshot",
            json!({}),
            "computer_use/screenshots",
        ),
        (
            "mcp__claude_ai_Gmail__search_threads",
            json!({}),
            "other_tools/addon",
        ),
        ("mcp__acme__thing", json!({}), "other_tools/addon"),
        ("mcp__acme", json!({}), "other_tools/addon"),
    ];
    for (name, input, expected) in cases {
        let call = claude_tool(&claude(), name, &input);
        assert_eq!(
            format!("{}/{}", call.kind.as_str(), call.part.as_str()),
            expected,
            "{name}"
        );
        assert_eq!(call.part.kind(), Some(call.kind));
    }
    // Add-on tools travel as server/tool.
    let call = claude_tool(&claude(), "mcp__Claude_Browser__computer", &json!({}));
    assert_eq!(call.tool.as_str(), "Claude_Browser/computer");
    assert_eq!(claude_tool(&claude(), "Read", &json!({})).file, None);
    // A relative path joins to the working folder, as shell reads do.
    let relative = claude_tool(&claude(), "Read", &json!({"file_path": "src/../lib/a.rs"}));
    assert_eq!(relative.file.as_deref(), Some("/w/repo/lib/a.rs"));
    let absolute = claude_tool(&claude(), "Read", &json!({"file_path": "/x/./y.md"}));
    assert_eq!(absolute.file.as_deref(), Some("/x/y.md"));
}

#[test]
fn images_follow_their_call_or_the_prompt() {
    let call = |name| claude_tool(&claude(), name, &json!({"file_path": "/w/repo/a.png"}));
    let cases = [
        (
            Some(call("mcp__computer-use__app_click")),
            "computer_use/screenshots",
        ),
        (
            Some(call("mcp__Claude_Browser__computer")),
            "web_and_browser/browser",
        ),
        (Some(call("Read")), "files_read/file_tool"),
        (Some(call("mcp__acme__thing")), "other_tools/addon"),
        (None, "your_prompts/by_you"),
    ];
    for (call, expected) in cases {
        assert_eq!(ids(image(&claude(), call.as_ref())), expected);
    }
    assert_eq!(
        ids(image(&by_agent(claude()), None)),
        "your_prompts/by_agent"
    );
    assert_eq!(
        ids(image(
            &with_request_1(claude(), Request1::StartMeasured),
            None
        )),
        "skip:RequestOne"
    );
    assert_eq!(
        ids(image(
            &with_request_1(claude(), Request1::StartNotMeasured),
            None
        )),
        "automatic_additions/start_not_measured"
    );
}

// A kinds_version 2 reader must classify every call the kinds_version 2 way;
// a kinds_version 1 class slipping through is caught in debug builds.
fn attachment(
    att_type: &'static str,
    file_type: Option<&'static str>,
) -> ClaudeAttachment<'static> {
    ClaudeAttachment {
        att_type,
        filename: None,
        file_type,
        has_rendered: true,
    }
}

#[test]
fn claude_attachments_every_type() {
    let cases = [
        (
            "instructions",
            Some("Project"),
            "automatic_additions/instructions_reloaded",
        ),
        (
            "instructions",
            Some("Local"),
            "automatic_additions/instructions_reloaded",
        ),
        (
            "instructions",
            Some("User"),
            "automatic_additions/instructions_reloaded",
        ),
        (
            "instructions",
            None,
            "automatic_additions/instructions_reloaded",
        ),
        (
            "instructions",
            Some("AutoMem"),
            "automatic_additions/memory_reloaded",
        ),
        ("nested_memory", None, "files_read/instructions_later"),
        (
            "invoked_skills",
            None,
            "automatic_additions/instructions_reloaded",
        ),
        (
            "deferred_tools_delta",
            None,
            "automatic_additions/tool_descriptions_later",
        ),
        ("skill_listing", None, "automatic_additions/lists_updated"),
        (
            "agent_listing_delta",
            None,
            "automatic_additions/lists_updated",
        ),
        (
            "mcp_instructions_delta",
            None,
            "automatic_additions/lists_updated",
        ),
        ("skill_mention", None, "automatic_additions/lists_updated"),
        (
            "total_tokens_reminder",
            None,
            "automatic_additions/reminders",
        ),
        (
            "silent_turn_reminder",
            None,
            "automatic_additions/reminders",
        ),
        ("task_reminder", None, "automatic_additions/reminders"),
        ("todo_reminder", None, "automatic_additions/reminders"),
        (
            "batching_reminder_sent",
            None,
            "automatic_additions/reminders",
        ),
        (
            "critical_system_reminder",
            None,
            "automatic_additions/reminders",
        ),
        ("auto_mode", None, "automatic_additions/reminders"),
        ("auto_mode_exit", None, "automatic_additions/reminders"),
        ("plan_mode", None, "automatic_additions/reminders"),
        ("plan_mode_exit", None, "automatic_additions/reminders"),
        ("plan_mode_reentry", None, "automatic_additions/reminders"),
        ("ultra_effort_enter", None, "automatic_additions/reminders"),
        ("ultra_effort_exit", None, "automatic_additions/reminders"),
        ("environment", None, "automatic_additions/environment"),
        ("session_context", None, "automatic_additions/environment"),
        ("model", None, "automatic_additions/environment"),
        ("date", None, "automatic_additions/environment"),
        ("date_change", None, "automatic_additions/environment"),
        (
            "remote_session_change",
            None,
            "automatic_additions/environment",
        ),
        ("credential_org", None, "automatic_additions/environment"),
        (
            "command_permissions",
            None,
            "automatic_additions/environment",
        ),
        (
            "hook_additional_context",
            None,
            "automatic_additions/hook_output",
        ),
        (
            "hook_blocking_error",
            None,
            "automatic_additions/hook_output",
        ),
        (
            "hook_non_blocking_error",
            None,
            "automatic_additions/hook_output",
        ),
        ("hook_success", None, "automatic_additions/hook_output"),
        ("hook_cancelled", None, "automatic_additions/hook_output"),
        (
            "async_hook_response",
            None,
            "automatic_additions/hook_output",
        ),
        ("file", None, "automatic_additions/files_mentioned"),
        (
            "compact_file_reference",
            None,
            "automatic_additions/files_mentioned",
        ),
        (
            "already_read_file",
            None,
            "automatic_additions/files_mentioned",
        ),
        ("directory", None, "automatic_additions/files_mentioned"),
        ("pdf_reference", None, "automatic_additions/files_mentioned"),
        (
            "selected_lines_in_ide",
            None,
            "automatic_additions/files_mentioned",
        ),
        (
            "opened_file_in_ide",
            None,
            "automatic_additions/files_mentioned",
        ),
        (
            "inlined_image_paths",
            None,
            "automatic_additions/files_mentioned",
        ),
        (
            "edited_text_file",
            None,
            "automatic_additions/files_changed",
        ),
        (
            "edited_image_file",
            None,
            "automatic_additions/files_changed",
        ),
        ("task_status", None, "other_tools/background_reports"),
        ("queued_command", Some("prompt"), "your_prompts/by_you"),
        ("queued_command", None, "your_prompts/by_you"),
        (
            "queued_command",
            Some("task-notification"),
            "other_tools/background_reports",
        ),
        // Never counted, rendered or not, in request 1 or not.
        ("prompt_snapshot", None, "skip:PromptSnapshot"),
        ("deferred_tools_record", None, "skip:DeferredToolsRecord"),
        // Unknown types count as other.
        ("structured_output", None, "automatic_additions/other"),
        ("diagnostics", None, "automatic_additions/other"),
        (
            "a_type_from_a_newer_client",
            None,
            "automatic_additions/other",
        ),
        ("", None, "automatic_additions/other"),
    ];
    for (att_type, file_type, expected) in cases {
        let att = attachment(att_type, file_type);
        assert_eq!(
            ids(claude_attachment(&claude(), &att)),
            expected,
            "{att_type} {file_type:?}"
        );
        let unknown = [
            "structured_output",
            "diagnostics",
            "a_type_from_a_newer_client",
            "",
        ];
        assert_eq!(
            claude_attachment_known(att_type),
            !unknown.contains(&att_type),
            "{att_type}"
        );
    }
    // A queued prompt in a session another agent drives.
    let queued = attachment("queued_command", Some("prompt"));
    assert_eq!(
        ids(claude_attachment(&by_agent(claude()), &queued)),
        "your_prompts/by_agent"
    );

    // The rendered rule: in a file that has `rendered`, an attachment without
    // it never reached the model; older files count it.
    let mut bare = attachment("hook_success", None);
    bare.has_rendered = false;
    assert_eq!(ids(claude_attachment(&claude(), &bare)), "skip:Unrendered");
    let mut older = claude();
    older.file_has_rendered = false;
    assert_eq!(
        ids(claude_attachment(&older, &bare)),
        "automatic_additions/hook_output"
    );
    let mut snapshot = attachment("prompt_snapshot", None);
    snapshot.has_rendered = false;
    assert_eq!(
        ids(claude_attachment(&older, &snapshot)),
        "skip:PromptSnapshot"
    );

    // Request 1: skipped when session start measured it, else its own part.
    let skill_list = attachment("skill_listing", None);
    let instructions = attachment("instructions", Some("AutoMem"));
    for att in [&skill_list, &instructions] {
        assert_eq!(
            ids(claude_attachment(
                &with_request_1(claude(), Request1::StartMeasured),
                att
            )),
            "skip:RequestOne"
        );
        assert_eq!(
            ids(claude_attachment(
                &with_request_1(claude(), Request1::StartNotMeasured),
                att
            )),
            "automatic_additions/start_not_measured"
        );
    }
    for request_1 in [Request1::StartMeasured, Request1::StartNotMeasured] {
        let ctx = with_request_1(claude(), request_1);
        assert_eq!(
            ids(claude_attachment(&ctx, &snapshot)),
            "skip:PromptSnapshot"
        );
    }
    // A measured start skips request 1 before the rendered rule, so only
    // content that would have counted is an unrendered skip.
    assert_eq!(
        ids(claude_attachment(
            &with_request_1(claude(), Request1::StartMeasured),
            &bare
        )),
        "skip:RequestOne"
    );
    assert_eq!(
        ids(claude_attachment(
            &with_request_1(claude(), Request1::StartNotMeasured),
            &bare
        )),
        "skip:Unrendered"
    );
}

#[test]
fn claude_user_text_authors_and_reports() {
    let user = |extra: Value, content: Value| {
        let mut line = json!({"type": "user", "message": {"role": "user", "content": content}});
        for (key, value) in extra.as_object().unwrap() {
            line[key] = value.clone();
        }
        line
    };
    let cases = [
        (
            user(
                json!({"entrypoint": "claude-desktop"}),
                json!("fix the bug"),
            ),
            "your_prompts/by_you",
        ),
        (
            user(
                json!({"entrypoint": "cli"}),
                json!([{"type": "text", "text": "fix"}]),
            ),
            "your_prompts/by_you",
        ),
        (
            user(json!({"entrypoint": "sdk-cli"}), json!("# Brief: fix")),
            "your_prompts/by_agent",
        ),
        (
            user(json!({"entrypoint": "sdk-ts"}), json!("go")),
            "your_prompts/by_agent",
        ),
        (
            user(json!({"entrypoint": "sdk-py"}), json!("go")),
            "your_prompts/by_agent",
        ),
        (
            user(json!({"isSidechain": true}), json!("search the repo")),
            "your_prompts/by_agent",
        ),
        (
            user(json!({}), json!("<command-name>/review</command-name>")),
            "your_prompts/by_you",
        ),
        (
            user(
                json!({}),
                json!("<task-notification>\n<task-id>x</task-id>"),
            ),
            "other_tools/background_reports",
        ),
        (
            user(
                json!({"isCompactSummary": true}),
                json!("This session is being continued"),
            ),
            "automatic_additions/compaction_summary",
        ),
        (
            user(
                json!({"isMeta": true}),
                json!([{"type": "text", "text": "Base directory for this skill: /s"}]),
            ),
            "files_read/skill_file",
        ),
        (
            user(json!({"isMeta": true}), json!("Caveat: local commands")),
            "automatic_additions/other",
        ),
        (
            user(
                json!({}),
                json!("<local-command-stdout>ok</local-command-stdout>"),
            ),
            "automatic_additions/other",
        ),
        (
            user(json!({}), json!("<system-reminder>x</system-reminder>")),
            "automatic_additions/reminders",
        ),
        // Tool results are not the record's own text.
        (
            user(
                json!({}),
                json!([{"type": "tool_result", "tool_use_id": "t", "content": "x"}]),
            ),
            "skip:NotMeasured",
        ),
        (user(json!({}), Value::Null), "skip:NotMeasured"),
    ];
    for (line, expected) in &cases {
        assert_eq!(ids(claude_user_text(&claude(), line)), *expected, "{line}");
    }
    let prompt = user(json!({}), json!("fix it"));
    assert_eq!(
        ids(claude_user_text(&by_agent(claude()), &prompt)),
        "your_prompts/by_agent"
    );
    assert_eq!(
        ids(claude_user_text(
            &with_request_1(claude(), Request1::StartMeasured),
            &prompt
        )),
        "skip:RequestOne"
    );
    assert_eq!(
        ids(claude_user_text(
            &with_request_1(claude(), Request1::StartNotMeasured),
            &prompt
        )),
        "automatic_additions/start_not_measured"
    );
    // kinds_version 1 measures no user text.
    assert_eq!(
        claude_user_text(&LineCtx::v1(), &prompt),
        Verdict::Skip(SkipReason::NotMeasured)
    );
}

fn command<'a>(
    cwd: Option<&'a str>,
    command: &'a str,
    parsed: &'a [ParsedCommand<'a>],
    output_chars: u64,
) -> InnerItem<'a> {
    InnerItem::Command {
        cwd,
        command,
        parsed,
        output_chars,
    }
}

fn parsed<'a>(kind: &'a str, path: Option<&'a str>) -> ParsedCommand<'a> {
    ParsedCommand { kind, path }
}

#[test]
fn codex_cells_split_across_inner_items() {
    let exec = codex_call(
        &codex(),
        Some("exec"),
        "await tools.exec_command({cmd: 'ls'})",
    );
    let read = [parsed("read", Some("a.md"))];
    // Two items: output split by each item's output length.
    let items = [
        command(Some("file:///w/repo"), "cat a.md", &read, 300),
        InnerItem::Mcp {
            server: "codex_apps",
            tool: "slack.search",
            output_chars: 100,
        },
    ];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 40)),
        [
            "files_read/shell_read 30 /w/repo/a.md",
            "other_tools/addon 10 -"
        ]
    );
    // Codex's own parse for reads and searches.
    let search = [parsed("search", None), parsed("list_files", Some("src"))];
    let items = [command(Some("/w/repo"), "rg x && ls src", &search, 10)];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 8)),
        ["command_output/search 8 -"]
    );
    let two = [
        parsed("read", Some("a.md")),
        parsed("read", Some("/abs/b.md")),
    ];
    let items = [command(Some("/w/repo/sub"), "cat a.md /abs/b.md", &two, 10)];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 9)),
        [
            "files_read/shell_read 5 /w/repo/sub/a.md",
            "files_read/shell_read 4 /abs/b.md"
        ]
    );
    // Ours when Codex gave up on any part.
    let unknown = [parsed("unknown", None)];
    let items = [command(
        Some("/w/repo"),
        "nl -ba src/x.rs | sed -n 1,20p",
        &unknown,
        10,
    )];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 6)),
        ["files_read/shell_read 6 /w/repo/src/x.rs"]
    );
    let mixed = [parsed("read", Some("a.md")), parsed("unknown", None)];
    let items = [command(
        Some("/w/repo"),
        "cat a.md && git status",
        &mixed,
        10,
    )];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 6)),
        [
            "files_read/shell_read 3 /w/repo/a.md",
            "command_output/git 3 -"
        ]
    );
    let items = [command(Some("/w/repo"), "cargo test", &[], 10)];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 6)),
        ["command_output/tests_builds 6 -"]
    );
    // Computer use by server name; web search items.
    let items = [
        InnerItem::Mcp {
            server: "cua_repl",
            tool: "js",
            output_chars: 10,
        },
        InnerItem::Extension {
            name: "web.search",
            output_chars: 10,
        },
        InnerItem::WebSearch { output_chars: 0 },
        InnerItem::Mcp {
            server: "codex_app",
            tool: "list_threads",
            output_chars: 10,
        },
    ];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 3)),
        [
            "computer_use/app_control 1 -",
            "web_and_browser/web 1 -",
            "other_tools/agent_reports 1 -"
        ]
    );
    // Items with no output length split evenly.
    let items = [
        InnerItem::WebSearch { output_chars: 0 },
        InnerItem::Mcp {
            server: "acme",
            tool: "x",
            output_chars: 0,
        },
    ];
    assert_eq!(
        cells(&codex_cell(&exec, &items, 5)),
        ["web_and_browser/web 3 -", "other_tools/addon 2 -"]
    );
}

/// `kind/part tokens tool` lines of a split result.
fn tool_cells(shares: &[CellShare]) -> Vec<String> {
    shares
        .iter()
        .map(|share| {
            format!(
                "{}/{} {} {}",
                share.kind.as_str(),
                share.part.as_str(),
                share.tokens,
                share.tool.as_ref().map_or("-", ToolKey::as_str)
            )
        })
        .collect()
}

#[test]
fn add_on_shares_keep_their_server_and_tool() {
    let exec = codex_call(&codex(), Some("exec"), "await tools.github__search({})");
    // Two add-on servers in one cell keep apart, each with its label.
    let items = [
        InnerItem::Mcp {
            server: "github",
            tool: "search",
            output_chars: 30,
        },
        InnerItem::Mcp {
            server: "linear",
            tool: "list_issues",
            output_chars: 10,
        },
        InnerItem::Mcp {
            server: "github",
            tool: "search",
            output_chars: 10,
        },
    ];
    assert_eq!(
        tool_cells(&codex_cell(&exec, &items, 50)),
        [
            "other_tools/addon 40 github/search",
            "other_tools/addon 10 linear/list_issues"
        ]
    );
    // A cell with no inner item: the first `tools.<server>__<tool>(` call.
    assert_eq!(
        tool_cells(&codex_cell(&exec, &[], 7)),
        ["other_tools/addon 7 github/search"]
    );
    // Direct add-on calls of either agent, and built-in calls (no label).
    let calls = [
        claude_tool(&claude(), "mcp__linear__list_issues", &json!({})),
        codex_mcp(
            &codex(),
            Some(&json!({"server": "linear", "tool": "list_issues"})),
        ),
        codex_call(&codex(), Some("mcp__linear/list_issues"), "{}"),
    ];
    for call in &calls {
        assert_eq!(
            tool_cells(&codex_cell(call, &[], 3)),
            ["other_tools/addon 3 linear/list_issues"],
            "{call:?}"
        );
    }
    let read = claude_tool(&claude(), "Read", &json!({"file_path": "a.md"}));
    assert_eq!(
        tool_cells(&codex_cell(&read, &[], 3)),
        ["files_read/file_tool 3 -"]
    );
}

#[test]
fn codex_calls_without_inner_items_fall_back_to_their_input() {
    let cases = [
        // A code cell's first tool call decides.
        (
            Some("exec"),
            "const r = await tools.exec_command({cmd: \"git status\", workdir: \"/w/repo\"});",
            vec!["command_output/git 10 -"],
        ),
        (
            Some("exec"),
            "await tools.exec_command({\"cmd\": 'cat a.md', \"workdir\": '/x'})",
            vec!["files_read/shell_read 10 /x/a.md"],
        ),
        (
            Some("exec"),
            "await tools.exec_command({cmd})",
            vec!["command_output/other_commands 10 -"],
        ),
        (
            Some("exec"),
            "await tools.write_stdin({session_id: 3})",
            vec!["command_output/other_commands 10 -"],
        ),
        (
            Some("exec"),
            "await tools.codex_app__list_threads({})",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("exec"),
            "await tools.mcp__codex_app__wait_threads({})",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("exec"),
            "await tools.clock__curr_time({})",
            vec!["other_tools/built_in_other 10 -"],
        ),
        (
            Some("exec"),
            "await tools.apply_patch('x')",
            vec!["other_tools/built_in_other 10 -"],
        ),
        (
            Some("exec"),
            "await tools.view_image({path: 'a.png'})",
            vec!["files_read/file_tool 10 -"],
        ),
        (
            Some("exec"),
            "console.log(1)",
            vec!["other_tools/built_in_other 10 -"],
        ),
        (
            Some("exec"),
            "mytools.exec_command(x)",
            vec!["other_tools/built_in_other 10 -"],
        ),
        // Function calls with arguments.
        (
            Some("exec_command"),
            r#"{"cmd": "rg foo", "workdir": "/w/repo"}"#,
            vec!["command_output/search 10 -"],
        ),
        (
            Some("shell"),
            r#"{"command": ["bash", "-lc", "cat a.md"], "workdir": "/w/repo"}"#,
            vec!["files_read/shell_read 10 /w/repo/a.md"],
        ),
        (
            Some("shell"),
            r#"{"command": ["cat", "b.md"]}"#,
            vec!["files_read/shell_read 10 /w/repo/b.md"],
        ),
        (
            Some("local_shell"),
            "bash -lc cat a.md",
            vec!["files_read/shell_read 10 /w/repo/a.md"],
        ),
        (
            Some("write_stdin"),
            "{}",
            vec!["command_output/other_commands 10 -"],
        ),
        (
            Some("wait"),
            "{}",
            vec!["command_output/other_commands 10 -"],
        ),
        (
            Some("collaboration/wait_agent"),
            "{}",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("collaboration/spawn_agent"),
            "{}",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("spawn_agent"),
            "{}",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("mcp__cua_repl/js"),
            "{}",
            vec!["computer_use/app_control 10 -"],
        ),
        (
            Some("mcp__codex_app/list_threads"),
            "{}",
            vec!["other_tools/agent_reports 10 -"],
        ),
        (
            Some("mcp__acme/thing"),
            "{}",
            vec!["other_tools/addon 10 -"],
        ),
        (Some("web_search"), "{}", vec!["web_and_browser/web 10 -"]),
        (
            Some("view_image"),
            r#"{"path": "/w/repo/shot.png"}"#,
            vec!["files_read/file_tool 10 /w/repo/shot.png"],
        ),
        // Relative file-tool paths join to the working folder.
        (
            Some("read_file"),
            r#"{"path": "src/main.rs"}"#,
            vec!["files_read/file_tool 10 /w/repo/src/main.rs"],
        ),
        (
            Some("view_image"),
            r#"{"path": "shot.png", "workdir": "/x"}"#,
            vec!["files_read/file_tool 10 /x/shot.png"],
        ),
        (
            Some("apply_patch"),
            "*** Begin Patch",
            vec!["other_tools/built_in_other 10 -"],
        ),
        (
            Some("update_plan"),
            "{}",
            vec!["other_tools/built_in_other 10 -"],
        ),
        (None, "", vec!["other_tools/built_in_other 10 -"]),
    ];
    for (name, input, expected) in cases {
        let call = codex_call(&codex(), name, input);
        assert_eq!(split(&call, 10), expected, "{name:?} {input}");
        assert_eq!(call.tool.as_str(), name.unwrap_or(""));
    }
    // Add-on results keep server/tool and decide by server.
    let mcp = [
        (
            json!({"server": "cua_repl", "tool": "js"}),
            "computer_use/app_control",
        ),
        (
            json!({"server": "playwright", "tool": "computer"}),
            "web_and_browser/browser",
        ),
        (
            json!({"server": "chrome-devtools", "tool": "take_snapshot"}),
            "web_and_browser/browser",
        ),
        (
            json!({"server": "codex_app", "tool": "list_threads"}),
            "other_tools/agent_reports",
        ),
        (
            json!({"server": "node_repl", "tool": "js"}),
            "other_tools/addon",
        ),
        (
            json!({"server": "web", "tool": "search"}),
            "other_tools/addon",
        ),
    ];
    for (invocation, expected) in mcp {
        let call = codex_mcp(&codex(), Some(&invocation));
        assert_eq!(
            format!("{}/{}", call.kind.as_str(), call.part.as_str()),
            expected,
            "{invocation}"
        );
    }
    assert_eq!(
        codex_mcp(&codex(), Some(&json!({"server": "a", "tool": "b"})))
            .tool
            .as_str(),
        "a/b"
    );
    assert_eq!(codex_mcp(&codex(), None).part, Part::Addon);
}

#[test]
fn codex_messages_events_and_authors() {
    use ContentLabel::{Absent, Present};
    let cases = [
        (
            "user",
            Present(Some("user.text")),
            "fix it",
            "your_prompts/by_you",
        ),
        (
            "user",
            Present(Some("user.heartbeat")),
            "",
            "automatic_additions/other",
        ),
        (
            "user",
            Present(Some("agents_md.instructions")),
            "",
            "automatic_additions/instructions_reloaded",
        ),
        (
            "user",
            Present(Some("environments.environment_context")),
            "",
            "automatic_additions/environment",
        ),
        (
            "developer",
            Present(Some("host_skills.instructions")),
            "",
            "automatic_additions/lists_updated",
        ),
        (
            "developer",
            Present(Some("plugins.recommendations")),
            "",
            "automatic_additions/lists_updated",
        ),
        (
            "developer",
            Present(Some("apps.instructions")),
            "",
            "automatic_additions/lists_updated",
        ),
        (
            "developer",
            Present(Some("tools.deferred_namespaces")),
            "",
            "automatic_additions/tool_descriptions_later",
        ),
        (
            "developer",
            Present(Some("hooks.additional_context")),
            "",
            "automatic_additions/hook_output",
        ),
        (
            "developer",
            Present(Some("additional_content.codex_apps_client_time_context")),
            "",
            "automatic_additions/environment",
        ),
        (
            "developer",
            Present(Some("permissions.instructions")),
            "",
            "automatic_additions/other",
        ),
        ("developer", Absent, "", "automatic_additions/other"),
        (
            "user",
            Absent,
            "# AGENTS.md instructions for /w",
            "automatic_additions/instructions_reloaded",
        ),
        (
            "user",
            Absent,
            "<user_instructions>",
            "automatic_additions/instructions_reloaded",
        ),
        (
            "user",
            Absent,
            "  <environment_context>",
            "automatic_additions/environment",
        ),
        (
            "developer",
            Absent,
            "<skills_instructions>",
            "automatic_additions/lists_updated",
        ),
        ("user", Absent, "<heartbeat>", "automatic_additions/other"),
        ("user", Absent, "please fix the bug", "your_prompts/by_you"),
        (
            "user",
            Present(None),
            "please fix the bug",
            "your_prompts/by_you",
        ),
        ("assistant", Absent, "done", "skip:NotMeasured"),
        ("system", Present(Some("user.text")), "", "skip:NotMeasured"),
    ];
    for (role, label, text, expected) in cases {
        assert_eq!(
            ids(codex_message(&codex(), role, label, text)),
            expected,
            "{role} {label:?} {text:?}"
        );
    }
    // An agent-created thread's prompts are written by an agent.
    assert_eq!(
        ids(codex_message(
            &by_agent(codex()),
            "user",
            Present(Some("user.text")),
            "go"
        )),
        "your_prompts/by_agent"
    );
    // The prelude: skipped when session start measured it.
    for (request_1, expected) in [
        (Request1::StartMeasured, "skip:RequestOne"),
        (
            Request1::StartNotMeasured,
            "automatic_additions/start_not_measured",
        ),
    ] {
        let ctx = with_request_1(codex(), request_1);
        assert_eq!(
            ids(codex_message(
                &ctx,
                "developer",
                Present(Some("host_skills.instructions")),
                ""
            )),
            expected
        );
        assert_eq!(
            ids(codex_message(
                &ctx,
                "user",
                Present(Some("user.text")),
                "go"
            )),
            expected
        );
    }
    assert_eq!(
        ids(codex_event(&codex(), "web_search_end")),
        "web_and_browser/web"
    );
    assert_eq!(
        ids(codex_event(&codex(), "compacted")),
        "automatic_additions/compaction_summary"
    );
    for event in [
        "mcp_tool_call_end",
        "agent_message",
        "context_compacted",
        "",
    ] {
        assert_eq!(
            ids(codex_event(&codex(), event)),
            "skip:NotMeasured",
            "{event}"
        );
    }
}

#[test]
fn command_arrays_give_their_script() {
    let cases = [
        (
            json!(["/bin/zsh", "-lc", "cat a.md && ls"]),
            "cat a.md && ls",
        ),
        (json!(["bash", "-c", "x"]), "x"),
        (
            json!(["/usr/bin/env", "bash", "-c", "x"]),
            "/usr/bin/env bash -c x",
        ),
        (json!(["bash", "-euc", "cat a.md", "arg0"]), "cat a.md"),
        // Only a shell's `-c` takes a script.
        (json!(["head", "-c", "10"]), "head -c 10"),
        (
            json!(["python", "-c", "cat a.md; git status"]),
            "python -c 'cat a.md; git status'",
        ),
        (json!(["bash", "run.sh"]), "bash run.sh"),
        (json!(["cat", "a.md"]), "cat a.md"),
        (json!(["cat", "my notes.md"]), "cat 'my notes.md'"),
        (json!(["cat", "a; git status"]), "cat 'a; git status'"),
        (json!(["echo", "it's"]), "echo 'it'\\''s'"),
        (json!(["printf", ""]), "printf ''"),
        (json!([]), ""),
    ];
    for (words, expected) in cases {
        assert_eq!(command_words_script(words.as_array().unwrap()), expected);
    }
    // Quoted arguments keep their boundaries through the shell parser.
    for (words, expected) in [
        (
            json!(["cat", "docs/my notes.md"]),
            vec!["/w/repo/docs/my notes.md"],
        ),
        (
            json!(["cat", "a; git status"]),
            vec!["/w/repo/a; git status"],
        ),
        (json!(["cat", "it's.md"]), vec!["/w/repo/it's.md"]),
    ] {
        let script = command_words_script(words.as_array().unwrap());
        assert_eq!(
            classify_shell(&script, Some(Path::new(WORKSPACE))),
            vec![ShellSegment {
                class: ShellClass::Read,
                paths: paths(&expected)
            }],
            "{script}"
        );
    }
    let call = codex_call(
        &codex(),
        Some("shell"),
        r#"{"command": ["cat", "a; git status"], "workdir": "/w/repo"}"#,
    );
    assert_eq!(
        split(&call, 4),
        ["files_read/shell_read 4 /w/repo/a; git status"]
    );
}

#[test]
fn split_tokens_is_exact_and_proportional() {
    assert_eq!(split_tokens(10, &[1, 1, 1]), [4, 3, 3]);
    assert_eq!(split_tokens(10, &[3, 1]), [8, 2]);
    assert_eq!(split_tokens(0, &[1, 2]), [0, 0]);
    assert_eq!(split_tokens(7, &[0, 0]), [7, 0]);
    let shares = split_tokens(u64::MAX, &[u64::MAX, 1]);
    assert_eq!(
        shares.iter().map(|share| u128::from(*share)).sum::<u128>(),
        u128::from(u64::MAX)
    );
    for total in 0..50 {
        for weights in [
            &[1u64][..],
            &[5, 3, 1],
            &[720_720, 360_360, 360_360],
            &[0, 9],
        ] {
            assert_eq!(split_tokens(total, weights).iter().sum::<u64>(), total);
        }
    }
}

#[test]
fn checkout_relative_names_need_the_v2_cache_and_the_same_repository() {
    let scratch = crate::test_scratch::ScratchDir::new("composition-git-roots");
    let root = scratch.to_string_lossy().into_owned();
    for checkout in ["main", "worktree", "elsewhere"] {
        std::fs::create_dir_all(scratch.join(checkout).join(".git")).unwrap();
    }
    std::fs::create_dir_all(scratch.join("plain/src")).unwrap();
    fn fake_hash(root: &Path) -> Option<String> {
        match root.file_name()?.to_str()? {
            "main" | "worktree" => Some("repo-a".to_string()),
            _ => Some("repo-b".to_string()),
        }
    }
    let workspace = scratch.join("main");
    let mut v2 = GitRootCache {
        repository_hash: fake_hash,
        ..GitRootCache::v2()
    };
    let mut v1 = GitRootCache::default();
    let cases = [
        // (path, v2 name, v1 name)
        (format!("{root}/main/src/a.rs"), "src/a.rs", "src/a.rs"),
        // Another checkout of the same repository keeps its folder.
        (format!("{root}/worktree/docs/b.md"), "docs/b.md", "b.md"),
        (
            format!("{root}/worktree/docs/../lib/c.rs"),
            "lib/c.rs",
            "c.rs",
        ),
        // Another repository, or no repository: the name only.
        (format!("{root}/elsewhere/src/d.rs"), "d.rs", "d.rs"),
        (format!("{root}/plain/src/e.rs"), "e.rs", "e.rs"),
        ("relative/f.md".to_string(), "f.md", "f.md"),
    ];
    for (raw, v2_name, v1_name) in &cases {
        assert_eq!(
            repo_relative(raw, &workspace, Some("repo-a"), &mut v2).as_deref(),
            Some(*v2_name),
            "{raw}"
        );
        assert_eq!(
            repo_relative(raw, &workspace, Some("repo-a"), &mut v1).as_deref(),
            Some(*v1_name),
            "{raw}"
        );
    }
    // No workspace repository: nothing to match.
    assert_eq!(
        repo_relative(&cases[1].0, &workspace, None, &mut v2).as_deref(),
        Some("b.md")
    );
    // Folders and roots are looked up once each.
    assert!(v2.roots.contains_key(&format!("{root}/worktree/docs")));
    assert_eq!(v2.hashes.len(), 2);
    assert!(v1.roots.is_empty() && v1.hashes.is_empty());
}

fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

#[test]
fn repository_hash_matches_the_workspace_identity_without_git() {
    let scratch = crate::test_scratch::ScratchDir::new("composition-repo-hash");
    let main = scratch.join("main");
    std::fs::create_dir_all(&main).unwrap();
    git(&main, &["init", "-q"]);
    git(&main, &["commit", "-q", "--allow-empty", "-m", "init"]);
    let worktree = scratch.join("worktree");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "side",
            worktree.to_str().unwrap(),
        ],
    );
    let identity = |root: &Path| {
        crate::context_footprint::resolve_repository_identity(root, false).repository_hash
    };
    for root in [&main, &worktree] {
        let hash = repository_hash(root);
        assert!(hash.is_some(), "{root:?}");
        assert_eq!(hash, identity(root), "{root:?}");
    }
    // Both checkouts are one repository.
    assert_eq!(repository_hash(&main), repository_hash(&worktree));
    // A `.git` that is not a git folder names no repository.
    let fake = scratch.join("fake");
    std::fs::create_dir_all(fake.join(".git")).unwrap();
    assert_eq!(repository_hash(&fake), None);
    // Nor one with `HEAD` alone: git also needs `objects` and `refs`.
    std::fs::write(fake.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    assert_eq!(repository_hash(&fake), None);
    std::fs::create_dir_all(fake.join(".git/objects")).unwrap();
    std::fs::create_dir_all(fake.join(".git/refs")).unwrap();
    assert!(repository_hash(&fake).is_some());
    // A pointer without the space after `gitdir:` is not one git reads.
    let pointer = scratch.join("pointer");
    std::fs::create_dir_all(&pointer).unwrap();
    let main_git = main.join(".git");
    std::fs::write(
        pointer.join(".git"),
        format!("gitdir:{}\n", main_git.display()),
    )
    .unwrap();
    assert_eq!(repository_hash(&pointer), None);
    std::fs::write(
        pointer.join(".git"),
        format!("gitdir: {}\n", main_git.display()),
    )
    .unwrap();
    assert_eq!(repository_hash(&pointer), repository_hash(&main));
}

#[cfg(unix)]
#[test]
fn a_fifo_in_place_of_a_git_pointer_never_blocks() {
    let scratch = crate::test_scratch::ScratchDir::new("composition-git-fifo");
    let root = scratch.join("checkout");
    std::fs::create_dir_all(&root).unwrap();
    let fifo = root.join(".git");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    // Opening a FIFO for reading blocks until a writer comes; the check
    // for a regular file returns first.
    let (done, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(repository_hash(&root));
    });
    let hash = wait
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the lookup returned");
    assert_eq!(hash, None);
}

#[test]
fn a_full_cache_stops_looking_up_and_counts() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn counted_hash(_root: &Path) -> Option<String> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        Some("repo-a".to_string())
    }
    let mut cache = GitRootCache {
        repository_hash: counted_hash,
        ..GitRootCache::v2()
    };
    for index in 0..MAX_CACHED_FOLDERS {
        cache.hashes.insert(format!("/r/{index}"), None);
        cache.roots.insert(format!("/f/{index}"), None);
    }
    assert_eq!(cache.root_hash("/r/new"), None);
    assert_eq!(cache.root_of("/f/new/sub"), None);
    // Cached entries still answer.
    assert_eq!(cache.root_of("/f/1"), None);
    assert_eq!(cache.skipped(), 2);
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(cache.hashes.len(), MAX_CACHED_FOLDERS);
    assert_eq!(cache.roots.len(), MAX_CACHED_FOLDERS);
}

/// Every Part but `Unsplit`.
const PARTS: [Part; 31] = [
    Part::ShellRead,
    Part::FileTool,
    Part::SkillFile,
    Part::InstructionsLater,
    Part::MemoryFile,
    Part::Git,
    Part::Search,
    Part::TestsBuilds,
    Part::OtherCommands,
    Part::AppControl,
    Part::Screenshots,
    Part::Web,
    Part::Browser,
    Part::Addon,
    Part::AgentReports,
    Part::BackgroundReports,
    Part::BuiltInOther,
    Part::StartNotMeasured,
    Part::ToolDescriptionsLater,
    Part::ListsUpdated,
    Part::InstructionsReloaded,
    Part::MemoryReloaded,
    Part::CompactionSummary,
    Part::Reminders,
    Part::Environment,
    Part::HookOutput,
    Part::FilesMentioned,
    Part::FilesChanged,
    Part::Other,
    Part::ByYou,
    Part::ByAgent,
];

struct WireFixture {
    kinds: Vec<String>,
    part_kind: BTreeMap<String, String>,
}

fn wire_fixture() -> WireFixture {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/context-composition/kinds-v2.json"
    ))
    .expect("fixture is JSON");
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .expect("array")
            .iter()
            .map(|id| id.as_str().expect("string").to_string())
            .collect()
    };
    assert_eq!(fixture["kinds_version"], 2);
    WireFixture {
        kinds: strings(&fixture["kinds"]),
        part_kind: fixture["part_kind"]
            .as_object()
            .expect("object")
            .iter()
            .map(|(part, kind)| (part.clone(), kind.as_str().expect("string").to_string()))
            .collect(),
    }
}

#[test]
fn wire_ids_match_the_shared_fixture() {
    let fixture = wire_fixture();
    assert_eq!(Kind::V2.map(Kind::as_str).to_vec(), fixture.kinds);
    let ours: BTreeMap<String, String> = PARTS
        .iter()
        .map(|part| {
            (
                part.as_str().to_string(),
                part.kind().expect("v2 part").as_str().to_string(),
            )
        })
        .collect();
    assert_eq!(ours, fixture.part_kind);
}
