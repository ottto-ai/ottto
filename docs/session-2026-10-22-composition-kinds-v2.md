# Composition kinds v2 classification (2026-10-22)

The `composition_kinds` interface now answers for both methodologies. The
kinds_version 1 reader is unchanged and its output is byte-identical; nothing
emits kinds_version 2 until the new-lines reader builds `LineCtx::v2` contexts.

## What kinds_version 2 classifies

Seven kinds (`files_read`, `command_output`, `computer_use`, `web_and_browser`,
`other_tools`, `automatic_additions`, `your_prompts`), each split into parts.
The wire ids are pinned by `fixtures/context-composition/kinds-v2.json`; a test
checks every id the classifier produces against it.

- Never counted: Claude's `prompt_snapshot` and `deferred_tools_record`, and, in
  a file whose attachments carry `rendered`, any attachment without it.
- Request 1: skipped when the session-start facts measured that start, else
  counted as `automatic_additions` / `start_not_measured`.
- Shell commands (Claude `Bash`, Codex commands): a lexical parser splits a
  command into output-producing pipelines (reads, git, searches, tests and
  builds, other). The output splits evenly across pipelines and a read's share
  evenly across its files. `cd` changes the folder relative paths join to;
  heredocs, `> file`, `tee` and `sed -i` are writes, never reads. Estimates.
- Codex cells: split across the inner `item_completed` items in proportion to
  each item's output length. Codex's own `parsed_cmd` is used when every entry
  is a read, search or listing; otherwise our parser reads the command. Cells
  with no inner item fall back to the first `tools.<name>(` call in the code.
- Add-on servers: computer use and browser are decided by server name, never
  by tool name (browser servers have a tool called `computer`). Plugin
  (`plugin_<p>_<s>`) and connector (`claude_ai_<s>`) forms match by suffix.
- Prompts: written by an agent for Claude side chains and SDK entry points, and
  for any session the reader marks `Author::Agent`. Background task
  notifications are `other_tools` / `background_reports`; compaction summaries
  are `automatic_additions` / `compaction_summary`.

## Contract notes for the reader

- `LineCtx::v2(agent, request_1, cwd, file_has_rendered, author)`; `cwd` is the
  line's own working folder when the transcript records one.
- `ClaudeAttachment.file_type` carries `files[].type` for `instructions` (one
  call per file) and `commandMode` for `queued_command`.
- `codex_call` takes `namespace/name` when the call has a namespace. For a
  local-shell call, pass `command_words_script(action.command)` as the input:
  it quotes each argument, so a file name with spaces or `;` stays one word.
- `InnerItem::Command.command` is the script (`command_words_script` turns a
  `[shell, -lc, script]` array into it); a `file://` cwd is accepted.
- `codex_cell` splits any kinds_version 2 call, Claude's included; a result
  with no call is classified with `claude_tool(ctx, "", &Value::Null)` or
  `codex_call(ctx, None, "")`, not `CallClass::unmatched()` (kinds_version 1).
- `codex_event(ctx, "compacted")` counts a Codex compaction record.
- `GitRootCache::v2()` finds each folder's checkout root (one `stat` per folder
  walked, cached) and its repository hash (once per root), so files in another
  checkout of the workspace's repository keep their repo-relative path.
- `claude_attachment_known` feeds an unknown-type health counter.

## Validation

`cargo test -p ottto-service --lib -- composition_kinds context_composition
session_start`, `cargo clippy -p ottto-service --all-targets -- -D warnings` and
`cargo fmt --all --check` on Rust 1.95.0.
