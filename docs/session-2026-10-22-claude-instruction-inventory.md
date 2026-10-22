# Claude Code instruction-file inventory

The six-hour Claude Code footprint collector now adds an optional
`instruction_inventory` block to each `/context` capture of a git checkout. It
answers one question: which `AGENTS.md` and CLAUDE files (`CLAUDE.md`,
`.claude/CLAUDE.md`, `CLAUDE.local.md`) exist in that checkout, and did the same
capture list them as loaded? The backend uses it to explain instruction files
Claude Code does not pick up on its own. The daemon reports facts only.

What is collected, per capture:

- `started_at_root`: the capture ran at the checkout's top level.
- `claude_mode`: Claude Code's Project instructions setting
  (`pluginConfigs.<agents-md plugin>.options.instructionFiles`) for the login the
  `/context` run uses: managed settings plus `~/.claude/settings.json`. Only named
  keys are read. No value means Claude Code's default, `claude-md-or-agents-md`.
  It is `unknown` when a consulted file is unreadable, not a regular file,
  oversized or malformed, when the legacy `projectInstructions` option is present,
  when the plugin is disabled, or when values disagree or are not one of
  `claude-md-or-agents-md` / `claude-md-and-agents-md`.
- `files.entries[]`: repo-relative path, size from `stat`, and whether the path
  matches a Project/Local row of the same capture. Both sides are compared after
  resolving symlinks, so `CLAUDE.md -> AGENTS.md` marks both observed.

How the list is built (no file contents, no hashes, no worktree data, no
whole-checkout walk):

- `stat` of the four root names; one `git ls-files -z` for tracked `AGENTS.md`
  files (index only, `.claude` folders excluded); `stat` of the three CLAUDE names
  in each folder between a nested `AGENTS.md` and the root, memoized per folder.
  This finds ignored files such as `CLAUDE.local.md` without listing untracked
  files.
- Order: root files first, then every other path in bytewise order.
- Bounds: 200 entries, 8 KiB serialized block (checked while adding entries with a
  512-byte reserve for other fields), 1 s cooperative time budget checked between
  stats and observed checks, at most 1,000 nested `AGENTS.md` candidates and 2,000
  memoized folders, git output capped at 1 MiB and drained while git runs, 2 s git
  timeout. A single blocked `stat` cannot be interrupted.
- Anything not established makes the list partial with a reason (`file_cap`,
  `size_cap`, `time_budget`, `stat_error`, `git_failed`, `paths_withheld`), never
  "missing". A tracked file deleted locally is simply not listed. A path the
  backend would refuse is withheld (`paths_withheld`) rather than rejecting the
  snapshot.

Privacy: paths are collected only when the activity hint explicitly sends
`workspace_labels_enabled: true`. The hint decoder now records whether that field
was sent; the labels themselves keep their old default. With labels off the block
carries only the mode and `paths_withheld`. When the hint cannot be read or omits
the field, no block is sent. The existing
collection opt-outs remove the block with the rest of the capture.

Upload: the block joins the existing upload-on-change digest only when present,
so captures without it (and Codex footprints) keep their digest, and the first
capture with a block uploads once. The shared `git_stdout` helper now drains
output while git runs instead of polling with an undrained pipe.

The frozen wire fixture `fixtures/context-footprint/instruction-inventory-v1.json`
is shared with the backend contract tests; the Rust tests build each variant from
a synthetic repository and compare it exactly. Backend admission must be deployed
before a daemon release sends the block.
