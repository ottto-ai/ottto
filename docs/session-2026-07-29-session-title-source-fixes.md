# Session title source fixes

Date: 2026-07-29

The Claude Code snapshot parser now consumes transcript `custom-title` events
and normalizes generated PR-fixer slugs such as
`pr-fixer-3532-<session-id>` to `Fix PR #3532`. This restores a durable title
that parser v21 ignored.

The parser also rejects first prompts beginning with resume boilerplate such as
`Continue the SAME ...` as title candidates. Legitimate task titles beginning
with `Continue`, such as `Continue Stage 3 backfill execution`, remain valid.

Claude subagent snapshots now emit only the task label as `agent_label`.
Parent-session provenance remains in the dedicated parent relationship fields;
the collector no longer composes `spawned by <parent> - <task>` into the title.
The subagent scan fingerprint still includes task metadata and workflow
manifests so late labels trigger re-emission.

These semantic parser changes bump the Claude Code parser and scan identity from
v21 to v22. The snapshot audit golden fixture and focused parser tests cover the
new behavior.
