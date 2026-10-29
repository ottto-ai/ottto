# Daemon rollback switches deleted — 2026-10-28

Six rollback switches have been removed:

- `codex_fast_mode_trace_enabled`: Codex scans read fast-mode trace evidence
  under the existing master collection gate and retain exact receipt replay.
- `claude_workflow_detect_enabled`: Claude Code sessions probe workflow manifests.
- `CLAUDE_PASSIVE_READING_ENABLED`: plain usage slots may reuse passive readings
  after the existing exact account/org binding and freshness checks.
- `CLAUDE_ACTIVITY_CADENCE_ENABLED`: in-use bindings use the five-minute slot;
  unused bindings retain the existing jittered gate and read alternation.
- `CLAUDE_DESKTOP_PAIRS_UPLOAD_ENABLED`: Desktop pair status appends after login
  snapshots, retaining coverage, ordering, upload limits and metered rows.
- `PAUSED_EXPIRED_SLOT_ASKS_FOR_SIGN_IN`: expired slots awaiting Claude Code
  refresh keep the quiet paused presentation and stale reading.

The `OTTTO_CODEX_FAST_MODE_TRACE` and `OTTTO_CLAUDE_WORKFLOW_DETECT` environment
opt-outs are retired. Rollback now requires a code revert and release.
