# Claude compaction boundary parsing

Date: 2026-07-30

## Problem

Claude Code now records automatic and manual compaction with a system event
whose subtype is `compact_boundary`. The snapshot parser only recognized the
older user-message shape carrying `isCompactSummary: true`, so current
transcripts reported an observed compaction count of zero.

## Change

- Count both the current `type=system, subtype=compact_boundary` record and the
  legacy `type=user, isCompactSummary=true` record.
- Preserve event timestamps for both shapes.
- Advance the Claude snapshot parser provenance to `claude_code_jsonl:v24`.
- Declare a one-shot Claude historical replay revision so installed daemons
  re-read existing transcripts and correct previously uploaded snapshots.

## Validation

- Parser fixtures cover current, legacy, false, and unrelated event shapes.
- Backfill tests prove the replay is requested once and stays complete after
  its revision marker is recorded.
- Targeted Rust compaction and backfill tests pass.
