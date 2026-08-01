# Claude compaction event deduplication

Date: 2026-08-01

## Problem

Current Claude Code transcripts represent one context compaction with two
adjacent records: a `type=system, subtype=compact_boundary` record and a legacy
`type=user, isCompactSummary=true` record a few milliseconds apart. Stable
0.1.102 recognized both formats independently, so historical replay counted
one real compaction twice.

## Change

- Pair current and legacy observations within 100 milliseconds and prefer the
  current boundary timestamp for the resulting event.
- Continue counting either record shape when it appears alone.
- Advance the Claude parser provenance to `claude_code_jsonl:v25`.
- Advance the one-shot Claude replay revision so corrected snapshots replace
  the doubled historical values after upgrade.

## Validation

- The parser fixture mirrors the provider's observed reverse-timestamp record
  order and proves the pair counts once.
- Standalone legacy and current events remain separate.
- Backfill tests prove the corrected replay revision is one-shot.
