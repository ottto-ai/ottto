# Claude Code compaction sizes and local context points

Claude Code snapshots now carry the same `compaction_events` list Codex
snapshots carry (see `session-2026-10-22-codex-compaction-sizes-and-local-points.md`
for the shared shape), and current Claude Code sessions carry the Mac app's
local context points. Both come from values the ownership fold already holds:
the retained compaction observations and the owned request occurrences. There
are no new reads, no new tail reads, no new pass and no parser or scan identity
bump.

## Where the list is built

Only in the ownership fold, through one setter, `set_claude_compaction_scalars`,
which writes the compaction count, timestamps, four totals, sizes and local
points from one owned set. Both posture writers call it:

- `rebuild_claude_context_posture` (strict ownership, complete request index):
  the owned occurrences minus any copied prefix, and the boundaries after it;
- `apply_own_context_scalars` (file-birth admission, and the strict branch
  whose request identity is incomplete): the occurrences the file-birth rule
  counts as own, and the owned boundaries.

`clear_claude_context_posture` clears the sizes and the points with the rest of
the tuple. `finish()` never builds Claude sizes or points, so a body the fold
never judged carries none.

## Values

- Events are exactly the ones `claude_compaction_summary` lists: every
  `compact_boundary`, plus every legacy summary the pairing
  (`paired_claude_legacy_compactions`) leaves unpaired, each with a timestamp;
  same sort, dedup and newest-64 bound, so `at` matches `compaction_timestamps`
  entry for entry.
- `before`: the owned non-zero request with the largest sequence below the
  boundary. `after`: the owned non-zero request with the smallest sequence at
  or after it, absent until seen. Prompt size = input + cache read + cache
  write, the first/peak/last measure.
- `trigger`: `compactMetadata.trigger` of the boundary (`auto` or `manual`;
  `idle` when Claude Code writes it). An automatic compaction whose last owned
  request is 50 minutes or more earlier is reported as `idle` (Claude Code
  compacts an idle session shortly before its one-hour prompt cache expires).
  A legacy summary has no trigger. Unknown values are omitted.
- Id-less responses carry no occurrence, so they are never a size or a point,
  although the file-birth first/peak/last may read them.

## Local points

The same rule as Codex (pinned first point, 15-minute slots, big-change rule,
64-point cap with halving, unique seconds) over the owned requests in sequence
order. Built only when the session's last activity is within 75 minutes of
collection; only then are the owned requests ordered. Local only (`serde(skip)`).

## Weight

- Reads: none added.
- Per line: one JSON pointer read on `compact_boundary` lines only.
- Per fold, items with an owned boundary: one pass over the owned requests,
  memory bounded by the events (at most 65 gap slots). Items without one: no work.
- Per fold, recent items only: one ordered list of owned request references
  (8 bytes each) for the points; at most 64 points of 8 bytes kept.
- Retained state: the trigger byte sits in `ClaudeCompactionObservation`'s
  existing padding (size pinned at 120 bytes); no new per-session vector.
- Upload: about 84 bytes per Claude event; outside the content hash, semantic
  fingerprint, envelope component hashes, revision v2 input and body witness.
