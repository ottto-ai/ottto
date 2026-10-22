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
- `before`: prompt size of the last owned request with a request id before the
  compaction. Responses without a request id are skipped, so this can come
  from an earlier request than the true last one (usually smaller). NULL when
  there is none.
- `after`: prompt size of the first owned request with a request id after the
  compaction. Responses without a request id are skipped, so this can come
  from a later request (usually larger). NULL until seen.
- Exactly: the owned non-zero request with the largest sequence below the
  boundary, and the one with the smallest sequence at or after it. Prompt
  size = input + cache read + cache write, the first/peak/last measure.
- `trigger`: `compactMetadata.trigger` of the boundary (`auto` or `manual`;
  `idle` when Claude Code writes it). An automatic compaction whose last owned
  request is 50 minutes or more earlier is reported as `idle` (Claude Code
  compacts an idle session shortly before its one-hour prompt cache expires).
  A legacy summary has no trigger. Unknown values are omitted.
- Id-less responses carry no occurrence, so they are never a size or a point,
  although the file-birth first/peak/last may read them. A size is therefore
  only ever under-counted this way, never over-counted, and a copied request
  is never a size.
- Local diagnostic: when responses are resolved, a compaction whose response
  just before (or just after) has no request id is marked (two flags in the
  observation's existing padding). The fold counts the shipped events so
  marked as `id_less_response_before_compaction_count` and
  `id_less_response_after_compaction_count` on the existing local
  `claude context basis counts` log line. Never uploaded. The strict path
  always counts zero (its request ids are complete).

## Local points

The same rule as Codex (pinned first point, 15-minute slots, big-change rule,
64-point cap with halving, unique seconds) over the owned requests in sequence
order. Built only when the session's last activity is within 75 minutes of
collection. Local only (`serde(skip)`). The requests are fed in sequence order
without being collected: the strict path's slice is already in order (one
pass); the file-birth path's request-id map is not, so
`LocalContextPoints::from_requests_by_sequence` replays it in fixed windows of
4,096 `(sequence, position)` keys, at most eight passes. Its exact iterator
length refuses maps above 32,768 entries before traversal. Admitted results
equal a stable sort by sequence; refusal clears only the LOCAL points, never
emits a partial curve, and increments
`local_context_points_work_refused_session_count` on the existing local
context-basis counter line. Compactions, first/peak/last, first-own request
time, money, identity, upload decisions and tuple-clear rules stay unchanged.

## Weight

- Reads: none added.
- Per line: one JSON pointer read on `compact_boundary` lines only.
- Per fold, items with an owned boundary: one pass over the owned compaction
  observations that keeps only the newest 64 distinct `at` values (sorted,
  evict before insert; length and capacity at most 64), then one pass over the
  owned requests with at most 65 gap slots, 64 cuts and 64 before/after
  entries. The legacy pairing set is built once and shared with the existing
  summary. Nothing 5b builds grows with the marker or request count. Items
  without an owned boundary: no request work.
- Per fold, recent items only: unordered points use one fixed 4,096-entry
  window (96 KiB for 24-byte reference tuples on 64-bit targets), at most
  eight complete map traversals (`work <= 8*n` entry visits). No empty final
  pass. Above the cap: zero point visits or scratch allocation. The strict
  path consumes its already ordered slice once, without ordering scratch or
  this cap. At most 64 points of 8 bytes are retained and charged as before.
  Fold transients have no heap charging site; scratch capacity is structurally
  fixed and asserted during selection.
- Existing debt, not changed here: the Claude parser keeps one
  `ClaudeCompactionObservation` (at most 120 bytes) per marker for the whole
  parse, and the fold's existing summary and owned-boundary copies are as
  long. That vector is owned by the Claude parser / StateMissing work; 5b does
  not grow its entries or copy it again.
- Retained state: the trigger byte and the two id-less flags sit in
  `ClaudeCompactionObservation`'s existing padding (at most 120 bytes, pinned);
  no new per-session vector. Id-less marking uses `partition_point` on the
  non-decreasing response-count cuts, then visits only the matching cuts
  (the response sequence and its saturating successor). Repeated cuts are
  all marked; out-of-order marker timestamps do not affect the search.
  The existing `compaction_before` check per response is unchanged.
- Upload: about 84 bytes per Claude event; outside the content hash, semantic
  fingerprint, envelope component hashes, revision v2 input and body witness.

## First own request time (`first_own_request_at`)

An optional Claude Code snapshot field: when the session's first own request
(design E's first own response) ended, RFC 3339 UTC, the same string the
transcript gave that response. Display-only: the web hides context hours that
end before it; money, cost, identity, family and proofs never read it.

- Set only by the file-birth admission, from values the fold already holds:
  `first_own_sequence` -> the occurrence with that sequence -> its terminal
  timestamp. No new reads, no new state, no parser or scan identity bump.
- Only when the birth was measured: a root transcript with a usable file
  birth, admitted, and not partially pre-birth (no copied response or copied
  boundary at or before the first own request). Absent otherwise: withheld
  verdicts, unknown birth, partially pre-birth, subagent files (exempt from
  the rule, so not measured), the strict path (with or without design E),
  Codex and Pi. Also absent when the first own response had no request id (no
  occurrence), any of its records was unstamped (the kept timestamp could be
  an earlier partial's) or its timestamp is not UTC. Never a guess, never
  `source_started_at`.
- Copied records later in the file with older timestamps never win: the
  value follows sequence, not the earliest timestamp.
- `clear_claude_context_posture` clears it with the other context scalars;
  the strict branch clears it too; `finish()` never sets it.
- Outside the content hash, semantic fingerprint, envelope component hashes,
  revision v2 input and body witness, so a change alone does not re-upload
  and old idle sessions keep today's behaviour until they upload for another
  reason (no backfill).
- Weight: about 30 bytes on the upload when present; charged like the other
  optional strings in `heap_layout_bound` and `retry_retention_bound`; the
  retry copy keeps it. Per admitted item, one pass over its request map to
  find the first own occurrence and one timestamp parse.
- The backend must accept the field (optional timestamp, malformed -> null)
  before a Mac release that sends it.
