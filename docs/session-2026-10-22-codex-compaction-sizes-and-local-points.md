# Codex compaction sizes and local context points

Codex snapshots now say how large the context was around each compaction, and
the Sessions list carries a few context points per current session for the Mac
app's graph. Both values come from the incremental tail pass that already
parses every owned rollout line. There are no new reads, no new pass and no
whole-file read.

## Upload field: `compaction_events`

`SnapshotItem.compaction_events` is a list of `{at, before, after, trigger}`:

- one entry per `compaction_timestamps` entry, with `at` byte-identical to it.
  It uses the same sort, the same dedup (the first marker in parse order wins
  an equal timestamp) and the same newest-64 bound;
- `before` is the prompt size of the last owned non-zero request before the
  marker. It is the session's `last_turn_context_tokens` value at that moment,
  so it uses the same measure and the same request set as first, peak and last
  (Codex `input_tokens` already includes cached input);
- `after` is the prompt size of the first counted non-zero request after the
  marker. Exact duplicate records and re-emissions are not counted, and
  zero-size records are skipped. Two markers with no request between them share
  one `after`. It stays absent until such a request is seen;
- `trigger` stays absent for Codex: the rollout states none. The closed values
  `auto`, `manual` and `idle` are reserved for Claude Code.

Unknown values are omitted, never null. An empty list is omitted.

The list is additive evidence. It is outside the `context_posture` component,
the content hash, the semantic fingerprint and the body witness (and its
version), so it never re-mints session identity. There is no parser version
bump and no scan identity bump. A body that changes only in this list is not
re-sent: a new `after` arrives together with the request that also moves usage.
Idle sessions and later corrections are not re-sent, by design. There is no
cutover: a resumed session also gets sizes for its earlier compactions.

State: one 16-byte size pair per marker. These pairs sit in a vector aligned
with the accumulator's `compaction_timestamps` and are bounded at finish with
them. The type exposes only `note_marker`, `note_counted_request` and
`into_events`, so a swap to a bounded map keyed by `at` stays local to
`snapshots/compaction_events.rs`.

Claude Code leaves the list empty in this change. Its events will be built by
the ownership fold, never in `finish()`.

## Local only: context points

`SnapshotItem.local_context_points` is `serde(skip)`: it is never serialized or
uploaded. The points come from the same Codex block that sets first, peak and
last. So the first point is the first request, the last point is the latest
request, and no point is above the peak:

- zero-size requests and requests without a usable timestamp are skipped;
- inside one 15-minute wall-clock slot, a newer request replaces the tail point
  unless the change is big (`max(20%, 20K)` tokens);
- at most 64 points per session. On overflow, every other middle point is
  dropped, keeping the first and the last;
- only items whose last activity is within 75 minutes of collection carry
  points. The accumulator itself is not gated, so a tail pass and a full read
  agree.

## Sessions list (`ActiveSession`)

`ActiveSession` gains `compaction_events` (`at`, `before_tokens`,
`after_tokens`, `trigger`), `context_points` (`at`, `tokens`),
`first_turn_context_tokens` and `last_turn_context_tokens`. All of them are
omitted when empty or unknown. The list file
`active_sessions/<source>.json` is now written as compact JSON, because the
status path reads it on every poll. That file is the 15-minute list and is
rewritten each scan; a row leaves it with its session.

## Weight

- Per Codex accumulator: two empty vectors (48 bytes). It grows by 16 bytes
  per compaction marker and by at most 512 bytes of points.
- Per `SnapshotItem`: two empty vectors (48 bytes).
- Per Codex line: a `compacted` marker pushes 16 bytes. A positive
  `token_count` record parses its timestamp once and updates or appends one
  8-byte point. A counted record checks the newest size pair. Every other line
  costs nothing.
- Upload: 0 bytes for sessions that never compact. About 65 bytes per Codex
  event, so at most about 4 KB at the 64 cap.

## Tests

- `snapshots/compaction_events.rs`: shared `after`, the 64 bound matching
  `bounded_compaction_timestamps` with duplicate and out-of-order markers, and
  the wire shape.
- `snapshots/local_context_points.rs`: the pinned first point, slot overwrite,
  big changes, skips, the out-of-order clamp, halving on overflow and the
  75-minute gate.
- `codex_compaction_events_take_last_before_and_first_counted_after` and
  `codex_compaction_events_and_points_match_full_read_at_every_tail_split`
  (tail parity at every line boundary).
- `compaction_events_and_local_context_points_are_identity_neutral`, the
  unchanged `context_posture` pin, the 64-event populated item under the item
  cap, the preflight bound, the backend contract field registry and the
  inherited-prefix fork fixture.
- `active_sessions` mapping, compact file and carried row, plus the protocol
  Swift-contract keys.
