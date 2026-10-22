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

State: a sorted vector keyed by the exact `at` string, retaining only the
newest 64 distinct timestamps while parsing. Duplicates keep the first marker;
timestamps below the current cutoff can never return because the cutoff only
increases. Eviction happens before insertion, and bounded `reserve_exact`
growth keeps capacity at most 64 even for cloned tail state. A counted
non-zero request fills every retained pending `after`, regardless of timestamp
order. A flag skips this scan when no marker is pending. Finish moves only
these at-most-64 events; it neither builds all-marker events nor clones the
existing timestamp vector. The existing `compaction_count` and timestamp
accumulator and their wire semantics are unchanged.

Claude Code leaves the list empty in this change. Its events will be built by
the ownership fold, never in `finish()`.

## Local only: context points

`SnapshotItem.local_context_points` is `serde(skip)`: it is never serialized or
uploaded. The points come from the same Codex block that sets first, peak and
last. So the first point is the first request and no point is above the peak.
The last point is the latest request, with two rare exceptions: while only the
pinned first point exists, a later request in that same second adds no point,
and a latest request without a parseable timestamp is never a point:

- zero-size requests and requests without a usable timestamp are skipped;
- inside one 15-minute wall-clock slot, a newer request replaces the tail point
  unless the change is big (`max(20%, 20K)` tokens);
- at most 64 points per session. On overflow, every other middle point is
  dropped, keeping the first and the last. The list halves before the new
  point is pushed. Bounded `reserve_exact` growth also keeps vector capacity
  at most 64, including when a tail pass resumes a cloned list;
- only items whose last activity is within 75 minutes of collection carry
  points. The accumulator itself is not gated, so a tail pass and a full read
  agree.

## Sessions list (`ActiveSession`)

`ActiveSession` gains `compaction_events` (`at`, `before_tokens`,
`after_tokens`, `trigger`), `context_points` (compact `[unix_seconds, tokens]`
pairs, whole seconds UTC), `first_turn_context_tokens` and
`last_turn_context_tokens`. All of them are
omitted when empty or unknown. The list file
`active_sessions/<source>.json` is now written as compact JSON, because the
status path reads it on every poll. That file is the 15-minute list and is
rewritten each scan; a row leaves it with its session.

## Weight

- Per Codex accumulator: two vector headers plus a pending flag (56 bytes
  including alignment). Size state owns at most 64 entries of 40 bytes each
  (a string header plus a 16-byte size pair), plus the capacities of their
  timestamp strings: 3,840 heap bytes for 64 ordinary 20-byte timestamps.
  Actual capacity, including string allocations, is charged. No new timestamp
  length limit is imposed; the general bound is 2,560 bytes plus the capacities
  of at most 64 retained strings. Points add at most 512 bytes (64 x 8).
- Per `SnapshotItem`: two empty vectors (48 bytes).
- Per Codex line: a `compacted` marker searches at most 64 sorted keys and
  inserts/evicts only when admitted. A positive `token_count` record parses its
  timestamp once and updates or appends one 8-byte point. A counted non-zero
  request fills at most 64 pending size entries, only when a marker has been
  admitted since the last fill. Every other line costs nothing here.
- Status: a point is about 20 bytes of compact JSON (`[1792576800,250000]`)
  instead of about 46 bytes as an object, and the daemon formats no timestamps
  for it. Compaction events on `ActiveSession` stay objects (about 74 bytes
  each). For 100 listed Codex sessions with 64 points each, realistic usage
  (about 3 events per session) is about 157 KB; the worst case (64 events per
  session) is about 610 KB, dominated by events. The former object points
  made those cases about 324 KB and 775 KB, respectively.
- Upload: 0 bytes for sessions that never compact. About 65 bytes per Codex
  event, so at most about 4 KB at the 64 cap.

## Tests

- `snapshots/compaction_events.rs`: shared `after`, the 64 bound matching
  `bounded_compaction_timestamps` over 10,000 duplicate/out-of-order markers
  and a cloned continuation, capacity bounded throughout and output equal to
  the old finish-time result, and the wire shape.
- `snapshots/local_context_points.rs`: the pinned first point, slot overwrite,
  big changes, skips, the out-of-order clamp, halving on overflow, the vector
  capacity bound across cloned tail state, and the 75-minute gate.
- `codex_compaction_events_take_last_before_and_first_counted_after` and
  `codex_compaction_events_and_points_match_full_read_at_every_tail_split`
  (tail parity at every line boundary).
- `compaction_events_and_local_context_points_are_identity_neutral`, the
  unchanged `context_posture` pin, the 64-event populated item under the item
  cap, the preflight bound, the backend contract field registry and the
  inherited-prefix fork fixture.
- `active_sessions` mapping, compact file and carried row, plus the protocol
  Swift-contract keys.
