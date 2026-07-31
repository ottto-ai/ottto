# Pi current-transcript snapshot ingestion

Date: 2026-07-31

## Problem

Pi's current transcript schema stores the session identifier as `session.id`
and both user prompts and assistant usage as nested `type: "message"` records.
The stable snapshot parser only recognized the historical `session_id` and
`message_end` schema. A bounded, privacy-safe scan therefore discovered Pi
transcripts but derived no session snapshots.

## Change

- Parse the current nested session, user-message, assistant-message, usage,
  model, and timestamp fields while preserving historical compatibility.
- Deduplicate a provider response if a transitional transcript contains both
  `message` and `message_end` usage records and exposes a stable response
  identifier. Distinct id-less responses remain distinct.
- Compare Pi's parsed RFC 3339 timestamps chronologically rather than
  lexicographically, including mixed fractional-second forms. Valid timestamps
  outrank malformed boundaries; malformed pairs retain deterministic lexical
  fallback.
- Normalize only parseable Pi timestamp strings or millisecond values whose
  civil year fits the backend datetime contract. A present-but-invalid timestamp
  drops that usage event instead of assigning it a prior activity time; healthy
  sibling events remain uploadable. The shared Codex state timestamp helper uses
  the same range fence.
- Persist an explicit zero-snapshot checkpoint for Codex, Claude Code, and Pi,
  bound to the exact file and scan identity. Truthful empty transcripts settle
  to zero repeated work; a file or parser/scan identity change reparses them.
  If a previously snapshot-bearing file reparses to zero, the checkpoint clears
  its manifest contribution instead of retaining a stale green witness.
- Persist only a content-free Boolean when a zero-snapshot file still contains
  an exact usage container with a positive allowlisted consumption, request, or
  cost field. Versions, limits, budgets, quotas, timestamps, and opaque positive
  metadata are excluded. Settled scans continue reporting `parse_error` until
  that file or parser changes, closing the gap where an hourly server check
  could miss the one scan that exposed parser drift.
- Persist a content-free per-file count when any Codex, Claude, or Pi positive
  usage record is deliberately dropped because it has no valid activity bucket.
  Mixed files still upload healthy siblings, but status remains `parse_error`
  across settled scans; correcting the file clears the count.
- Advance Pi parser and scan identity to `pi_jsonl:v12`, causing one bounded
  correctness rescan without changing the explicit historical replay policy.
- Add a content-sanitized current-shape fixture plus parser, transitional
  deduplication, timestamp-boundary, zero-checkpoint, scan-manifest, and
  settled-idempotency coverage.

## Validation

A read-only audit used a dedicated temporary scan index and blinded session
keys against the current local Pi transcript tree. It found 456 files and
derived 426 usage-bearing sessions; every emitted session had at least one
request and usage bucket. Thirty files contained no usage-bearing session.
The next scan did zero repeated work for those genuine empties while preserving
the 426-entity manifest, and none set the positive-usage evidence marker. The
audit did not alter the daemon's production replay
index or upload data.
