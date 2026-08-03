# Tail-parse checkpoints

Date: 2026-08-03

## Outcome

The local snapshot scanner can now checkpoint an append-only transcript at its
last complete JSONL line and resume the next parse from that byte offset. The
checkpoint is additive state inside the existing per-destination scan index;
there is no database, fact ledger, outbox, or protocol change.

The feature is dark. An unset `OTTTO_TAIL_PARSE_CHECKPOINTS` keeps the previous
behavior, where any changed transcript is parsed from byte zero. Explicit
`on`, `1`, `true`, `yes`, or `enabled` values opt in for local validation ahead
of a later release decision.

## Resume authority

A checkpoint is eligible only when all of these witnesses still agree:

- checkpoint schema, source parser version, and source scan-identity version;
- attribution/artifact/sidecar parse-context fingerprint;
- Unix device and inode;
- strict file growth beyond the completed-line offset; and
- bounded SHA-256 samples from the beginning and tail of the parsed prefix.

New files and every failed witness take the full-parse path. Equal-size edits,
truncations, replacement/rotation, parser changes, and guarded-prefix rewrites
therefore cannot resume. A successfully parsed append atomically replaces the
old accumulator and offset with the new scan-index entry only when the existing
upload settlement path commits that entry.

Parser provenance is now recorded separately on each file entry. Existing
entries adopt the current source version once without a replay when every
other identity is unchanged; a later source parser bump forces a full parse for
that source.

## Privacy boundary

The serialized accumulator includes the running selector, cumulative baseline,
usage buckets and totals, response-dedup sets, model/effort/turn state, activity,
latency, context posture, compaction observations, artifacts, and drop
counters. The explicit content exclusion list is:

- `first_prompt_material` (raw bounded user text);
- `workspace_path` (raw local path); and
- `provider_skills` (provider names before HMAC derivation).

The Codex turn-trace and Claude effort maps are runtime handles, not accumulated
state, and are also skipped and reinjected. Before persistence, the raw content
fields are replaced with privacy-safe repository identity and HMAC-derived
attribution results. The accumulator remains an opaque JSON value inside the
index so an incompatible future accumulator cannot corrupt the surrounding
scan state; its parser-version mismatch takes the rebuild path before decoding.

## Equivalence and savings evidence

The fixture corpus covers:

- Codex plan changes, model/reasoning changes, and a non-monotonic cumulative
  usage reset that clears prior buckets;
- Claude Code repeated content-block rows whose response dedup keys straddle a
  checkpoint; and
- Pi current/legacy response-shape dedup straddles.

A deterministic randomized-order property sweep checks every complete-line
split in the three transcripts. Fourteen resume points produced byte-for-byte
identical serialized snapshots and diagnostics versus a full reparse while
bypassing 8,088 parser bytes in aggregate. Separate regressions force the full
path for parser-version mismatch, prefix mutation, truncation, and inode
replacement. The source scan census accumulates
`tail_checkpoint_bytes_skipped` locally; it is deliberately not added to a
batch or status request while the feature is dark.
