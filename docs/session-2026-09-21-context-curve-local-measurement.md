# Local context curve measurement and cache contract

Date: 2026-09-21

## Decision boundary

Context curves remain local-first. The daemon does not enable curve upload,
replay, or backend projection through this work. The existing production parser
is the single derivation owner; the privacy-safe `snapshot-audit` command now
reports only coverage, counts, parser revisions, and serialized curve bytes.
It never reports request tokens, timestamps, model names, paths, transcript
identifiers, prompts, tool results, commands, URLs, screenshots, or reasoning.

Missing or non-authoritative curve evidence is unavailable, never zero.
Only `complete` and `sampled` coverage are available. Every other parser
coverage value is unavailable and must retain its reason.

The additive measurements advance the audit report contract from
`local_snapshot_audit:v2` to `local_snapshot_audit:v3`. The private audit-state
schema remains unchanged, so an existing audit index can continue incrementally.

## Local measurements

Measurements used the current scanner against local transcript roots with a
private audit index. They performed no upload and did not mutate source logs.
The Codex audit exercised the same evidence inputs as production parsing. The
Claude audit was transcript-only: `snapshot-audit` intentionally did not load
the local Claude OTLP API/trace sidecars used by the production sync path.

| Source and window | First pass | Settled incremental pass | Curve result |
| --- | --- | --- | --- |
| Claude Code, 30 days, transcript-only audit | 3,581 files; 1,458 sessions; 458.45 s; 1.58 GB max RSS | 1 changed session; 23.88 s; 176 MB max RSS | Without local OTLP sidecars, 1,457 `ownership_unresolved`, 1 `payload_budget_exceeded`; zero usable points |
| Codex, 1 day | 140 files; 136 sessions; 114.22 s; 143 MB max RSS | 10 changed sessions; 40.91 s; 139 MB max RSS | 107 complete, 29 sampled; 15,430 retained points; 234 retained boundaries |

The Codex curves occupied 4,145,009 serialized bytes in total. Per session,
serialized bytes were 23,039 at p50, 65,496 at p95, and 65,536 maximum.
Retained points were 85 at p50 and 248 at p95/maximum. Sixty-three sessions
had at least one retained compaction boundary; the per-session boundary maximum
was 64.

A 30-day Codex first pass was stopped after approximately twelve minutes. The
eligible local transcript root was tens of gigabytes, so continuing the scan
would not change the architectural conclusion: transcript parsing cannot run
on a UI request path.

## What the evidence proves

1. The session graph must read a compact local cache. It must never scan local
   transcripts while serving a UI request.
2. Initial census and repair are explicit background work with bounded pages,
   resumable checkpoints, and resource budgets. A caller sees `building` or
   `stale`, not partial data presented as complete.
3. Incremental parsing is necessary but not sufficient. Active large sessions
   still make a settled pass material, so watcher hints and per-cycle work
   limits must preserve liveness without starving the durable census.
4. The current Codex representation is small enough for a bounded local cache
   after sampling. The measured 64 KiB per-session wire ceiling is an upper
   bound, not a recommended resident-cache allocation.
5. The transcript-only Claude audit does not measure production curve
   availability. Production can prove some owned starts by pairing transcript
   occurrences with complete local OTLP API/trace evidence. The parser still
   intentionally rejects sessions whose owned start cannot be proven; unique
   request identifiers alone cannot exclude a missing predecessor with a copied
   prefix. Cache and UI work must preserve that refusal instead of reviving the
   old misleading first/peak/compaction values.

## Proposed versioned local cache contract

This is the contract to validate before implementing a durable cache or local
control API:

- Schema: `local_context_curve_cache:v1` with parser, ownership, sampling, and
  cache-writer revisions on every record.
- Key: local source plus a non-exported local session identity. No backend or
  cross-machine identifier is required.
- Value: the existing bounded curve, its coverage/reason, source revision,
  last successful parse time, last attempted parse time, and checkpoint
  generation. No transcript content or source path is stored.
- Availability: `building`, `available_complete`, `available_sampled`,
  `unavailable_ownership`, `unavailable_parser`, `unavailable_budget`, `stale`,
  and `source_removed`. Partial census output is never available.
- Per-session bound: retain the existing 64 KiB serialized curve ceiling and
  existing point/boundary sampling rules. Preserve requests 1/2/5/10/20,
  compaction-adjacent points, peak, and tail.
- Global bound: start with 128 MiB serialized on disk and 32 MiB resident,
  subject to a post-prototype measurement. Evict oldest inactive available
  sessions first; never evict the active scan checkpoint merely to retain a
  graph.
- Lifetime: keep active sessions and a provisional 30-day inactive window.
  One-hour idle expiry is not supported by the measurements and would discard
  data needed for 7-day/30-day views.
- Restart: atomically replace cache pages after a complete parse; retain the
  prior committed curve across crashes and expose it as stale until rechecked.
- Rotation/truncation: a changed source identity starts a new parse generation.
  Truncation or missing prefix invalidates ownership-dependent results and
  cannot inherit the prior curve silently.
- Resume: persist the existing scan index plus a cache checkpoint only after
  the curve page is durable. Reprocessing is idempotent by source revision and
  derivation revisions.
- Access: local authenticated control socket only. The response is available
  to the same signed/authorized local clients as other daemon state and is not
  exposed on a listening TCP port.
- Cohorts: compute from committed local curves in background. The 7-day
  startup/request-index cohort includes sessions whose first owned request is
  inside the window. Cycle cohorts include completed segments whose terminal
  boundary is inside the window. Never include copied prefixes or partial
  cycles. Median is primary, mean secondary, with p25/p75 and contributing `n`
  at every point.

## Remaining gates

1. Add a production-equivalent, content-free Claude measurement that loads the
   same local OTLP sidecars as sync. Quantify complete/sampled/unavailable
   coverage without exporting request values, model names, paths, or session
   identifiers.
2. Pin and test the existing Claude owned-start proof across ordinary root,
   continuation, takeover, resumed, restart, rotation, truncation, missing
   predecessor, and partial-sidecar cases. Any session that fails the proof is
   explicitly unavailable.
3. Prototype the cache behind a local opt-in using the existing parser; measure
   disk bytes, resident bytes, write amplification, and CPU under watcher-driven
   updates.
4. Add a versioned read-only local control response and session-detail graph,
   including loading, building, sampled, stale, unavailable, and accessibility
   states.
5. Add local 24h/7d/30d cohort materialization only after the individual curve
   is correct for both Codex and Claude Code.
6. Keep daemon release and any backend aggregate activation separate from this
   evidence-gathering change.
