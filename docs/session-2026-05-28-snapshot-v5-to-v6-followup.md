# 2026-05-28 — snapshot batch schema_version v5 → v6 follow-up

## Status

**Resolved** in `693e2654` (daemon v6 batch schema) on `main`. The
`cargo fmt` fix for that commit landed in `rons/v6-fmt-and-doc`. The
daemon now emits `SNAPSHOT_SCHEMA_VERSION = 6` with per-hour
`usage_buckets` and per-`model_usage` attribution row keys matching the
backend's `AgentSessionSnapshotBatchRequest`
(`backend/app/schemas/agent_session_snapshots.py`).

Verified in production against the live backend: a hot-swapped v6 daemon
completed the full retroactive backfill for all three sources and the
backend accepted every batch — `snapshot_backfill_state.json` recorded
`codex_jsonl:v15`, `claude_code_jsonl:v7`, `pi_jsonl:v6` (only written
after an accepted upload), and all three scan-index files saved (only
written after a clean upload loop). The 422 is fixed.

One operational caveat remains: the **live daemon** still runs the old
`/Applications/Ottto.app/Contents/Helpers/ottto-service` (v5) binary, so
the 422 log spam continues on this machine until a clean reinstall of an
official Ottto.app carrying the merged v6 daemon. Non-blocking — this is
session-level usage/cost data, not the agent-status surface (schema
v2, separate table) that drives the ottto.net/apps "DETECTED" counter.

The analysis below is retained as the historical record of why the fix
was scoped as a separate change.

---

### Original problem (historical)

The daemon was pinned at `SNAPSHOT_SCHEMA_VERSION = 5` while the backend
required `schema_version: Literal[6]` with
`model_config = ConfigDict(extra="forbid")`, so daemon batch uploads to
`POST /api/v1/agent-session-snapshots/batches` returned 422 every tick:

```
local snapshot sync skipped for codex: local snapshot upload failed
local snapshot sync skipped for claude_code: local snapshot upload failed
```

## What changed on the backend (causing the drift)

Public-repo backend commit `8fd4c058f` "Add accurate hourly activity
buckets" (2026-05-24) bumped `LOCAL_SNAPSHOT_SCHEMA_VERSION = 4 → 5` and
later commits moved to 6, with a clean cutover (no v5 acceptance). The
v6 shape replaces `SnapshotItem.activity_buckets` (which had
`{bucket_start, request_count, first_activity_at, last_activity_at}`)
with `usage_buckets` of `AgentSessionSnapshotUsageBucket`:
`{bucket_start, model_usage: list[AgentSessionSnapshotModelUsage] (min_length=1), first_activity_at, last_activity_at}`.
Also the backend's `_usage_row_key` now incorporates `gateway_provider`,
`auth_mode`, `billing_channel`, etc. into each model_usage row — so the
SnapshotItem-level `gateway_provider` / `plan_fingerprint` /
`backfill_source` fields the daemon sends are now `extra="forbid"`
rejections.

## Why it was scoped as a separate change (historical)

A simple "drop the rejected fields + bump schema_version" patch fails
the backend validator at line 327-328:

```python
if expected_has_usage and not self.usage_buckets:
    raise ValueError("usage_buckets are required for schema_version 6 usage snapshots")
```

Empty `usage_buckets` is rejected whenever the snapshot has any usage
tokens. Real fix requires populating `usage_buckets` with per-hour
`model_usage` rows that sum to the SnapshotItem-level model_usage —
which is data the daemon's current `SnapshotPartition` aggregator
doesn't track. `partition.activity_buckets` has the per-hour
`request_count`, `partition.model_usage` has the per-row aggregate
across all hours; there's no per-hour-per-model breakdown to serialize.

The proper fix is a focused daemon refactor:

1. **Extend `SnapshotPartition`** (`crates/ottto-service/src/snapshots.rs`
   around the activity_buckets accumulator) to track
   `BTreeMap<bucket_start, BTreeMap<row_key, ModelUsageRow>>` so each
   hour records its own per-row model usage.
2. **Replace `SnapshotActivityBucket` with `SnapshotUsageBucket`**
   carrying `Vec<SnapshotModelUsage>` instead of `request_count`.
3. **Move `gateway_provider` / `plan_fingerprint` off SnapshotItem**
   into each `SnapshotModelUsage` row (so it's part of the row key that
   backend computes — see `backend/app/schemas/agent_session_snapshots.py:164-182`).
4. **Drop `SnapshotItem.backfill_source`**, or move into `provenance`
   (currently rejected at the item level).
5. **Bump `SNAPSHOT_SCHEMA_VERSION = 6`**.
6. **Update all SnapshotItem construction sites** — `to_snapshot_items`
   at `snapshots.rs:730-806` plus the cached scan-index emitters at
   `snapshots.rs:2853, 2896` etc.

That was a real day-of-work change in the daemon's partition state,
scoped separately from the "fix the broken-pipe and 422" session that
spawned this note. **It has since landed** — see Status above.

## How it was resolved

The daemon's `SnapshotPartition` (separate per-row `model_usage` + per-hour
`activity_buckets` maps) was replaced by a single per-hour-per-row
aggregator: `BTreeMap<bucket_start, BTreeMap<RowKey, BucketRowAccumulator>>`,
where `RowKey = (model, reduced selector_hash, auth_mode, billing_channel,
billing_provider, gateway_provider, model_provider, subscription_product)` —
mirroring the backend's `_usage_row_key`. `into_items` sums per-row across
hours for the top-level `model_usage`/totals and emits the per-hour
breakdown as `usage_buckets`, so the backend's bucket-vs-top reconciliation
passes. The six billing fields are hoisted out of `selector_context` onto
each row, and the selector is reduced to the backend's 12-key allowlist so
stripped keys (`plan_window_bucket`, `agent_quota_*`) don't create phantom
rows. Codex state-only snapshots synthesize a single bucket at
floor(`updated_at` → hour). The status endpoint stays at schema v5
(`SNAPSHOT_STATUS_SCHEMA_VERSION`); only the batch endpoint moved to v6.

## Recommendations

- Daemon v6 is on `main`. Package it into the next official Ottto.app
  release alongside the OTLP-relay broken-pipe fix (PR #7) so the live
  daemon stops emitting v5 and the 422 log spam clears on reinstall.
- Backend already has a strict `extra="forbid"` v6 contract, matching
  the repo's "clean cutover" policy, so no backward-compatibility shim
  is needed (or wanted) on the backend side.

## Companion fix shipped in this PR

`crates/ottto-service/src/otlp_relay.rs` — when the OTLP forward client
(Codex / Claude Code) disconnects mid-write, the daemon was logging
`local OTLP relay request failed: Broken pipe (os error 32)` one line
per disconnect. After my change, BrokenPipe / ConnectionReset I/O
errors are recognized via a small helper and silently swallowed
(everything else still surfaces). Unit-tested in
`otlp_relay::tests::client_disconnect_during_write_recognises_routine_io_errors`.
