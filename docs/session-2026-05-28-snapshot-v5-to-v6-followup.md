# 2026-05-28 — snapshot batch schema_version v5 → v6 follow-up

## Status

Open. The daemon is pinned at `SNAPSHOT_SCHEMA_VERSION = 5`
(`crates/ottto-service/src/snapshots.rs:16`) while the private backend's
`AgentSessionSnapshotBatchRequest`
(`backend/app/schemas/agent_session_snapshots.py:380-390`) requires
`schema_version: Literal[6]` with `model_config = ConfigDict(extra="forbid")`.
Daemon batch uploads to `POST /api/v1/agent-session-snapshots/batches`
return 422 every tick, surfacing in the daemon log as:

```
local snapshot sync skipped for codex: local snapshot upload failed
local snapshot sync skipped for claude_code: local snapshot upload failed
```

Non-blocking — the agent-status snapshots endpoint (different surface,
different table) is on schema_version=2 and works end-to-end, which is
what populates the ottto.net/apps "DETECTED" counter. This is the
session-level usage/cost data that's stuck, not onboarding state.

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

## Why we didn't just patch this autonomously

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

That's a real day-of-work change in the daemon's partition state. Out
of scope for the autonomous "fix the broken-pipe and 422" session that
spawned this note.

## Recommendations

- Open a separate, focused PR for the daemon v6 sync.
- While that lands, the 422 is harmless to onboarding — keep an eye on
  the daemon log line count if it ever becomes noisy. Currently it
  fires at the snapshot-sync cadence which is sparse.
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
