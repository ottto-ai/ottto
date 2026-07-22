# Cloud Session Complete Snapshots

Completed the public Codex Cloud Sessions batch-v1 completeness contract while
keeping production startup hard-deferred.

## Wire contract

Every `cloud_session_observations.v1` batch now carries both fields required by
backend Phase 10:

```json
{
  "batch_kind": "snapshot",
  "snapshot_complete": true,
  "observations": [
    {
      "entity_key": "hmac-sha256:<64 lowercase hex characters>",
      "entity_kind": "task",
      "lifecycle": "running",
      "measurement_basis": "not_itemized",
      "coverage": ["identity", "status"],
      "observed_at": "2026-07-22T09:00:00Z"
    }
  ]
}
```

A health-only batch is strictly different:

```json
{
  "batch_kind": "heartbeat",
  "snapshot_complete": false,
  "observations": [],
  "health": {
    "state": "healthy",
    "observed_at": "2026-07-22T10:00:00Z"
  }
}
```

Closed Rust enums reject unknown batch kinds. Strict decoding and relay-send
validation reject heartbeat observations, complete heartbeats, unknown batch
fields, and batches above 200 observations.

## Completeness boundary

`snapshot_complete: true` is emitted only after a successful terminal-cursor
enumeration for the exact bound grant/account scope. A terminal empty result is
an authoritative complete snapshot. Hitting the ten-page, 200-observation, or
45-second cycle bound leaves the snapshot incomplete. An overfull provider
page also leaves it incomplete because ignored rows cannot be recovered from
that page. Provider errors, rate limits, malformed required rows, kill-switch
changes, and pause/revoke races either emit an incomplete observation-empty
health update or stop without a semantic batch; they never claim absence.
Bounded partial snapshots report `degraded` health with the backend v1 contract's
coarse `provider_error` category. That category is intentionally less precise
than the local reason because v1 has no coverage-limited value; UI coverage and
absence claims must use `snapshot_complete`, not health state alone.

The local semantic digest includes completeness, so a partial scan followed by
the same entity set from a complete scan still uploads the completeness
transition. Pagination cursors and raw provider identifiers remain memory-only.

## Cadence and load

- Healthy polling preserves the product's five-minute metadata freshness target,
  plus up to 20 seconds of jitter. Semantic no-ops suppress unchanged uploads;
  failures use exponential backoff.
- Unchanged data is normally a transport no-op.
- An observation-empty heartbeat remains eligible hourly.
- The first healthy complete enumeration on each active UTC day is uploaded
  even when its semantic digest is unchanged. This permits bounded backend
  stale-row draining across duplicate complete snapshots.
- Existing exponential circuit backoff remains capped at 64 minutes.
- Each CLI process remains capped at 12 seconds and 5 MiB of stdout; each cycle
  remains capped at 45 seconds, ten pages, and 200 observations.

## Privacy and activation

No upload boundary expanded. The collector still uses only the supported
`codex cloud list --json` CLI, immediately HMACs provider identity, retains no
raw cursors or responses, reads no credential store, and calls no provider,
Claude, WHAM, browser, or undocumented endpoint. Grant UUID/version, exact
scope fingerprints, disclosure version, server policy approval, local
pause/revoke, and the runtime kill switch remain mandatory.

The collector build containing `batch_kind` and `snapshot_complete` must not be
activated against an older backend. `spawn_cloud_session_collector` still
constructs only `DeferredCloudSessionTransport`. Do not release 0.1.90 or opt in
users until backend Phase 10 is deployed and the retention, cardinality,
affected-grain pruning, indexed revoke/delete, live EXPLAIN, WAL/index-write,
p95, bloat, consent, and demo-user privacy/revocation/load QA gates are green.

## Validation

- Focused cloud-session unit tests cover strict wire serialization, empty and
  populated complete snapshots, incomplete capped/overfull pagination,
  provider error and revoke races, daily complete replay, hourly heartbeat,
  bounded cadence/backoff, 200-row maximum, policy transitions, and deferred
  startup.
- Full runtime tests, Clippy with warnings denied, formatting, connector tests,
  public export checks, authoritative manifest verification, and secret scans
  are required before landing.
