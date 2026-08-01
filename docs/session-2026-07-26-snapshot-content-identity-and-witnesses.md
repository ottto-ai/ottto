# 2026-07-26 — Snapshot content identity and upload witnesses

## Outcome

Every uploaded snapshot item now carries a policy-neutral `content_hash` at a
declared `hash_epoch`, every batch carries a client loss report, and every
collector check-in carries a scan-index manifest. All of it is additive and
write-only: nothing in this release changes what the daemon uploads or how the
backend decides what changed. The fields exist so the server can *later* key
change detection on content identity, and audit its own entity set against the
machine's, without a second daemon release.

The attribution wire budget also moves 2,048 → 4,096 bytes.

## Why these fields ship before anything consumes them

The daemon release train is the long pole. Sparkle and Homebrew mean old daemons
persist indefinitely, so a field added later is a field the fleet does not carry
for months. Anything the server will want is cheaper to ship now as write-only
than to ship twice.

## `content_hash` — what it is over

`content_hash` = SHA-256 over the RFC 8785 (JCS) canonical bytes of:

```json
{
  "canonicalization": "rfc8785:integers-only:v1",
  "components": { "<policy-neutral component>": "<component sha256>", … },
  "hash_epoch": 1,
  "source": "codex",
  "source_session_id": "…"
}
```

The policy-neutral components are `usage_accounting`, `lifecycle_activity`,
`latency`, and `context_posture` — the four that survive every upload policy and
every org display toggle.

**What is deliberately NOT in it**, each because identity may not depend on
implementation state, mutable inventory, or wall-clock:

| Excluded | Why |
| -------- | --- |
| `collected_at` | scan wall-clock |
| `source_file_fingerprint` | scan/inventory state — the same content read from a rotated or recopied transcript is the same content |
| parser version, scan-identity version | a parser fix must not re-mint every session's identity; they stay in `revision_hash`, which is the re-upload trigger |
| `provenance.collector`, `provenance.source_file_count` | implementation state and mutable inventory |
| `display_identity`, `attribution`, `artifacts` components | policy-scoped; a privacy toggle is a change in content, never in identity |
| lifecycle scalars (`status`, the `source_*_at` timestamps, `state_total_tokens`, `state_archived`) | already inside the `lifecycle_activity` component hash |

`hash_epoch` is independent of `SNAPSHOT_SCHEMA_VERSION` and of the parser
versions. A new semantic field is invisible to `content_hash` until the epoch
moves, and moving it re-mints every session's identity fleet-wide — so it is a
deliberate, announced change, never a side effect of shipping a field.

SHA-256 rather than a faster hash: every component hash here is already SHA-256
and so is the backend's, and a second cross-language hash implementation would be
a second thing to keep byte-identical for no measurable gain at this volume.

### Canonical JSON

`canonical_json` implements RFC 8785 with one deliberate restriction: non-integer
numbers are **rejected**, not approximated. RFC 8785 requires ECMAScript
`Number::toString` shortest round-trip formatting; emitting Rust's `f64`
rendering instead would silently produce bytes a conforming implementation
disagrees with. Payloads that need fractional values carry them as decimal
strings, which is what the snapshot wire already does for money.

## `client_report` — daemon-side loss accounting

Sentry's client-report triple, on every batch:

```json
"client_report": {
  "schema_version": 1,
  "entries": [
    {"reason": "queue_overflow",    "category": "snapshot_item",  "quantity": 0},
    {"reason": "ratelimit_backoff", "category": "snapshot_batch", "quantity": 0},
    {"reason": "network_error",     "category": "snapshot_batch", "quantity": 1},
    {"reason": "poisoned",          "category": "snapshot_item",  "quantity": 0}
  ]
}
```

Two disciplines matter more than the shape:

* **Every reason is emitted every time, including the zeros.** A counter that
  appears only when non-zero cannot distinguish "healthy" from "not reporting".
* **Counters are reported before they are cleared, once.** The report is
  subtracted only after the server accepts the batch, so a failed upload
  re-reports its losses instead of erasing them. Exactly one lease is live at a
  time: a second concurrent claim carries an empty report rather than the same
  numbers, because two batches reporting the same losses would have the server
  count them twice and the second acknowledgement could clear losses the first
  already cleared. The lease releases on drop, so an upload that fails anywhere
  between claiming and acknowledging cannot strand the counters.

`network_error`, `poisoned`, and `ratelimit_backoff` have live writers in this
release. `queue_overflow` reports 0 until the durable outbox lands.

Two classification rules are worth stating because getting them wrong makes the
report actively misleading:

* **A shed request is not a network failure.** HTTP 429 is counted as
  `ratelimit_backoff`; 503 joins it with the typed `Retry-After` handling, which
  is where the backoff itself lives (the redacted diagnostics currently expose
  429 distinctly and fold 503 in with every other 5xx).
* **One poisoned entity is one loss, not one loss per cycle.** The server has no
  per-entity rejection vocabulary yet, so a permanently invalid entity is
  re-attempted every cycle — and if the source has no valid sibling, no request
  ever succeeds, so nothing commits the report and the number would only grow.
  Counted fingerprints are therefore deduplicated, and the ledger is pruned to
  the current scan exactly like the accepted-fingerprint ledger. Durable poison
  marking arrives with the per-entity ACK contract.

## Scan-index manifest on check-ins

`snapshot_manifest:v2` on the collector status receipt, from the scan index the
sync cycle already had open:

* **Grain:** one entity per indexed transcript that produced a snapshot, plus one
  per Codex state-only session. A transcript that parses into several snapshots
  contributes its last fingerprint — the same value the index uses for no-op
  suppression.
* **Scope, declared exactly on the wire** as
  `scope: "semantic_activity_window"`, `window_start`, and `window_end`.
  Membership is the half-open `[window_start, window_end)` interval over stable
  usage/session activity, never file mtime or `collected_at`. Metadata-only
  entities have an explicit null activity witness: they are still uploaded and
  ACKed, but cannot enter this semantic window. Census completeness and loss
  diagnostics remain top-level status counts; the manifest never presents a
  locally computed count as server-acceptance proof.
* **`rolling_hash`:** SHA-256 over the length-prefixed concatenation of the
  manifest contract version, the scope, the source slug, and then each distinct
  in-window entity fingerprint in ascending byte order. Window timestamps are
  not hash inputs. Length prefixes are load-bearing: without them two different
  fingerprint splits can produce identical bytes. Sorting makes the fold
  order-independent, so the server can recompute it from its own stored
  fingerprints for this (user, machine, source).
* **No path, session id, title, or byte offset participates.** The fold is over
  fingerprints that are already on the wire.
* Absent before the first completed scan of a process — absent, not zeroed. A
  fabricated `entity_count: 0` would read as "this machine has nothing", which is
  a different and wrong statement.
* **Keyed by upload destination, not just source.** A setup or account switch
  replaces the relay binding without restarting the daemon, and a cache keyed by
  source alone would report the previous account's entity count and rolling hash
  to the new one — a false witness and a disclosure of the previous account's
  local session set. Publishing for a new destination retires the old entries
  outright.

Check-ins carry it deliberately, including the liveness-only shape: a receipt
that says "alive" while the entity sets disagree is exactly the state the
manifest exists to expose.

## `last_semantic_noop_count`

`SourceScanResult` has always computed how many sessions the local semantic fuse
classified as unchanged, and the status receipt always threw it away. Without it,
"the collector suppressed 718 unchanged sessions" and "the collector did nothing"
are the same receipt.

## Attribution budget 2,048 → 4,096 bytes

The byte budget, not the 24-fact cap, was the binding constraint: a skill-heavy
session hit the ceiling at ~13 facts and lost its tail — which is exactly where
the grouping evidence (`template_group_id`, `schedule_definition_id`, `skill_id`)
is appended. A workflow subagent lost `spawn_depth` for the same reason and now
keeps it.

**Release ordering is not optional here.** The backend must accept the wider
budget *before* this daemon reaches an installed base, or every
attribution-carrying batch from an upgraded daemon is rejected.

## Fixture corpus

Two fixtures are the cross-language contract, both regenerable:

* `fixtures/snapshot-audit/semantic-envelope-golden.json` — 60 cases (3 sources ×
  20 valid upload policies) carrying, per case, the component hashes, the
  policy-neutral subset, `content_hash`, `hash_epoch`, the additive explicit
  `snapshot_revision:v2` canonical body and digest, the canonical byte count,
  and the envelope byte count. Regenerate with
  `UPDATE_SEMANTIC_ENVELOPE_GOLDEN=1 cargo test -p ottto-service --lib semantic_envelope_cross_language_golden`.
  The corpus itself asserts the identity contract: for each source all twenty
  policies agree on `content_hash` while the policy-scoped fingerprint does not.
* `fixtures/snapshot-audit/attribution-budget-golden.json` — three attribution
  payloads at the budget edges (over the retired 2 KiB budget, largest accepted
  by the current budget, one fact past it) with their byte counts and payload
  digests, carried verbatim so the other implementation can replay them rather
  than reconstruct a guess. Regenerate with
  `UPDATE_ATTRIBUTION_BUDGET_GOLDEN=1 cargo test -p ottto-service --lib attribution_budget_corpus`.

Fact values in the fixtures are synthetic.
