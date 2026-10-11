# Claude per-request identity on unchanged usage rows (contract 5, dark)

Claude Code snapshots today carry at most one login per usage row, and a row
that mixes logins in one hour loses its identity. Contract 5
(`claude_code_jsonl:own_request_identity_rows:v1`) keeps today's usage rows,
row keys and totals and adds per-request identity next to them:

- A row whose requests share one authority key carries it:
  `account_identifier_hash` plus `evidence_ref` into the item's
  `request_evidence` (`{identity_basis, provider_workspace_hash?}`).
- A row that mixes keys carries exact `identity_parts` instead. Each part has
  all eight counts and the row's money fields, and the parts sum to the row.
- The authority key is (login, organization, full basis). Different bases
  never merge on the daemon.
- `request_identity_refusals` counts bucket rows left untagged for a refused or
  pending reason. Only its zero/positive state is hashed.

Old collectors keep their exact bytes and hashes.

## Emission is off

`claude_request_identity::EMISSION_ENABLED` is `false`. A released daemon
captures no markers, records no placements and emits no contract-5 body. The
scan hook and every new field stay inert until a compatible receiver is
confirmed, and flipping the constant is a separate change. Tests exercise the
same code through `capture_enabled()` (`cfg(test)`).

## How tagging works

- Rows are built exactly as today. Afterwards, each counted request is
  classified and the rows are regrouped per request. The item is tagged only
  if that regrouping reproduces every bucket and top-level row exactly:
  counts, and money folded the way today's rows fold it. Otherwise the item
  stays on today's path unchanged.
- **Transcript path:** placements come from the owned usage occurrences the
  parser already retains.
- **Reported path:** `rebuild_claude_reported_usage` optionally records where
  each request landed. This does not change its output.
- **Classification:**
  - Telemetry wins: login plus organization from complete request identity.
    Login-only telemetry joins a trusted transcript organization only when
    complete telemetry in the same pass pairs that login with it.
  - A supplied conflicting organization is refused. It is never dropped to
    get login-only attribution.
  - Duplicates, foreign owners, invalid evidence and missing original clocks
    are refused.
  - Missing telemetry is pending only for that request's own clock, within
    `TELEMETRY_FLUSH_WINDOW_SECONDS` (300, provisional) of the scan, and with
    a qualified witness that the folder's telemetry writer is healthy now. A
    complete paired-sidecar load proves only what was already written, and no
    existing qualified current-writer witness exists, so the scan supplies
    none: pending never fires and a young missing request is missing (SESSION
    ruling requested). Only missing requests are open to transcript bases.
  - Auxiliary (telemetry-only) reported rows are refused for a bad clock. Their
    `observed_at` may be the observer clock and the v2 capture does not record
    which, the same reason they cannot qualify today's request accounts. The
    trace span start is event-origin, but no existing rule qualifies it
    (SESSION ruling requested). Transcript clocks are never borrowed.
  - Unreadable sidecars refuse every request; they never fall through.
- **Transcript markers** (`credential_org` attachment lines):
  - They are captured only on owned lines, after inherited-fork exclusion,
    as an organization hash positioned by response sequence.
  - The trust rule for terminal markers: an unchanged organization stays
    trusted. An organization change needs a new `session_context`; without
    one it is untrusted and refused.
  - Each file keeps at most 64 markers. Overflow switches transcript bases off
    for that file.
  - No email or raw text is kept. `transcript_email` stays off.
- **`transcript_sole_login`** (Desktop only) needs all of the following:
  - a complete Desktop identity census;
  - a new additive index witness. The witness is set only on a complete,
    error-free store sweep and is bound to process, store inventory and clock.
    It is absent (unknown) for older indexes;
  - a census completed after the request;
  - exactly one native login for that organization.
- **Caps:**

  | Bound | Limit |
  |---|---|
  | Evidence entries | 16 |
  | Authority keys | 16 |
  | Parts per row | 17 |
  | Parts per item | 2,048 |
  | Rows | 100 |
  | Item size | 640 KiB (sorted compact JSON) |
  | Money per value | micro-dollar exact, at most $1e9 |

  Over any bound, the item is sent in today's shape under the new collector,
  with refusals = max(1, rows that lost identity).
- A tagged item gets the same UTC lifecycle spelling (`source_started_at`,
  `source_ended_at`, `source_last_activity_at`) that request-account
  qualification gives every item it handles, which leaves new-collector items
  alone. An item that cannot be tagged returns unchanged.

## Validation

- `fixtures/session-identity/` mirrors the shared fixture revision
  `session_identity_w0:r5` byte for byte (63 bodies plus `index.json`). Its
  digest `2a9b46f1…e8e6` reproduces in-tree.
- The daemon's own component hashing reproduces `usage_accounting`,
  `attribution` and the identity leaf for all 63 bodies.
- Typed rows serialize to the exact wire members.
- From per-request contributions, the builder re-emits every tagged body:
  - identical bytes for canonical bodies;
  - an identical hash leaf for intentionally reordered ones.
- The cap rule reproduces the fallback bodies.
- Synthetic tests cover:
  - classification rulings;
  - markers, including fork exclusion;
  - the census witness;
  - money exactness and unsplittable reported money;
  - order-free hashing that still moves with the login;
  - both usage paths end to end;
  - unqualified items keeping today's bytes.
- Equal-input end-to-end comparison (debug build, synthetic: 2,000 responses,
  2 logins, 64 markers, parsed once). Both paths start from the same parsed
  items and the same loaded sidecar reports. The transcript is deleted first,
  so neither path can re-read it. Legacy is today's request-account
  qualification. Enabled is contract-5 evidence, tagging, then that same
  qualification, then admission.

  | Measure | Legacy | Enabled |
  |---|---|---|
  | Wall time | about 143 ms | about 187 ms |
  | Sidecar fingerprint checks (api, trace) | 2,000, 2,000 | 2,000, 2,000 |
  | Allocations | 64,226 | 113,719 |
  | Peak requested heap | 0.52 MB | 1.98 MB |
  | Retained heap after | 31 B | 6.4 KB |
  | Item payload | 6.7 KB | 13.8 KB |

  Marker capture during the parse adds about 2 ms, 573 allocations and
  6.6 KB retained for 2,063 lines.

  - Request-account qualification leaves the tagged item alone, and contract 5
    validates each login once and reuses it. So enabled repeats no
    fingerprint check.
  - Tagging installs in place, without copying the item, and moves each
    request's placement into its contribution.
  - The remaining peak is the per-request contribution buffer (544 B per
    request) plus the scan's own request maps. Folding contributions straight
    into row groups would make it proportional to rows instead of requests.
    That is a recorded follow-up.
- With emission off, released builds still pay for:
  - 8 B per `SnapshotItem` and accumulator (`claude_org_markers`, always
    `None`);
  - 40 B in `ScanIndex` for the census witness slot. Dark builds keep it
    `None`: they neither compute nor persist a witness, and they clear one
    left by an earlier build at the next Desktop sweep;
  - an empty placement map in the reported-usage disposition and a `None`
    check per rebuilt row;
  - two constant-false branches.
  These costs are small but not zero.
