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
    `TELEMETRY_FLUSH_WINDOW_SECONDS` (300, provisional) of the scan and with
    a healthy sidecar pair for its folder. Otherwise it is missing, and only
    then do transcript bases apply.
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
- Equal-input observation, debug build, 2,000 responses with 64 markers:

  | Measure | Result |
  |---|---|
  | Marker capture | about 2 ms for 2,063 lines |
  | Retained marker state | 6.6 KiB |
  | Tagging | about the same cost as the parse |

  Tagging is dominated by the same per-request sidecar fingerprint checks the
  existing request-account qualification performs. Struct growth is 8 bytes
  per item and accumulator. Released builds pay no runtime cost while emission
  is off.
