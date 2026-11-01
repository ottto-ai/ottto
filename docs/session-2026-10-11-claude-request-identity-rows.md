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
captures no markers, classifies and groups no requests, and emits no
contract-5 body. The
scan hook and every new field stay inert until a compatible receiver is
confirmed, and flipping the constant is a separate change. Tests exercise the
same code through `capture_by_default()` (`cfg(test)`).

Since 2026-10-15 the constant is `true`
([master-on](session-2026-10-15-claude-request-identity-master-on.md)).
Flipping the constant alone still emits nothing: each sync cycle also needs
the exact cohort token in that cycle's activity hint (`emission_permit`). See
[the activation-readiness note](session-2026-10-14-claude-request-identity-activation-readiness.md).

## How tagging works

- Rows are built exactly as today. Each counted request is classified as it
  is placed and folded straight into a bounded per-item grouping, at today's
  (bucket, row key) x authority-key grain. No request is retained.
  - Groups are capped by the rows the item carries. More groups could never
    reproduce, so construction stops there.
  - Each group holds at most 16 authority keys plus the untagged entry. Keys
    past the cap fold into untagged as they arrive, before anything is
    encoded.
  - The item is tagged only if the grouping reproduces every bucket and
    top-level row exactly: counts, and money folded the way today's rows fold
    it. Otherwise the item stays on today's path unchanged.
- **Transcript path:** requests stream from the owned usage occurrences the
  parser already retains. Each distinct bucket and row key is built once.
- **Reported path:** `rebuild_claude_reported_usage` hands each request to the
  grouping as it places it. This does not change its output.
- An item whose request count includes auxiliary (telemetry-only) requests
  fails the existing request-id precondition and keeps today's bytes.
- **Classification:**
  - Telemetry wins: login plus organization from complete request identity.
    Login-only telemetry joins a trusted transcript organization only when
    complete telemetry in the same pass pairs that login with it.
  - A supplied conflicting organization is refused. It is never dropped to
    get login-only attribution.
  - Duplicates, foreign owners, invalid evidence and missing original clocks
    are refused.
  - A request with no telemetry row but a trace owner is refused before any
    transcript basis: a foreign owner (another child, a parent's request seen
    from a child, or an owner record failing its integrity checks), a
    duplicated owner, or this session's owner without its telemetry row. It
    never borrows the transcript's organization or sole login.
  - Per the SESSION ruling, there is no production pending without a
    qualified current-writer health witness, and none exists. Genuinely
    absent telemetry is missing; present but unusable evidence is refused.
    Only `cfg(test)` can supply a witness (pending then also needs the
    request's own clock within `TELEMETRY_FLUSH_WINDOW_SECONDS`, 300,
    provisional). Only missing requests with no trace owner are open to
    transcript bases.
  - Auxiliary (telemetry-only) reported rows stay refused for a bad clock
    (SESSION ruling). Their `observed_at` may be the observer clock and the v2
    capture does not record which. Transcript clocks are never borrowed. A
    reported item whose request count includes auxiliary requests fails the
    request-id precondition and keeps today's bytes wholesale.
    2026-10-31 ID1: telemetry-only side calls take their own row's complete account (B3, #1018); BadClock refusal no longer applies to them; money bucket unchanged.
  - Unreadable sidecars refuse every request; they never fall through.
- **Transcript markers** (`credential_org` attachment lines):
  - They are captured only on owned lines, after inherited-fork exclusion,
    as an organization hash positioned by response sequence.
  - The trust rule for terminal markers: an unchanged organization stays
    trusted. An organization change needs a new `session_context`; without
    one it is untrusted and refused.
  - Each file keeps at most 64 markers. Overflow switches transcript bases off
    for that file.
  - No email or raw text is kept: a local digest only detects an email
    change, with the positions of the first email and the first switch.
- **`transcript_email`** (terminal/SDK; compiled out unless both
  `EMISSION_ENABLED` and `TRANSCRIPT_EMAIL_ENABLED`, each `false`) **never
  binds a login.** No qualified join from a recorded email to a login exists,
  and sampled status coverage cannot prove that one login ran continuously
  (equal samples 300 s apart do not exclude an unseen A→B→A switch). So it
  only decides whether a request keeps its earlier meaning:
  - Not applicable (the org-only path stands): compiled out, Desktop, no
    unchanged email before the request, the shared default folder, or a
    folder proven never registered over the window (unregistered at every
    pass since registration became known, before the window began, and not
    a removed slot).
  - Otherwise the request is refused, never weakened to `transcript_org`.
    The reasons are typed locally and counted on the wire:
    `CoverageUnavailable` (feed failed or not run since restart, a removed
    slot or forgotten registration, unknown session start, gap, unavailable sample, logout, eviction, window past
    the last sample), `ContradictoryOrg` (a nearby sample names another org
    or another login), and `CoverageUnqualified` (samples span the window
    but prove nothing). Usage and money are conserved, and the positive
    refusal blocks Desktop-pair fill.
  - Qualifying it needs an approved continuity witness and an approved
    email-to-login join; neither exists, so the flag stays off.
- **Status-coverage feed** (`claude_status_coverage.rs`, same gate):
  - The Claude status pass reports each registered slot's already-qualified
    login/org hashes after `claude_slot_post_resolution_gate`, or
    unavailable/signed-out on every failure branch, plus the registered
    folders at the end of the pass. It adds no read, provider call or cadence
    change, and returns nothing to the status pass.
  - A process-local ledger keeps sampled runs (freshness only): consecutive
    same-identity samples at most 600 s apart. Caps: 10 slots, 32 runs per
    slot, 30 days, 64 KiB (worst case 63,360 B). Nothing is persisted or
    uploaded; a restart forgets both history and registration.
  - Removing a slot clears its history but records the loss in a bounded
    set (at most 10 folders). The same request stays refused rather than
    turning org-only. One more loss than the set holds, more registered
    folders than the 10 the ledger keeps, a restart, or a window that began
    before registration was first known makes every unregistered folder
    unknown (refused), never proven absent.
  - Slots past the status pass's collection capacity are still reported as
    registered folders. Scan roots and descriptors read the same registry
    string, and the folder key is lexical.
  - The ledger's (login, org) pairings prove marker-org membership for
    login-only telemetry (§2a.12(b)).
  - A status-pass fixture shows byte-identical status output (SOURCE account
    and plans, quota, health, persisted slot state) with the feed working,
    failed, or holding a conflicting history.
- **`transcript_sole_login`** (Desktop only) needs all of the following:
  - `TRANSCRIPT_SOLE_LOGIN_ENABLED`, a separate constant that is `false`
    until the receiver's time-scoped sole-login veto is verified as deployed.
    Off, a qualifying census yields `transcript_org`;
  - a complete Desktop identity census;
  - a new additive index witness. The witness is set only on a complete,
    error-free store sweep and is bound to process, store inventory and clock.
    It is absent (unknown) for older indexes. A changed store inventory
    drops it on every pass, including passes inside the retry backoff;
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
- **Session owners:** request identities never bind or rewrite an owner. An
  already-bound session admits only this scan's exact contract-5 body, and
  only when the session creator is absent or equal to the retained owner. The
  creator check runs before the matching-owner shortcut, so all-owner rows
  cannot hide a different creator. An unbound session gains no owner from
  contract-5 rows.

## Validation

- `fixtures/session-identity/` mirrors the shared fixture revision
  `session_identity_w0:r5` byte for byte (63 bodies plus `index.json`). Its
  digest `2a9b46f1…e8e6` reproduces in-tree.
- The daemon's own component hashing reproduces `usage_accounting`,
  `attribution` and the identity leaf for all 63 bodies.
- Typed rows serialize to the exact wire members.
- From per-request contributions (a test-only oracle feeding the same
  grouping), the builder re-emits every tagged body:
  - identical bytes for canonical bodies;
  - an identical hash leaf for intentionally reordered ones.
- The cap rule reproduces the fallback bodies.
- Synthetic tests cover:
  - classification rulings;
  - markers, including fork exclusion;
  - the census witness;
  - money exactness and unsplittable reported money;
  - order-free hashing that still moves with the login;
  - both usage paths end to end, including the real reported rebuild (output
    unchanged with or without identity) and an auxiliary-row item;
  - a grouping that retains the same heap for 1,000 and 10,000 requests, folds
    keys past the cap, and stops at the item's rows;
  - unqualified items keeping today's bytes.
- Equal-input end-to-end comparison (debug build, synthetic: 2,000 responses,
  2 logins, 64 markers, parsed once). Both paths start from the same parsed
  items and the same loaded sidecar reports. The transcript is deleted first,
  so neither path can re-read it. Legacy is today's request-account
  qualification. Enabled is contract-5 evidence, streamed tagging,
  request-account qualification over the shared request index, then
  admission.

  | Measure | Legacy | Enabled |
  |---|---|---|
  | Wall time (3 runs, noisy) | 145-212 ms | 155-181 ms |
  | Sidecar fingerprint checks (api, trace) | 2,000, 2,000 | 2,000, 2,000 |
  | Allocations | 64,226 | 66,826 (+4%) |
  | Peak requested heap | 518,112 B | 526,920 B (+8.6 KB) |
  | Retained heap after | 31 B | 6.4 KB |
  | Item payload | 6.7 KB | 13.8 KB |

  Marker capture during the parse adds about 2 ms, 573 allocations and
  6.6 KB retained for 2,063 lines. The test asserts equal fingerprint checks,
  peak within 64 KiB and allocations within 5% of legacy.

  - Classification builds no strings: keys are borrowed, and a grouping copies
    one only when it admits it.
  - Contract 5 validates each login once. Request-account qualification
    reuses the request/owner index contract 5 already built and leaves tagged
    items alone.
  - Tagging installs in place, without copying the item.
  - What remains is per item, not per request: byte-cap encoding, install,
    the fingerprint, and the admission witness. Retained growth is the larger
    tagged payload.
- With emission off, released builds still pay for:
  - 8 B per `SnapshotItem` and accumulator (`claude_org_markers`, always
    `None`);
  - 40 B in `ScanIndex` for the census witness slot. Dark builds keep it
    `None`: they neither compute nor persist a witness, and they clear one
    left by an earlier build at the next Desktop pass;
  - an empty grouping map in the reported-usage disposition, an `Option`
    check per rebuilt item and per rebuilt row, and one extra call frame
    around the reported pass;
  - constant-false branches.
  These costs are small but not zero.
