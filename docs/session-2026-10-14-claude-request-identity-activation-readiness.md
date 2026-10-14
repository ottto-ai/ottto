# Contract 5 activation readiness: owner refusals, census backoff, cohort gate

Contract 5 (`claude_code_jsonl:own_request_identity_rows:v1`) merged dark. This
change closes the defects found in the dark-merge review and adds the gates an
emitting build needs. It turns nothing on: `EMISSION_ENABLED`,
`TRANSCRIPT_EMAIL_ENABLED` and the new `TRANSCRIPT_SOLE_LOGIN_ENABLED` are all
`false`, and a released build's bytes, hashes and uploads are unchanged.

## Trace owners outrank the transcript

`classify_ref` used transcript bases (`transcript_org`, `transcript_sole_login`)
for any request without a telemetry row, before it looked at trace ownership.
A request that a trace assigns to another child could therefore take this
transcript's organization or sole login.

Now a request with no telemetry row but a trace owner is refused first:

| Trace owner | Result |
|---|---|
| Another child, a parent's request seen from a child, or a record failing its integrity checks | `ForeignOwner` |
| Duplicated | `ConflictingDuplicate` |
| This session, but no telemetry row (unpaired) | `IncompleteEvidence` |
| None | Transcript bases, as before |

The checks are the ones the telemetry path already applied, minus the
client-request-id match that needs a row. A valid paired owner still yields
telemetry attribution. Refusals conserve usage and money; only the
refused-versus-missing state reaches the wire.

## The census witness follows the store inventory during backoff

The Desktop census witness was reconciled against the store inventory only
after the retry-backoff early return. A store added or removed during backoff
kept the old witness, so a request from the new store could get the old
census's sole login. The reconcile now runs before the return. Dark builds
clear any leftover witness on every pass, which costs nothing when there is
none.

## `transcript_sole_login` has its own gate

The email flag never covered this basis. `TRANSCRIPT_SOLE_LOGIN_ENABLED` is
`false` until the receiver's time-scoped sole-login veto is verified as
deployed. While it is off, a qualifying Desktop census yields `transcript_org`
(org only), the same as when no census qualifies. Tests opt in per evidence
set.

## Cohort gate: default deny, no seam yet

A global `EMISSION_ENABLED = true` would emit from every install. Emission now
also needs an `EmissionPermit` for the current sync cycle, which
`emission_permit` grants only when all hold:

- emission is compiled in;
- a `CohortGrant` is present;
- the grant names exactly `COLLECTOR`; any other spelling is refused;
- the grant's account witness equals the cycle's (`snapshot_scan_account_witness`),
  so a grant never survives an account switch.

The permit is computed per cycle and never persisted, so a restart starts
denied. `apply_claude_local_evidence_to_scan_with_permit` builds contract-5
evidence only under a permit; the old entry point is the dark path.

**No trusted seam supplies a grant today**, so production passes none and
every install is denied. This is not operational targeting. The existing
per-account, authenticated capability channel is the activity-hint response
(`ActivityHintResponse`, re-read every cycle with the device credential;
absent or unknown values fail closed). It carries no contract-5 field, and
adding one is a server-contract change that needs its owner's decision. A
scoped build that is never published to the stable channel is the other
option. Neither is chosen here.

What to settle before wiring a seam:

- revocation applies from the next cycle: bodies are rebuilt each cycle
  (upload progress keeps ACK ledgers, not bodies), so a revoked install sends
  today's shape again. How the receiver treats a contract-5 entity later
  re-sent in today's shape is its rollback contract, not decided here;
- marker capture and the census witness follow `EMISSION_ENABLED`, not the
  permit. They stay local and are never uploaded, but every install pays
  their parse-time cost once emission is compiled in.

## Status-coverage registration past capacity

- The status pass reports slots past its collection capacity as registered
  folders too (`claude_status_coverage_dirs`). Before, their transcripts
  could read as never registered and keep the org-only path instead of
  refusing.
- More registered folders than the ledger's 10 now mark registration
  knowledge incomplete for the rest of the process, so every unregistered
  folder is unknown (refused). Before, extra folders were silently dropped.
  The byte bound is unchanged.
- Scan roots and descriptors both read the registry's own `config_dir`
  string, and the folder key is lexical. A test pins trailing-slash, doubled
  slash, `./` and nested-`projects` spellings.
- Not fixed: when `<config dir>/projects` is itself a symlink, the scanner
  walks the resolved path, so a transcript's folder key does not match the
  registered one. Its email request could read as never registered. Closing
  this needs the configured root threaded to the parser, which is out of this
  change's scope. `transcript_email` stays compiled out, and it also still
  lacks a continuity witness and an email-to-login join.

## Validation

- Synthetic tests:
  - foreign, duplicated and unpaired owners refuse before the transcript;
    valid-owner and no-owner controls;
  - inventory changed during backoff drops the witness; unchanged keeps it;
  - sole login suppressed by default, available only with the opt-in;
  - the permit matrix: missing, malformed or other-account grants deny, and
    so does a valid grant while emission is off;
  - one production fixture through the evidence entry point: denied cycles
    keep today's bytes exactly; a permitted cycle reaches contract 5;
  - registration past the slot and ledger caps never proves absence; within
    the caps, absence is still proven (control);
  - folder-key spellings.
- Compile-time pins keep all three flags `false`.
- The W0 fixtures (`session_identity_w0:r5`), resource comparison and
  old-collector round trip are unchanged; the hosted workspace test run
  covers them.
