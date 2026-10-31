# Contract 5 activation readiness: owner refusals, census backoff, cohort token, hex logins

> Partly superseded 2026-10-31: `TRANSCRIPT_EMAIL_ENABLED` and the
> status-coverage feed were deleted while still off. See
> `session-2026-10-11-claude-request-identity-rows.md`.

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

## Cohort gate: the activity-hint token

A global `EMISSION_ENABLED = true` would emit from every install. Emission now
also needs an `EmissionPermit` for the current sync cycle. `emission_permit`
grants one only when all of these hold:

- emission is compiled in;
- the source is Claude Code;
- the cycle's activity hint carries `session_request_identity_contract` equal
  to exactly `own_request_identity_rows:v1`. That is the cohort token, not the
  collector name; prefixed, padded or other spellings are refused.

The hint is the existing per-source response the daemon already fetches each
cycle with its device credential. The new field is optional and defaults to
none, so an older server, a missing field or `null` all deny, and the body
stays exactly today's. A failed hint fetch still aborts the cycle before any
scan. The server sends the token only to its approved cohort. That makes this
compliant producer control, not security enforcement: the server's admission
is unchanged and stays permissive. The daemon holds no allowlist and makes no
extra fetch or provider read.

The permit is computed from the hint each cycle and never persisted. A token
the server drops denies from the next fetched cycle, and a restart or account
switch starts from that cycle's hint. Prepare and finish read the same
cycle's hint. Bodies are rebuilt each cycle (upload progress keeps ACK
ledgers, not bodies), so a revoked install sends today's shape again. How the
receiver treats a contract-5 entity later re-sent in today's shape is its
rollback contract, not decided here.

## Local identity work follows the permit

Marker capture and the Desktop census witness now follow the cycle's permit,
not the compiled switch. A scan without a permit captures no transcript
markers and clears any stored witness, so installs outside the cohort pay no
extra parse-time cost even once emission is compiled in.

- The permitted cycle's sampled-scan cache scope gains a `:request_identity`
  suffix, so a parser retained in one capture mode never resumes in the
  other. The scope string without a permit is unchanged.
- A file parsed in an earlier cycle without capture carries no markers.
  Transcript bases then do not qualify, and those requests stay untagged.
  This is the conservative direction.
- After a clear, the witness returns only with the next complete store
  sweep.

## Logins must be lowercase hex

A login reaches the wire only as strictly lowercase hex of 8 to 128
characters, the receiver's stored `account_identifier_hash` spelling. Every
authority key passes through one grouping step, which refuses any other
spelling there: uppercase, other characters, too short or too long. The
refused request's usage and money stay on the row untagged, and a valid key
beside it is still tagged. A login is never lowercased, trimmed or re-hashed.

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
  - the permit matrix: the exact token permits; a missing, empty, prefixed,
    padded, upper-case or other-version token denies; Codex and Pi deny; the
    exact token denies while emission is off;
  - the hint field: missing and `null` read as none, and any string is kept
    as sent;
  - revocation: a token dropped from the next cycle's hint denies that cycle;
  - one production fixture through the evidence entry point: denied cycles
    keep today's bytes exactly; a permitted cycle reaches contract 5;
  - lowercase-hex logins at 8, 64 and 128 characters are tagged as read;
    upper-case, mixed-case, non-hex, empty, 7- and 129-character logins are
    refused without poisoning a valid key, and usage is conserved;
  - registration past the slot and ledger caps never proves absence; within
    the caps, absence is still proven (control);
  - folder-key spellings.
- Compile-time pins keep all three flags `false`.
- The W0 fixtures (`session_identity_w0:r5`), resource comparison and
  old-collector round trip are unchanged; the hosted workspace test run
  covers them.
