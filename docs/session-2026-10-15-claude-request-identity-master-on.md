# Contract 5 master-on: emission compiled in, cache and cross-root gaps closed

> Partly superseded 2026-10-31: `TRANSCRIPT_EMAIL_ENABLED` and the
> status-coverage feed were deleted while still off. See
> `session-2026-10-11-claude-request-identity-rows.md`.

Date: 2026-10-15.

`claude_request_identity::EMISSION_ENABLED` is now `true`.
`TRANSCRIPT_EMAIL_ENABLED` and `TRANSCRIPT_SOLE_LOGIN_ENABLED` stay `false`,
and a compile-time assertion pins all three. This change does not activate
anything:

- A cycle emits contract 5 (`claude_code_jsonl:own_request_identity_rows:v1`)
  only for Claude Code, and only when that cycle's activity hint carries
  exactly `own_request_identity_rows:v1`.
- No token, `null`, another version, a padded or prefixed spelling, or the
  collector name all give the same body bytes as the build before this change.
  Such a cycle captures no markers and keeps no Desktop census witness.
- A hint that cannot be read aborts the cycle before any scan, as before.

The server sends the token only to its approved cohort. Until it does, this
build behaves as the previous build did.

Prepare (capture) and finish (emission) now get the permit from one helper,
`cycle_request_identity_permit`. Its input is that cycle's hint only.

Two gaps had to close before emission could be compiled in.

## Non-capture cache coverage

The scope of the retained-parser cache already gained `:request_identity`
under a permit. A scope change forces a full read (`ScopeChanged`). Retained
native state now also records its capture mode: `prepare_acquisition` reuses
retained state only if it was built in the same capture mode. Otherwise it does
a full read (`StateMissing`). A prefix parsed without capture has no markers.
Extending it with a capturing tail would read as "no marker before this
request", which is a different claim from "markers not looked at".

Files that have not changed are not parsed again. Their last body stays as the
server holds it, in today's shape. The scope suffix only changes how a changed
file is read. This change does not trigger a replay, re-select files, or bump
the upload context. Those would be a backfill, and re-reading history is a
separate step outside this change. So once a cohort install receives the
token, contract 5 covers sessions whose transcript changes after that.

The cost is one full re-read of each changed file in the first cycle after the
permit flips, in either direction. After that, cycles in the same mode reuse
the tail as before.

## Cross-root trace owners

Telemetry and trace rows are keyed by trace root. A fork, resume or takeover
copy under another root contains its original's requests. Unmarked copies
also contain the original's `credential_org` markers, whereas lines marked
`forkedFrom` were already excluded at parse time. Before this change, such a
copy could tag its original's request from the copied markers. The rules now
are:

1. **Rows under another root own the request.** This applies to a request
   with no API or trace row under its own root. If rows under exactly one
   other loaded root name the request, it is refused as `ForeignOwner`. If
   rows under several other roots name it, it is refused as
   `ConflictingDuplicate`. The id-to-root index is a sorted vector built
   lazily, the first time a request without its own rows is classified. A pass
   in which every request has its own rows never builds it. A root's own rows
   still decide that root's requests.
2. **A request in the duplicate witness refuses.** If the duplicate census has
   witnessed the request in another transcript, a transcript-path request
   without its own rows is refused as `ConflictingDuplicate`. It never borrows
   either copy's markers.
3. **Unsettled passes withdraw marker tags.** Only a census that compared
   every indexed Claude transcript can show that a request is this
   transcript's alone. That needs a complete census, complete coverage, a
   valid census, an open fence after the pass, and the census's own
   ownership qualification (`TranscriptOwnership::after_census`).

   Fence coverage alone is not enough. It excuses a family held by a bound
   authority quarantine, whose retained pending is from an older window, so
   its requests were never compared. An unmarked copy of such an original
   under a new root carries the original's request and org marker, and would
   pass all four census flags. The census therefore also records
   `transcript_ownership_complete`: every indexed member's current requests
   were observed this window, and a quarantine excuses nothing. It is taken
   before the census prunes this window's pending, so it can never claim
   completeness from pending that was already cleared. A pass with no
   terminal census leaves it false. It is not a census, fence or upload
   input, and no counter, cap or fence rule changes.

   In any pass that is not settled, every tag that rests on markers is
   withdrawn:
   - a `transcript_org` tag becomes untagged (missing);
   - a marker org joined to login-only telemetry becomes login-only
     (`telemetry_login` with no org).

   Telemetry tags and refusals are kept. Usage, money and row grain do not
   change.

As a result, `transcript_org` and marker orgs reach the wire only from passes
whose census settled. A fresh install's first complete scan is one example.
While any indexed Claude family is under a bound authority quarantine and not
re-observed in the window, no pass settles. A terminal (`UnprovenTerminal`)
quarantine can persist, so on such a machine marker-derived tags stay
withdrawn, for every session, until the quarantine resolves. Telemetry
attribution is unaffected. An original whose transcript is gone from the index
and whose telemetry is unavailable leaves no local evidence at all; a copy of
it cannot be told from an original.
Per-request telemetry attribution (`telemetry`, `telemetry_login`) is
unaffected. This is the bounded handling that stays within the current source
and store contract. To recover org-only coverage from unsettled passes, one of
the following would be needed:

- (a) accept this coverage;
- (b) an SI ruling that a non-binding org-only tag may stand when no foreign
  owner is seen;
- (c) a store contract change that persists a per-request settled-ownership
  witness and adds a re-selection path.

The plan's second activation step (transcript email and marker org) is where
(b) or (c) would be decided.

`ClaudeDuplicateCensusCounts` used to be read only by its log line. Contract 5
now reads one pass's counts to decide whether that pass settled. No gate,
hash, or index depends on them.

## Tests

- Flag pins and permit parity:
  - the compile-time assertion;
  - the exact token is permitted under this build;
  - denied cycles keep today's bytes;
  - the released permit's bytes equal `permit_when(true, …)`.
- Cross-root classification: rows under another root give `ForeignOwner`, and
  this includes a trace owner alone. Rows under two other roots give
  `ConflictingDuplicate`. In the control cases, own rows still tag and a
  request no root names keeps the transcript bases.
- `apply_scan_with_ownership` end to end:
  - in a settled pass, the bases match `apply_scan`;
  - a witnessed duplicate refuses;
  - each of the four unsettled conditions withdraws the transcript and marker
    orgs and refuses nothing new;
  - the refusal survives an unsettled pass;
  - usage is conserved in every case.
- Quarantined original (`census_convergence_tests::transcript_ownership_needs_quarantined_originals_observed`):
  a real terminal census over an index holding a quarantined, unobserved
  original whose retained pending names the copied request. All four census
  flags pass, and the copy's request is withdrawn to missing with no refusal
  and usage conserved. In the control, with no original indexed, the copy
  keeps `transcript_org`. Hosted CI ran this test red before the fix.
- Capture-mode cache guard: a dark seed, an append, then a capturing cycle
  under the same scope does a full read (`StateMissing`) and captures the
  prefix's marker. In the control case, the same mode on both cycles tails.
- `prepare_sync_source` pipeline (`snapshot_sync/request_identity_pipeline_tests.rs`):
  - The real preparation runs against a mock backend (relay token, activity
    hint, status upload). The status collection is injected, so no provider or
    credential state is read.
  - It steps the scan, then runs finish's Claude stage with the permit that
    finish derives.
  - With the token: the contract-5 collector, captured markers, and a Desktop
    census witness.
  - With no token, `null`, another version, a prefixed token, or the collector
    name: the bytes equal a pre-change oracle (no capture, no permit, same
    preparation and clock), with no markers and no witness.
  - An unreadable hint aborts the cycle and writes no scan state.

## Not claimed

This change makes no claim about activation, savings or coverage. Activation
is a separate SI/Ron decision. The server's environment allowlist is not set,
so no install receives the token yet.
