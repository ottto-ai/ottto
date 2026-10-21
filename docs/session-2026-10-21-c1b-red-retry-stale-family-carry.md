# Carry unchanged witnessed Claude families across red retries (C1b)

A Claude traversal that ends red (one unrelated file disappeared, failed to
open, or holds a line that is not JSON) keeps its census-window pending. The
retry's traversal start (`ensure_bounded_traversal`) then cleared the source
revision of every family parsed in that red window, so every retry re-read
those families whole. While the duplicate fence stays closed, those re-reads
of unchanged, already witnessed families are semantic no-ops, and a red chain
repeats them at every retry.

## Change

At a traversal start, a stale family keeps its committed revisions (it is
"carried") only when every check below holds. Every other case takes the old
whole-family re-arm.

Start-wide checks:
- the start retries the prior traversal's context after its red terminal;
- no page of that traversal settled partially (the marker is read before the
  start resets it);
- the duplicate fence is already closed;
- the contract-5 identity latch from C1a is clear and a contract is recorded;
- the accepted ledger is current and not being rebuilt, and the upload
  context is active;
- a whole re-arm could not plausibly reopen the fence: some indexed Claude
  file outside the stale families keeps its revision, or some stale family's
  pending is invalid.

Family checks:
- complete membership: the root and exactly one path per member;
- no authority quarantine record, which includes correction debt;
- a witness with no legacy exclusion, whose request and occurrence member sets
  equal that membership;
- no member in the owned-start census, no pending request in the persisted
  duplicate-owner witness, and no legacy owner or shared legacy prefix link
  from another witness;
- no pending request that also appears in another family's pending: a legacy
  fork or takeover successor derives its copied-prefix exclusion only while
  its owner's root sequence is read in the same window;
- valid pending that names only current members and, for every member it still
  holds occurrences for, matches the witness exactly (a tripwire, vacuous on a
  compacted entry);
- every member file has a committed revision, an accepted unquarantined body
  (or is confirmed empty), and no account-deferred hold.

Unwitnessed and invalid families always keep the re-arm, so first-proof
opportunities for never-proven families are unchanged.

A carried family's pending is compacted: occurrences are dropped and request
hash sets emptied, while member keys, the old window and `invalid = false`
stay. That entry credits no evidence: it covers nothing, feeds no legacy
derivation, holds no cap budget, and keeps the next complete census invalid,
so the fence cannot open on it. That census retires it as before.

A carried member that changed on disk, including its sidecar stats (M1), is
still selected by the ordinary fingerprint comparison and re-read; its parse
resets the family pending to the current window.

No persisted field, schema, cap or constant changes. The traversal-start row
gains two counters, `carried_pending_families` and `carried_index_files`; an
extra fixed-text log line reports the same counts.

Shared with C1a (#663): `claude_index_file_body_accepted`,
`claude_accepted_ledger_is_current` and `claude_usage_family_witness_legacy_free`
replace the equivalent inline checks in C1a's unchanged-proof check.

## Tests

- `snapshots/stale_family_carry_tests.rs` runs the real traversal start on a
  synthetic persisted index against a BASE arm
  (`KeepStaleClaudeFamilyRearmForTest`): the carry and compaction, red-chain
  idempotence, the released occurrence budget, the invalid-stale-family
  residual, and negative controls that each equal BASE byte for byte.
- `snapshot_sync/stale_family_carry_pipeline_tests.rs` runs the C1a fixture
  through the real bounded pipeline with a red chain caused by an unrelated
  session: the carry at both retries, plus controls for invalid pending, a
  sidecar change, a changed member, and a lost contract-5 record. Every window's
  liveness equals BASE.

## Residual risks

- A red full-coverage window with any invalid stale family no longer gets an
  immediate whole retry; reopening waits for the scheduled full re-arm
  (at most 86,400 s).
- While a carried entry exists, the next complete census reports
  `census_invalid` where a whole re-read might not have.
- A member that changes after the carry takes the ordinary witnessed-family
  path (demotion, RetryPending, forced family reparse) instead of the
  incidental whole-family re-read.
- A compacted entry keeps no request hashes, so a fork that first copies a
  carried root's prefix after the carry is not seen at the next retry. It is
  held like C1a's dormant-owner successor (counted in the first-proof hold
  counters) until the root is read again, at the latest at the scheduled full
  re-arm.
- No predicate for h527 targets or protected copied-overlap identities exists
  in this tree; the duplicate-owner, owned-start and legacy-link exclusions are
  the conservative proxies.
