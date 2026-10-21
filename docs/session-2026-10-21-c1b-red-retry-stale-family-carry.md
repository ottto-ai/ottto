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

Unwitnessed and invalid families always keep the re-arm, so their own files
are selected as before. That does not make every first-proof opportunity
unchanged: a fork that depends on a carried root's sequence is the residual
below.

Before it builds any scratch, the carry check prices everything it keeps live
at once (the blocked-root set, the legacy-witness vector, the
complete-membership graph, the carried-root set, the request-owner map and the
shared-owner set) with the same supported-layout full-node pricing and parked
budget as C1a's unchanged-proof check. An unsupported layout, an overflow or a
refused price carries nothing, so the start is BASE's, and a content-free
counter plus a fixed-text log line record the refusal.

A carried family's pending is compacted: occurrences are dropped and request
hash sets emptied, while member keys, the old window and `invalid = false`
stay. That entry credits no evidence: it covers nothing, feeds no legacy
derivation, holds no cap budget, and keeps the next complete census invalid,
so the fence cannot open on it. That census retires it as before.

A carried member that changed on disk, including its sidecar stats (M1), is
still selected by the ordinary fingerprint comparison and re-read. Any parse
of a carried family's member (changed, new, or selected by another gate)
before any other member of that family is parsed in the window cancels the
carry: every other member's revision is cleared, and members the walk already
passed are queued again at the front of the traversal, so a later bounded
page of the same window reads them and the whole family is co-observed in
that window as BASE's re-arm observes it. The page file limit is unchanged.
On the page that ends the walk, queueing a passed member would end that page
without its terminal fold, which demotes the changed revision before the
family can be re-proved; there the carry stays and the family takes the
ordinary path (the held path below). A content-free counter and a fixed-text
log line record each hold. A content-free counter and a fixed-text log
line record each cancellation.

The carry funds each family's worst-case cancellation when it is admitted:
queueing every indexed member of the family again, one queue slot each plus a
cloned scan root and a member path no longer than its index key, priced as
growth of the start's empty candidate queue against the same parked budget.
Families are funded cumulatively in root order. One whose worst case does not
fit beside those already funded is not carried and keeps BASE's re-arm,
counted content-free with a fixed-text log line; a later, smaller family may
still fit. The funding map is part of the carry check's priced scratch.

The cancel builds no scratch collection: it counts the family's other
members by borrowing, confirms it draws no more than the worst case the carry
funded, and reserves its queue growth before its first mutation, so it is
never refused. The queue's existing entries move with its buffer when it
grows, as on every discovery push; the funding covers what the cancel adds.
Should a defensive check find the funding missing or the reservation fail
(not expected), it debug-asserts and re-arms the family's other members as
BASE does, without queueing them, counted content-free; it never keeps the
carry.

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
  sidecar change, a changed member, and a lost contract-5 record. Those
  cases' liveness (RetryPending, red, census complete, census invalid, fence,
  full re-arm, proof) equals BASE in every window.
- Round 2 adds: the scratch admission (a forced refusal and a 12,000-hash
  priced refusal both equal BASE byte for byte, an admitted positive, and
  admission equal to the supported-layout predicate); the reviewed
  recoverable change (the provider ledger already holds a subagent request,
  and the transcript gains it with matching usage) found on a non-terminal
  page, where the cancel co-observes the family and the proof, RetryPending,
  liveness and witness equal BASE's; the same change found on the page that
  ends the walk, where the family takes the held path; and the
  removed-member held path.
- Round 3 adds: an admitted cancel (the passed member is re-armed and queued
  once at the front of the traversal), the cancel price at its budget
  boundaries, and a refused cancel on a full candidate queue that leaves the
  index, the carry and the queue untouched and is counted once.
- Round 4 replaces round 3's refused-cancel test, whose kept carry the owner
  ruled out, and adds: a funded cancel behind a full candidate backlog that
  round 3 refused (re-armed and queued once); the carry-time funding boundary
  with two witnessed families (exactly funded, one byte short, and only the
  smaller, later family funded); an unfunded carry whose start equals BASE
  byte for byte; and the walk-ending-page change with the family unfunded,
  whose every window, proof, heads and witness equal a real BASE arm's
  through the fold.

## Residual risks

- A red full-coverage window with any invalid stale family no longer gets an
  immediate whole retry; reopening waits for the scheduled full re-arm
  (at most 86,400 s).
- Census-invalid residual. One retained, indexed, unquarantined old-window
  entry makes the duplicate census invalid. With C carried families and M
  nonempty indexed member files, a red retry saves up to M family file reads
  and releases their occurrences (the fixture saves 3 reads per retry, 6 over
  two). The invalidity lasts until the first complete fold of the carry span,
  which removes the carried pending; red retries can extend the span. At that
  fold, new cross-family duplicate detection is withheld, the fence cannot
  reopen, and transcript ownership stays incomplete for unread members, so
  reopening may wait for the scheduled full re-arm (capped at 86,400 s) plus
  eligibility, traversal and settlement time. `note_policy_settled` can reset
  #588 process history. Ordinary first proofs still run, and C1a is not
  globally disabled by `census_invalid`; C1a's independent fence-recovery
  path can still re-arm every family when unread witnessed families are the
  only obstacle.
- Held path (SOURCE B9), walk-ending page: when a carried family's first
  member parse in the window falls on the page that ends the walk and
  another member was already passed, the carry stays. Only that member is
  read, its pending lacks the others, and the family takes the ordinary path
  (demotion, RetryPending, forced family reparse). BASE reads the whole
  family there and, when the changed member's whole family sits on that
  terminal page, re-proves it without RetryPending.
- Held path (SOURCE B9), unparsed change: a carried member that changes
  without being parsed in the window (it is removed, moved, or ages out of
  the backfill window) does not cancel the carry. The remaining members are not read in that
  window, while BASE re-reads them. They are read again only when a later
  start re-arms the family or one of its members is parsed.
- A compacted entry keeps no request hashes, so a fork that first copies a
  carried root's prefix after the carry is not seen at the next retry. It is
  held like C1a's dormant-owner successor (counted in the first-proof hold
  counters) until the root is read again, at the latest at the scheduled full
  re-arm.
- No predicate for h527 targets or protected copied-overlap identities exists
  in this tree; the duplicate-owner, owned-start and legacy-link exclusions are
  the conservative proxies.
