# Skip no-progress Claude full re-arms; carry full-rearm-window families

While the Claude duplicate fence stays closed, a due closed-fence full re-arm
clears every Claude family file's source revision, so the next walk re-reads
all of them. When the only thing keeping the fence closed is a family that is
invalid from its own bytes (a response without a request id, one id on two
responses, a request count that does not match its ids or occurrences), that
re-read cannot open the fence: the same bytes give the same invalid census.
The backoff caps the repeats at one a day, but each repeat re-reads every
family. A second waste came from the walk right after a full re-arm. When that
walk needed a clean follow-up (one of its pages settled only partially), the
follow-up re-armed every family parsed in it again.

## Fix 1: skip a full re-arm that cannot make progress

At a complete terminal where the fence was closed before and stays closed
after, the fold records the structurally invalid family set. The record holds
a root digest per family and one digest over every indexed member's index key
and committed source revision. It is local, content-free (digests and counts),
and persisted with the fence state as `claude_full_rearm_progress`. It is
recorded only when the census observed every other indexed family member in
this window, and the record basis digests the record version, the D1
request-census derivation (`CLAUDE_REQUEST_CENSUS_DERIVATION`), the scan
identity version and the contract-5 contract.

The classification lives in one function, `claude_member_invalidity_is_structural`.
A page marks a family structural when one of its parsed members has a nonzero
request count and either its request-id count or its occurrence count differs
(the parser's identity check). A request count of zero and an occurrence key
mismatch are not treated as structural (conservative). Any cap, member-changed
or occurrence-mismatch invalidation on any page of the window marks the window
as having another cause, and so does a duplicate-owner overflow.

A due full re-arm is skipped (no revision clear, no attempt bump, no new
deadline) only when all of these hold:
- the fence was closed before and stays closed;
- no current-window family is invalid for another cause, and no stale pending
  keeps the census invalid;
- the contract-5 latch is clear and the recorded contract is the current one;
- a record exists under the current basis, every recorded family's member
  digest is unchanged, every current structural family is in the record, and
  a fully observed window's set equals the record;
- no first-proof hold (see below).

Any change (a member revision, a new family, a basis change, a latch flip, an
unrecorded contract, a lost or malformed record) re-arms exactly once as
before, and that window records the new set. An incremental window that reads
nothing is closed only by coverage; the same unchanged families keep it
closed, so it is skipped too. The skip never touches `identity_contract_rearm`
or `fence_recovery_rearm`, never clears the latch, and leaves the posture veto
and M1 per-file re-emission unchanged.

First-proof veto. A copied-prefix successor of a dormant owner (C1a) can prove
only in a window that also re-reads the owner, and the due full re-arm is the
only path that does. A closed terminal that counts such a held first proof
(`dormant_owner_successor_family_count > 0`) sets a sticky flag, and the flag
vetoes the skip until a full re-arm runs or the fence opens.

Disclosure: the Claude local-evidence census line prints
`full_rearm_suppressed=<bool>` and `full_rearm_skipped_invalid_unchanged=<n>`.
Its `full_rearm_suppression` JSON summary (beside `duplicate_census`, omitted
while empty) carries `full_rearm_skipped_invalid_unchanged`,
`structural_invalid_family_count` and `suppressed_since_unix_seconds`. The
boolean is emitted once in the line prefix so the numeric summary keeps its
192-byte bound even at maximum counter width. The counters stay in their own
struct so the duplicate-census line keeps its bound.

The persisted value decodes leniently: any malformed value decodes as "no
progress", so the index still loads (nothing is quarantined) and the next due
terminal re-arms.

## Fix 2: carry unchanged full-rearm-window families at a clean follow-up

A complete terminal that runs a full re-arm behind a closed fence marks the
next traversal start, which opens a full-rearm window tied to its upload
context fingerprint and this daemon process. A complete census retires the
window; another context or a restart drops it (BASE).

At a later clean follow-up start in that window, stale families whose pending
came from the window go through the C1b family checks
(`claude_fence_closed_retry_carry`, unchanged), and the carried families are
compacted exactly like C1b's: no credit, and the next complete census stays
invalid while the fence stays closed. Families touched by the partially
settled pages fail those checks (an uncommitted revision, an unaccepted body
or an account hold), so the prior-unsettled refusal still holds for them.

The families the carry refuses are re-read whole at most
`CLAUDE_STALE_FULL_REARM_WINDOW_REARMS_PER_DEADLINE` (one) time per fence
backoff deadline. After that, a window family that is committed, accepted,
not account-held and without an authority quarantine record is kept without
reparse and compacted the same way. The cap holds nothing while the latch is
set, the contract is unrecorded, the ledger is stale, the upload context is
inactive or no deadline is set. Every other stale family keeps BASE's re-arm.
Capped families retain a digest of their committed member revisions before the
stale re-arm; a changed revision fails the cap. Capped families share C1b's
funded cancellation/replay buffer, so M1 selection of a changed member cancels
the cap and queues passed siblings. The window origin is recorded at the
terminal; restart before its first start or during a carried window restores
BASE before selection.

The traversal start row reports `rearm_window_families`,
`rearm_window_carried_families`, `rearm_window_rearmed_families`,
`rearm_window_rearmed_files`,
`stale_rearm_capped_families` and `stale_rearm_capped_files`, each omitted
while zero.

## COST ruling 3: no ramp after an index rebuild

When `load_for_snapshot_source` sees the #700 rebuild (a fresh generation-0
Claude index beside the re-emission seen marker), it seeds the fence re-arm
attempt at its maximum. The first close still re-arms once, because the posture
correction and the contract-5 latch (which an unrecorded contract sets) need
it, but the next due re-arm waits the capped delay (24 hours) instead of
ramping from one hour. An opening fence resets the attempt as before.

## Tests

- `snapshots/full_rearm_progress_tests.rs` covers:
  - N due terminals versus BASE (re-armed files and bytes), the disclosure and
    the content-free record;
  - a coverage-only skip;
  - a changed member revision re-arming once and then skipping;
  - a new structural family;
  - member-changed and cap invalidations;
  - a latch flip and an unrecorded contract;
  - a basis bump and the first-proof veto;
  - malformed persisted values that still load and then re-arm;
  - the rebuild seed against the base delay.
- `snapshots/stale_family_carry_tests.rs` covers:
  - the window carry at a clean follow-up, and the one-per-deadline cap;
  - a new deadline;
  - the unaccepted and latched controls;
  - context, process and no-window controls (BASE).
- `snapshot_sync/stale_family_carry_pipeline_tests.rs` runs the C1b red chain
  with the red window turned into a clean follow-up: the family is carried
  and liveness equals BASE. A late-API-row control re-reads the family like
  BASE.
- `snapshots/traversal_transition.rs` checks that the new start counts are
  omitted at zero and that a maximum-width row stays within budget.

## Rulings

SI and COST rulings are in: structural means only a pure function of the
member's own bytes, and the cap is one whole stale re-arm per backoff
deadline. Acceptance comes after release.
