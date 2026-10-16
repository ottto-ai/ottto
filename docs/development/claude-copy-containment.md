# Claude copied-request containment checkpoint

Two transcripts can carry the same native provider request IDs under different
session IDs, without a declared fork marker. Withdrawing account attribution or
context evidence does not remove the duplicated request's usage. Containment
must decide whether a candidate can be offered before any new body is uploaded.

This checkpoint is **inactive and incomplete**. It adds no scan-index field,
runtime switch, upload decision, local-status field, retry policy or exclusion.
It does not lower accepted history or change account, name or tag facts.

## Components and validation scope

`snapshots/claude_copy_containment.rs` borrows the exact native ID sets from two
parser-produced items. It reports the observed intersection count, a same-session
pair, no overlap in just that pair, or an existing-owner-bound refusal. It never
materializes another owner graph. A lookup miss or non-overlapping pair proves
nothing about unobserved transcripts. Possible-owner envelopes, counts, aggregate
body fingerprints and set digests are not inputs to this comparison.

The proposed typed held-revision value has a closed reason, source revision,
comparison context and optional first-observed time. Deserialization rejects an
unknown version/reason/field, malformed full fingerprint or invalid epoch. It is
not yet part of a persisted index. Unknown historical age stays unknown; changing
revision or context cannot reset the recorded start or clear an incident reason.
The first observed time describes the new typed hold's observation, not an
inferred transcript lifetime or prior hold age.

A distinct parking result compares the held revision to the actual opened
revision and meaningful evidence context. It does not use the committed entry's
fingerprint, which rearm can clear repeatedly. Parking is neither a normal Skip,
current request evidence, settled coverage nor an ACK. The complete wake context,
scanner integration and restart semantics still need source review and tests.

The first ten component tests passed on exact head `2b162a96`, automatic CI
`38958674335`, with all four checks successful. They parse synthetic native transcripts,
exercise copied IDs despite rewritten session IDs, preserve the original usage
while observing a conflict, distinguish equal amounts from ID membership, reject
truncated state, carry unknown/known age and measure the pair comparison and hold
clone allocations separately. The rearm component control invokes the real base
candidate gate after repeated fingerprint invalidation. It does **not** execute
the proven/stale rearm controllers, native scan loop, upload or selected saves.
It is not proof of repeated heavy-read elimination or healthy-sibling progress.
The full native repeated-pass/ACK/save regression remains the next deliverable.

The next candidate adds an actual native A/B/healthy-C bounded-census
characterization: B and C on an early page leave the conflict map empty, while
the terminal A page discovers the exact A/B conflict. A miss before that point
cannot authorize uniqueness. C's usage is preserved; sibling upload/ACK progress
is not yet exercised by this characterization.

An inactive process-only membership index shares immutable native ID strings
between forward and reverse links. New parses look up only their own IDs; reverse
links remove one held revision without walking the whole pool. The existing
layout model conservatively preflights the old graph, owned input and prospective
tree/Arc allocations before mutation. No post-allocation rollback substitutes for
peak admission. Cached charges only grow until the pool is discarded. Peer events
preflight all affected records before allocating or invoking any callback and
emit once per peer/revision. Fixed scratch epochs deduplicate links without a new
temporary owner set. No peer query traverses every held graph for sizing.

This cache supplies negative wake information, never current native coverage,
ACK membership or an upload permit. Shared remaining owner/hold/heap allowances
must come from the real caller; that integration is unfinished. Unsupported
layout refuses admission. Seeded lookup/removal tests are explicitly component
tests before admission; positive budget/event tests must disclose when the real
guard leaves their branch unexecuted. Missing-cache W4 observability remains a
separate qualified residual; there is no fallback that rereads all held files.

## Conservative interim and final behavior

The short interim contains **known exact native overlaps**. A session with no
known overlap retains existing base behavior, without a new uniqueness claim.
The inherited first-unseen-overlap case can still double count and must remain
disclosed in status, the PR body and release notes. The interim ends only when
bounded exact pre-offer coverage and final exclude-and-send are implemented.

An already-qualified exact native/provider/declared-parent exclusion may remove
copied requests from the copy's usage. Excluded requests supply no tags, names or
other identity evidence for the copy. Otherwise, an unresolved overlapping new
revision must remain locally held with visible debt; prior accepted bodies and
unrelated sessions must remain intact. The short whole-body interim can delay
genuinely new requests in an already-overlapping pair. That limitation must be
tracked until exact exclude-and-send is available.

The existing duplicate census identifies current conflicts but does not retain
which IDs belonged to each earlier ACKed body. Current pending sets can precede
ACK and are normally pruned at census completion. Accepted body/set hashes cannot
recover old membership: IDs are local-only, and different sets can yield the same
usage totals. Earlier transcript revisions are not snapshotted. There is no
persisted per-session first-ACK clock. Unknown membership must not be treated as
known absence for a deterministic counting tie-break.

## Remaining integration and safety gates

- Current exact comparison and coverage before the first permissive offer,
  including reversed page order, missing peers, unreadable files and overflow.
- Held-body withholding before kind-11 construction or any name/tag update;
  keep all actual native observations available to the authoritative fold.
- Typed bounded debt through normal and partial/shed selected saves, exact
  source/context changes, failed CAS, restart and window shrink. A window miss
  is not proof of absence. No silent hold retirement or completion relaxation.
- Parking under actual repeated base/proven/stale rearm, healthy siblings'
  upload/ACK progress, and measured read/owned/clone cost. A generic rearm must
  not replenish the parking allowance every traversal.
- No customer-specific incident selector is permitted. Private full identities
  are regression evidence only; the generic guard must demonstrate coverage.
  The currently installed runtime has no new protection from this checkpoint.
- Local reason/count/oldest-known-age and a separate class for new fully held
  sessions, without presenting unknown cost as zero. Local exclusion receipts
  need count, owning-session display hash and tokens by dimension. No additional
  server field or collection is planned.
- Persisted load/default/downgrade policy and actual shared resource bounds.
  An old reader rejecting an index and rebuilding under old unsafe code would
  not enforce a new containment rule. Merely adding a version is insufficient.
  Containment requires a containment-capable runtime; downgrading below that
  release is unsupported for containment and the overlap can recur. A rebuild
  on the new binary must execute its pre-offer guard before offering bodies.

No installed CPU, memory, reread, monetary-conservation, merge or release
acceptance follows from this checkpoint. Local builds/tests were not run.
