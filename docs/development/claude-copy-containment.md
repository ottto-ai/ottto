# Claude copied-request containment checkpoint

Two transcripts can carry the same native provider request IDs under different
session IDs, without a declared fork marker. Withdrawing account attribution or
context evidence does not remove the duplicated request's usage. Containment
must decide whether a candidate can be offered before any new body is uploaded.

This checkpoint is **inactive and incomplete**. The ordinary daemon owner does
not attach a containment context. It adds a typed scan-index hold field and
native scanner/pre-offer/checkpoint seams, exercised with an explicit test
context. It adds no runtime switch, local-status activation claim, retry counter,
timer, automatic restart read or new exclusion. It does not lower accepted
history or change production account, name or tag facts.

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
part of a separately validated scan-index hold ledger. Unknown historical age stays unknown; changing
revision or context cannot reset the recorded start or clear an incident reason.
The first observed time describes the new typed hold's observation, not an
inferred transcript lifetime or prior hold age. Current native integration tests
seed known ages; automatic classification keeps age UNKNOWN until the actual
owner supplies an observation witness.

A distinct parking result compares the held revision to the actual opened
revision and meaningful evidence context. It does not use the committed entry's
fingerprint, which rearm can clear repeatedly. Parking is neither a normal Skip,
current request evidence, settled coverage nor an ACK. The scanner checks this result after its actual opened-object/sidecar witness
and before selecting a native parser. A supplied UNKNOWN wake witness parks the
held revision. Real process-owner context acquisition and all W1–W5 bindings
remain unfinished. Restart alone need not grant a read: a lost W4 cache is a
qualified disclosed residual, not a reason to add automatic retry work.

## Bounded local observation and marker safety

The inactive required-policy path projects a content-free aggregate through the
existing local health-event envelope. It retains one current observation, replacing
its previous observation rather than growing a per-pass history. Identical payloads
do not create a new event. The event stays in local status; its exact type is omitted
from canonical backend health evidence, while unrelated evidence remains unchanged.
No protocol field, server upload, endpoint or new state file is added.

Counts distinguish recorded held revisions, unique parked revisions, unavailable
or repeated process attempts, closed reasons, retained prior local ACK evidence,
and unknown past acceptance. Missing ACK evidence never means a session is known
new. Missing or future observation time stays UNKNOWN. Per-pass observations are
not persisted and become UNKNOWN after reload. W4 currently reports unavailable
because native capture is not connected. Overflow decisions are counted; the
number of distinct unrecorded held revisions remains UNKNOWN because refused keys
are not retained. Projection visits only the existing bounded hold ledger and
allocates no key or native-ID graph.

Transcript marker ownership requires both no recorded copy hold and no withheld
copy in the current disposition. The shared account-hold cap can prevent a copy
record from being inserted while its body remains withheld; zero recorded copy
holds alone cannot certify settled ownership. The native regression fills that
actual cap, withholds an overlapping copy and compares the healthy session against
the matched unsettled base: own telemetry bytes and accepted witnesses are
unchanged, markers stay suppressed, and the no-copy control still permits markers.
A separate test exercises the real peer-link cap with retained holds and no ledger
growth. With zero retained holds, peer-cap refusal is unreachable under valid
production duplicate-map limits; no artificial lower-limit seam is used.

These new source tests require exact-head CI. They do not activate the policy or
establish installed tag share, memory, read-admission or whole-frame peak behavior.

## Inactive process-attempt integration

A positively observed own-file or sidecar revision change can request native
comparison independently of unrelated unknown peer or approval inputs. Unknown
evidence alone cannot request work. Re-evaluation never grants an upload, identity,
coverage, ACK or hold settlement. The selected durable hold revision can remember
an evaluated input while retaining the entire unresolved obligation.

Before constructing the heavy parser, the actual shared process owner atomically
claims the full semantic destination/source/index, root/path, opened revision and
meaningful event. Connection, lease and cycle churn are excluded from that key.
The bounded exact attempt history competes with parser reductions and membership
under the same existing retained-memory and owner/hold allowances. Preflight
includes old resident nodes, prospective nodes and the fixed input. Optional cache
clearing or pressure cannot evict an attempt and make its old event readable again.
Unavailable owner, lock, layout or budget parks the revision; a claimed event
forces native comparison instead of falling through an unchanged-file Skip.

The new synthetic owner tests cover malformed input without a snapshot and actual
generation-CAS losing selected saves across repeated preparations. Their positive
branches require supported layout admission. An unavailable layout must report
those branches as unexecuted; refused reads and passing test names do not establish
successful event handling or peak-memory acceptance. This integration remains
unvalidated until exact-head CI executes its tests. It remains inactive afterward
until settlement, full status acceptance and resource gates are complete.

Process attempt memory does not guarantee no repeated attempt across a crash when
the durable input witness was never saved. No automatic restart read, retry timer
or persistent attempt journal is introduced. Crash behavior and full frame/index
clone/decoder peak remain explicit acceptance gaps.

The first ten component tests passed on exact head `2b162a96`, automatic CI
`38958674335`, with all four checks successful. They parse synthetic native transcripts,
exercise copied IDs despite rewritten session IDs, preserve the original usage
while observing a conflict, distinguish equal amounts from ID membership, reject
truncated state, carry unknown/known age and measure the pair comparison and hold
clone allocations separately. The rearm component control invokes the real base
candidate gate after repeated fingerprint invalidation. It does **not** execute
the proven/stale rearm controllers, native scan loop, upload or selected saves.
It is not proof of repeated heavy-read elimination or healthy-sibling progress.
The later native checkpoint below validates injected-context scanner, serialized ACK and save seams; actual controller/owner integration remains unfinished.

The component checkpoint includes an actual native A/B/healthy-C bounded-census
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

## Inactive native integration checkpoint

Six tests execute the actual native scanner, selected index and identity
machinery. They compare twelve committed-fingerprint invalidations on a large
synthetic transcript, check UNKNOWN-versus-changed wake input, preserve an old
accepted file/entity/empty checkpoint and new-copy debt across partial selection
and disk reload, reject an unknown hold record, and send only the healthy native
sibling through serialization and the actual entity-ACK validator before saving.
Exact `204bca94`, automatic CI `38966378133`, passed all four checks,
all 22 containment tests and 2,891 service tests (0 failed, 22 ignored). The
1,053,581-byte scanner fixture produced twelve full base reads and zero parked
reads under twelve committed-fingerprint invalidations. An in-process
serialized ACK is not an installed service measurement or live server test.
The identity control compares the same healthy session under the base's
uncompared census and a census with parked debt: own telemetry must remain
byte-identical, and copied markers cannot confer identity. A fully settled
marker-positive control prevents an always-disabled marker path from passing.
This is a matched synthetic identity check, not the installed marker-rate floor.

All actual native observations remain available to the existing single census
fold. Only after that fold does the new context classify known exact-ID overlap;
its exclusion predicate comes from this pass's actual reconstructed native
exclusion witness. A generic proven body does not waive overlap. Held candidates
are removed before request-identity construction or account/name binding. A
known-map miss preserves interim BASE behavior for a new candidate and never
releases existing debt. No context plus no prior debt returns immediately.

Held file/entity/empty/acceptance state is restored before correction settlement
on both ordinary and partial selected-save paths. Held keys stay out of the
accepted set, a new fully withheld key remains uncommitted, and the independent
hold record survives. Window misses never remove that record. No account or
authority quarantine row is synthesized. While any copy hold remains, transcript
ownership stays globally incomplete; no scoping exception manufactures coverage.

These seams are not the completed runtime integration. Missing gates include
actual process/source/destination cache custody and shared peak-byte admission,
cheap complete W1–W5 witness acquisition, atomic resolved-body/no-op hold drain,
exact no-op preservation, bounded overflow-debt visibility, local status and age
classes, full normal/partial/shed/CAS tests, and the matched installed healthy
marker-rate floor. The peer/hold cardinality guards are not a proof
of shared heap-byte admission. No new retry timers or restart allowances are
required. No source review, merge, release or installed savings is claimed.

## Required-load follow-up

The ordinary loader's quarantine/fresh-index recovery is not sufficient once
copy debt is required: rebuilding could forget a known hold before comparison.
An inactive strict load entry point preserves invalid original bytes and returns
an error instead of rebuilding. Its test covers unknown hold version/reason,
an invalid unrelated required index fact, truncated JSON and restoration of the
valid debt. The strict-load controls passed on exact `ce33e88d`, CI `38968604971`;
the ordinary production owner remains disabled. Runtime attachment must use
this policy before it can claim malformed debt is fail-closed; decoder rejection
alone is not containment.

## Real preparation policy checkpoint

The existing `LocalDaemon` shared transcript-cache lifecycle now carries an
internal required-debt policy. It defaults to false in production and has only
a test opt-in, with no CLI, environment, wire or installer switch. It is policy,
not native evidence, permission, settled coverage or a read allowance. Clones
share the same process owner; clearing optional reductions cannot disable it.

When required, the real `prepare_sync_source` selects strict loading and attaches
an UNKNOWN comparison context after the committed baseline clone. The scope
binds source/destination/account/capture inputs; those are not complete Claude
slot, peer or W1–W5 witnesses. Existing holds stay parked, including after cache
clear, an index generation/reload or a new process under the required policy.
New no-known-overlap candidates keep interim base behavior. No positive cache
admission or new ID graph is implemented by this step.

Two synthetic real-preparation tests check default-disabled base scanning,
required parked debt with healthy native progress, shared process ownership,
cache clear/generation/reload without a new read grant, and strict failure before
scanner construction while invalid bytes remain intact. Exact `50226748`, automatic CI `38973116004`, passed all four checks,
all 25 containment tests and 2,894 service tests (0 failed, 22 ignored). The
actual preparation receipt records two base reads versus zero held reads plus
one healthy read per cycle. These are synthetic owner tests. Healthy wire ACK, normal/partial settlement,
positive meaningful wake detection, shared peak admission, status and installed
performance remain separate gates. This is not production activation.

## Shared optional cache custody checkpoint

The actual process-owned `SharedCache` now places reduction and negative-ID
graphs under the same mutex. Both compete inside the existing 31 MiB retained
remainder; there is no second budget, copied graph owner or persisted cache.
A parser budget check consumes the membership pool's cached conservative charge
instead of traversing every native ID. Reduction admission reserves that charge
and live finalization room; membership admission subtracts frozen reduction
resident bytes and live/owner room before existing peak preflight. The latter
admission call remains test-only until the real native completion supplies its
scoped input and all W1-W5 bindings. No production positive cache capture or
permissive coverage follows from constructing the shared owner.

When membership is resident, reduction insertion preflights the existing cache,
incoming owned state, reserved sibling graphs and prospective map/key allocation
peak before inserting. It retires optional entries without cloning victim keys.
The caller still must preflight creating the incoming graph; this is not a
post-allocation license or a bound for the whole index/scan. Unsupported layout,
lock failure or insufficient room cannot grant a wake or clear durable debt.
Eviction drops optional negative observations and leaves the required policy
intact; unavailable W4 detection remains the qualified, disclosed residual.

Four new tests exercise disabled/busy/live-overlap refusal on the actual shared
cache, native reduction and membership custody, and strict reduction insertion's
refusal and combined resident/input/eviction allocation peak. Exact `ce146c70`, automatic CI `38975130480`, passed all four checks,
all 29 containment tests and 2,898 service tests (0 failed, 22 ignored).
The refusal controls ran; positive admission/peak paths were unexecuted because
the hosted layout was unsupported.
On an unsupported compiler the positive peak/admission branches remain explicitly
unexecuted. Conservative monotone membership charges can refuse earlier than
actual residency; capacity/eviction cost remains unmeasured there. All-frame and
index-clone/decode peaks, actual native capture, positive wakes, drain, status and
installed acceptance are still separate unfinished gates. Production remains off.

## Bounded registered-slot input checkpoint

The core registration store exposes a read-only semantic fingerprint for one
required wake input. It uses the existing strict 1 MiB regular-file/no-follow
decoder, without credentials or the retired reconnect sidecar. Required missing
storage returns unavailable; it cannot become an inferred empty approval set.
An explicit validated empty registry is distinguishable. Existing discovery's
missing-is-empty contract and all settings writers/sign-in/upkeep callers retain
their behavior.

The fingerprint sorts at most nine borrowed registration references and streams
length-delimited scope, approval/provenance and effective pending identity fields
into a digest. It does not copy/serialize another settings graph. Operation
progress, nonce, upkeep and maintenance timestamps are excluded; selection of
the effective pending binding continues to use the existing policy. This is
registered-slot metadata, not default-slot/Desktop evidence or an account permit.

The actual required preparation path acquires this optional fingerprint from
the same registration store used by transcript-root discovery. It attaches the
signal only after the committed baseline clone, in the ephemeral context; no
new persisted/wire field is introduced. Missing/error inputs stay UNKNOWN. A
known slot input alone cannot complete per-key W1-W5 context, grant reads, offer
bodies or settle debt. Production remains disabled.

Five core tests cover unavailable versus explicit empty, malformed/oversize/IO
state, canonical reordering and irrelevant maintenance, and meaningful approval
or pending identity changes. One real preparation test acquires the signal
without granting reads while other required inputs remain UNKNOWN. They require
the new exact head's CI; the previous 29-test green is not acceptance. An actual
meaningful W5 change waking exactly once, the other wake inputs, native comparison
and durable body/no-op settlement remain unfinished. Whole decoder/frame/index
allocation peaks are not inferred from the bounded metadata input.
