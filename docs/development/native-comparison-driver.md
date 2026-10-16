# Default-inactive native comparison driver

This draft implementation begins a moving two-phase Claude scan. There is no
runtime flag, environment switch, API, or production opt-in. Only a scoped test
can enable preparation. Production behavior remains unchanged; no rearm
suppression or selected-body deferral is activated.

## Initial checkpoint

The existing owned scanner retains its parser, candidate queue, index and
budgets. After initial native collection, an opted-in scanner pauses before
census finalization. The existing source preparation owns that pause and resumes
the same scanner. It does not launch another scan or create an upload queue.

Certificates are recorded only in the actual native `Skip` branch, after safe
open, physical/sidecar identity and launcher preparation. Each carries the exact
key, member, source revision, current census window and upload context. Missing,
legacy, authority-held, account-held, terminal, empty and policy-empty states
cannot become certificates from a restored or seeded index entry. Conservative
read/parser or retained traversal uncertainty makes preparation unavailable.

A prepared evidence owner loads API and trace rows before body enrichment.
Preflight borrows the rows. The normal effort fold still receives the original
permissive API rows before strict usage consumption. Unchanged opened generations
move into finish without another decode; changed or unknown API/trace generations
use the existing strict load. No full index or snapshot graph is cloned to
simulate a fold, and no ephemeral certificate is persisted.

Retained proof is frozen before any proof replacement. Its reconstruction uses
the same exact ledger reduction and legacy-owner validation as the authoritative
fold. Native request-set and occurrence checks, then the complete reported-usage
projection derivation, are shared with the authoritative rebuild. A current
nonreported member withdraws the family from preparation. These are conservative
preparation facts, not a process bootstrap permit, duplicate owner, complete
coverage, settled body, or authorization to skip a later read.

## Remaining integration

The moving controller now retains the initial qualification through same-owner
native target yields, then discards it before finish. The lifecycle bootstrap
component below passed its scoped hosted tests; positive end-to-end source
bootstrap is still an integration gate.
The candidate still needs pre-offer B/C withholding when comparison cannot finish,
atomic selected-state restore/rearm/save, and one authoritative final fold.
Revision/context/row changes during that continuation must revoke eligibility.
Target acquisition remains default inactive; no performance benefit is claimed.

The two pending original regression oracles keep their original expectations.
They require the complete driver and real scanner/ACK/save lifecycle before they
can run as eligible optimization tests. Existing fallback and boundary tests are
carried from draft #587 head `ae772a30f2a03b97cacebded02b3f3a20b8ea04b`,
whose CI `38907116962` passed all four checks with 2,890 service tests passed,
zero failed and 24 ignored. This provenance does not validate new implementation.

No schema, wire/ACK contract, persisted metadata, cache cap, retry cap, account
binding or hold policy is changed. Strict review and installed resource and
interaction acceptance remain separate, unperformed gates. This draft is not
ready for intake, merge or release.

## Lifecycle continuation

The next inactive source component stores bootstrap in the daemon lifecycle,
shared by its clones. It is absent from disk and from the transcript cache.
Preparation captures an error-revoking lease before fallible work, then binds a
hash of destination, account witness, frozen root/upload context, replay and
capture mode. Restart, unknown/context change, concurrent generation change or
unfinished drop leaves the next cycle on base. An index loaded from disk does
not mint permission.

Only the actual complete native conjunction receipt can be noted after the
normal selected-index save; any later finish failure revokes it. A clean complete
finish may retain an already valid lease. These internal gates do not themselves
activate envelopes or suppress rearming. New lifecycle tests exercise real native
collection/fold and an actual index save, then context/restart/drop and a real
failed index CAS. Hosted CI `38917089098` at
`0e98ea45785726b3e3cbbb5ad495683946c4ceb0` passed all four checks,
including all eight preparation/lifecycle tests (2,898 passed, zero failed,
24 ignored). This component evidence is not full-driver or installed acceptance.


## Frozen hashes and same-owner target seam

Preparation now retains the old witness, assigned request hashes and exact native
prior revisions, dropping the temporary reduced API rows after validation.
The authoritative reconstruction shares the exact ledger validator and keeps its
previous output shape. The frozen plan never reads a replacement proof from the
live index. The initial Q5 subtraction requires the old proof, empty legacy
exclusions, exact native request-set and occurrence fingerprints and the same
revision. Unsupported or changed inputs use all actual native IDs.

A possible intersection with assigned or legacy-excluded IDs only requests
comparison. It withdraws the affected family's negative eligibility; it cannot
add an exact duplicate owner, change authority or mark coverage complete.
All family members must already be present natively or have actual normal-Skip
certificates on this page. Incomplete families or insufficient remaining file
budget return an explicit unresolved source set.

The same owned scanner can enqueue those frozen canonical candidates and pause
again after parsing. It reuses the existing safe-open path, parser and remaining
file budget, disallows sampled restore for targets, rejects a replaced frozen
object/revision, and attempts each selected path at most once per pass. Real
native observations remain present before any body enrichment. The new tests
exercise Q5 changes, a copied-prefix hit with two real target reads, budget
refusal and replacement between target selection and safe open. Their new head
requires hosted validation; previous lifecycle CI does not validate these tests.

The default-inactive source preparation now calls this seam only under its
process lease and current frozen paired generations. Pre-offer emission
separation, fallback/selected settlement and rearm suppression remain inactive.
Component tests drive the same controller and native owner; they are not a
shipping optimization or a positive end-to-end lifecycle bootstrap proof.
No reread, CPU, RSS or interaction improvement is claimed. Requested layout
accounting in a synthetic test describes the retained plan, not process memory.


The first Q5/target run, CI `38920853932` at `a3acb45b`, compiled and
passed Clippy, then failed the target test before its native-acquisition assertions:
the test incorrectly required a layout bound on Rust 1.98.1. The existing layout
guard correctly returns unavailable for that unvalidated compiler. The corrected
test keeps the guard closed, reports the optional bound as unavailable and still
executes the target acquisition assertions. No compiler allowlist or heap policy
was changed. That failed run passed 2,901 service tests and failed one; it is not
target-read or resource-cost acceptance. The correction needs its own CI.

## Observation and acquisition source boundary

The next component separates actual native observations from emission bodies.
A non-cloneable receipt carries bounded occurrence counts, census window and
index generation into the same authoritative fold. The existing entry points
still accumulate the full body vector as before. The new entry point can consume
all raw observations once even if an unresolved current body is withheld.
It cannot receive provider envelopes or possible-owner identities.

A fixture with two actual native files sharing a second request compares full
base behavior with one withheld body. A filter-first control demonstrates the
lost duplicate; the observation receipt keeps both actual owners visible to the
same final fold. Another test compares the unfiltered receipt path with base
index/body/count output. The effective upload is marked unsettled only after
that actual-native fold; marking it incomplete beforehand would prevent existing
complete-census duplicate detection from seeing a new duplicate.

Pending target plans now retain their dependent sources and expected member
revisions. Acquisition succeeds only after this pass's real full target reads
complete at those revisions with healthy census/sidecar state. Enqueueing,
restored entries and partial or replaced targets cannot release a dependency.
An acquisition result permits the next exact fold, not a body offer or ownership.
Unresolved results retain known rearm paths and family roots for the later
selected-state callback. No callback is active yet.

Qualification groups native references once, limits reconstruction to selected
roots and rejects ambiguous indexed family membership. A hash-to-root-slot lookup
moves certified assigned hash strings into one index and includes legacy-excluded
IDs. Withdrawn roots are ignored by that lookup. Current native prior sets remain
separate for Q5. The empty-exclusion validator does not use a legacy-owner graph,
so preparation avoids building that graph when no selected proof needs it.
This removes repeated family scans without cloning decoded rows or snapshots.

Six additional tests cover native/emission parity, the real copied-prefix
exclusion, successful and failed native acquisition, and ambiguous membership.
These follow-on changes require their own hosted validation. CI for the earlier
layout-test correction does not validate them. Positive source bootstrap,
permit-bound controller, selected restore/rearm/save and original optimized
oracles remain unfinished. In particular the final callback must reconcile
terminal traversal retirement, next-pass target priority before audits and
unsettled follow-up rules without weakening census or settlement evidence.


Corrected target checkpoint: CI `38923150184` at
`7e175a184219494f563437276042c7f48fb6a9e6` passed all four checks,
with 2,902 service tests passed, zero failed and 24 ignored. All twelve new
preparation/lifecycle/Q5/target tests passed. The actual target test observed
one initial native file, two queued targets and two completed target reads in
the same scanner/context and file budget before enrichment; repeated targets
were zero. Requested layout remained unavailable on Rust1.98.1, as required.
The nine base-exit receipts and four blocked controls passed; two original
optimized-prelude bodies remain compiled and ignored. No installed or CPU/RSS
benefit follows from this source checkpoint.

## Revalidating frozen evidence across yields

An additional read-only seam checks the current opened API and trace generations
before a frozen view can support another negative comparison. It must include
all required roots, including retained legacy predecessors. Unknown or changed
pairs return false without issuing a new paired view; checking them never reloads rows or substitutes a new
proof for the frozen proof. Normal final enrichment retains its existing fresh
load fallback. The moving controller now invokes this seam before every target callback and
finish. Required legacy predecessor roots are frozen with the original proof.

Scoped tests cover unchanged pairs, independent same-byte API and trace object
replacement, and an unloaded predecessor. They also count actual evidence opens
to distinguish metadata validation from another decode. This candidate needs its
own hosted validation and establishes neither full-driver nor resource savings.


## Recovery selection before audit

A further inactive constructor seam accepts known recovery paths already queued
in the current traversal and carrying an empty source revision. Selection runs
before audits, within the existing file limit. It retains every unselected queue
entry and audit obligation. Missing or outside-page paths are not injected, and
an ordinary constructor passes no priorities. The seam is additionally guarded
by the same nonshipping test scope; production remains inactive.

The selection test saves and reloads real rearm debt, then compares the ordinary
constructor's audit choice with a one-file recovery choice and native read. Other
controls cover inactive scope, absent debt, a missing path and zero budget.
These tests need hosted validation. They do not establish the controller's
process/context binding, selected-state fallback settlement, missing-path recovery
or cross-generation liveness. The full controller must supply those proofs before
using this seam; no source fingerprint, deadline or census flag is changed here.

## Moving the terminal traversal separately

An additional inactive component moves the original completed Claude traversal
through native completion into source preparation. Its opaque owner has no Clone
or serialization implementation. It remains outside the cloneable scan result;
ordinary callers discard it, and current finish drops it before upload because
selected-state fallback is not wired yet. The optional owner is boxed, avoiding
an inline traversal graph in every preparation. Its fields remain covered by
exhaustive requested-layout accounting.

Capture requires the active comparison phase, the same completed census window,
and a healthy terminal traversal. Incomplete traversal stays in its existing
index owner. The current index/result keep their original census flags and
serialized shape. Tests compare base index/body output, check that the context
allocation moved from the original traversal, clone the result independently,
and exercise inactive/wrong-source/incomplete/wrong-window guards. These tests
need hosted validation; they establish neither selected restoration nor process
memory savings. No checkpoint is restored, persisted or treated as a permit by
this component.

## Moving target controller

One controller now owns the original qualification through source preparation.
It retains one prepared API/trace owner across yields and never requalifies from
a later proof. A frontier over appended actual native bodies avoids reconsidering
the initial bodies at each continuation. Only roots hit by that delta require
whole-page sibling grouping; no-hit steps skip that allocation. Successful target
acquisition is consumed before examining the new native delta. The scanner,
context, file limit, safe-open and parse budgets remain the same.

Unknown/replaced generations, a revoked process lease, unhealthy native work,
an unresolved dependency or insufficient remaining budget disable comparison
and revoke the lease. All actual native bodies remain available for the base
authoritative fold; no body is withheld, ownership promoted, rearm suppressed or
selected state restored by this checkpoint. Finish rechecks the frozen opened
generations and then drops the controller. Production remains default inactive.

Three new tests cover a copied request followed by two actual target reads
and a single delta frontier, generation/budget fallback, and safe-open rejection
of an independently replaced target. They require hosted CI. Full source
bootstrap, pre-offer filtering, both selected-save callbacks, original optimized
oracles, per-class cost and installed acceptance remain unfinished.

Terminal-owner checkpoint `36dcfbc18b6a168dd400d656c1cfa79dad50d915`, hosted
CI `38935288344`, passed all four checks: 2,914 service tests passed, zero failed,
24 ignored, including all 24 new tests. The original traversal allocation moved
outside the cloned result and base index/body parity held. This validates that
carrier, not selected restoration. The controller continuation above needs its
own hosted CI; this prior result is not its acceptance.
