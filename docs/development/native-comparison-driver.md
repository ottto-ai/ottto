# Default-inactive native comparison driver

This draft implementation begins a moving two-phase Claude scan. There is no
runtime flag, environment switch, API, or production opt-in. Only a scoped test
can enable preparation. It does not suppress a rearm or change an upload.

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

The initial qualification is deliberately discarded before finish. The lifecycle
bootstrap component below passed its scoped hosted tests. Positive end-to-end
source bootstrap is still an integration gate.
The candidate still needs actual same-census targeted acquisition under the
existing budgets, negative-only target intersection, pre-offer B/C withholding when comparison cannot finish,
atomic selected-state restore/rearm/save, and one authoritative final fold.
Revision/context/row changes during that continuation must revoke eligibility.
No target selection or performance benefit is claimed by this checkpoint.

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

This seam is intentionally not called by source preparation yet. Pre-offer
emission separation, fallback/selected settlement and final-fold integration
must be complete first. A component test manually drives the same moving owner;
that is not a shipping optimization or a positive lifecycle bootstrap proof.
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
