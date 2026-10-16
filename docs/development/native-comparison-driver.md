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

The initial qualification is deliberately discarded before finish. The candidate
still needs actual same-census targeted acquisition under the existing budgets,
bootstrap from a complete native conjunction plus durable save, negative-only
target intersection, pre-offer B/C withholding when comparison cannot finish,
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
