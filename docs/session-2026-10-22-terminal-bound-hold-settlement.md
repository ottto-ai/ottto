# Checkpointed pages settled with non-progressing restorable holds

A validated `Rejected` upload can settle traversal when every local hold is
non-progressing and restorable through the same path as a `Completed` upload.
Held bodies remain undelivered; their committed predecessors remain selected.
Permanent refusals keep their exact-body quarantine and health disclosure.
Traversal completion does not certify accepted usage or complete ownership.

Recorded Claude account deferrals use these same settlement semantics. Durable
recording must succeed; an unrecorded or cap-refused account hold still blocks.
Recorded account holds remain non-terminal ownership loss: public ownership
incomplete exceeds its terminal share, disclosed loss stays `Unsettled`, and
backfill and replay stay pending. Restored account-held keys retain a blank
source fingerprint so a later generation reparses them. Even backend-dominated
refusals still report an error while such a hold persists.

`Deferred` pages retain their existing behavior: their retryable server conflict
keeps the traversal unsettled, with or without local holds. RetryPending
families, unbound authority holds, and unrestorable holds also keep blocking.
Settling an eligible later page never clears earlier traversal debt.

## Counter scope

The existing checkpointed-upload log line includes
`N page(s) settled with non-progressing restorable holds`. The content-free relaxed atomic
`CHECKPOINTED_PAGES_SETTLED_WITH_NON_PROGRESSING_RESTORABLE_HOLDS` counts eligible settlement
**decisions across the process lifetime**. It increments exactly once when a
`Rejected` page selects the non-progressing, restorable-hold branch, including
recorded Claude account deferrals and literal holds. These holds need not
have terminal authority; the label names the existing Completed eligibility
predicate without asserting an authority reason.

The increment precedes the durable index save. It counts neither durable-save
successes nor unique pages, sources, windows, files or families. A repeated
eligible decision counts again; restart resets the total. Completed settlements,
Deferred pages, blocking holds and no-hold pages add zero. The counter carries no
identifiers or contents and changes no decision, persisted state or wire data.

## Regression coverage

Synthetic pipeline tests exercise a real permanent entity ACK beside an accepted
sibling and either a terminal authority hold or a recorded account hold. They
select settlement from the uploader result, save and reload the refusal ledger
and index, check the accepted manifest fold, and finish the next-page census.
Account coverage also checks later-generation reparsing, pending replay/backfill,
public ownership loss and the error state with dominated refusals.

Additional controls cover two held entities (terminal and RetryPending), unbound
authority, account disclosure-cap refusal, earlier-page debt, and exact zero/one
counter deltas. Every test that can mutate this counter shares the
`source_manifests` serial lock, including the authority-correction pipeline and
the dominated-refusal/local-hold fixture. Counter tests retain that lock across
both observations and never reset the process total.

Capture-ON coverage accepts a v1 identity body, flips to v2, and puts a revised
family with contradictory creator evidence on a real Rejected page. The durable
restore keeps its accepted predecessor and reparse debt. After that account hold
is released, the exact body sent to transport must carry v2 provenance and row
identity evidence, and become durably accepted.

The counter wording and identifier now describe all eligible holds accurately.
This follow-up changes diagnostics, tests and documentation; settlement behavior
is unchanged. CI supplies execution receipts; no local cargo command, tests or
installed-runtime reads are needed.
