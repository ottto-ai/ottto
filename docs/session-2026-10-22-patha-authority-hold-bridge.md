# Path-(a) bridge: authority-only holds no longer mark the sweep

A bound RetryPending Claude authority family used to stamp
`bounded_sweep_had_unsettled_upload` from three places: the census-withheld
branch, the `Completed` hold fallback and the `Rejected`/`Deferred` settlement.
Every later red retry then refused the C1b stale-family carry, and the scanner
terminal owed a clean follow-up that the same debt could never satisfy.

## What changes

- A RetryPending hold that is bounded, bound to the retained witness and to the
  held revision, and carries no correction grant is non-progressing, like an
  `UnprovenTerminal` hold. Its key keeps the committed revision; its quarantine,
  failure count and retry clock are unchanged; it is never claimed accepted.
- The global RetryPending count no longer makes unrelated pages
  progress-blocking. It still keeps backfill, replay and `fully_settled`
  pending.
- The census-withheld branch keeps `census_complete = false` and the
  non-terminal scan, with no v1 for held families, but no longer marks the
  sweep.
- The scanner terminal keeps its ordinary census incomplete while RetryPending
  debt exists, without owing a clean follow-up. On the ordinary scanner path
  the complete proof fold, quarantine rebinding and upload-context adoption
  therefore stay withheld as the mark withheld them; the first fix run (CI
  39871789318) showed that without this gate a held family's quarantine
  rebound to a newly proven witness and the accepted ledger moved to the new
  upload context. Native comparison is separate: its own native census can
  still re-prove and rebind a RetryPending family, as before this change.
- Before that gate, a raw-complete census retires every RetryPending family
  it proves wholly absent: no member path is indexed, observed by the
  completed raw traversal, or named as its residue (this includes a member
  that vanished beneath its present parent, and excludes a live member that
  only parses as residue, for example after a historical replay reset). The
  ordinary whole-family disappearance rule needs a complete census, which the
  debt itself would otherwise withhold forever once no member remains to
  advance the failure count. Only the record and its pending entry go,
  removed in place; absence earns no acceptance, and a present held family
  stays held. The check is one pass over that membership evidence into a set
  of borrowed roots, at most one per RetryPending record, priced against the
  parked overlap budget first; a refused price retires nothing.
- A fresh single-page traversal that starts with RetryPending debt no longer
  completes its ordinary census (before this change its start reset the mark,
  so it could). This bridge does not deliver census completion on a source
  with debt; it is the cost-only fallback, as designed.
- The C1a latch clear and `identity_contract_rearm` additionally require zero
  authority debt, because the sweep flag no longer carries it.

## What does not change

Server errors, sheds, conflicts, lost ACKs, refused CAS, account holds,
correction-granted RetryPending holds, unbound holds and unrestorable holds
mark the sweep exactly as before. The C1b carry stays per-family: quarantined
roots, families that share a root or member with a held family, and families
with pending owned by another family get no carry. A second cause beside the
debt keeps the BASE re-arm. `claude_unchanged_proof_roots` still excludes every
quarantined or demoting root. No persisted field is added.

The process counter `CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS`
keeps its name, but its population now also includes `Rejected` pages whose
holds are bound RetryPending; it is not an UnprovenTerminal-only count.

When the unsettled-cause bits (#691) compose with this change, the
authority-only census stamp stays removed (no `AuthorityCensusWithheld` cause
at that site), and the debt gate at the scanner terminal is a census reason,
not an unsettled-upload cause.

## Regression coverage

Pipeline tests cover a bound RetryPending hold that settles on `Completed` and
`Rejected` pages, the same hold beside a second cause (server deferral and an
unbound record), unrelated pages settling like no debt, a held family beside a
witnessed stale family on a red retry (carry only for the unrelated family), a
held root that is never carried, debt beside an existing mark, and the C1a
latch surviving debt. Unit tests cover the bound predicate, a held root that is
never an unchanged-proof root, and debt beside a retryable server conflict.
Ordinary-fallback absence tests (native comparison absent) retire a wholly
removed RetryPending family and its pending on a single-page traversal and
after a parent-present removal. Controls keep the family, its pending and the
withheld census when it is still present, when only a subagent transcript is
left, when its only member is observed but unindexed residue after a replay
reset, and when the retirement scratch is refused.

CI supplies execution receipts; no local cargo command, tests or
installed-runtime reads were used. Landing stays gated on carry-line and
cause-bit evidence from a live scan.
