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

## Regression coverage

Pipeline tests cover a bound RetryPending hold that settles on `Completed` and
`Rejected` pages, the same hold beside a second cause (server deferral and an
unbound record), unrelated pages settling like no debt, a held family beside a
witnessed stale family on a red retry (carry only for the unrelated family), a
held root that is never carried, debt beside an existing mark, the C1a latch
surviving debt, and a held root that is never an unchanged-proof root.

CI supplies execution receipts; no local cargo command, tests or
installed-runtime reads were used. Landing stays gated on carry-line and
cause-bit evidence from a live scan.
