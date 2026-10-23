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
  parked overlap budget first. When that price is refused (an unsupported
  heap layout, which also disables native comparison, or an over-budget
  count), an allocation-free fallback applies the same rule to at most 16
  RetryPending roots per raw-complete census, using fixed-size stack arrays,
  and resumes from a runtime-only cursor scoped to that index (keyed by the
  scan's sampled-acquisition namespace, a digest of the index path, upload
  destination and scan mode; never persisted; a restart begins at the first
  root). The cursor map holds at most 32 indexes and evicts the least
  recently used one. Every root of an index is checked within ceil(P / 16)
  raw-complete censuses of that index, assuming its RetryPending population
  changes only by these retirements, no restart, and at most 32 alternating
  indexes; so retirement never depends on the priced path.
- Absence retires only when it is positive (SOURCE Round 11). A raw-complete
  census keeps every absent family while the #700 re-emission stop latch is
  set, while its index's history is unverified in this process (the path was
  loaded missing, quarantined, or as an empty generation-0 index, remembered
  in a runtime-only memo of at most 64 paths until restart; #712's LoadOrigin
  and `prior_history_unverified` replace it when both land), or when the
  traversal recorded any read, permission or symlink error, entry cap,
  unsettled residue or unfinished page. Traversal counts carry no
  per-directory attribution, so any such problem anywhere refuses.
- Each retired root is tombstoned: the index persists the SHA-256 of the root
  with its retirement unix seconds, at most 1024 entries, the oldest evicted
  first. The field decodes leniently: a malformed entry drops alone and any
  other container decodes as empty, each counted, so damage never quarantines
  the index. A tombstoned family keeps its proven witness through complete
  censuses (Round 12, SOURCE/COST/SI). A returning member (a restored file, a
  re-mounted directory) is never read as a new file and never skipped
  forever: it re-enters the family's authority path. The ordinary parser
  rebuilds it from the current sidecar rows; if that reconstructs the
  retained witness the bodies are offered as usual, otherwise the demotion
  hold keeps them back and a RetryPending record re-forms against that
  witness, re-read only when its revision changes or its retry is due, and
  going terminal (disclosed) at the existing failure cap. While tombstoned,
  the whole-family disappearance rule does not resolve that record, because a
  held returning member is unindexed. The tombstone clears in the fold of
  the page that settles the proof: every member it read carries the
  reported-usage contract and no authority record is left. Never earlier,
  because the scan indexes a returning member before the fold demotes it. A
  lost or malformed tombstone falls back to a fresh read of that root.
- Local content-free process counters appear on each Claude traversal's
  `retiring` transition row: `absent_retry_pending_retired`,
  `absent_family_tombstone_hits`, `retirements_refused` and
  `tombstone_decode_drops`.
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
not an unsettled-upload cause. This branch composes #691 and #706 (merge
of `c2e5fbf6`) that way: `AuthorityCensusWithheld` stays in the cause enum
so recorded bits still decode, but no path produces it; #691's transition-line
test pairs the RetryPending debt with a server deferral and expects only
`deferred_conflict`.

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
left, and when its only member is observed but unindexed residue after a replay
reset. With the retirement scratch refused for the whole test, an absent
family still retires on its first raw-complete census and a present one stays
held; a unit test walks 40 roots through the fallback cursor in 16-root
windows, another alternates two 32-root indexes so each keeps its own cursor,
and a third checks the cursor map evicts only its least recently used entry.
Round 11 adds one pipeline test per guard: an absent family is kept while the
re-emission stop is latched and on an index loaded fresh in this process (each
retires after a simulated restart), and a unit test keeps it after each kind
of traversal problem. Round 12 adds two returning-family tests: a member that
never re-proves is held with nothing uploaded through one bounded failure per
changed revision until the terminal; and a proven family that returns under
unhealthy evidence is held, then re-proves from the repaired sidecar rows, is
re-offered and accepted, and its tombstone clears. Unit tests cover the
lenient tombstone decode (malformed entries and wrong containers, with the
rest of the index kept), the 1024 cap, and the fresh-load memo.

CI supplies execution receipts; no local cargo command, tests or
installed-runtime reads were used. Landing stays gated on carry-line and
cause-bit evidence from a live scan.
