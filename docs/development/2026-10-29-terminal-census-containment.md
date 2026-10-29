# Terminal census containment

A completed Claude traversal used to load the entire retained API/trace cohort
without an aggregate input limit, then could invalidate the entire transcript
index for replay. This emergency containment deliberately trades completion
liveness for bounded terminal work.

Terminal admission uses sidecar metadata only. The union of both consumers'
sessions, parents and roots must fit 64 session keys, 16 MiB aggregate API+trace
input and a 512 MiB decoded-memory estimate (32 times input plus 8 KiB per key).
These conservative limits sit below the existing 1 GiB history-upgrade page
budget. Unknown metadata refuses admission; missing sidecars remain ordinary
absence under the existing proof rules. No content is read to decide admission.

Admission precedes page-end reconciliation and raw-completion absence retirement,
tombstone-fence draining and request-census pruning. A rejected offer remains
incomplete and stops before evidence folding, finalization, ACK bookkeeping,
upload and selected saves. Previously durable pending, account, usage, body,
ACK and hold witnesses stand. Current-page collection still runs; its uncommitted
rows remain owed. Ordinary nonterminal pages keep their collection path.

`terminal_fold_deferred` reports roots, estimated decoded bytes and sidecar
bytes, with a local alarm. This stopgap can stall completion indefinitely for
an over-budget machine. A separate paged terminal-fold implementation must land
before the census-completion fix is rolled out to such machines.

Whole-index re-arm is intentionally disabled. A requested corpus replay reports
`rearm_full_suppressed` and raises a local alarm. Re-enabling it requires explicit
typed operator approval and a byte estimate. Suppression does not open a fence,
prove ownership, settle a first proof or authorize a money/account correction.

Only family-specific proof changes and the existing scoped correction causes
can request invalidation. Their combined allowance is 32 files and 512 MiB per
offer, matching the 512 MiB single-transcript ceiling while staying below the
history-upgrade page budget. `rearm_scoped` reports families, files, bytes and
deferred files. All account and usage correction entry points share the cap.
Prior scoped debt dispatches through ordinary scanner selection in the existing
frozen traversal. Outstanding debt withholds raw completion, so all paced
members of a large family remain in one census window for account reproof.
This is invalidation continuation, not a paged terminal evidence fold.

SOURCE persisted-shape note: `claude_full_rearm_progress.scoped_rearm_pending`
adds a map from existing index file keys to the exact source fingerprints that
incurred scoped correction debt and an `armed` scheduling bit. The bit retains
a clear until it has been transferred once into ordinary traversal selection,
including clears created after the preceding page finished collecting. The fold consumes/replaces its trigger
witnesses, so fingerprints alone cannot reconstruct deferred debt afterward.
This map is scheduling only; it cannot prove absence, ownership or acceptance.
There is no persisted cursor. Removed, changed and already-cleared revisions
cancel only scheduling debt. A selected save that restores a held revision
retains its uncommitted clear as debt. Missing/older progress defaults empty;
older binaries ignore the map. Downgrade therefore loses scheduling continuation,
never creates authority. No wire or body-witness format changes.

Money rule: deferral never counts unread evidence as absent or as zero usage.
Tests cover rejection before raw retirement/folds, admitted completion, disabled
full replay, scoped continuation over multiple offers and restart, and revision
and budget vetoes. Tests run in CI; the package-scoped Clippy check compiles all
targets locally under the authorized serialized wrapper.
