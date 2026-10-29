# M3 write-ahead assembly

The assembly now stages the existing format-3 envelope from the native PRE
accumulator, commits an owned private temporary file, and settles its exact
receipt before cursor, membership or publication effects. Retained and no-copy
completion use the same typed serializer. The five facade entry points remain
`prepare_live`, `commit_prepared`, `resolve_failed_preparation`,
`resolve_unprepared` and `reconcile_receipt`.

D3 follows the source split. A Codex write/cleanup double failure disables its
store for this process, drops pending/owed claims, and clears only the retained
entry's source selection fingerprint. `finish_sync_source` saves that retained
PRE entry before any upload request can be acknowledged. Revision, extent,
accepted body, witness, membership and audit debt remain authoritative; an
index-save failure returns before upload. The 0.1.201 reader also rejects a
cleared selection before reading A. The v3 envelope adds only the designed
nine bytes (acquired revision LE64 and protocol U8); no index field was added.
The persisted representation and early ordinary Codex native seam require
SOURCE/E2 review before landing; Codex group, side, proof, archive and paging
qualification are not inferred from the singleton implementation.

Claude publishes degraded when initial cleanup proves A absent. A surviving A
holds only its own key. Held files retain accepted state and audit debt, bypass
age/absence retirement, count growth, and release on that key's successful store
write or a proved content/object change. A funded inactive edit proof survives
failed settlement until a replacement receipt, so the key cannot be re-held
against an obsolete predecessor. Unknown representations retain their existing
protection. Original-v1 Claude mapping and account identity inputs are unchanged.

Release-note disclosure: **on a full disk, affected Claude files pause until
space frees (delayed, not lost)**.

Native writes use a saved predecessor stamp, no store listing per write, and
one owned plain directory flush per bounded pass. ENOSPC preserves A and enters
a store-level wall-clock backoff with one recovery probe, rather than retrying
per key. D3 hold age, fault reason, degraded publications, stale refusals and
pause duration share the existing resource diagnostics. Source-fault Full pacing
is spent at actual input admission, after any Codex page/cursor deferral.
Durability is crash-safe (SIGKILL), not power-loss-safe.

Normal no-old-byte restores use a separate bounded pending-authority map,
not `retail_spent`; overflow is counted and falls toward the existing paced
read. Owed/hold metadata has its own funded map. Restored head re-reads have a
2 MiB per-source/pass budget reserved before input. The canonical resident-map
pin is **1,978,368 bytes**: 131,072 memo + 270,336 compact pending + 1,050,624
spent/witness/pacing + 526,336 new key maps. The new reserve is subtracted from
the existing retained-state budget; cache, record and active caps were not raised.
Full receipt/stage identities stay outside compact pending and are actively funded.

Validation: serialized package-scoped all-target Clippy with warnings denied
passed for the implementation. D3 store/native/content-change/ENOSPC, funded
resources, and subprocess SIGKILL controls are authored and compiled only.
No cargo test ran. Runtime, RSS/layout, money-equivalence, complete crash corpus
and exact-head Linux/macOS qualification remain unexecuted. Integration ancestry
contains the separately green composition-fix head, merged forward without rebase.

Remaining resource debt: inherited M1 post-save write, GC and startup sync still
perform I/O while holding the shared Stores lock; native staging/rename/cleanup
and pass flush do not. M1 zero-old-byte pending authority uses lazy refresh/24-hour
reclaim rather than exact batch-receipt release. The DailyGrant clock still uses
Instant (separate from wall-clock Full pacing). These are explicit follow-ups,
not a qualification or merge-ready claim. No PR was opened.

Round 9 adds the compressed-input guard before native descriptor/chain
acquisition, plus a failed post-save rename retry from retained RAM on a quiet
selected pass. The failed rename preserves the exact verified predecessor.
The retry reconstructs scope from the retained checkpoint after `begin_pass`
clears per-pass decisions. PR #904 owns the separate
`store_write_after_save_failed` / `store_write_failed_restart_full` counters;
this branch does not duplicate them.

Native pass and debt-capacity limits return counted `NotPersisted::PassBudget`
before an unstarted write can create an unfunded Claude hold. The bounded
verification memo can turn over non-pending entries, including allowed entries:
eviction revokes that optimization and requires fresh verification before a
later mutation; spent grants and original witnesses remain in their own owner.
The 257-record fixture exercises a cold-memo reread and a later update.
Batch receipts stay pending until the bounded directory flush and final path
checks succeed; a flush fault requeues without issuing a clean acknowledgement.

Codex group inventory records a class exclusion before member acquisition.
Completed excluded classes also record it for same-pass restore refusal and GC.
GC retires only verified native format-3 write-ahead records in the live context;
#865 envelope debt must already have an equal-or-earlier index carrier, otherwise
the record stays parked. Side reads alone do not change a singleton's class.
Post-read proof/compatibility transitions remain unqualified across passes when
GC has not retired the old record. Class changes never clear pending or owed
claims by themselves. Overflow retains discovery conservatively and does not
force unrelated quiet files into parsing.

The shared #882 transition fixture is composed by merge, with a draft M3
`TransitionDriver` using its one emitted-money comparator and an observer at the
real pre-effects boundary. Its frozen `53d05a43` writer provenance deliberately
remains unchanged. M3 replaced a pinned envelope entry point and can persist v3
before that seed expects v1. This is a blocker requiring the fixture owner to
choose an archived exact v1 producer or a separately versioned M3 seed; current
hashes must not be substituted as old-writer proof. The inherited `FileSynced`
crash name also lacks a production traversal in the plain-flush M3 engine;
existing vocabulary is retained without claiming that boundary was executed.

At the future E2 B/C composition seam, discovery must use one union of
`DiscoveryRecovery` and `DiscoveryRetention` at directory traversal, retained
rosters, candidates, opened descriptors, parent windows and absence retirement.
Both archive retention and M3 receipt/hold obligations must survive that union.
