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
