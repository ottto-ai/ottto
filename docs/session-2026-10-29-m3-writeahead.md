# M3 write-ahead assembly

The assembly stages the existing format-3 envelope on a supported restore
layout from the native PRE accumulator, commits an owned private temporary file, and settles its exact
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
pin is **2,204,088 bytes**: 131,072 memo + 270,336 compact pending + 1,050,624
spent/witness/pacing + 526,336 new key maps + 225,720 fixed-digest restart diagnostics. The new reserve is subtracted from
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
the record stays parked. Retirement rechecks the classified record's stamp and
counts only a successful unlink; a failed unlink leaves A available for the
existing committed-class refusal across restart. Side reads alone do not change a singleton's class.
Post-read proof/compatibility transitions remain unqualified across passes when
GC has not retired the old record. Class changes never clear pending or owed
claims by themselves. Overflow retains discovery conservatively and does not
force unrelated quiet files into parsing.

The shared #882 transition fixture is composed by merge, with a draft M3
`TransitionDriver` using its one emitted-money comparator and an observer at the
real pre-effects boundary. Its frozen `53d05a43` writer provenance deliberately
remains unchanged. M3 replaced a pinned envelope entry point and can persist v3
before that seed expects v1. E4 chose an exact hash-pinned archived v1 producer in a follow-up after
#882 lands. Composition stays parked until that PR is available; M3 will then
merge it forward and add a separately versioned native-M3 seed. The extractor
and frozen old-writer pins remain unchanged; a format-3 record is never an old
writer artifact.

Qualification fixtures settle the real policy-finalized index before saving,
so an unchanged file with no remaining selection reads zero bytes. Native D3
cold comparisons include the production semantic fingerprint (usage, pricing
selectors and costs) alongside the additive upload-body witness; additive
evidence alone cannot qualify money equivalence. A post-read priority transition
fixture covers failed GC and restart with the actual protected-tier receipt.
Execution of the supported-layout fixture remains a macOS CI requirement.

For native-M3, `FileSynced` is explicitly N/A: **plain-flush engine: no fsync
boundary**. The M1/old-writer matrix retains its historical row. A portable
contract checks the native crash-point enumeration and the real stream/temp
commit source for file fsync calls. Native stages finish buffered writes before
rename and exact receipt, so process termination cannot expose partially written
canonical bytes. Kernel page-cache survival across SIGKILL is sufficient for
this crash-safety contract. Power loss can discard those bytes; the checksum and
binding fences refuse incomplete/stale records and fall back through existing
recovery. Directory flushes remain bounded to the pass, with no synthetic
per-record fsync or crash boundary.

Round 11 narrows the post-save requeue shortcut to verified predecessors with
successful temporary cleanup. Corrupt survivors and cleanup ambiguity retain
their actual pending reconciliation and failure breaker. A native byte-zero Full
also reaches normal audit completion instead of the H3c prefix-only branch.
The protected-history fields already in the index now refuse singleton restore
across passes, even if the bounded per-pass class map cannot insert a marker;
GC uses that same canonical classification. No persisted field is added.
Portable cap fixtures cover actual native publication with a full debt map and
one-pass saturation/eviction of 256 authorized memo entries for both sources.

Round 13 applies the accepted layout qualification. Native live staging uses
exactly the restore codec's supported-layout predicate, before acquiring a chain
or writing a v3 record. Unsupported layouts keep the legacy path and count
`native_stage_skipped{layout_unsupported}`.

A known v3 record on an unsupported layout is absent for an already-selected
read: `restore_unavailable{layout}` is counted and the selector keeps its own
reason for an ordinary `Full(StateMissing)`. An unselected key still reads zero
bytes. Newer formats and unknown representations retain their holds and bytes.
The existing bounded per-pass decision map carries whether that actual native
read settled. Deferred reads preserve the record. After settlement or a counted
read failure, post-save GC may retire only the fully verified known record;
a failed or lossy read must first retain any envelope audit debt in the index.
A verified Full can discharge that audit through its normal completion. GC
rechecks the verified target stamp before unlink and counts successful removal.
No layout fallback creates receipt, money ACK, membership or a new Full cause.

The existing diagnostics snapshot includes platform, stage skips, unavailable
restores and retirement counts. Both layout fallback and GC counts stay zero on
the qualified macOS production layout. Portable fixtures use only a downward
test override of the real predicate; they never declare Linux layout supported.
A supported-layout control still exercises actual restore and Tail.

Linux runtime qualification remains open, including #882's parked provenance
rows. Runtime results and exact-head Clippy receipts are reported separately;
compile checks and authored fixtures are not claimed as executed money proof.

At the future E2 B/C composition seam, discovery must use one union of
`DiscoveryRecovery` and `DiscoveryRetention` at directory traversal, retained
rosters, candidates, opened descriptors, parent windows and absence retirement.
Both archive retention and M3 receipt/hold obligations must survive that union.

The portable unsupported-layout qualification also reads a genuinely lossy
transcript with a terminal oversized line against an existing native record
carrying #865 debt. It requires
positive usage and cold semantic/additive equivalence, preserves the record
when its index debt carrier is missing, and verifies that a failed unlink
neither changes A nor increments retirement. After the carrier is saved and
unlink succeeds, restart must retain the debt in the index. This fixture uses
the production read-settlement and GC paths; it does not qualify the separate
supported-layout native class-transition matrix.

Retryable malformed JSON is a separate conservative case: the existing parser
quarantines the whole derived entity and emits no replacement. Its fixture
requires the prior positive body's finalized fingerprint and upload witness to
survive index save/reload, with #865 debt retained after the unusable record is
retired. Neither case changes native publication or source-verification rules.

The missing-carrier GC negative control commits its own index generation.
Qualification explicitly checks stale-writer rejection, reloads that committed
index, and carries only the completed read's audit obligation before saving its
finalized body. It never stamps an invented generation onto stale state.

Merging main composes the #904 counter and alarm names with M3's existing
post-save retry path. A bounded u64 digest set replaces copied key strings.
Its conservative charge is 512 entries plus one retained root, each 440 bytes:
225,720 bytes are subtracted from the existing retained-state allowance. The
canonical Stores pin becomes 1,978,368 + 225,720 = 2,204,088 bytes. Collisions
can only mis-attribute the upper-bound diagnostic; they grant no admission,
receipt, owed, read or money authority. Existing store-failure retries and
predecessor protection remain authoritative. The alarm fires on the process's
first counted restart Full, then at most once per 24 hours. No persisted field
or Full cause is added.
