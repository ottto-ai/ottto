# ScanIndex staged persistence: writer release N+1

This writer component folds the reader branch through a merge, retaining a
main-based PR while the reader is unmerged. Release N reads both layouts and
writes legacy. N+1 adds immutable shard writes and migration on the first
existing synchronous save. Downgrade N+1 to N loads shards and the next successful
save rewrites legacy. The writer does not lengthen a durability interval.

The production reader registers the private storage adapter, existing semantic
map codecs, availability, bounded custody charging and local counters. It still
writes legacy. The separately admitted N+1 writer remains disabled until reader
N is published AND installed on M4 with at least one successful save; the release
owner must supply actual numeric version and commit before switching it on.

## SOURCE packet: candidate representation

The original index pathname is the sole atomic root. A legacy logical-schema-2
JSON object/array remains readable. Candidate outer schema **3**, storage format
**1**, logical schema **2** are independent of durable-tail record formats.
These assignments and storage digest domains need representation review before
production integration. No digest/generation is an acquisition or P4 receipt.

New files, relative to that existing root:

- `<index>.shards/metadata-<digest>.json`: one JSON object containing all shared
  serializer fields except schema, generation and the three sharded maps.
- `<index>.shards/{account,usage,census}-<bucket:02x>-<digest>.json`: nonempty
  JSON objects containing complete existing-key/value entries. These represent
  `claude_account_family_pending`, `claude_usage_family_pending` and
  `claude_request_census`, respectively. Nested history stays intact.
- `<index>.shards/.tmp-<32 hex>` and `<index>.storage-tmp-<32 hex>`: private
  create-new payload/root staging files; unreferenced crash leftovers are GC
  candidates only after current-generation validation.

Directories are owner-only 0700; new files are 0600. Final-component symlinks,
nonregular files, foreign owners, unsafe modes and hardlinks are refused.
Existing trusted state-directory ancestors and the existing checkpoint flock
remain caller preconditions. Payload paths are derived solely from allowlisted
slot labels and validated lowercase digests, never manifest-provided paths.

The strict, bounded manifest schema is:

```json
{
  "schema_version": 3,
  "files": {},
  "storage_format": 1,
  "logical_schema_version": 2,
  "generation": 1,
  "binding": {"source": "claude", "namespace_hash": "<existing 64 hex namespace>"},
  "padding_bytes": 0,
  "maps": [
    {"field":"account_pending","generation":1,"buckets":[7]},
    {"field":"usage_pending","generation":1,"buckets":[]},
    {"field":"request_census","generation":1,"buckets":[]}
  ],
  "objects": [
    {"slot": {"kind": "metadata"}, "generation": 1, "bytes": 2, "digest": "<64 hex>"},
    {"slot": {"kind": "bucket", "field": "account_pending", "bucket": 7},
     "generation": 1, "bytes": 100, "digest": "<64 hex>"}
  ]
}
```

The manifest's required `files: {}` is an empty old-reader compatibility
sentinel. Old header visitors require its presence before checking schema;
it contains no logical file state and never feeds the new logical view. A
nonempty sentinel refuses. Actual files remain entirely in metadata.

`source` admits `claude`, `codex`, `pi`; bucket field admits `account_pending`,
`usage_pending`, `request_census`; bucket is u8. At most 769 ordered, unique
objects (mandatory metadata plus 3×256 nonempty buckets) and 256 KiB root bytes.
Unknown envelope fields/tags/versions and root bindings refuse without quarantine or reset. Unavailable map objects instead produce scoped Unknown as specified below.

SHA-256 domains start with `ottto.scan-index.storage.v1\0`. Bucket assignment
hashes `bucket\0` plus the complete existing key and uses the first byte.
Object hashes cover `object\0`, compact JSON `(binding, slot)`, a zero byte,
exact payload bytes and little-endian u64 length. Root identity hashes `root\0`
plus exact root bytes. These are local storage integrity classes, not identity,
acceptance or upload evidence. The namespace must reuse the existing destination
scope; cloning a fixture must not invent a namespace from its scratch path.

A seekable logical JSON reader retains one payload FD, bounded descriptors and
streaming scratch. Integration runs the existing lenient semantic decoder on it.
All nested map values and held raw values remain under the shared field table.
This reader adds no new semantic field list and no acquisition or retry authority.

## Hard minimum downgrade and release notes contract

The minimum supported downgrade from the future shard-writing release N+1 is
**release N: the first published release containing this reader AND its completed
production integration**. A component-only merge does not meet that definition.
The numeric version of N is not assigned by this component PR. Before publishing
N+1, release notes MUST name the actual published N version and its reader commit,
and MUST say: **Minimum downgrade version: N. Do not install an earlier version
against a sharded scan index. Never delete, rename or replace the index to make a
downgrade start. Downgrade to N, allow a successful legacy save, then evaluate any
older downgrade against the existing logical-schema contracts.**

This is a hard release prerequisite: do not enable or publish the writer switch
while N is unpublished, has not been installed on the M4 with at least one successful save cycle, the version is unresolved, or those notes are missing.
The writer component remains draft until that prerequisite and the integration
qualification are met. No arbitrary version number is invented here. There is
no promise that forcibly running an unsupported pre-N binary is intercepted by
its installer. The intact original-path manifest remains an additional strict
schema refusal for 0.1.201; it is not the supported downgrade path.

A metadata-only legacy copy is rejected as the primary protection. An absent or
renamed original file becomes a fresh index in the old loader. Corrupt JSON can
be quarantined and rebuilt. A valid legacy stub could discard large-map state
if any marker is ignored, while retaining a full live legacy copy defeats the
write reduction. The minimum-version contract avoids those reset paths by
requiring a reader that actually understands every committed shard.

## Pinned 0.1.201 and current-main investigation

Historical source is commit `f174d111fbcdfb0ab9c2abeb299c12d50b435c29`.
Current source for this investigation is main
`edcbf5edc60ddf61560ca4155b199e1323709755`. Paths below are crate-relative.

| Input at the original index path | 0.1.201 | Current main |
| --- | --- | --- |
| Missing, including renamed away | `snapshots.rs:46026` returns `Default`, `LoadOrigin::Missing` | `snapshots.rs:46466` does the same |
| Syntax corruption, first event | `snapshots.rs:46079` routes quarantinable errors; `snapshots/load_containment.rs:641` renames to a corrupt sibling, syncs, returns `Default` at 645 | `snapshots.rs:46517`, same containment lines 641–645 |
| Recent quarantine, no armed repair | `snapshots/load_containment.rs:625` refuses with rebuild-loop error at 636 | Same lines and decision |
| Unknown schema / newer accepted-ledger version | `snapshots/lenient_decode.rs:1037` controls refuse; `:436` excludes strict refusal from quarantine | Controls `:1039`; non-quarantining classification `:435` |
| Outer schema 3 manifest with empty `files` sentinel | Header's required-files check `snapshots/lenient_decode.rs:1947` precedes controls; then strict `scan index refused: schema_version` | Required-files check `:1949`; same schema refusal |

Unparseable is not one universal category: JSON syntax and hold-budget errors
may rebuild; unsupported shape and strict controls refuse. Missing/Quarantined
origins count as fresh (`snapshots.rs:23669` historical, `:23870` current), so
none of the reset cases is an acceptable downgrade mechanism. Existing history
gates can limit collection after reset; they do not preserve the original index.

The fixture freezes verbatim historical control ordering, missing-files check,
error classification and load/quarantine branches with their source lines. A
source guard requires those decisions to remain byte-for-byte present in the
production decoder being exercised. Runtime fixtures call the real production
`ScanIndex::load` for missing, renamed, syntax-corrupt and future-version inputs,
including the frozen manifest. This qualifies those unchanged historical
control decisions; it is not a separately built full historical executable or
qualification of every old record decoder. Shared integration must replace the
source guard with its integrated-reader compatibility coverage where appropriate.

## Replacement and validation boundaries

Caller holds the existing checkpoint flock across open, semantic decode, full
semantic CAS/claim merge and legacy replacement. Retain the exact loaded root
through Clone/subsets; equal generation never substitutes for root identity.
Legacy replacement streams to a private create-new temp, validates its control
header, flushes/syncs, compares the original root again, renames and syncs the
parent. Post-rename errors carry `CommitPublished`; retain the published RAM
generation, pause effects and reload. Storage digests never act as P4 receipts.

The reader retains the existing full semantic CAS and serializer. Header/root
comparison does not replace retry-maxima merge or hold/repair checks. No change
to synchronous saves, scan identity, selection, money, or acquisition is made.
Fixtures cover seeking, two reads, shard-to-legacy rewrite, stale/equal-generation
roots, corrupt/missing shards and unknown manifests. Reader tests use a frozen
sharded bundle, not an otherwise-unused production shard writer.

No local cargo test. CI executes fixtures; guarded package Clippy compiles them.
Process-SIGKILL qualification of shard publication belongs to the writer PR;
no power-loss claim. Full typed production round-trip, hold/positional coverage,
resource accounting, 12k/100k measurements and P1–P4/E4 emitted-money equivalence
remain integration gates. This component changes no live daemon or state.

## Writer publication and collection

The three dominant maps use 256 hash buckets each. A borrowed, charged key index
is built once per map, sorted in place and partitioned into bucket ranges. Each
fragment is streamed into a digest/length sink; only changed objects are encoded
again to immutable payload files. Other fields stay in one metadata object.
No mutator dirty flags, delta log, debounce or semantic-field deletion is added.
A no-op generation still increments and atomically publishes its root while
reusing every payload. Existing serializer/held-output rules remain authoritative.

The writer's sharded CAS reads the bounded root and exact loaded identity rather
than decoding the old semantic index again. Integration must retain a charged,
immutable baseline containing the actual retry-claim maxima and hold/repair
provenance through every Clone/subset/reset path. A hash alone cannot reconstruct
those controls. Legacy first-save CAS retains the existing full decoder and merge.

An available-space probe precedes writes. Changed payload temp creation, buffered
write, flush, sync, rename and payload-directory sync precede the root temp
write/flush/sync/rename and parent-directory sync. Root rename publishes exactly
one generation. Post-publication failures return typed `CommitPublished` errors;
callers retain the candidate generation, pause effects and reload. No power-loss
claim: child tests exercise process SIGKILL and restart twice at all 13 edges.

Bounded GC validates the current root and immutable stamps, retains a RAM cursor
across quanta, and deletes only owned unreachable objects and temp names. It
never opens transcripts or durable-tail records. Missing or legacy roots cannot
authorize destructive shard GC. Integration owns incomplete-cleanup space admission.

The writer fixture retains sparse/no-op/dense/empty saves, corrupted/future roots
and payloads, stale/equal-generation comparisons, held depth, partial-write death,
ENOSPC/EIO and GC continuation/error cases. It adds N+1 -> N legacy export ->
N+1 migration for two cycles, using the exact reader-branch legacy exporter.
These are generic storage fixtures; full typed semantic and emitted-money parity,
real-data performance and resource evidence remain integration gates.

Fresh initialization validates absence before publication. If interrupted before
any root existed, only this release's verified owned orphan payloads and temp
files are discarded, counted `scanindex_orphan_init_discarded`, then fresh init
may resume. Prior-root markers, quarantine/legacy siblings, or any unknown object
refuse cleanup. No prior state is discarded. GC continuation binds exact root
identity and restarts its sweep after any root change.

## SOURCE and money conditions: scoped unknown state

Outer schema 3 / storage 1 / logical 2, naming and digest domains are approved.
The root now has an explicit `maps` inventory, three `{field,generation,buckets}`
descriptors. Each object also records its reference `generation`. References
must pair with this root's generation; immutable bytes from an earlier physical
write can be reused under a new reference generation when their digest matches.
Generation remains one increment per published root; no parser/scan identity
changes. Empty inventories are explicitly known-empty. Absent inventories or
missing, stale, corrupt or undecodable buckets make ONLY their map UNKNOWN.

`Opened::Partial` carries metadata and independently known siblings, with typed
`MapAvailability::Unknown` for unavailable maps. There is no iterator/default or
complete legacy-JSON conversion for Unknown. It never authorizes retirement,
release, fence opening, acquisition re-read, whole-index quarantine or reset.
A partial generation cannot be saved/exported over its unavailable evidence.
Root binding/format or metadata-integrity failures still refuse because their
files/custody authority cannot be established. Known sibling data stays usable.
The production adapter must supply the existing semantic map decoder through
`open_with_map_validator`; semantic decoder failure becomes scoped Unknown,
never a default empty census. Structural `open` is available only in tests; already-serialized publication reconciliation uses a private structural helper. Production load cannot use a public no-op validator.

Unshipped draft roots have no compatibility inference: missing map inventories
or bucket descriptors remain Unknown, and absent reference generations never
become current generations. A known-empty map requires its explicit, paired empty
inventory. Unpaired metadata refuses the root; paired metadata remains readable
while affected maps block export and publication. Fixtures cover descriptor loss
for each of the three maps and the rejected unshipped draft shape.

`ReadStats` exposes `index_shard_unavailable{map,cause}` and
`scanindex_orphan_init_discarded` for the existing diagnostic registry. These are
fixed map/cause axes, never keys or digests. Shared integration must drain these
counts and carry Unknown state through semantic readers and Clone/subsets;
these component PRs do not claim activated production diagnostic wiring.

A new private `<index>.storage-prior` marker (`scan_index_prior_root_v1` plus
newline, 0600) retains negative evidence after root recognition or successful publication. It grants
no acceptance/acquisition/receipt authority. Missing root plus marker, legacy or
quarantine sibling stays fail-closed. No-root recovery makes two directory walks:
validate all owned names/binding/digests before unlinking owned fresh-init debris.
No transcripts or durable-tail files are traversed or removed.

The byte fixture runs the SAME real legacy ScanIndex serializer before and after
a real-shaped shard round-trip, comparing complete serialized byte arrays and
each moved map's bytes. A real #865 `DurableTailStore::write_after_save` fixture
uses the committed root generation and restores its record after store restart.
The writer fixture executes an actual shard commit before that durable write.
An exhaustive metadata-complement assertion keeps every other serialized field
in metadata, including files/custody, fingerprints, versions, traversal and census
completion. This is a serializer round-trip, not a claim of identical physical
fragment ordering/whitespace or full emitted-money/oracle qualification.

Pinned downgrade fact, including absence of all three inline maps: 0.1.201
`f174d111` has logical schema 2 (`snapshots.rs:542`), header pass plus controls
(`lenient_decode.rs:922–923`), strict schema refusal (`:1037–1040`) and
non-quarantine refusal classification (`:436–438`). Loader `snapshots.rs:46079`
quarantines only Syntax/HoldBudget. 0.1.202 `79488a7` has schema 2 at
`snapshots.rs:566`, the same header/control sequence at `lenient_decode.rs:924–925`,
strict refusal at `:1039–1042`, non-quarantine classification at `:435–437`, and
loader quarantine branch at `snapshots.rs:46403`. The schema-3 root includes the
required `files:{}` sentinel, satisfying the historical required-files check
(:1947 in 0.1.201; :1949 in 0.1.202), then refuses BEFORE full map decoding.
Defaulted maps in the temporary header object never escape as a loaded index.
Exact refusal: **scan index refused: schema_version**. Neither pinned binary
resets, quarantines or loads the absent maps empty. No inline-map duplication is
needed; the strict refusal fence is retained and frozen for both versions.

## Reader N: visible version refusal

A source-aware schema or accepted-ledger version refusal immediately records
`scan_index_newer_than_app` for that source. The source row is unavailable and
its source-owned warning makes machine health degraded, preserving other
sources. Label: **Not collecting: update Ottto**. Hover detail explains that a
newer Ottto must load the index; preserve local state. No restart, reset,
quarantine or transcript read is added. A compatible root load clears it;
missing state or unrelated errors cannot clear an existing version refusal.

Each source transition emits one content-free log. The next daemon status emits
one `ScanIndexCollectionChanged` event with only source slug, fixed reason,
blocked-source count and transition count in its payload, advancing projection
revision. Repeated passes/status reads emit no duplicate transition event.
Machine-health uploads retain their existing cadence and envelope.

Blocker codes remain open strings. The blocker's existing `source` wire string
now also admits a source slug; machine-level authority strings remain unchanged.
Existing backend and companion string decoders preserve unknown codes, with
known `degraded` / `warning` enums. Updated companion/web consumers provide the
short label and hover text; older consumers retain a degraded warning and the
clear-condition text. No field, enum tag, parser or scan-identity bump.

## Production reader integration

Each map is validated by its existing record decoder and admission policy. Held,
repaired or discarded records make the entire map unavailable; census validation
uses the same index visitor with its actual dropped-record count. Metadata and
known siblings are decoded together, preserving held-file family scopes.
Partial views retain their schema-3 fence until this typed adapter attaches the
three-map availability state. Clone, selected subsets and captured recovery keep
that state and an unavailable root witness. No partial view can be exported.

Any unavailable map leaves Claude family proof unproven, retains file/entity
holds, and refuses source acquisition before restoration, cleanup or selection.
Retirement, history release, tombstone/family-fence opening, retry admission and
native/money fold boundaries also fail closed. Known sibling maps and metadata
remain readable; no partial load becomes a quarantine, default index or global
reset. Only the fixed representation-version refusal maps to the newer-app
class; other storage shape/IO/repair errors stay repair refusals. A partial load
cannot clear an existing newer-app blocker.

Binding, root descriptor custody, the availability array, immutable held/raw
controls and exact retry-claim maxima are charged through the ordinary heap
visitor, including Arc headers and Clone custody. A separate preflight bounds
additional retained baseline allocations by the shared 8 MiB parked budget.
Root descriptors remain capped at 256 KiB / 769 objects. No field is added to
ScanIndexEntry; its native 480-byte pin remains authoritative. Existing namespace
directories may be owner-readable 0755 if owned and not writable by others;
shard directories remain 0700 and new payloads/root/markers remain 0600.

`take_read_stats()` is drained after every storage open, including errors, and
after publication. The existing local_resources envelope reports cumulative
`scanindex_orphan_init_discarded` and `index_shard_unavailable` counts with only
the three fixed map labels and six fixed causes. No key, path or digest is a
dimension. Storage versions, logical schema, parser and scan identity are unchanged.

Integrated fixtures cover every map/cause, metadata/known-sibling retention,
Clone/subset/recovery, no retirement/release/fence/re-read/export, fresh orphans,
error-path stats draining, legacy rewrite/generation and admission/heap custody.
Runtime and macOS layout results are CI evidence, not inferred from compilation.
The N+1 release pairing and actual downgrade-stall release notes remain required.
