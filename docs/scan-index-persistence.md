# ScanIndex staged persistence: reader release N

This is the reader component. It reads legacy logical-schema-2 JSON and storage
format 1, and always writes legacy JSON with the existing semantic serializer.
After a sharded load, the next synchronous save atomically replaces the manifest
with a complete legacy index. It does not create, modify or collect shard files.
The shard encoder, migration switch and shard GC belong to a separate writer PR.

Shared production module registration, semantic load/save integration, witness
heap charging and diagnostics are delivered to the integration owner separately.
The isolated test target compiles this module; this component alone does not
activate production readers or change the installed daemon.

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
  "objects": [
    {"slot": {"kind": "metadata"}, "bytes": 2, "digest": "<64 hex>"},
    {"slot": {"kind": "bucket", "field": "account_pending", "bucket": 7},
     "bytes": 100, "digest": "<64 hex>"}
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
Unknown fields/tags/versions, invalid lengths and bindings refuse without
quarantine, default-state substitution, fallback, repair or destructive GC.

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
while N is unpublished, the version is unresolved, or those notes are missing.
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
