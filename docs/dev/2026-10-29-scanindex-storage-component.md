# ScanIndex sharded storage component

This component supplies the private persistence module and isolated synthetic
fixtures. Production ScanIndex registration, semantic field routing, load/save
hooks, baseline controls, resource accounting and diagnostics are integration
work. The module is compiled through the integration-test target until those
shared changes land. No production save boundary or acquisition policy changes
in this component.

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

A seekable logical JSON reader supplies one global semantic decode. It retains
one payload FD, bounded descriptors and streaming scratch, plus explicitly
charged borrowed-key indexing at writes. It checks bucket/key membership and
ordering before exposing a generation. The three large maps are enumerated
once into borrowed indices, never N×256 times. Values are streamed twice only
when changed (digest/count, then immutable write). Generation-only commits write
only the root. `padding_bytes` supplies virtual whitespace when needed to retain
the shared pretty serializer's held-output funding; it cannot exceed total
payload bytes. It does not allocate or write that padding as a corpus buffer.

## Publication, recovery and downgrade

Keep the existing checkpoint flock across load/decode/commit/GC. Retain the exact
loaded-root witness through Clone and selected subsets. The integration must
also retain an immutable, charged baseline of retry-claim records and hold/repair
provenance; a root equality hash cannot reconstruct those controls. First legacy
save still performs the original full CAS. Sharded CAS reads a bounded manifest
and compares its exact byte identity, including same-generation changes, without
another logical decode. Unchanged objects must retain their verified opened-file
stamps. An available-space probe admits the complete changed-object/root plan
before payload writes.

Payload flush/sync/rename and payload-directory sync precede root temp
flush/sync/rename, then parent-directory sync. Root rename is the only publication
edge. A typed `CommitPublished { generation, verified }` error means publication
already happened: the integration must retain that RAM generation and stop
caller effects until reload/reconciliation. It must never roll back generation
on that error. Persistent fsync errors remain errors even after exact-candidate
verification. Qualification targets process SIGKILL, **not power-loss safety**.

GC retains a RAM-only directory cursor across bounded calls so retained entries
cannot starve later orphans or root temps. GC compares the exact current root
and every verified immutable-file stamp
before deleting only unreachable owned payload/temp names. It bounds inspected
entries and reclaimed bytes, reports incomplete cleanup, and never traverses
transcripts, durable-tail records or other checkpoint stores. Legacy/missing
roots do not authorize destructive GC in this component. Integration must
account for incomplete GC/migration orphan space before admitting more work.

Supported old readers must return **`scan index refused: schema_version`**,
retain the root/payloads, and pause. No stale legacy fallback is emitted. The
component's subprocess fixture uses the genuine unchanged production reader at
its base revision; it is not a copied fence check. That does **not** qualify all
historical binaries. A pinned release reader and the integrated new semantic
reader still need the full old→new→old-refusal→new compatibility run.

## Validation boundaries

The synthetic target covers legacy migration, sparse/no-op/dense/empty writes,
seeking, two restart decodes, same-generation changed manifests, stale/missing
roots, corrupt/truncated/missing/unsafe payloads, unknown manifests, bounded GC,
ENOSPC/EIO injection, changing serializers and SIGKILL children at every exposed
write edge. It also verifies real production old-reader refusal in a subprocess.
Local tests are prohibited; CI runs this target as part of the existing Linux
suite. The prescribed guarded package Clippy check compiles all targets.

Real-data startup/save timing, RSS, syscall counts, the 12k/100k scale matrix,
all semantic hold/positional fixtures, emitted-money equivalence and P1–P4/E4
replay qualification remain integration-owner work. No live daemon or state is
modified; no speedup or smaller resident index is claimed from this component.
