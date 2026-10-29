# M1 disabled publication and write-attempt diagnostics

Disabled stores retain every pending obligation and refuse disk reuse. Overflow
or a namespace switch does not hold independently valid, funded native RAM:
ordinary acquisition, publication and census fences still apply. Guard retries
recheck the current disposition if active-owner acquisition times out. Disabled
stores cannot reconcile, write, unlink or collect records.

The post-save M1 writer counts failed setup, inventory and statvfs attempts in
`store_write_failed[setup,inventory,statvfs]`. Its adapter records the same
`not_persisted` subcause and emits it through existing local resource diagnostics,
then requeues the offered keys with their original selection fingerprints.
Index-metadata failure also preserves retry provenance. These are persistence
attempt counters; they never increment actual Full-read counters.

Fixtures use the production scanner for overflow and namespace-disabled RAM
publication, exact prior witness/census retention, unchanged disk metadata/bytes
and zero unreadable/Full/native bytes. Both M1 source adapters inject each early
failure, require no receipt, and retry successfully without new acquisition.
Poison and full FIFO refusal use isolated owners; the global owner stays usable.

Validation is static only: explicit-file rustfmt and diff checks. Fixtures were
not executed. Linux/native, shared emitted-money, layout/memory and independent
review qualification remain outstanding. Lead A approved the resident pin on
2026-10-29: 65,536 -> exactly 401,408 bytes (392 KiB), comprising 131,072 bytes
for both verification memos and 270,336 bytes for pending obligations. The budget
fixture asserts that exact value. Any further growth requires a new owner
decision; native/container evidence remains owed at CI. The constant describes
an allowance, not production enforcement by the cache heap walk.
