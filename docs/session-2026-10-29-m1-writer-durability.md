# M1 writer durability and disk admission

The existing post-save writer syncs its private store and parent before warming
an existing store, and syncs both after each record replacement. Repairs,
startup sync, reconciliation and mutations require the held state-directory
writer proof. Read-only callers can read usable records without repairing modes.

An ambiguous write keeps a bounded pending obligation independently of the
verification memo and GC. Reconciliation verifies the actual survivor, expected
content and generation, and exact metadata stamp. A matching successor becomes
a receipt only after file, store and parent sync. A stale ordinary known
predecessor can be retired conditionally; successful unlink and directory sync
produce a counted no-record result. Unknown, corrupt and changed survivors stay
protected. Failed retirement remains pending and does not mark the file
unreadable or change its accepted witness. Namespace replacement and obligation
overflow disable writes while retaining outstanding obligations.

Disk admission no longer uses the 256-entry verification memo or 32 MiB aggregate
limit. The encoded envelope remains at most 8 MiB. An absent key must leave its
envelope, current index length and max(2 GiB, 1% volume) available, with checked
arithmetic. Existing-key updates bypass that floor. This intermediate writer
still defers new keys at 512 records per source, and retains its 32-record batch,
8 MiB pass, cache-retention and post-save publication limits. Cache-transit
restore remains; this is not a receipt-before-publication writer.

Existing local resource diagnostics emit store counts, including
`durable_floor_skipped`, `receipt_pending_records`, `receipt_pending_held`,
`receipt_reconciled` and `durable_write_failed_published`. Counts are cumulative
between explicit pass resets; disk/pending records are levels. The existing M1
writer also emits service microseconds and a >64-second slow observation,
excluding active-owner wait and earlier startup/guard operations. Page timing
continues to include those operations. Reserved bytes are not measured RSS.

Fixtures cover the floor boundary, more than 256 records, aggregate disk above
32 MiB, pending overflow, failed unlink/sync, impostor protection, census/witness
retention and subprocess SIGKILL at rename/store/parent-sync edges. Static
validation is explicit-file formatting and diff checks. Runtime, native memory,
shared transition/money-oracle evidence and owner reviews remain required.
