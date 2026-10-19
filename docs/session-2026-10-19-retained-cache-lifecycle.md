# Retained transcript cache lifecycle diagnostics

A full acquisition with `state_missing` identifies the missing retained
checkpoint at lookup. It cannot identify whether that state was never retained,
refused, evicted, cleared, or consumed by an earlier attempt.

The existing local resource log now emits one additional bounded record at
sampled collection completion:

- stage: `process_retained_cache_lifecycle_totals`
- source: `unknown` (the cache is shared across sources and namespaces)
- counts: saturating cumulative process totals, reset by process restart

The independent relaxed counter reads are not a transactional snapshot. Compare
records only within one verified process lifetime. Overlapping scans contribute;
these totals do not attribute a historical miss to an individual file or page.
No paths, request IDs, session IDs or per-key history are retained or logged.

Take counts separate a hit, an absent entry and a poisoned cache lock. Insertion
counts report the actual existing refusal branches, admission or self-eviction.
Evicted-entry counts separate insertion pressure from cursor reservation. Clear
counts report the actual release branch and number of entries released; poisoned
clear/insert locks are separate outcomes. A bound refusal remains a bound refusal,
without guessing whether its internal cause was size, traversal or layout.

Ordinary native reduction completion reports the existing incomplete/lossy,
incompatible, bound, missing-plan, unsealed-EOF and post-clone refusal facts.
These facts are not mutually exclusive outcomes or successful cache admissions:
a produced reduction may still fail finalization or insertion. The cursor's
sealed-prefix retention path is not included in the ordinary completion counts.
Its insertion and eviction transitions share the process totals.

The 29 counters occupy 232 bytes of fixed static atomic storage. No scan/cache
owner or retained graph gains fields, and no accounting walk, lock, retry,
acquisition selection, eviction policy, capacity, wire payload, persisted state,
body, ACK or upload-debt behavior changes. Counter updates allocate no memory.
The separate record uses the existing local log sink and completion trigger;
it adds serialization/log cost but no CPU/RSS probe. Its maximum-width encoding
must remain under 2,048 bytes; the existing collection record stays under its
unchanged 4,096-byte guard.

Transition tests exercise move/reinsert, ordinary absence, insertion refusal,
self/other eviction, cursor-room eviction, clear, poisoned locks, native body and
audit-debt parity, and paused-cursor preservation. Existing native full/tail,
selected-save, ACK and resource guards remain relevant. CI supplies execution;
no installed-performance benefit or root-cause attribution is claimed here.
