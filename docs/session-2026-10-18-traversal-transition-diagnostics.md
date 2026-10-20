# Local traversal transition diagnostics

The existing service log now emits `local_resources` records with stage
`bounded_traversal_transition` when a bounded traversal starts or retires.
No per-file record, extra filesystem scan, CPU/RSS sample, wire field or
persisted state is added. Logging is best effort and cannot change scan outcomes.

Correlate records by process ID, source, numeric census-window time and index
CAS generation. Index generation may advance across pages; window time pins the
traversal. A missing or invalid time is null, never an arbitrary checkpoint string.

Start reasons are closed values:

- `no_retained_traversal`: no prior traversal is available. This alone does not
  distinguish startup, earlier completion or a previous reset. Consult an earlier
  retirement record if present; after restart that history may be unavailable.
- `context_changed`: a retained traversal's scan context differs.
- `terminal_unhealthy_retry`: the existing same-context unhealthy retry was due.
  Prior queue sizes, retry deadline/attempt, error counters and residue gates
  explain the retained state. This timer differs from per-file sampled audits.

The starting record captures the prior unsettled-upload flag before reset and
reports actual stale-pending-family and rearmed-index-file counts. These explain
fingerprint invalidation, not durable data loss or necessarily physical I/O.

Retirement reasons distinguish complete traversal, complete traversal needing a
clean follow-up, watcher overflow and parent-resolution restart. All existing
census gates and numeric loss counters remain visible even if causes overlap.
A retirement record is a scan decision, not an upload ACK or successful save.

The diagnostic does not disable rearming, change retry timing, prove audit
benefit, or relax ownership/completeness. `StateMissing` acquisition remains
ambiguous: expired/evicted/refused caches and invalidated fingerprints can all
lead to a full read. Semantic-vs-additive audit comparisons remain separate work.
