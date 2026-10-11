# Local Codex census outcome carrier

An outer authority rejection retains the previous census. An inner rejection or
diagnostic publication failure attempts to remove it. Stderr outcomes alone do
not provide a fixed, bounded witness of those transitions. This change persists
the last non-success outcome without changing collection, authority, delivery,
checkpoint or retry decisions.

The census stays at `snapshots/codex-fenced-census-v1.json` under the support root;
the filename remains stable while its schema advances to
`local_fenced_codex_census:v2`. It adds `producer_start_sec`,
`producer_start_usec` and `attempt_sequence`. The new
`snapshots/codex-fenced-census-outcome-v1.json` sidecar uses
`local_fenced_codex_census_outcome:v1` and carries only schema, producer PID,
start seconds/microseconds, bounded producer version, attempt sequence,
observation UTC, and the existing closed phase/outcome/invalidation enums.

Both records use the same optional process-start tuple. On macOS it comes from
one cached `PROC_PIDTBSDINFO` call for the process's own PID using the existing
libc binding. A short result, different PID, invalid microseconds or unavailable
platform gives paired null start fields, including cached failures. No subprocess,
hardware, boot, account or credential identity is added. The tuple is neither
an image attestation nor installation time; those remain external evidence.

The process-local sequence advances at the existing Codex outer boundary. The
existing `SNAPSHOT_SYNC_LOCK` serializes production outer/inner calls within one
process. The inner census and a non-success sidecar use that same attempt.
Other sources do not advance it. Zero/uninitialized or saturated sequence is
null, never wrapped or reused. Tests isolate counters and injected identity on
their own threads rather than depend on shared test ordering.

Outer rejection writes one sidecar and preserves census bytes. Inner rejection
or publication failure retains the existing census invalidation and then writes
one sidecar. Sidecar failure is ignored: no retry, recursive failure record,
second invalidation or change to the original return value. Outer pass and census
publication success add **zero sidecar writes or unlinks**. A retained older
sidecar is deliberate. Existing stderr diagnostics stay unchanged.

The sidecar uses a fixed 1 KiB serialization buffer and the existing owner-only
atomic cache writer, with no fsync. Producer versions are capped at 64 bytes;
oversize encoding refuses boundedly. The census retains its 8 KiB cap. This adds
one synchronous best-effort cache write on non-success only, with the same
filesystem latency limitations as the existing cache helper. It adds no file
reader, cross-process lock, timer, queue, thread or healthy-path filesystem work.
Existing parent-directory and temporary-file security behavior remains unchanged.

A future validator must bind PID and both start fields to independent kernel
metadata before and after a separately authorized read. Seconds-only `ps` output
cannot exclude same-second PID reuse. Each record needs the expected schema,
version, a valid observation after its producer's start and the declared freshness
floor, plus a nonzero, unsaturated sequence. Unavailable identity/clock or a
process change makes the join UNKNOWN. A combined read requires a 9 KiB ceiling,
not the old single-file 8 KiB ceiling.

For current-process records, a census with no sidecar or an earlier sidecar shows
the last persisted publication; a newer sidecar shows a later persisted failure.
Equal attempts contradict each other and give UNKNOWN. A foreign record is only
predecessor residue if its observation strictly predates the current process
start. A foreign record at or after that start gives UNKNOWN. No cross-process
exclusion is added: a foreign writer later overwritten can leave no trace.
Clock regression or ambiguous timing also gives UNKNOWN. Last persisted is never
last executed; publication proves neither healthy census, current account
authority, upload, checkpoint durability nor ACK.

Native temporary-directory controls cover retained outer rejection, exact inner
invalidation outcomes, sidecar failure remaining nonfatal, no healthy sidecar
write/unlink, monotonic attempts and saturation, optional identity, kernel return
guards, private permissions, bounded encoding/privacy and original fence
call/order/error behavior. Separate offline controls cover the join table,
same-second PID reuse, foreign-current and equal-attempt refusal, and native ABI
comparison plus stable kernel tuples for the helper's own PID and its owned child.
These controls read no daemon state. A containing signed release and separately
scoped installed observation remain necessary; no historical incident or healthy
ingestion claim follows from this source change.

A native synthetic debug measurement of the complete sidecar writer produced
128 records in 807,447 microseconds, with a 927-byte allocation peak, 14 allocation
events per record and zero retained bytes. Each record was 282 bytes. Encoding
alone used zero heap allocations. These temporary-directory measurements include
filesystem latency and do not predict installed performance or sink availability.
