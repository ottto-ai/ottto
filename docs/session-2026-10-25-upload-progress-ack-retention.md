# Upload-progress ACK lifetime

Uploader input is an incremental page, not an authoritative entity census.
Missing entities retain their accepted fingerprint and exact body witness.
An explicitly different body for the same fingerprint still invalidates the
old ACK before upload; the replacement needs its own validated response.

After the selected ScanIndex saves, progress may retire an ACK transferred to
its accepted ledger and exact file body-set witness, or an entity positively retired from previously committed
incidence. Carried, shared, decode-held and unknown incidence prevent inferred
retirement. An accepted entity absent from both index censuses remains unsettled
progress until settlement adopts it. Final backfill/index ordering and cache
head retention remain intact. Acquisition, body hashes, carry eligibility,
conflict budgets and monetary calculations are unchanged.

Admission reserves space before each POST, including retained retries. Bootstrap and main upload drain the same admitted input subset before a
capacity stop selects the partial-index save. Positive retirement is retained
across partial saves; adopted siblings remain in progress during retained retry.
Only ACKs held for current committed/carried incidence and current input
entities proved live by that committed incidence grant live slots; all other
admitted entities share 4,096 unsettled slots. The ledger is
bounded by current live incidence plus 4,096, with one exact body per entity.
Unused index incidence never grants additional unindexed debt. At supported
native layouts the 4,096-entry hash ledger is asserted below 8 MiB, and its
serialized checkpoint below 2 MiB. Scratch is bounded by held ACKs or the current
input page, not a second cloned index census. No ACK is evicted for new work.

The index commit that retires incidence also atomically stores a hash-only
handoff: destination namespace, authorizing generation, and exact entity/body
pairs. Both final and partial saves stage it after selected-state restoration.
A restart replays this authority before admission, preserving current/shared,
carried, unknown and held incidence and every unindexed or changed-body ACK.
Progress cleanup must save before its handoff can be removed from the index.
A cleanup-save failure retains the proof and stops admission; a failure clearing
the proof is idempotently recoverable after the already durable cleanup.
Handoff metadata is bounded by the retiring ledger, compacted against remaining
exact bodies, and cleared on recovery rather than retained as a historical
high-water census. The two-checkpoint commit window may still contain the old
ledger plus its cleanup handoff; recovery completes it before admitting uploads.

Local capacity refusal uses a typed settlement outcome. The existing redacted
upload diagnostic reports `kind=ack_settlement_required`, retained ACK count,
capacity, and unique deferred entity count. The terminal receipt uses the
existing `scan_error` code with an ACK-settlement message, and no network-loss
quantity is charged. Real transport failures keep their existing accounting.

Synthetic persistence regressions cover unrelated, empty, failed and cache
bootstrap inputs; an ACK-save/index-save crash followed by actual scanner deltas;
body replacement; explicit retirement with shared/carried/unknown protections;
index CAS failure; bounded admission; and obsolete poison-revision retention.
The crash regression uses the existing paced quarantine gate so it can run
independently of later reconstruction-contract changes.

Recovery regressions retain 5,000 overlapping ACKs through a crash after the
retirement index save, shrink live incidence to zero, retry progress/index CAS
cleanup failures, preserve unindexed debt, and prove a new unrelated upload
succeeds after restart. Destination/generation/body mismatches and protected
incidence cannot authorize replay cleanup. Capacity diagnostics are checked with
successful HTTP-boundary attempts and with no attempt.

A full unsettled allowance still permits a newly ACKed body for a committed
live entity. Reservations are recomputed from held ACKs and the frozen input
page, so repeated admission cannot accumulate credit, and unrelated omitted
entities never borrow unused live-incidence slots.
