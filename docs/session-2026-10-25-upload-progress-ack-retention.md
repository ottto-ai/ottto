# Upload-progress ACK lifetime

Uploader input is an incremental page, not an authoritative entity census.
Missing entities retain their accepted fingerprint and exact body witness.
An explicitly different body for the same fingerprint still invalidates the
old ACK before upload; the replacement needs its own validated response.

After the selected ScanIndex saves, progress may retire an ACK transferred to
its accepted ledger and exact file body-set witness, or an entity positively retired from previously committed
incidence, or an entity proved absent by a complete scanner census. Carried,
shared, decode-held and unknown incidence prevent inferred retirement. An
accepted entity without either retirement proof remains unsettled progress
until settlement adopts it. Final backfill/index ordering and cache
head retention remain intact. Acquisition, body hashes, carry eligibility,
conflict budgets and monetary calculations are unchanged.

Admission reserves space before each POST, including retained retries. Bootstrap and main upload drain the same admitted input subset before a
capacity stop selects the partial-index save. Positive retirement is retained
across partial saves; adopted siblings remain in progress during retained retry.
Only ACKs held for current incidence and current input entities proved live
by the current scan index grant live slots; all other
admitted entities share 4,096 unsettled slots. The ledger is
bounded by current live incidence plus 4,096, with one exact body per entity.
Unused index incidence never grants additional unindexed debt. At supported
native layouts the 4,096-entry hash ledger is asserted below 8 MiB, and its
serialized checkpoint below 2 MiB. Scratch is bounded by held ACKs or the current
input page, not a second cloned index census. No ACK is evicted for new work.

The index commit that retires incidence also atomically stores a hash-only
handoff: destination namespace, authorizing generation, and exact entity/body
pairs. Both final and partial saves stage it after selected-state restoration.
Blocked obligations persist separately while incidence is opaque or entities
are held. A later eligible selection promotes them before cleanup; replay
alone cannot promote a locally held obligation. A complete census compares
only the existing ACK ledger against the complete pre-selection scan incidence
(including legacy, state-only and carried entries). Its absence proof survives
a partial upload save, so a file that vanished before its first committed
settlement cannot permanently consume the unsettled allowance.
A restart replays this authority before admission, preserving current/shared,
carried, unknown and held incidence, and unindexed/changed-body ACKs without
matching retirement authority.
Progress cleanup must save before its handoff can be removed from the index.
A cleanup-save failure retains the proof and stops admission; a failure clearing
the proof is idempotently recoverable after the already durable cleanup.
Handoff metadata is bounded by the retiring ledger, compacted against remaining
exact bodies, and cleared on recovery rather than retained as a historical
high-water census. The two-checkpoint commit window may still contain the old
ledger plus its cleanup handoff; recovery completes it before admitting uploads.

Local capacity refusal uses a typed settlement outcome. The existing redacted
upload diagnostic reports `kind=ack_settlement_required`, retained ACK count,
capacity, unique deferred entity count, and retained-stale ACK count.
The last count conservatively includes all ACKs outside known live incidence,
including valid unindexed debt; it is a local pressure counter, not pruning
authority. The terminal receipt uses the
existing `scan_error` code with an ACK-settlement message, and no network-loss
quantity is charged. This local stop records pending work on the ordinary
cadence without failure backoff or a completed full-sweep marker. Real transport
failures keep their existing accounting. Current live input is eligible on a
first install, so more than 4,096 new live entities need no artificial
4,096-entity drain or capacity backoff.

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

Consuming the handoff always crosses a successful progress-save/CAS barrier,
even when an earlier cleanup is already visible. A failed cleanup or stale
progress generation keeps the proof available for the next recovery attempt.


Further persistence coverage exercises every post-index finish boundary
(native correction receipt, unverified-history marker, backfill completion,
and progress finish), opaque file incidence, decode and local holds across
multiple saves, never-committed partial-file ACKs followed by file deletion,
a stale 5,000-entry cap followed by successful unrelated upload, and a
4,100-entity first install. The actual finish capacity case checks typed reason,
terminal status, cadence and zero network/rate-limit loss with no upload POST;
the callback-level case also checks successful HTTP attempts and omitted counts.
A cache-head probe capacity stop follows this same partial-settlement path
before returning; it cannot exit ahead of the durable retirement proof.
Head-CAS re-offer capacity is checked before removing a saved ordinary probe
ACK, including zero net-growth re-offers in an already overfull ledger. This
keeps the durable-equality checkpoint guard usable after a resumed-probe stop.
A routed bootstrap stop retains bootstrap's single lease-finalization count;
the common finish does not classify the same unattempted offer twice. The
actual finish regression covers both main/probe capacity stops and all 4,100
first-install entities in one successful pass.

The existing cache-event restart-correction test now explicitly settles and
saves its exact ACK into the durable index before retiring disposable resume
progress. No assertion was weakened. The poison-size test likewise uses real
replacement/retirement scope. The two protected retry-budget tests are unchanged.

Per-entity admission versus per-file settlement for one very large file remains
a named follow-up, planned for 0.1.198 (planning target, not release authority).
This change does not implement per-entity file settlement. Complete-census
cleanup is included here, so it is not left as a recovery follow-up. The
terminal-contract lease integration regression remains with its separate
integration change once that contract is available.
