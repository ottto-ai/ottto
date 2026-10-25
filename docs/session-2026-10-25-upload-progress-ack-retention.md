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
Capacity is loaded committed/carried incidence edges plus 4,096 unsettled entities; each
entity retains one accepted body witness. The extra ACK state is conservatively
priced at 8 MiB, plus one scalar on progress. Retirement scratch contains only
already admitted ACK keys, not a cloned index census. A capacity stop preserves
all ACKs and uses the existing partial-index checkpoint path to adopt accepted
files. Existing oversized ledgers retain their evidence and cannot grow until
settlement releases space. No ACK is evicted to make room for unrelated work.

Synthetic persistence regressions cover unrelated, empty, failed and cache
bootstrap inputs; an ACK-save/index-save crash followed by actual scanner deltas;
body replacement; explicit retirement with shared/carried/unknown protections;
index CAS failure; bounded admission; and obsolete poison-revision retention.
The crash regression uses the existing paced quarantine gate so it can run
independently of later reconstruction-contract changes.
