# Claude local evidence cap refusal

Local API-request and trace-ownership capture must report success only when every
row in the capture call was fully appended below the strict reader's usable
64 MiB boundary. This is an internal local-capture result, independent of the
raw OTLP upstream response. It is not an fsync or crash-durability guarantee.

Before this fix, a file already at the boundary silently skipped new rows while
capture returned their input count. A final append could also reach or cross the
boundary and return success, although strict loading rejected the resulting
file. API compatibility loaders and its sidecar fingerprint allowed exactly
64 MiB while strict API/trace readers rejected it.

The appender now reports an error at or above the existing boundary and after
an append reaches it. All API readers/fingerprints use the strict `>=` boundary.
Existing bytes are preserved. The final crossing row is still appended: its
resulting file size remains the existing persistent incomplete-evidence signal.
Refusing it prospectively without a durable refusal witness would leave a
readable prefix that could falsely prove complete coverage after an auxiliary
request was lost. Retries against the now-capped file do not append duplicates.

The relay continues raw forwarding independently, with unchanged upstream
response/retry behavior. Local capture refusal is logged as reduction failure,
without claiming the incoming payload was invalid and without including payload,
paths, identifiers or detailed errors. No exporter retry is introduced by local
refusal. A capture error may follow earlier writes in the same batch; it does
not return a successful count or roll those writes back.

This is a refusal/count and boundary-consistency repair. It does not provide
unbounded retention, overflow recovery, file rotation, cap increases, expiry,
row deletion, new journal format, money/identity changes or forwarding policy.
Strict readers continue to reject the whole capped file; recovery must preserve
existing canonical rows and follow the existing store owner's contract.

The unresolved I/O boundary is different. A zero-byte disk error can leave an
old healthy prefix unchanged; a partial write generally makes a malformed final
row, but a missing final newline can still leave valid JSON. A durable signal
covering every refused request therefore needs an explicit failure witness or a
transactional admission/retry contract. Neither is implemented here. Adding a
persisted loss marker must be designed with the existing store owner and consumed
by health, selection/invalidation, restart and correction paths; changing HTTP
admission requires separate exporter retry/idempotency proof. Do not represent
this narrow fix as full persistent loss-health coverage.

Focused checks cover below/exact/crossed/over-cap append outcomes, no-write
refusal/retry, partial and zero-byte writer errors, both public capture APIs,
strict health and compatibility/fingerprint boundaries. Existing identity,
ownership and reported-usage tests remain relevant. Release acceptance must bind
the merged source to the signed manifest and verify ordinary installed behavior;
source tests alone do not establish deployed acceptance.
