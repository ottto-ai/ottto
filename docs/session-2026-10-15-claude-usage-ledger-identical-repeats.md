# Identical repeated evidence is idempotent in the Claude usage ledger

`reduce_claude_usage_ledger` builds one ledger row per request id from the
local `claude_api_request:v2` and `claude_llm_request_ownership:v1` sidecar
rows. It refused any repeated request id, so a family whose only defect was a
replayed capture of the same row could not prove its reported usage.

The reducer now still validates every row on its own: capture revision, root
session, request id, model and request count, fingerprint, and timestamp. A
repeated request id is then accepted only when the repeat is equal to the kept
row in every field. A repeat that differs in any field refuses the ledger,
including one that copies the kept row's fingerprint string but changes other
fields. API and trace key sets must still match exactly, client request ids
must agree, and every trace owner must be a family member. Because the kept row
equals the repeat, input order and repeat count do not change the ledger rows,
per-member totals, assigned request ids or the evidence digest.

Both strict sidecar loaders already drop rows whose fingerprint string repeats
within one sidecar, and they mark a request id with differing fingerprints as a
conflict, which keeps the report unhealthy so the reducer is not reached. So
current loader output does not deliver identical repeats to the reducer, and
this change is not expected to alter any family's proof today. It makes the
reducer's own contract idempotent for exact repeats instead of depending on
loader deduplication.

This does not recover sessions that already lost proof for other reasons:
requests with no API row, trace-only request ids, or a stored head that a
later unproven body cannot extend. Their missing rows stay missing. No parser,
replay, rearm, upload, server, file-cap or logging change is included.

Regressions cover doubled, interleaved, reversed, one-sided and triple
repeats (equal digest, ownership, rows and totals, and one fingerprint check
per input row), and fail-closed cases: conflicting API or trace repeats, copied
fingerprints over changed evidence, identical rows with an invalid fingerprint
or timestamp, a foreign owner, a foreign root, a wrong capture revision,
missing API or trace partners and a client id mismatch, each in both orders.
