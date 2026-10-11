# Exact snapshot ACK settlement and permanent refusals

A valid `snapshot_entity_ack:v1` response partitions the request by session,
semantic fingerprint and occurrence count. Accepted/unchanged items settle
independently of permanently rejected items. Optional evidence also requires
its exact body-witness proof; negotiated head-CAS proofs remain mandatory.
HTTP 200 and a scalar stored count do not prove this partition. Unknown,
missing, overlapping, foreign or malformed entity outcomes remain unacknowledged.

The upload driver already checkpointed valid siblings in mixed responses.
Three remaining decisions needed repair:

- ACK validation/decode errors were untyped and could become a network error.
  They now carry a fixed, content-free validator reason. Terminal status uses
  admitted `server_error` for invalid responses and `scan_error` for local state
  failures; the previous unadmitted codes could themselves lose the receipt.
- A permanent refusal now terminates only the exact destination, semantic
  fingerprint and upload-body witness. Its bounded reason and body hash stay
  in the existing atomic upload ledger through restart, ledger retirement and
  replay/parser epochs. Premature retry timers cannot override it. Changed
  bodies remain owed; a valid accepted replacement removes the corresponding
  refusal. Retire obsolete fingerprints only after the canonical index commits.
- Retryable conflicts keep bounded, staggered backoff without spending the
  permanent reconstruction failure budget. They never become permanent merely
  because the same conflict occurred four times.

No rejected body enters the accepted set. A fully accounted response containing
only accepted/unchanged/permanent-rejected items finishes transport normally;
its health remains `backend_validation_error`, its delivered count includes
only accepted/unchanged items, and it does not claim a clean `last_success_at`.
An all-rejected batch therefore reports zero delivered items. Terminal refusals
settle traversal/backfill/replay and retain normal scan cadence; their usage
health stays incomplete. Local preflight holds disclose local index loss rather
than backend deferral. Pending conflicts
report `server_error`. Accepted siblings and the terminal index are durable
before reporting either state. Incomplete/terminal census counters stay intact.

Permanent metadata uses an additive field in upload-progress schema v3. The
existing index-facing `unproven_terminal` representation uses its saturated
counter as a terminal sentinel, not as evidence of four actual remote attempts.
The separate exact-body permanent fact records why immediate terminal settlement
was authorized. Existing bounded state serializers and heap-layout accounting
cover the added map. Public receipt DTOs, source identities and wire hashes do
not change. Private receipts retain only the known fence-reason vocabulary;
unknown reasons become `other`, and arbitrary detail is never copied.

Claude qualification clears `usage_accounting_contract` before reconstruction
and restores `session_exclusive_reported_usage:v1` only after current family,
request-set, occurrence and usage checks succeed. A fresh parse cannot borrow
retained proof or current-account identity. Saved aggregate refusal evidence
cannot establish which qualification/fence clause failed for a specific session;
that requires matched candidate/head and qualification witnesses. No historical
proof repair, account/provider inference or write-fence change is included.

Offline fixtures cover reordered 50-item/43-settled/7-rejected ACKs, exact-body
restart, retirement/replay, premature deadlines, another destination, changed
bodies, malformed/missing/overlapping/unknown ACKs, later-page timeout, and
partial versus clean health. Existing synthetic Claude refusal/recovery tests
verify proof qualification without reading installed state or providers.
