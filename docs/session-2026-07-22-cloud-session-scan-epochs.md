# Cloud Session Bounded Scan Epochs

Implemented the public Rust collector half of the cloud-session v2 bounded
scan protocol while preserving hard-deferred public startup.

## Contract

- Active full scans live only in the long-lived collector process and continue
  across five-minute cycles. Restart discards cursor/inventory state and starts
  a new UUID from page zero.
- Each cycle remains limited to ten provider pages and 45 seconds. A scan is
  limited to 100 pages, 2,000 unique observations, and ten ordered chunks of at
  most 200 observations. The same deadline covers provider execution, grant
  revalidation, token refresh, chunk upload, and finalize; an immutable
  prepared upload resumes next cycle when the budget expires.
- Chunks contain positive observations only. Finalize is emitted only after a
  terminal, non-truncated provider response. A one-response terminal result of
  at most 20 entities is `single_response`; every multi-page result is
  `unstable_cursor`, leaving absence authority entirely to the server.
- Identity and inventory digests SHA-256 hash length-framed, lexically ordered
  HMAC entity keys. Semantic digests hash canonical observations without
  `observed_at`/`collected_at`. Epoch digests hash ordered chunk index, count,
  identity digest, and semantic digest tuples.
- Provider cursor/raw identity/title/URL/prompt/output/repository path never
  reaches disk, wire, or logs. Exact response-loss retries preserve byte-for-
  byte DTO identity.
- Every provider page and upload revalidates local kill/pause/revoke state and
  the exact backend grant/policy. Normal polls inspect one head page; unchanged
  heads produce zero observation/ingest upload while mandatory grant
  revalidation still occurs, hourly v1 heartbeats remain available, and full
  scans run daily and until completed.
- Cycle ownership is reserved under the runtime mutex, but provider and network
  I/O run after releasing it. Revalidation denial reports an explicit unsent
  outcome, so no heartbeat or failure-upload checkpoint is fabricated.
- A v2 upload advances only after a strict, unknown-field-denying receipt with
  `accepted=true` exactly binds the scan, chunk/count fields, and request
  digests. Negative or mismatched receipts preserve the prepared chunk or
  finalize for a later exact retry and cannot mark a checkpoint complete.
- The relay recomputes chunk identity/semantic digests and finalize
  inventory/epoch digests from the DTO observations before network I/O. The
  public fixture uses canonical lowercase HMAC fingerprints and is checked by
  connector testkit against its recomputed digests.
- V1 relay upload is restricted to strict empty, incomplete health heartbeats.
  Snapshot, nonempty, complete, raw-key, and open-enum payloads fail locally
  before relay-token or ingest network traffic.
- Cloud-session HTTP agents split each remaining hard budget between a
  deadline-aware DNS resolver and the request. Blocking in-process resolution
  returns at the DNS deadline; a process-wide single-flight gate bounds a
  wedged resolver to one worker while later attempts fail fast. macOS fallback
  resolver subprocesses are killed at their deadline, and bounded grant
  revalidation never falls back to an unbounded trait method.

## Activation

`spawn_cloud_session_collector` remains hard-wired to
`DeferredCloudSessionTransport`. The v2 relay routes compile for contract
testing only; this change cannot invoke Codex or a real provider at startup.

## Validation

Focused Rust tests cover 100x20 and 101x20 page bounds, deterministic digest
vectors, duplicate collapse, cursor churn, restart, malformed/truncated/timeout
paths, exact retry identity, head/hour/day cadence, grant controls, strict
single-response marking, exact/negative/mismatched real-HTTP acknowledgments,
pre-network v1 rejection, DNS/subprocess deadlines, and deferred startup.
Required closeout also runs
formatting, Clippy with warnings denied, full cloud-session tests, connector
tests, manifest validation, and public-surface checks.
