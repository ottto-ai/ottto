# Claude Code local reasoning-effort collection

Claude Code transcripts do not persist the applied effort tier, while the
official `claude_code.api_request` OTLP log carries the actual tier and exact
request token counts. The loopback relay now reduces those logs locally before
cloud forwarding and stores only allowlisted, content-free evidence in
owner-only files keyed by a hash of the session id.

Snapshot sync uses that evidence to split one transcript model/hour row into
effort-tier rows only when the ownership is unambiguous and every observed
token/request component fits inside the transcript total. Partial coverage
leaves a residual `unknown` row. Mixed effort is part of row identity, so high
and low requests no longer collapse under the same model/selector/billing key.

Cloud forwarding remains synchronous. Organization-disabled live telemetry
returns the backend's normal OTLP-compatible success response after the local
reduction, while an unavailable backend keeps the existing exporter retry
contract. Local deduplication makes those retries safe. Metrics and traces
retain their existing protobuf transport.

Live Claude Code 2.1.205 validation found that its OTLP/HTTP JSON exporter uses
HTTP/1.1 `Transfer-Encoding: chunked`. The relay previously read only
`Content-Length`, so it reduced and forwarded an empty body even though the
event and `effort` attribute were present on the wire. The relay now decodes
bounded chunked bodies, accepts chunk extensions and bounded trailers, and
forwards the normalized body with client transfer framing removed. Ambiguous
`Transfer-Encoding` plus `Content-Length`, duplicate framing headers,
unsupported transfer codings, malformed chunks, and decoded bodies over the
existing 25 MiB limit fail closed. Independent chunk-count and encoded-framing
budgets also prevent tiny-chunk or extension floods from monopolizing the
bounded relay worker pool.

Validation:

- content redaction and retry deduplication unit test;
- real-exporter-shaped chunked framing through the effort reducer;
- malformed, ambiguous, unsupported, and oversized chunk framing rejection;
- chunk-count and encoded-framing denial-of-service budget coverage;
- exact effort split with invariant snapshot totals;
- backend-compatible duplicate-row identity by effort;
- targeted `ottto-service` Rust tests.

## Cache-creation attribution correction

Claude's public `claude_code.api_request` event exposes one aggregate
`cache_creation_tokens` count, while its transcript carries the billing-sensitive
5-minute/1-hour split. Stable `0.1.77` temporarily placed the aggregate count in
the 5-minute evidence field. A real request that wrote only 1-hour cache therefore
failed the byte-exact enrichment fit and remained `unknown` even though its effort,
request count, input tokens, and output tokens were available.

The reducer now stores aggregate cache creation separately. Snapshot enrichment
attributes only fields whose effort grain is exact and leaves cache-creation tokens
on the transcript's `unknown` residual row, preserving TTL pricing without invented
per-effort precision. Legacy `0.1.77` sidecars remain readable and receive the same
conservative treatment. Claude parser version `v15` forces a one-shot replay so
already-indexed sessions are corrected after upgrade.
