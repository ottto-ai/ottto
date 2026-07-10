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

Validation:

- content redaction and retry deduplication unit test;
- exact effort split with invariant snapshot totals;
- backend-compatible duplicate-row identity by effort;
- targeted `ottto-service` Rust tests.
