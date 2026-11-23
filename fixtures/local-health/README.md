# Local Health Contract Fixtures

`contract-matrix.v1.json` is the Phase 0 golden fixture matrix for the Ottto local health contract. It is intentionally contract-only: these cases deserialize into `ottto-protocol` structs and name the reducer, runtime, backend, and UI behavior that later phases must implement.

The matrix covers current and previous stable upgrade compatibility, runtime identity, heartbeat freshness, command idempotency, object authorization, machine identity collision, local state recovery, clock skew, diagnostics redaction, and backfill safety. Implementation tests that need daemon reconcile, backend projection, or frontend rendering should consume these fixtures rather than inventing new state names.
