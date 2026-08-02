# Scanner Preflight-Poison Liveness

Date: 2026-08-02

## Outcome

Deterministic item-level daemon preflight failures no longer pin a bounded
snapshot traversal page. The upload driver reads the failing request-local
index from the validator error, durably quarantines that exact semantic
fingerprint under the existing contract witness, and retries only its healthy
siblings. The completed caller boundary can therefore persist both settlement
and the traversal cursor.

The quarantine remains bounded and repairable: a collector, parser, schema, or
entity-ACK contract change makes the entity eligible again, as does the existing
retry deadline. Remote 422 responses are not treated as proven-permanent local
failures; malformed responses, authorization failures, network failures, and
checkpoint failures remain unsettled.

## Regression Coverage

- A valid long-lived Pi session with 1,000 internally consistent hourly usage
  buckets exceeds the 128 KiB item wire cap on the first page.
- Its healthy sibling uploads once, the poison quarantine is durable before the
  upload ledger clears, and a reloaded scan index reaches the later page.
- A failed quarantine checkpoint remains a local-state error and cannot settle
  the source or emit/suppress the eventual durable poison-loss signal.
- Legacy item-specific 422 and timeout restart tests continue to prove remote
  errors stay pending.

Focused tests run with a fresh explicit
`OTTTO_SERVICE_SECRET_FALLBACK_DIR`; macOS Keychain state was never consulted or
modified.
