# Claude upkeep completion status

## Symptom

Live QA on macOS `0.1.130` completed Claude's official browser authorization
without a Terminal fallback, but an expired saved account stayed on `Checking
connection`. The exact-account `Sign in again` action therefore remained
hidden even after the background upkeep worker had finished.

## Cause

The foreground status path enqueued upkeep and always returned `InProgress`.
The worker's durable post-claim results were not read back. More importantly,
missing or expired refresh grants return `NeedsLogin` before `claim_attempt`, so
the most common reconnect outcome had no durable witness at all.

## Fix

- Read the current credential-expiry attempt's durable completed result during
  its backoff window.
- Keep `NeedsLogin` actionable until the credential expiry changes.
- Publish pre-claim `NeedsLogin` results from the queued-worker path and request
  a status refresh immediately.
- Hold the account-registry lock across the final registration check and
  durable publication so concurrent removal always wins.
- Do not republish post-claim `NeedsLogin`; that result can be caused by a
  concurrent account removal whose witness was deliberately pruned.
- Ignore an old witness after browser authorization advances the credential
  expiry.

## Validation

- Focused queued-worker, completed-result, and queue responsiveness tests pass.
- `cargo clippy -p ottto-service --all-targets --locked -- -D warnings` passes.
- Full `ottto-service` library suite passed serially after the worker-publication
  fix (`1,721` passed, `2` ignored). Parallel execution exposed unrelated
  loopback timing flakes; every reported test passed immediately in isolation.
- After focused review added the registry-lock requirement, all Claude upkeep
  tests, the new removal-race regression, and clippy pass.
- Public export bundle and manifest are regenerated and checked before landing.

## Release consequence

The behavior lives in the public local service, so the merged fix requires a
new signed macOS release. Final live QA should reconnect the existing saved
account in its matching browser profile, then verify that its card changes from
reconnect-required to fresh full limits and that the hosted subscription view
receives the refreshed snapshot.
