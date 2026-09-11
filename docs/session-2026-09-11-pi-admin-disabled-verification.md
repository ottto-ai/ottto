# Pi admin-disabled verification follow-up

Date: 2026-09-11

## Context

Post-release pairing QA confirmed that a local-only logout can reattach with
the retained prior credential: the installation and machine identities stayed
stable, the browser-approved claim completed, and the daemon returned to a
connected account with an active relay device and valid setup token.

The same QA run exposed a separate error-classification problem. When workspace
telemetry is disabled, Pi session import correctly receives the backend's
bounded `telemetry_disabled_by_admin` response, but the daemon previously
collapsed that response into `verification_service_rejected` and advised the
user to sign in again. Pi route aggregation then replaced the reason with
`pi_route_smoke_failed`, and persistent local health reduced it again to
`telemetry_not_verified`.

## Resolution

- Recognize only the exact structured backend detail on HTTP 403; arbitrary 403
  responses keep the generic rejection behavior.
- Preserve `telemetry_disabled_by_admin` through per-route results, Pi
  aggregation, stored source health, and canonical local-health projection.
- Present the condition as a warning with the action to enable workspace
  telemetry. Do not offer a sign-in or automatic Verify action.
- Exclude the policy condition from automatic smoke retry and agent-status
  refresh paths so the daemon does not consume provider quota or overwrite the
  backend-authoritative state.

## Regression coverage

The daemon test starts with the recorded backend shape
`{"detail":"telemetry_disabled_by_admin"}` and proves that the route result,
aggregate result, stored health problem, and canonical blocking reason all keep
the typed code. It also proves the message does not ask the user to sign in,
the source remains a non-critical warning, no retry action is emitted, and the
source is excluded from background failed-verification retries.

Release publication is intentionally out of scope for this change.
