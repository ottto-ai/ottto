# Public daemon Claude multi-account collection

**Date:** 2026-08-04
**Scope:** W3 Slice B collector fanout only; no connection setup or upkeep

This slice makes the daemon collect full Claude usage from the config slots
registered by Slice A. It does not add the later prepare/check/stop-waiting
connection contract, run `/login`, refresh OAuth, write Keychain, or change the
backend wire schema.

## Collection contract

- One pass captures one timestamp, considers the default slot first, then up to
  nine registered custom slots in stable opaque-id order.
- Each exact-slot `claude auth status --json` probe clears the daemon
  environment, restores only resolved `HOME`, `USER`, command `PATH`, safe
  locale, and the exact custom `CLAUDE_CONFIG_DIR` (or no config-dir variable
  for default), closes stdin, and retains bounded timeout/output handling.
- The real auth-status fields must positively agree: signed-in state, email,
  and organization UUID must be present and match that exact slot's
  `.claude.json`. Only after agreement does the account UUID in the same file
  become strong account identity. Missing fields and stale/rotated identity
  fail closed.
- Exact-slot identity is read, the credential is captured once into a
  non-serializable, non-debug value, auth status is probed, and identity is
  read again. A concurrent identity change fails closed as
  `concurrent_mutation`; otherwise the captured credential is used directly.
  Collection does not invoke a model or mutate authentication.
- Every full quota window and credit balance carries exact strong account and
  organization hashes. Full-meter rows with missing or mixed identity are not
  uploadable. Existing default statusLine partial rows retain their prior
  account-attribution contract and never apply to custom slots.
- Duplicate strong accounts emit one snapshot. Candidate quality wins in this
  order: fresh full meters, stale full meters, then the default's partial
  statusLine meters. Stable slot order breaks equal-quality ties. A failed
  earlier slot never suppresses a healthy later slot.
- Provider, identity, credential, and capacity failures are isolated. Healthy
  siblings continue. Typed per-slot status is persisted locally without raw
  paths in the state file or backend payload.

## Cache, rollback, and synchronization

Account-keyed OAuth caches and breakers remain isolated. Cache v4 requires the
cache header and every embedded meter to match the current strong account and
organization hashes exactly; an account-only match is discarded, never
relabeled. Default-slot writes mirror a schema-v3 singleton so downgrading
restores the previous single-account behavior. Custom reads never migrate,
delete, or overwrite that legacy singleton. A positively verified exact cache
remains usable for the existing 24-hour stale fallback even if the attempt's
single token read is unavailable or the provider circuit breaker is already
open; no live fetch is attempted without a token, and open-breaker diagnostics
remain visible. An over-age or differently attributed cache does not produce a
row.

Refresh, startup reconfirmation, and snapshot sync consume the multi-snapshot
collection. Upload batches keep all same-source Claude rows together. Active
session reconciliation always receives the separate default/source-health
snapshot, never the first custom upload row. An empty upload vector is a no-op
and does not abort normal transcript telemetry scanning.

## Local status and diagnostics

Authenticated Claude-account status reports `unverified`, `fresh`,
`identity_unknown`, `credential_unavailable`, `identity_mismatch`,
`concurrent_mutation`, `provider_unavailable`, `duplicate_account`, or
`capacity_exceeded` per slot.
Raw registered paths remain confined to authenticated local control. Backend
source health stays one Claude source row with generic sibling-failure detail;
per-slot path and diagnostic state remain local.

## Validation coverage

Tests cover deterministic fanout, one-default-plus-nine capacity, two healthy
accounts with identical weak labels, duplicate suppression, unavailable and
stale default behavior, partial statusLine preservation, exact account+org
stamping for windows and credits, poison-environment removal, real auth JSON
without account UUID, missing/mismatched/failed auth, partial success, local
path redaction, default/custom rotation during auth, one credential read per
attempt, downgrade cache/breaker mirroring, custom-first legacy access,
two-hour stale cache fallback through an open breaker with zero provider calls,
same-source upload batching, empty upload liveness, and default-only session
reconciliation ownership.
