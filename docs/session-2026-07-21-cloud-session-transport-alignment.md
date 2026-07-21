# Cloud Session Transport Alignment

Aligned the public Codex cloud-session collector to the private backend's
strict, content-free contract without activating collection or releasing a new
runtime.

## Contract and consent

- Replaced the provisional DTO with the exact
  `cloud_session_observations.v1` shape: backend grant UUID/version/scope,
  collector/account binding, `collected_at`, bounded `observations`, and nested
  collector health. Each observation carries only opaque entity identity,
  lifecycle, attempts, normalized environment, not-itemized measurement basis,
  closed coverage, safe provider timestamps, and observation time.
- Removed client `semantic_digest`, source, execution-location, freshness, and
  other server-derived fields from the network payload. The local semantic
  digest remains checkpoint-only; the backend computes canonical digests.
- Split local consent preparation from authenticated server consent. The
  companion/UI owns ordinary-user `POST /api/v1/cloud-sessions/grants` and exact
  `DELETE /api/v1/cloud-sessions/grants/{grant_id}`. The daemon validates and
  stores only the returned grant UUID/version, refuses mismatched scope, and
  requires a strictly newer epoch after revoke/re-consent.
- Refuses scope replacement while an old grant is not confirmed backend-revoked,
  so a single local-state slot cannot orphan an exact-delete target. Runtime
  upgrades also stop collection until the persisted collector version is
  rebound to the current compiled release; no binary silently claims an older
  allowlisted version.
- Persists an ambiguous-create tombstone plus a content-free descriptor of the
  exact scope before handing the authenticated POST to the companion/UI. A lost
  response or restart returns the same idempotent request; a grant-list absence
  cannot clear the tombstone because the original POST may still commit. A late
  response is retained as the exact-delete target even when local revoke already
  won. Unsolicited bind responses remain rejected. Re-enabling either the same
  scope or a replacement scope is blocked until the exact grant is bound and,
  when locally revoked, deleted.
- Requires the backend's strict `server_policy_state` on every grant response.
  Persisted bindings without policy default disabled, while missing or unknown
  response values fail strict decoding. Local `enabled` is runtime-ready only
  for `approved`; server `disabled` transitions to `policy_disabled` without a
  provider call and can return to enabled only after a later approved response.
- Treats `account_fingerprint` only as opaque local Ottto org/user collector
  scope. The sanctioned CLI does not expose a provider-account discriminator;
  known account switches require stop, exact delete, and explicit re-setup.

## Bounded transport and freshness

- Added a prepared relay adapter for
  `POST /api/v1/cloud-session-observations/batches`. It reuses the established
  device-secret relay-token path, caches one token in memory, and refreshes once
  on 401/403. Tokens and response bodies are not persisted or logged.
- Added a separate bounded authenticated grant-list preflight before every
  five-minute provider cycle. Network/auth/parse/absence failures stop before
  Codex invocation, as do server disabled/revoked responses. Upload wiring alone
  is not reported transport-ready; the prepared relay remains deferred until an
  ordinary-user revalidation channel is composed.
- Unchanged five-minute entity polls remain a local transport no-op. Successful
  observation uploads also carry health; otherwise one empty, health-only batch
  is eligible hourly. This stays safely below the backend's two-hour stale
  boundary while avoiding observation or Sessions GOLD writes.
- Provider CLI/payload failures send a bounded health-only `failing` update when
  relay transport is available. Recovery sends an immediate healthy heartbeat;
  it does not wait for the hourly cadence or rewrite unchanged entities.
- Rejects every material invalid required-field row. Identity and a present,
  nonempty string status are required before claiming mandatory coverage; a
  present but unfamiliar status alone may normalize to `unknown`. In
  particular, a nonempty page yielding zero valid rows is locally
  `provider_payload_invalid` and can never become a healthy empty observation.
  The health upload maps this local detail to the backend's strict
  `provider_error` enum.
- Existing caps remain three pages, 60 observations, 45 seconds per cycle, and
  12 seconds per Codex CLI process. Provider timestamps after collection,
  inconsistent chronology, and attempts above 100,000 are dropped locally
  instead of causing retry churn.

## Activation gate

Production `spawn_cloud_session_collector` remains hard-wired to
`DeferredCloudSessionTransport`; no Codex runner or network transport can start.
Do not activate or release 0.1.90 until all are true:

1. Private backend foundation is landed and deployed.
2. Retention/cardinality/prune/delete-cost evidence is green.
3. Authenticated companion setup/revoke composition is landed and QA'd.
4. Demo-user consent, revocation, privacy, load, and stale-freshness QA pass.

## Validation

- `cargo test -p ottto-service cloud_sessions --lib`: 29 passed.
- `cargo test -p ottto-service snapshot_client --lib`: 10 passed.
- `cargo test -p ottto-service`: 757 passed, 1 ignored across library, binary,
  and doc-test targets.
- `cargo clippy -p ottto-service --lib -- -D warnings`: passed.
- First-party connector testkit and generated-registry/schema JSON checks passed.
- Private-backend Pydantic validation accepted aligned strict grant and batch
  fixtures, including populated observation coverage.
- Public export check, refreshed 246-file manifest verification, current/history
  secret scan, and 247-file staged-output secret scan passed.
- Tests cover strict wire absence, scope privacy, exact-create restart and late
  response races, strict server-policy parsing and transitions, per-cycle
  preflight failure/revocation, invalid provider identities/status without
  fabricated coverage, strict backend health-enum mapping, monotonic
  revoke/re-consent epochs, unchanged-poll no-op, hourly heartbeat freshness,
  relay auth reuse, caps, circuit breaking, deferred startup, and provider-value
  bounds.
