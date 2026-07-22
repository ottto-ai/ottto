# Cloud Session Activation Authority Bridge

Implemented the default-off security bridge needed for a future browser-consent
activation without changing public startup.

## Contract

- Added additive local-control protocol action `cloud_sessions_control` with
  prepare, bind, pause, revoke, confirm-revoked, and status operations. It uses
  protocol v15 so older daemons reject the unknown command and older clients do
  not send it.
- Browser JWTs remain in the browser. The daemon accepts only a short-lived
  backend-signed action token, validates it against a trusted Ottto backend,
  requires exact organization/user/device/source agreement with local account
  and relay-device bindings, and consumes it before any mutation.
- The action token is a redacted `SecretString` in request debug output. The
  replay ledger persists only SHA-256(token id) and expiry, is atomically locked
  and written with owner-only permissions, prunes by TTL, and is capped at 64
  entries.
- Prepare returns the credential-free backend create DTO. Bind and
  confirm-revoked accept only the strict backend grant response. Revoke stops
  locally and returns one exact grant UUID for ordinary-browser DELETE.

## Runtime authority and stop fence

- `RelayCloudSessionTransport` now revalidates one exact grant UUID/version via
  the source-scoped device relay token and refreshes that relay token once on
  401/403. Absence, epoch conflict, policy mismatch, auth, parse, or network
  failure prevents the provider call.
- A process-shared provider-call fence closes new admission after local
  pause/revoke and boundedly waits for an already admitted subprocess before
  local control returns. The Codex subprocess already has a 12-second hard
  bound; control waits at most 15 seconds and fails closed.
- `spawn_cloud_session_collector` remains hard-wired to
  `DeferredCloudSessionTransport`. The prepared path is testable, but this
  change cannot start Codex or upload in production.

## Privacy and load

- No browser JWT, device secret, raw token id, provider identifier, CLI output,
  cursor, or account identifier is added to logs or persistence.
- Normal authority cadence is one exact indexed backend read before provider
  access. The path creates no backend writes or heartbeat churn. Existing
  five-minute+jitter polling, hourly empty heartbeat, circuit backoff, and scan
  bounds remain unchanged.

## Exact local-control wire

Each attempt uses protocol v15 plus a newly minted action token. Prepare has no
backend grant in its request:

```json
{
  "request_id": "cloud-prepare-1",
  "protocol_version": 15,
  "client_kind": "web_ui",
  "command": "cloud_sessions_control",
  "action": "prepare",
  "control_token": "<ottto_app_control JWT>",
  "api_base_url": "https://api.ottto.net"
}
```

Its successful response is a normal local-control envelope. The values below
show the complete response shape; fingerprints and version are daemon-derived:

```json
{
  "request_id": "cloud-prepare-1",
  "ok": true,
  "payload": {
    "action": "prepare",
    "status": {
      "schema_version": "cloud_session_collector_status.v1",
      "collector_id": "cloud_sessions",
      "grant_status": "consent_required",
      "runtime_state": "consent_required",
      "transport_configured": false,
      "provider_cli_invocation_permitted": false,
      "reason_code": "consent_required"
    },
    "backend_create_request": {
      "installation_id": "00000000-0000-4000-8000-000000000001",
      "source": "codex",
      "collector_id": "cloud_sessions",
      "schema_version": "cloud_session_observations.v1",
      "collector_version": "<daemon version>",
      "grant_scope_fingerprint": "hmac-sha256:<64 lowercase hex>",
      "account_fingerprint": "hmac-sha256:<64 lowercase hex>",
      "consent": true
    }
  },
  "error": null
}
```

Bind uses `action: "bind"` and includes only this credential-free projection
from the ordinary-browser backend grant response:

```json
{
  "id": "00000000-0000-4000-8000-000000000002",
  "installation_id": "00000000-0000-4000-8000-000000000001",
  "source": "codex",
  "collector_id": "cloud_sessions",
  "schema_version": "cloud_session_observations.v1",
  "collector_version": "<daemon version>",
  "release_lane": "supported",
  "disclosure_version": "cloud_sessions_disclosure.v1",
  "grant_scope_fingerprint": "hmac-sha256:<same 64 lowercase hex>",
  "account_fingerprint": "hmac-sha256:<same 64 lowercase hex>",
  "status": "enabled",
  "grant_version": 1,
  "server_policy_state": "approved"
}
```

Pause, revoke, and status omit `backend_grant`. Revoke returns
`backend_revoke_target: {"grant_id":"<exact UUID>"}`. Confirm uses
`action: "confirm_revoked"` with the same projection carrying
`status: "revoked"` and the backend's incremented `grant_version`.

The runtime authority wire is exactly:

```http
GET /api/v1/cloud-session-observations/grants/<exact UUID>/authority?grant_version=<exact epoch>
Authorization: Bearer <source-scoped relay token>
```

## Rollback and retry invariants

- Action-token reuse always fails. Browser retries mint a new token; they do not
  reuse an action JWT after timeout or connection loss.
- Prepare persists a same-scope pending tombstone before returning. An unknown
  backend POST outcome retries the unchanged create DTO; it never prepares a
  replacement scope while the first create may have committed.
- Bind and confirm are retry-safe with a new action token plus the exact prior
  backend response. A paused bound grant resumes through prepare without a new
  POST.
- Pause/revoke close provider admission before waiting for the at-most-12-second
  subprocess. Revoke remains local even if browser DELETE fails. The consumer
  exposes cleanup pending and retries exact DELETE then confirm; it does not
  roll local state back or create another grant.
- A local-control timeout is an unknown outcome. The consumer mints a fresh
  `cloud_sessions_status` token and observes local state before repeating any
  backend mutation.
- Authority absence, auth failure, epoch conflict, disabled/revoked policy,
  malformed response, timeout, or network failure admits zero provider calls.
  Rollout kill switch plus local pause/revoke are independent stop layers.

## Validation

- Protocol round-trip proves action transport and redacted token debug output.
- Replay tests cover concurrent consume, restart replay, TTL pruning, hard cap,
  raw-token absence, and 0600 permissions.
- Race tests prove revoke waits for an admitted call and blocks later admission.
- HTTP tests prove exact authority path/query/Bearer binding and that 404/409
  stop before provider invocation.
- Full cloud-session, control workflow, formatting, check, Clippy, and public
  export/secret scans are required before merge.
