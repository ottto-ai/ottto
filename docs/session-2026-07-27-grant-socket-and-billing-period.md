# Session: daily-aggregates consent socket and the ChatGPT billing period

**Date:** 2026-07-27 · **Target release:** `0.1.98` · **Change:**
`crates/ottto-protocol/src/lib.rs`,
`crates/ottto-service/src/provider_daily_reference.rs`,
`crates/ottto-service/src/control.rs`,
`crates/ottto-service/src/agent_status.rs`, `crates/ottto-cli/src/main.rs`

Two independent daemon items for the next stable. Item 1 unblocks the Codex
daily-aggregates consent surface. Item 2 stops throwing away the one piece of
real subscription-period evidence the Codex credential already carries.

## Item 1: `provider_daily_reference_control`

### Why a socket command exists at all

`provider_daily_reference.rs` (shipped in `0.1.97`) has had public, tested grant
APIs - `enable` / `grant_create_request` / `bind_backend_grant` - that nothing
called. The product consent surface established that the browser **cannot**
create a grant on its own: the backend's `POST /api/v1/provider-daily-reference/grants`
needs an `installation_id` plus two `hmac-sha256:` fingerprints derived from a
per-installation HMAC key that only the daemon holds and never writes out. The
missing link was a control-socket command so the companion app or web UI can
drive consent through the existing app-control channel.

This mirrors the `cloud_sessions_control` bridge exactly, so the product-side
`AppControlActionLiteral` extension is mechanical.

### What it does *not* do

- It never creates consent. Prepare packages consent an operator explicitly
  asked for in the UI and hands back a DTO; nothing collects until the backend's
  answer is bound and approved.
- It changes none of the five collection gates: sentinel off-switch, live
  consent at the current epoch with an approved server policy, per-build
  admission, identity proof against the live device and provider account, and
  the circuit breaker/cadence.
- No browser JWT, provider credential, device secret, raw token id, tenant
  scope, or provider account id crosses this boundary or reaches disk.

### Local-control wire

Command name: **`provider_daily_reference_control`**.
Command-scoped protocol version: **`17`**
(`PROVIDER_DAILY_REFERENCE_CONTROL_PROTOCOL_VERSION`). Older daemons reject it,
so a UI that can drive this consent is told to update instead of silently doing
nothing. Every unrelated command stays on base v15; cloud sessions stays on v16.

Request fields:

| Field | Type | Notes |
| --- | --- | --- |
| `request_id` | string | ordinary local-control envelope |
| `protocol_version` | `17` | exact; anything else is rejected at deserialize |
| `client_kind` | `"web_ui" \| "companion_app" \| "cli"` | optional |
| `command` | `"provider_daily_reference_control"` | |
| `action` | `"prepare" \| "bind" \| "revoke" \| "confirm_revoked" \| "status"` | |
| `control_token` | string | one-shot `ottto_app_control` JWT; redacted in debug output |
| `api_base_url` | string, optional | advisory only - the daemon validates against its own trusted set |
| `backend_grant` | object, optional | see below |

`backend_grant` is **required** for `bind` and `confirm_revoked`, **allowed** for
`revoke` (a POST response that raced a local revoke), and **refused** for
`prepare` and `status`. A mismatch is `InvalidRequest` before any local mutation.

### Control-token action slugs (what the backend must mint)

The wire `action` and the control-token `action` claim are different strings, the
same way cloud sessions splits them. The backend mints a token whose `action`
claim is the slug; the daemon rejects a token minted for any other slug.

| Wire `action` | Control-token action slug |
| --- | --- |
| `prepare` | `prepare_provider_daily_reference` |
| `bind` | `bind_provider_daily_reference` |
| `revoke` | `revoke_provider_daily_reference` |
| `confirm_revoked` | `confirm_provider_daily_reference_revoked` |
| `status` | `provider_daily_reference_status` |

Token `source` is `codex` for every one of them. These five strings are what the
product lane adds to `AppControlActionLiteral` in
`backend/app/schemas/apps.py`.

There is deliberately **no** `pause`. The `provider_daily_reference` grant has no
paused state (`off | consent_required | enabled | revoked`), and inventing one
here would mean a persisted status the collector has never been taught to read.

### Responses

Every action answers with the same envelope inside the normal local-control
`payload`:

```json
{
  "action": "prepare",
  "status": {
    "schema_version": "provider_daily_reference_collector_status.v1",
    "source": "codex",
    "collector_id": "provider_daily_reference",
    "grant_status": "consent_required",
    "runtime_state": "consent_required",
    "provider_read_permitted": false,
    "network_disabled": false,
    "backend_create_pending": true,
    "reason_code": "backend_grant_reconciliation_required"
  },
  "backend_create_request": {
    "installation_id": "00000000-0000-4000-8000-000000000001",
    "source": "codex",
    "collector_id": "provider_daily_reference",
    "schema_version": "provider_daily_reference.v1",
    "collector_version": "<daemon release version>",
    "disclosure_version": "provider_daily_reference_disclosure.v1",
    "grant_scope_fingerprint": "hmac-sha256:<64 lowercase hex>",
    "account_fingerprint": "hmac-sha256:<64 lowercase hex>",
    "consent": true
  }
}
```

`backend_create_request` and `backend_revoke_target` are omitted when absent.
`backend_create_request` is exactly the body of
`POST /api/v1/provider-daily-reference/grants`.

`backend_revoke_target` (returned by `revoke`) is:

```json
{ "grant_id": "00000000-0000-4000-8000-000000000002" }
```

It is the id for `DELETE /api/v1/provider-daily-reference/grants/{grant_id}`
under ordinary user auth. It is **omitted** when the create was never
reconciled - there is genuinely nothing to delete, and that is not a failed
revoke: the local stop already happened and already blocks collection.

`backend_grant` (request side, for `bind` / `confirm_revoked` / raced `revoke`)
is the strict credential-free projection of the backend grant response:

```json
{
  "id": "00000000-0000-4000-8000-000000000002",
  "installation_id": "00000000-0000-4000-8000-000000000001",
  "source": "codex",
  "collector_id": "provider_daily_reference",
  "schema_version": "provider_daily_reference.v1",
  "collector_version": "<daemon release version>",
  "release_lane": "supported",
  "disclosure_version": "provider_daily_reference_disclosure.v1",
  "grant_scope_fingerprint": "hmac-sha256:<same 64 lowercase hex>",
  "account_fingerprint": "hmac-sha256:<same 64 lowercase hex>",
  "status": "enabled",
  "grant_version": 1,
  "server_policy_state": "approved"
}
```

`server_policy_state` is `approved | disabled | rollout_disabled` and **defaults
to `disabled` when omitted**, so a response that lost the field can never read as
approval.

### Status vocabulary

`grant_status` is the persisted consent record: `off`, `consent_required`,
`enabled`, `revoked`.

`runtime_state` folds in everything else: `off`, `consent_required`, `enabled`,
`revoked`, `policy_disabled`, `network_disabled`.

`reason_code`, in the order the daemon evaluates them - the most restrictive true
statement wins, so a status can never read `enabled` while something above it is
stopping collection:

| `reason_code` | Meaning |
| --- | --- |
| `network_disabled` | the local off-switch sentinel is present |
| `revoked` | consent was withdrawn |
| `policy_disabled` | the server has not approved this grant, or revoked it server-side |
| `backend_grant_reconciliation_required` | a create was handed out and its response is not bound yet |
| `collector_version_rebind_required` | the daemon was upgraded; consent is per build, so re-consent is needed |
| `enabled` | every gate passes |
| `consent_required` | a consent record exists but cannot collect yet |
| `setup_required` | no consent record exists |

`provider_read_permitted` is true only when all five gates would pass right now.
It is never an assertion that a read is in flight.

### Authority, replay, and ordering

Identical to the cloud-sessions bridge:

1. The token must be a fresh `apps_control` JWT whose `source` is `codex` and
   whose `action` is this action's slug.
2. It is validated against a trusted Ottto backend (`/api/v1/apps/control-token/validate`).
   A caller-supplied `api_base_url` never widens that trust.
3. Exact organization/user/device agreement with the local account and relay
   device bindings is required, and the device must carry the `codex` source.
4. Non-`status` actions take the process-local identity lifecycle lock and
   require that no identity mutation is in flight.
5. The token id is consumed in a bounded, owner-only replay ledger **after**
   validation and **before** any local grant side effect. Only SHA-256(jti) and
   expiry are persisted. The ledger lives at
   `<support>/codex-daily-aggregates/control-token-uses.json` - its own file, so
   a burst on one capability cannot exhaust the other's fail-closed capacity.

### Two behaviours worth knowing about

- **A lost Prepare response is recoverable.** An authenticated `status` returns
  the same `backend_create_request` while `backend_create_pending` is set, so the
  browser retries the idempotent POST and binds its answer rather than guessing a
  DTO. Unlike cloud sessions this DTO is recomputed rather than replayed from a
  persisted tombstone, so a retry after a daemon upgrade carries the new
  `collector_version`; the backend's upsert bumps the epoch when the scope
  changed, so the pair stays coherent.
- **Binding never resurrects withdrawn consent.** `bind_backend_grant` now
  preserves a locally revoked status and retains only the backend grant's
  identity, so a POST that committed just before a local revoke leaves an exact
  DELETE target without re-enabling collection. `apply_backend_revocation` is
  separate from `bind_backend_grant` because the backend's DELETE is idempotent:
  a retried delete answers with the same `grant_version`, which the bind path
  rightly refuses.

### Known gap, deliberately not closed here

`revoke` has no collector-I/O fence. Cloud sessions waits for an in-flight
provider subprocess before returning; this collector has no subprocess and
re-reads the grant at the top of every cycle, so the worst case is one already
started HTTP read/upload finishing after the local stop, bounded by its own
20-second timeouts. A fence is a separate change; the grant is inert from the
next tick onward either way.

## Item 2: the ChatGPT billing period

Implements the daemon half of the backend-acceptance spec recorded in the
product repo (product PR #3427).

- `AgentAccountStatus` gains `subscription_period_start` /
  `subscription_period_end` as optional RFC3339 timestamps with
  `skip_serializing_if`, so today's wire payload is byte-identical when nothing
  is reported. The names are provider-neutral on purpose: any provider that
  publishes real boundaries fills these same fields rather than growing a
  vendor-prefixed sibling.
- `parse_codex_id_token_account` reads `chatgpt_subscription_active_start` and
  `chatgpt_subscription_active_until` from the same
  `https://api.openai.com/auth` claim object `chatgpt_plan_type` already comes
  from.
- **Format-tolerant, because the claim's wire type was never captured.** Epoch
  seconds (number or numeric string) and RFC3339 strings are both accepted and
  normalized to offset-bearing UTC. An offset-bearing string is *converted*, not
  reinterpreted, so the instant is preserved.
- **Sanity-bounded to 2015-2100.** A millisecond-encoded value lands far outside
  that window and reads as "not reported" rather than as a year-57000 renewal
  date. Malformed values, nulls, objects, and arrays are all `None`. No failure
  path substitutes `now`, a calendar month, or a first-seen date - the backend
  contract is "reported or absent".
- One-sided reporting is legitimate and is passed through as-is.
- The early return in `parse_codex_id_token_account` is unchanged: a period with
  no plan, account, email, or organization does not by itself resurrect an
  account row.
- **`merge_codex_accounts` carries both fields.** That function rebuilds the
  struct field-by-field, so a field added upstream and not carried there is
  dropped silently on every merged Codex account. A test pins both the carry and
  the "a later silent probe must not blank a known period" direction.

## Release gates (recorded, not acted on)

- **The billing-period fields must not reach users before product PR #3427
  (backend acceptance) is deployed.** `AgentAccountStatus` is `extra="forbid"` on
  the ingest contract, so an unknown field does not get ignored - it 422s the
  **whole snapshot batch**, destroying every valid sibling snapshot in the same
  request. Merging this to `main` is safe; cutting the `0.1.98` **stable
  release** is gated on #3427 being live in production.
- **The consent socket has no such backend gate** - the grant API shipped in
  product PR #3389. The app/backend action-passthrough lane (extending
  `AppControlActionLiteral` with the five slugs above) lands separately against
  the contract recorded in this document.

## Validation

- `cargo test --workspace`: **1241 passed, 0 failed** (1036 `ottto-service` lib,
  80 + 71 + 44 + 10 across the other targets), run twice.
- `cargo clippy --workspace --all-targets`: clean.
- `cargo fmt --all`: clean.

New tests:

- `provider_daily_reference.rs` - a raced create never resurrects a revoked
  grant; an unreconciled create has no DELETE target; backend revocation binds
  the exact DELETE response and refuses a wrong id, wrong status, regressed
  epoch, or wrong installation; the status view reports every stop before it
  reports `enabled`; policy and build admission stay distinguishable; the status
  view is content-free.
- `control.rs` - the full prepare → status-retry → bind → off-switch → revoke →
  confirm-revoked composition, with the replay ledger proven to persist digests
  only; and the authority suite: no signed-in Codex account refuses to create
  consent, `backend_grant` presence mismatches are refused before any mutation,
  and a token minted for a different action is not trusted.
- `ottto-protocol` - command round trip with a redacted token, `server_policy_state`
  defaulting closed, and the v17 command-scoped protocol version in both
  directions.
- `agent_status.rs` - period present, absent, one-sided, RFC3339 with a non-UTC
  offset, malformed/out-of-range (five shapes), period-alone does not resurrect
  an empty account, the merge carries both fields, and the wire omits them when
  absent.
