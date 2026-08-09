# Codex Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it reads local transcript files and uploads aggregate session usage only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` requires setup. It should prefer the local Codex app-server
  `account/rateLimits/read` protocol for quota windows and ChatGPT credit
  balance metadata. Any older/private quota path that reads the local Codex
  OAuth credential or calls an undocumented ChatGPT usage endpoint remains
  setup-gated and must redact local paths, account secrets, and token material
  from all uploads.
- `identity_probe` requires setup because `~/.codex/auth.json` is the file that also stores OAuth access / refresh / id tokens; reading the file at all is classified as a hidden-credential-file read by the connector-manifest safety rules. Once the user enables it, the probe subprocesses `codex doctor --json` and reads `~/.codex/auth.json` solely to derive a hashed `tokens.account_id`. Token bytes (access/refresh/id) are never read into memory. Keychain is never accessed. The fsevents watcher fires only when `tokens.account_id` changes (full OpenAI user swap), not for Personal-vs-Team toggling.
- `cloud_sessions` requires explicit setup. Its single supervisor starts normally but remains inert until a versioned local grant exactly matches the connected user, organization, and Codex relay device. It invokes only the officially documented, upstream-experimental `codex cloud list --json` command as the effective user, with local pause/revoke, a runtime kill switch, bounded pagination, and a grant-epoch-scoped circuit breaker. Every provider cycle first requires one bounded authenticated backend grant-list result for the exact bound grant; only a strict `server_policy_state: "approved"` response permits that cycle to invoke Codex. Missing/unknown policy, disabled/revoked grants, list absence, authentication failure, and network or parse errors fail closed before provider invocation. Healthy polling is limited to one cycle every five minutes plus up to 20 seconds of jitter; semantic no-ops suppress unchanged uploads and failures use exponential circuit backoff. It does not read `auth.json`, browser state, OpenAI provider credentials, or provider endpoints directly. After consent, exact local identity, and trusted relay destination checks, it loads only Ottto's existing relay device binding and device secret from local credential storage to authenticate the Ottto backend; that secret remains in memory and never enters browser control payloads, logs, checkpoints, or observation wire data. Later consent or server approval activates the existing supervisor on its next cycle without daemon restart. `ottto-service cloud-sessions-status --json` reflects local grant/policy/readiness; `provider_cli_invocation_permitted` becomes true only when those local runtime checks are complete, while backend authority is still revalidated immediately before provider admission.

## Documented Surfaces

- Codex local transcript JSONL files may be read by `ottto-locald` for aggregate local usage snapshots.
- Codex `[otel]` settings may be inspected or managed only through the explicit live telemetry setup path.
- Local quota/status observations may be captured from safe agent status
  snapshots when they are available from documented local CLI/app-server/status
  surfaces. Display-only reset-bank counts such as `2 resets available` may be
  represented as redacted credit-balance metadata only when an explicit count is
  present; current app-server `credits.balance` is ChatGPT credit metadata and
  must not be relabeled as reset-bank availability. App-server
  `individualLimit` may be represented separately as
  `workspace_monthly_credits`, preserving only used/quota/remaining,
  utilization, reset, status, and safe limit metadata.
- The documented `codex doctor --json` CLI may be subprocessed by `identity_probe`. Only `auth.credentials.details` fields that do not expose token bytes (`auth storage mode`, `stored auth mode`, presence flags) may be parsed.
- The officially documented, upstream-experimental `codex cloud list --json` CLI may be subprocessed by `cloud_sessions` after explicit setup. Only task identity (immediately HMAC-transformed), lifecycle, safe timestamps, attempt count, and a closed normalized environment kind are emitted.
- Any nonempty provider page containing a row without valid task identity and status strings is rejected locally as `provider_payload_invalid`; it cannot be reported as an empty healthy collection or fabricate mandatory status coverage. The strict backend health wire uses only the allowed coarse `provider_error` category; local detail never crosses that boundary.
- The cloud-session `account_fingerprint` is only an opaque local Ottto organization/user collector scope. The documented upstream-experimental CLI exposes no sanctioned provider-account discriminator, so it must not be described as OpenAI/Codex account identity or used to merge work across known provider-account switches. A user-known switch requires explicit stop, exact backend delete, and re-setup.
- The plain-JSON file `~/.codex/auth.json` may be read by `identity_probe` solely to extract `tokens.account_id`. The extracted value is hashed before emit; the raw value never leaves the machine, and `tokens.access_token`, `tokens.refresh_token`, and `tokens.id_token` are never read into memory.

## Undocumented Surfaces

- Do not scrape browser sessions, cookies, private web UI state, or account pages.
- Do not default-enable quota/status probes that read `auth.json` token material or call private ChatGPT endpoints.
- Do not infer undocumented selector fields from model names or provider identity.
- Do not add static platform fields to the manifest. Runtime operation state reports unsupported or degraded local availability.
- `identity_probe` must never read `tokens.access_token`, `tokens.refresh_token`, or `tokens.id_token` from `~/.codex/auth.json`. Reading is scoped to `tokens.account_id` only.
- `identity_probe` must never access OpenAI Keychain items or call any ChatGPT or OpenAI endpoint.
- `cloud_sessions` must never read `~/.codex/auth.json`, call WHAM/private endpoints, scrape browser sessions, or persist raw provider ids, cursors, CLI JSON, titles, summaries, URLs, diffs, worklogs, prompts, outputs, or repository paths.

## Local-Only Behavior

- Local transcript reads stay on the user's machine until transformed into aggregate usage or collector-health records.
- Local OAuth credential reads for quota/status must stay in `ottto-locald`; only redacted quota windows, reset-bank counts, credit state, plan evidence, and collector health may leave the machine after setup.
- Local status collection must hash or omit workspace, path, account, and machine-specific details before upload.
- Cloud-session grant state, HMAC key material, semantic checkpoint, and temporary pagination cursor handling stay local. Pause/revoke first persists stopped state, closing new provider and relay admission, and then waits for every already admitted provider subprocess or chunk/finalize/heartbeat/failure write before returning. No admitted I/O outlives the completed control action. The authenticated companion/UI owns exact backend grant create/delete. Before handing off create, the daemon persists a content-free descriptor for that exact scope. A timed-out create is retried idempotently after restart until its grant UUID is bound; a single grant-list absence never clears the tombstone or permits scope replacement. The daemon retains the opaque grant UUID/version/policy binding and refuses stale pre-revoke epochs after re-consent.

## Upload Boundaries

- Do not upload raw Codex prompt, response, command output, tool output, or local file paths.
- Do not upload OAuth access tokens, ID tokens, refresh tokens, cookies, account pages, or raw provider responses.
- Do not upload raw reset-bank source payloads. Emit only normalized counts, names, units, freshness, and timestamps. If no explicit reset-bank count is available, omit the reset-bank credit balance instead of inferring it from rate-limit windows or ChatGPT credits.
- Preserve selector context v1 names such as `service_tier`, `batch_mode`, `billing_channel`, `auth_mode`, and `gateway_provider`.
- Cloud-session observations use ordered v2 scan chunks (at most ten chunks of 200, 2,000 unique entities and 100 provider pages per scan) plus a separate terminal finalize; v1 remains only for observation-empty hourly heartbeats. Chunks prove positive observations only. Only explicit official `cursor: null` proves terminal enumeration. The server owns absence authority and may consider it only for `enumeration_consistency: single_response`, emitted after one such response of at most 20 entities. Multi-page official terminal scans are `unstable_cursor`. Fieldless objects, root arrays, and alias-only nulls may preserve valid nonempty positive facts but never finalize or authorize absence; empty ambiguous responses fail closed. Cap, cursor churn, malformed/truncated response, timeout, cancellation, and provider errors also never finalize. Cursor and active inventory remain process-memory only, and restart begins a new UUID from page zero. Exact response-loss retries reuse identical DTOs. Normal five-minute unchanged head polls produce zero observation/ingest upload while mandatory backend grant revalidation still occurs; full scans run daily and until completed.
