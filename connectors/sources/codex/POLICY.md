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
- `cloud_sessions` requires explicit setup. It invokes only the official `codex cloud list --json` command as the effective user, with a local versioned grant, local pause/revoke, a runtime kill switch, bounded pagination, and a circuit breaker. It does not read `auth.json`, Keychain, browser state, or provider endpoints directly. Until an ingest transport is wired, `ottto-service cloud-sessions-status --json` reports `transport_deferred` and `provider_cli_invocation_permitted: false`; this state cannot invoke Codex.

## Documented Surfaces

- Codex local transcript JSONL files may be read by `ottto-locald` for aggregate local usage snapshots.
- Codex `[otel]` settings may be inspected or managed only through the explicit live telemetry setup path.
- Local quota/status observations may be captured from safe agent status
  snapshots when they are available from documented local CLI/app-server/status
  surfaces. Display-only reset-bank counts such as `2 resets available` may be
  represented as redacted credit-balance metadata only when an explicit count is
  present; current app-server `credits.balance` is ChatGPT credit metadata and
  must not be relabeled as reset-bank availability.
- The documented `codex doctor --json` CLI may be subprocessed by `identity_probe`. Only `auth.credentials.details` fields that do not expose token bytes (`auth storage mode`, `stored auth mode`, presence flags) may be parsed.
- The documented `codex cloud list --json` CLI may be subprocessed by `cloud_sessions` after explicit setup. Only task identity (immediately HMAC-transformed), lifecycle, safe timestamps, attempt count, and a closed normalized environment kind are emitted.
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
- Cloud-session grant state, HMAC key material, semantic checkpoint, and temporary pagination cursor handling stay local. Revocation stops CLI/provider access before the next poll and before transport; scoped backend deletion is owned by the future ingest endpoint.

## Upload Boundaries

- Do not upload raw Codex prompt, response, command output, tool output, or local file paths.
- Do not upload OAuth access tokens, ID tokens, refresh tokens, cookies, account pages, or raw provider responses.
- Do not upload raw reset-bank source payloads. Emit only normalized counts, names, units, freshness, and timestamps. If no explicit reset-bank count is available, omit the reset-bank credit balance instead of inferring it from rate-limit windows or ChatGPT credits.
- Preserve selector context v1 names such as `service_tier`, `batch_mode`, `billing_channel`, `auth_mode`, and `gateway_provider`.
- Cloud-session upload is `cloud_session_observations.v1` only: content-free metadata with opaque provider entity keys and no provider-day usage or fabricated task cost.
