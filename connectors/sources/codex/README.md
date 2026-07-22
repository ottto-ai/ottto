# Codex Source Package

Codex remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back that app.

Collectors:

- `local_sessions`: reads local Codex session JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry config capability for Codex `[otel]` settings.
- `quota_status`: requires setup. Prefer the local Codex app-server
  `account/rateLimits/read` protocol for quota windows and ChatGPT credit
  balance metadata; it returns primary/secondary reset windows, used
  percentages, plan type, and `credits.balance`. The current official/local
  app-server and JSONL surfaces do not expose a dedicated reset-bank count, so
  the collector must emit `unit: "resets"` only when a future local surface or
  gated quota probe provides an explicit reset count. Older/private quota paths
  that read local OAuth material or call undocumented ChatGPT endpoints remain
  setup-gated and must not upload raw provider responses or token material.
- `identity_probe`: subprocesses `codex doctor --json` and reads the plain `~/.codex/auth.json` only to derive a hashed `tokens.account_id`. Never reads token bytes (access/refresh/id tokens) and never touches Keychain. Personal-vs-Team disambiguation is handled by the JSONL `rate_limits.plan_type` signal, not this probe.
- `cloud_sessions`: an explicit-setup supported collector for the official `codex cloud list --json` metadata surface. It runs separately from snapshot sync on a five-minute cadence plus up to 20 seconds of jitter, bounds pages/items/wall time, uses local HMAC entity keys and semantic no-ops, and supports immediate local pause/revoke plus the `OTTTO_CODEX_CLOUD_SESSIONS_DISABLED` kill switch. Before every provider cycle it requires one bounded authenticated grant-list result for the exact grant and a strict server policy approval; disabled/revoked/unknown policy and backend errors fail closed before Codex invocation. Ambiguous grant creation is retried as the same idempotent request after restart until the exact backend grant is bound or deleted, and provider pages with invalid required identity/status rows are rejected as failing without fabricated coverage. Strict snapshot batches declare completeness only after terminal provider enumeration; cap/deadline/error/cancellation paths never authorize absence. Empty complete snapshots are valid, and one bounded complete snapshot is replayed per active UTC day. Detailed local provider categories map only to the backend's strict coarse `provider_error` health enum. The strict backend DTO and prepared relay adapter are compiled and tested, including server-owned grant epochs and observation-empty hourly heartbeats. The relay alone is not transport-ready because ordinary-user grant revalidation is intentionally separate. Public startup still uses deferred transport until backend Phase 10 deployment plus retention/cardinality/prune/delete-cost approval; `ottto-service cloud-sessions-status --json` remains `transport_deferred` with `provider_cli_invocation_permitted: false`.
- `logs2_trace`: reads the requested per-turn `service_tier` from the undocumented
  Codex `logs_2.sqlite` debug database (read-only, time-bounded, row-capped,
  best-effort) to mark fast-mode turns — a turn whose `response.create` request
  asked for `priority` is billed at the fast rate. Reads only the request type,
  `service_tier`, and the `turn.id` tracing span; never reads prompt, instruction,
  response, or tool output, and never uploads raw content. Disabled with
  `OTTTO_CODEX_FAST_MODE_TRACE=off`.

Raw prompts, responses, tool output, local paths, tokens, and credentials must not be uploaded by these collectors. Local enriched uploads stay aggregate and metadata-only unless a later manifest version explicitly declares a different upload boundary.
