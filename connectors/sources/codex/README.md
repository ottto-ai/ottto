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
- `cloud_sessions`: an explicit-setup experimental collector for the officially documented, upstream-experimental `codex cloud list --json` metadata surface. One supervisor starts normally but remains inert until the user's versioned local grant exactly matches the connected user, organization, and Codex relay device and the server approves that same grant epoch. Later consent activates on the next cycle without restarting the daemon. Only after those local checks and trusted-destination validation does the collector load Ottto's relay device credential; it never reads provider credentials or passes the device secret through browser control, logs, checkpoints, or observation payloads. Five-minute unchanged head polls produce zero observation/ingest upload; mandatory backend grant revalidation still occurs. Full scans run daily and until completed. A process-memory-only scan continues across cycles, capped at 100 pages/2,000 unique entities and uploaded as ordered v2 chunks of at most 200. Cursor pagination proves positive observations only. Only an explicit official `cursor: null` proves terminal enumeration; one such response of at most 20 entities may be labeled `single_response`. Multi-page official terminal scans are `unstable_cursor`. Fieldless objects, root arrays, and alias-only nulls may preserve valid nonempty positive facts but never finalize or authorize absence; empty ambiguous responses fail closed. Cap, cursor, payload, and timeout failures also never finalize. Restart discards cursor/inventory and begins a new UUID from page zero. Every provider page and upload revalidates local kill/pause/revoke state plus the exact backend grant and policy, then enters a shared provider/relay admission fence; response-loss retries reuse identical DTOs. Pause/revoke persists the stopped state before waiting for already admitted provider or relay I/O, so no new upload can begin and no admitted upload outlives the completed control action. V1 remains only for observation-empty hourly heartbeats. Status reflects local consent, policy, and transport readiness; provider invocation stays forbidden until all local gates pass and exact backend authority is then revalidated before admission.
- `logs2_trace`: reads the requested per-turn `service_tier` from the undocumented
  Codex `logs_2.sqlite` debug database (read-only, time-bounded, row-capped,
  best-effort) to mark fast-mode turns — a turn whose `response.create` request
  asked for `priority` is billed at the fast rate. Reads only the request type,
  `service_tier`, and the `turn.id` tracing span; never reads prompt, instruction,
  response, or tool output, and never uploads raw content. Disabled with
  `OTTTO_CODEX_FAST_MODE_TRACE=off`.

Raw prompts, responses, tool output, local paths, tokens, and credentials must not be uploaded by these collectors. Local enriched uploads stay aggregate and metadata-only unless a later manifest version explicitly declares a different upload boundary.
