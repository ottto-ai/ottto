# Privacy

Ottto separates local enriched data, live telemetry, integration connectors,
cloud billing connectors, and calculated estimates. The local platform keeps
local state and secret material on the Mac unless a user-approved setup or
diagnostics flow sends a redacted payload.

## Local Ownership

`ottto-service` owns:

- account binding metadata;
- setup-run binding metadata;
- source/app health;
- local control token storage;
- repair planning and backups;
- diagnostics redaction;
- update and uninstall state.

Agents, the CLI, the macOS app, and the web app are clients. They should not
duplicate local setup or repair logic.

## What Stays Local

The local platform must not upload raw prompts, raw responses, tool output,
command output, browser cookies, OAuth credentials, API keys, passwords,
absolute local paths, or raw provider account ids.

Local usage snapshots use derived and redacted fields such as session ids,
timestamps, usage totals, model usage, hashed workspace identity, and
display-safe account or plan evidence.

Session attribution follows the same boundary. The daemon may use bounded
first-prompt material, provider-native skill metadata, and local scheduled-task
definitions in memory to derive tenant-scoped HMAC identifiers. It does not
upload the source prompt, skill name, schedule text, definition path, or HMAC
key. Provider schedule inventory is bounded, cached for six hours, and
reprocesses only files whose size or modification time changed. Missing or
ambiguous evidence produces no attribution label; it is never reclassified as
human activity.

## Live Telemetry

Live telemetry is source-level opt-in. Setup can mint scoped setup keys and
write local source config through `ottto-service`. Opt-out must remove fenced
local config or Keychain state before backend setup-key revocation completes.

Claude Code can continue sending its documented OTLP logs to Ottto's loopback
daemon when cloud live telemetry is off. The daemon reduces only content-free
per-request effort evidence (session id, timestamp, model, effort, and token
counters) into owner-only hashed local sidecars and uploads it later through
the aggregate local snapshot path. It never persists the raw OTLP request or
identity/content attributes such as email, prompts, responses, commands, or
paths. Any transcript usage not exactly covered by local evidence remains
explicitly effort-unknown.

## Repair Boundaries

`ottto fix --json` returns repair authority metadata. Terminal repair is allowed
only for setup-safe actions tied to an active setup-run binding. Credential,
auth-adjacent, stale-account, or disconnected cases require browser approval.
`ottto verify --repair --json` is narrower: it can repair only Codex or Claude
Code WriteConfig drift after a read-only config check, then re-read config before
telemetry smoke. `OTTTO_PATCH_CODEX_DISABLED` and
`OTTTO_PATCH_CLAUDE_CODE_DISABLED` block repair writes and return
`patch_disabled`.

## Diagnostics Redaction

Diagnostics collection is local-only by default. Uploads require explicit
approval, retention disclosure acceptance, and either an active login or a
support claim. Redaction covers local paths, secret tokens, account identifiers,
machine identifiers, raw prompts, and command output before display or upload.

## Reporting Guidance

Support and agents should summarize status and next actions. Do not paste full
diagnostics payloads or raw JSON containing local identifiers unless the user
explicitly asks and the payload has been reviewed for redaction.
