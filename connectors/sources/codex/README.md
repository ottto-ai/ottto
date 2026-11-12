# Codex Source Package

Codex remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back that app.

Collectors:

- `local_sessions`: reads local Codex session JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry config capability for Codex `[otel]` settings.
- `quota_status`: requires setup. Prefer the local Codex app-server
  `account/rateLimits/read` protocol for quota windows and ChatGPT credit
  balance metadata; it returns primary/secondary reset windows, used
  percentages, plan type, `credits.balance`, and the recurring workspace
  monthly pool in `individualLimit`. The latter is emitted as a distinct
  `workspace_monthly_credits` native-count balance so exhausting the weekly
  window does not erase a still-available workspace pool. The current official/local
  app-server and JSONL surfaces do not expose a dedicated reset-bank count, so
  the collector must emit `unit: "resets"` only when a future local surface or
  gated quota probe provides an explicit reset count. Older/private quota paths
  that read local OAuth material or call undocumented ChatGPT endpoints remain
  setup-gated and must not upload raw provider responses or token material.
- `identity_probe`: subprocesses `codex doctor --json` and reads the plain
  default `~/.codex/auth.json` only to derive the existing hashed account
  identifier. It never touches Keychain. Durable quota collection separately
  derives identity from the access token authenticated by the same provider
  session that returned quota, then requires expiry, issuer, audience, stored
  workspace metadata, and any ID token to agree before hashing the ChatGPT user
  and active workspace; uncorroborated claims never carry meters, and token
  bytes never leave the process or enter an upload. The raw ChatGPT user id and
  selected workspace id are uploaded only as the agent-status `account_id` and
  `organization_id`, next to their hashes.
- `cloud_sessions`: an explicit-setup experimental collector for the officially documented, upstream-experimental `codex cloud list --json` metadata surface. One supervisor starts normally but stays idle until the user's versioned local grant exactly matches the connected user, organization, and Codex relay device and the server authorizes collection for that same grant epoch. New consent wakes it without restarting the daemon. Only after those local checks and trusted-destination validation does the collector load Ottto's relay device credential; it never reads provider credentials or passes the device secret through browser control, logs, caches, or upload payloads. Each due work slice makes one authority read, then lists the newest page (every five minutes while a task there is queued, running or unknown, every 30 minutes while local Codex is active, otherwise every six hours) and continues a daily crawl of every page, ten pages per slice, with no page or task ceiling. Only tasks that changed since their last exact server acknowledgement are uploaded (`cloud_session_changes.v1`); a local 30-day ACK cache in the upload-history file remembers each task's digest and head etag. Pause/revoke persists the stopped state before waiting for already admitted provider or relay I/O, and revoke erases the cache. Cloud backoff is separate from local snapshot delivery. Against a server without this contract the collector stays idle and quiet.
- `logs2_trace`: no longer read. The daemon does not open the undocumented
  Codex `logs_2.sqlite` debug database; fast-mode turns come from rollout thread
  settings. A row an earlier build marked fast from that database keeps its tier
  through the daemon's protected tier receipt. The manifest stays declared until
  the server's collector bindings retire it. It never read prompt, instruction,
  response, or tool output, and never uploaded raw content.

Raw prompts, responses, tool output, local paths, tokens, and credentials must not be uploaded by these collectors. Local enriched uploads stay aggregate and metadata-only unless a later manifest version explicitly declares a different upload boundary.

See [`docs/codex-accounts.md`](../../../docs/codex-accounts.md) for the additive
default/durable connection contract and exact composite deduplication rules.
