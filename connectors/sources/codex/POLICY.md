# Codex Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it reads local transcript files and uploads aggregate session usage only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` requires setup. It should prefer the local Codex app-server
  `account/rateLimits/read` protocol for quota windows and ChatGPT credit
  balance metadata. Explicit durable connections may decode access-token claims
  from their exact owner-only `CODEX_HOME` only after expiry, issuer, audience,
  stored workspace metadata, any ID token, and the same authenticated provider
  session agree. Uncorroborated claims remain low-confidence and never carry
  meters.
  Any older/private quota path that calls an undocumented ChatGPT usage
  endpoint remains disabled for durable connections and must redact local
  paths, account secrets, and token material from all uploads.
  Scheduled app-server reads stop for every Codex home while the owner's
  "Background limit refresh" setting (on until chosen) is off; a person's
  Refresh and setup checks still read.
- `identity_probe` requires setup because `~/.codex/auth.json` is the file that also stores OAuth access / refresh / id tokens; reading the file at all is classified as a hidden-credential-file read by the connector-manifest safety rules. Once the user enables it, the probe subprocesses `codex doctor --json` and reads `~/.codex/auth.json` solely to derive a hashed `tokens.account_id`. Token bytes (access/refresh/id) are never read into memory. Keychain is never accessed. The fsevents watcher fires only when `tokens.account_id` changes (full OpenAI user swap), not for Personal-vs-Team toggling.
- `cloud_sessions` runs under the same consent as local Codex sessions: the user's "List my Codex cloud tasks" setting, resolved by the server inside the existing "Usage check from your Mac" switch. Its single supervisor starts normally. Each due work slice first reads the Codex activity hint once with the existing relay credential; only `codex_cloud_tasks_enabled: true` and `codex_cloud_tasks_contract: "cloud_session_changes.v3"` let that slice invoke Codex, and the same hint's title and workspace-label settings decide which labels may leave. Listing off, an older server without these fields or naming another contract, authentication failure, and network or parse errors stop before provider invocation; listing off is read again every 30 minutes and a missing route every six hours. The runtime kill switch stops everything. It invokes only the officially documented, upstream-experimental `codex cloud list --json` command as the effective user. The newest page is read every five minutes, and the wait doubles after each listing the server accepted nothing new from, up to a day; a task the server accepts resets it. One daily crawl walks every page, ten pages per slice. Only tasks that changed since their last exact server acknowledgement are uploaded. Failures back off with jitter, separately from local snapshot delivery; any 409 is treated like listing off, and a 410 (this contract retired) like a missing route. It does not read `auth.json`, browser state, OpenAI provider credentials, or provider endpoints directly. After exact local identity and trusted relay destination checks, it loads only Ottto's existing relay device binding and device secret from local credential storage to authenticate the Ottto backend; that secret remains in memory and never enters logs, caches, or upload data. Turning listing on needs no daemon restart. State changes are logged as one line per transition.

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
- Authenticated local control may create owner-only Codex homes, launch the
  official `codex login` flow, and accept a durable connection only after an
  exact user/workspace match plus a fresh post-restriction App Server read.
  The normal default home remains additive and user-controlled.
- The documented `codex doctor --json` CLI may be subprocessed by `identity_probe`. Only `auth.credentials.details` fields that do not expose token bytes (`auth storage mode`, `stored auth mode`, presence flags) may be parsed.
- The officially documented, upstream-experimental `codex cloud list --json` CLI may be subprocessed by `cloud_sessions` while the server turns listing on for the connected user. Only the task id (uploaded as the session identifier, the same as local session ids, and opening a task only within the user's own Codex/ChatGPT access), lifecycle, safe timestamps, attempt count, a closed normalized environment kind, and, only while the matching local metadata setting allows it, the task `title` and `environment_label` (each cut to 2,048 characters; the server cleans and caps them again) are emitted.
- Any nonempty provider page with no row carrying task identity and status strings is rejected locally as `provider_payload_invalid`; it cannot be reported as an empty healthy collection or fabricate mandatory status coverage. A single malformed row is skipped and its valid siblings are kept. A well-formed row whose id breaks the session-id rule is skipped and counted instead, so a page of only such rows still follows its official cursor; the count covers pages that parse. Local failure detail never crosses the upload boundary.
- The server keys each task by (user, source, task id), so every Mac of that user sends one head per task. Only the official `id` field is read, byte for byte: an id that is empty, longer than 255 code points, padded with whitespace or holding a control character is skipped (never repaired) and counted in one counts-only log line. The documented upstream-experimental CLI exposes no sanctioned provider-account discriminator, so the task id must not be described as OpenAI/Codex account identity.
- The plain-JSON file `~/.codex/auth.json` may be read by `identity_probe` solely to extract `tokens.account_id`. `identity_probe` hashes the extracted value before emit. The same selected-workspace id is uploaded raw only as the agent-status `organization_id`, next to its hash, and `tokens.access_token`, `tokens.refresh_token`, and `tokens.id_token` are never read into memory.

## Undocumented Surfaces

- Do not scrape browser sessions, cookies, private web UI state, or account pages.
- Do not automate passwords or MFA, pool entitlements, rotate work to evade a
  provider limit, or treat two subscriptions as one combined allowance.
- Do not default-enable quota/status probes that read `auth.json` token material or call private ChatGPT endpoints.
- Do not infer undocumented selector fields from model names or provider identity.
- Do not add static platform fields to the manifest. Runtime operation state reports unsupported or degraded local availability.
- `identity_probe` must never read `tokens.access_token`, `tokens.refresh_token`, or `tokens.id_token` from `~/.codex/auth.json`. Reading is scoped to `tokens.account_id` only.
- `identity_probe` must never access OpenAI Keychain items or call any ChatGPT or OpenAI endpoint.
- `cloud_sessions` must never read `~/.codex/auth.json`, call WHAM/private endpoints, scrape browser sessions, or persist raw provider ids, cursors, CLI JSON, titles, summaries, URLs, diffs, worklogs, prompts, outputs, or repository paths. Summaries, URLs, diffs, worklogs, prompts, outputs and environment ids are never uploaded; task ids are never logged.

## Local-Only Behavior

- Local transcript reads stay on the user's machine until transformed into aggregate usage or collector-health records.
- Local OAuth credential reads for quota/status must stay in `ottto-locald`; only redacted quota windows, reset-bank counts, credit state, plan evidence, and collector health may leave the machine after setup.
- Local status collection must hash or omit workspace, path, account, and machine-specific details before upload.
- The per-task ACK cache (local digest and server head etag, 30-day expiry) and temporary pagination cursor handling stay local; the cache holds digests, never titles or task ids: each row is keyed by a local digest of its task id. A local identity change (sign-out, account or device replacement) first closes new provider and relay admission and then waits for every already admitted provider subprocess, hint read, changes upload or cache write before replacing identity. No admitted I/O outlives that change. Startup removes the files of the retired per-Mac grant (`grant.json`, its lock, its replay ledger and the old checkpoint under the support directory's `cloud_sessions` folder) and nothing else.

## Upload Boundaries

- Do not upload raw Codex prompt, response, command output, tool output, or local file paths.
- Do not upload OAuth access tokens, ID tokens, refresh tokens, cookies, account pages, or raw provider responses.
- Do not upload raw reset-bank source payloads. Emit only normalized counts, names, units, freshness, and timestamps. If no explicit reset-bank count is available, omit the reset-bank credit balance instead of inferring it from rate-limit windows or ChatGPT credits.
- Preserve selector context v1 names such as `service_tier`, `batch_mode`, `billing_channel`, `auth_mode`, and `gateway_provider`.
- Cloud-session uploads use `cloud_session_changes.v3`: `source: "codex"`, each task's raw id as `source_session_id`, no grant fields, an `upload_policy` stamp naming the title and workspace-label settings applied, and only tasks whose facts or applied policy changed since their last exact acknowledgement. Requests hold at most 200 tasks and stay under the server's 512 KiB body ceiling, splitting a page into more requests rather than dropping tasks; each task carries the predecessor head etag it last saw (or null). The local change digest never leaves the machine. A per-task accepted or noop ACK whose `source_session_id` matches an offered id byte for byte alone settles the cache with its head; a rejected task, or a conflict without a server head, is remembered with no head and no credit so identical content is not resent; a malformed or partial ACK settles nothing. A conflict that names the server's head re-lists the page once and offers the fresh facts against it. Only an explicit official `cursor: null` ends the daily crawl as complete; there is no page or task ceiling. A repeating or cycling cursor chain, fieldless objects, root arrays, and alias-only nulls end that day's traversal without completion while keeping valid positive facts; empty ambiguous responses fail closed. The cursor stays in process memory; a restart begins again from the newest page and the cache suppresses already acknowledged tasks.
