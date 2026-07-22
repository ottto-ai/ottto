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

The optional Codex Cloud Sessions collector is disabled until explicit local
setup. It invokes only `codex cloud list --json` as the effective user and
derives opaque HMAC entity/account keys plus lifecycle, timestamps, attempt
count, safe environment kind, coverage, and freshness. It never reads
`~/.codex/auth.json`, calls private provider endpoints, or uploads raw CLI JSON,
titles, summaries, URLs, diffs, worklogs, prompts, outputs, repository paths,
raw provider ids, or cursors. Its local grant is versioned and can be paused or
revoked immediately; `OTTTO_CODEX_CLOUD_SESSIONS_DISABLED=1` prevents runtime
collection. The collector is isolated from snapshot sync, bounded by page/item/
wall-time limits, and uses semantic no-ops plus circuit-breaking backoff. Active
full scans are bounded to 2,000 unique entities, 100 provider pages, and ten
ordered chunks of at most 200 observations. The current cursor, raw response,
and scan inventory exist only in the long-lived collector process; restart
drops them, creates a new local UUID, and starts again from page zero.

Cursor pagination proves positive observations only. Absence can be considered
only by the server after a single terminal provider response containing at most
20 entities; multi-page terminal scans are labeled `unstable_cursor`. Cap,
cursor churn, malformed/truncated response, timeout, cancellation, or error
paths can upload bounded positive chunks but never finalize an absence-capable
epoch. Chunk identity, semantic, inventory, and ordered epoch digests are
content-free SHA-256 values; semantic digests exclude observation/collection
time. Identical response-loss retries reuse the exact chunk or finalize body.

The collector polls no more often than every five minutes plus up to 20 seconds
of jitter. Normal polls read one head page; unchanged heads produce zero
observation/ingest upload, though mandatory backend grant revalidation still
occurs, and allow an observation-empty v1 heartbeat hourly. A full scan runs
daily and until one has completed. Every provider page, chunk, finalize, and heartbeat is
preceded by local kill/pause/revoke checks and exact backend grant/policy
revalidation. Only a strictly decoded
`server_policy_state: "approved"` permits that cycle to invoke Codex. Missing or
unknown policy, disabled/revoked state, backend absence, authentication failure,
and network or parse errors stop before provider access. A nonempty CLI page
with any missing/invalid task identity or status string is classified locally
as `provider_payload_invalid`; it neither fabricates mandatory status coverage
nor becomes an empty healthy observation. The wire emits only the backend's
allowed coarse `provider_error` category, never detailed local diagnostics.
The raw installation id is discarded after deriving grant-local HMAC
fingerprints. Grant state is stored with private-directory and exclusive 0600
atomic-write semantics. Earlier v1 grants migrate on first read, removing their
raw installation id while preserving pause and revoke controls. The Codex
subprocess receives no provider API keys and does not start an interactive
shell.

The uploaded `account_fingerprint` is an opaque local Ottto organization/user
collector scope, not an OpenAI or Codex provider-account identity. The official
CLI path currently exposes no sanctioned safe account discriminator; Ottto does
not infer one or merge histories across a user-known provider-account switch.
Such a switch requires explicit local stop, exact backend deletion, and setup
again.

The strict v2 chunk/finalize relay adapters and backend DTOs are present for contract testing, but
public service startup remains hard-wired to deferred transport. It cannot
invoke Codex or upload until the private backend is deployed and the retention,
cardinality, prune, and exact-delete-cost gate is approved. Authenticated
companion/UI code owns backend grant create/delete. Before a create handoff the
daemon persists only a content-free exact-scope descriptor, never the raw
installation id. A timeout or restart retries that same idempotent create until
the backend grant UUID is bound; one intervening list absence cannot clear the
tombstone or permit replacement while the original POST may still commit. The
daemon stores only the opaque grant UUID/version/server-policy response and
rejects stale pre-revoke epochs.

Session attribution follows the same boundary. The daemon may use bounded
first-prompt material, provider-native skill metadata, and local scheduled-task
definitions in memory to derive tenant-scoped HMAC identifiers. It does not
upload the source prompt, skill name, schedule text, definition path, or HMAC
key. Provider schedule inventory is bounded, cached for six hours, and
reprocesses only files whose size or modification time changed. Missing or
ambiguous evidence produces no attribution label; it is never reclassified as
human activity.

On macOS, external-scheduler attribution may also inventory bounded user
launchd definitions and the user's crontab at startup and once per day. Raw
plist, crontab, wrapper-script, command, and path content stays local. A
specific-file `lsof`, content-free process parent table, and bounded
`launchctl print` lookup run only for a changed session that already matches a
plausible scheduler definition; there is no process watcher. Static
correlation requires matching schedule time, prompt signature, provider, and
repository. Interval jobs require a live job-PID relationship. Missing access,
timeouts, and ambiguity produce no external-scheduler fact.

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
