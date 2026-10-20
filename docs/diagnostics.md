# Diagnostics

Diagnostics help support understand local runtime state without exposing raw
local content.

## Local Collection

Collect a redacted diagnostics bundle locally:

```bash
ottto diagnostics collect --json
```

The response includes sectioned runtime, install, account, source, repair,
update, and security facts plus a redaction report.

`versions.app_version` comes only from the Ottto app's own `Info.plist`, and
only when its bundle identifier is the Ottto app's. When the service runs
from inside the app, it is that app's version. When Homebrew or the installer
owns the service, it is the version of the app in `~/Applications` or
`/Applications`, but only if every copy found there reports the same version.
In every other case it is `unknown`. It is never taken from the service or CLI
version, because the app and a Homebrew install can be at different versions.

## Claude Local Evidence Health

Local collection includes a `claude_local_evidence` section with separate API
and trace counters for available canonical rows, duplicate/conflicting requests,
malformed or unframed rows, oversized files/lines, unavailable or changed files,
and limited selection/reads. The inspection is on demand: at most four files per
store, 64 directory entries per store, 64 KiB read per file (512 KiB total),
16 KiB per line and 128 physical rows per file. Selection can be partial and is
not a complete census or a retained-history replay. Symlinks and non-files are
refused; no file is rewritten.

These are support facts, not new session totals or account evidence. The section
always reports `complete_capture_authority: false`. Available rows in a capped
file remain incomplete; a partial line or JSON object missing its final newline
is not counted as a validated framed row. Strict upload/account readers retain
their existing refusal behavior. Counts do not detect every zero-byte capture
failure, establish power-loss durability or solve capped-file growth. No request
ids, paths, fingerprints, identity observations, token/cost values or row content
appear in this section. Approved upload uses the existing disclosure and consent.

## Local Resource Measurements

The existing service error log contains content-free JSON lines prefixed
`ottto-service: local_resources`. The macOS app/dev LaunchAgent writes
`~/Library/Logs/Ottto/ottto-service.err.log`; Homebrew writes
`~/Library/Logs/Ottto/ottto-service.error.log`. These records add no remote
telemetry endpoint or CLI command. They contain counts, byte lengths, timing,
process id and a fixed source label; no paths, account/session identifiers,
payloads, credentials or backend response bodies.

Records use `schema_version: 2`. Within a version, fields and stage values may
only be added; readers must ignore unknown keys and stages. Removing a field
or line, or changing its meaning, increments the version. Version 2 removes
the `sampled acquisition` text line: full-read reasons now come from
`counts.sampled_acquisition.page_events.full_reasons` in `local_resources` JSON.
Version 1 readers that need reasons must retain their text fallback while
accepting version 1 binaries; there is no version negotiation.

Each completed `native_collection_page` records existing scanned-file and
semantic-no-op counts. `sampled_acquisition` is `null` when unavailable. Its
full/tail/unchanged selection counts describe acquisition decisions, including
repeated or subsequently failed plans; they are not distinct file counts.
`completed_native_bytes` and `completed_guard_bytes` count only completed
sampled JSONL read plans. Failed reads, joined-file replay, discovery, headers,
sidecars and independent identity reads are excluded. Zero here does not prove
zero filesystem work. Collection timing covers native initialization and steps,
including time parked between steps, and ends before post-policy finalization
and upload. A capped/partial page is still a completed page.

When sampling is present, `page_events` records existing full-read reasons as a
sparse map of closed snake_case keys (`state_missing`, `audit_due`,
`clock_changed`, `scope_changed`, `invalid_checkpoint`, `replaced`, `shrunk`,
`same_size_edit`, `head_changed`, `boundary_changed`, `unsupported_identity`).
Their sum equals `full_selections`. It also records `priority_full_replays`,
`audits_started`, `audits_completed`, `max_start_overdue_seconds` and
`max_completion_overdue_seconds`. Separate `index_state_at_page_end` gauges
record `pending_audits`, `overdue_audits` and `oldest_due_age_seconds` using the
existing index calculations. These are state, not events; overdue work remains
owed until full verification. Both objects are absent when sampling is null.

A `source_finish` record wraps rotation finish, including its validation,
post-policy finalization and upload work. It exists exactly when finish was
called and returned normally, including an error return. It has `counts: {}`
and no result field; outcome reporting and transport receipts remain the
existing outcome owners. Prepare failures, prepare returning no frame,
rotation validation failures before finish, panics, aborts and hard kills
produce no finish record.

Each `snapshot_batch_call` records the actual serialized body length and the
encoded/decoded body lengths across attempts passed to HTTP. Gzip refusal adds
both the compressed attempt and its identity fallback. A refusal before send
adds no attempt; serialization failure leaves the body length `null`. These
are **attempted body bytes**, excluding headers, TLS, responses and library-level
transport activity; they do not prove successful delivery or ACK settlement.
Encoding settings, packing and delivery semantics are unchanged. Upload timing
covers serialization, compression, request/response handling and existing local
receipt processing, including failures.

`shared_process_cpu_delta_us` samples self-process CPU across the observation
window, including concurrent stages; it excludes child processes. It must not
be attributed to one provider. `process_lifetime_max_rss_bytes` is the process's
lifetime memory high-water mark, not a collection/cycle peak or current RSS.
`process_lifetime_max_rss_before_bytes` preserves the start sample when both
samples are available and non-regressing; otherwise it is `null`. A rise
correlates only with a process-wide time window, not allocation ownership.
Unavailable measurements and regressing CPU deltas are `null`. Unix observation
time and process id support comparison with an independently measured matching
process. Never subtract or sum overlapping windows or infer per-stage memory
use: the finish window contains its batch-call windows.

There is one bounded observation per completed page, batch call and normally
returned finish, with two OS resource samples per observation, no per-row
sampling, extra transcript reads or new diagnostic store. Version 2 adds one
record per finish and removes one text line per sampled page; total log writes
are not unchanged. Output is a synchronous best-effort write on the calling
thread under std's stderr lock; errors are ignored, with no retry, queue or
thread. It may block for the duration of a regular-file write, like existing
service stderr lines. Log output uses existing service retention and may be
unavailable; diagnostic write errors do not fail collection or upload.
Status/quota refresh, OTLP reception and independent metadata/discovery work are
outside this measurement slice. Installed comparisons must use the same
source/encoding settings and distinguish idle, ordinary changes, import and
recovery. A containing release and matching installation are required before
calling these measurements installed evidence.

## Private Codex Census Outcomes

The support-root `snapshots/codex-fenced-census-v1.json` file now uses schema
`local_fenced_codex_census:v3`: bounded completed-page scan/index aggregates plus
producer PID/version, optional kernel start seconds/microseconds, attempt sequence
and observation UTC. A separate `snapshots/codex-fenced-census-outcome-v1.json`
file records only the last non-success outer/inner outcome and actual invalidation.
Census v3 adds a fixed eight-category unreadable-event histogram, an explicit
unattributed remainder for old traversals, and existing terminal-loss shares.
Categories identify the original failing branch, not an OS diagnosis or distinct
files; see [branch attribution](session-2026-10-12-codex-unreadable-causes.md).
The census remains limited to 8 KiB; the sidecar to 1 KiB. Healthy attempts add
no sidecar write or unlink. Both are owner-only disposable atomic caches without
fsync, excluded from public status, upload DTOs and diagnostics bundles.

These files are structural diagnostic evidence, not health, current account,
delivery, checkpoint or ACK proof. A separately scoped reader needs matching exact
PID/start tuples before and after, image continuity, freshness and attempt ordering.
Unavailable identity, equal-attempt contradiction or foreign-current writer evidence
gives UNKNOWN; files show last persisted, never latest executed. See the
[carrier contract](session-2026-10-11-codex-census-outcome-carrier.md) before interpreting
either file. This adds no reader, runtime repair or installed acceptance.

## Approved Upload

Upload only when the user approves the upload and accepts the retention
disclosure. An active login or support claim is required:

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

If the user is already logged in, a support claim may not be needed. Follow the
JSON `upload_report` and next-action fields.

Support claims are authorization material. They are sent only on the upload
request and must not appear in the returned JSON payload or uploaded bundle
content; the JSON report exposes only whether a support claim was provided.
Stable local identifiers, including machine ids, must appear only as redacted
placeholders such as `[machine_id]` in diagnostics output. Account, user,
organization, device, and installation identifiers must follow the same
redacted-placeholder rule.

## What To Share

Share:

- command family;
- exit code;
- high-level status;
- support bundle id or uploaded state;
- next user action.

Do not share raw local paths, prompts, account ids, machine ids, credential
material, cookies, or command output. Also keep raw user, organization, device,
and installation ids out of diagnostics summaries and support handoffs.

## Upload Receipts

An upload receipt is a local, bounded record of one snapshot batch attempt and
the backend acknowledgement, when one was returned. Use receipts to confirm
when a source uploaded, how many entities the backend accepted, and whether the
backend shed, rejected, or partially accepted a batch:

```bash
ottto receipts --limit 20
ottto receipts --json --since 2026-09-10T00:00:00Z --source codex
```

The daemon keeps at most 500 receipts. Public receipt output replaces source
session ids with a 12-hex SHA-256 prefix and limits snapshot fingerprints to
12 hex characters. Raw source session ids are never stored in receipts.
Request bodies, authorization headers, tokens,
and raw backend rejection details are not included. `device_label` and
`account_binding` use only the user-facing label and binding state already
shown by `ottto status`; raw device, account, user, and organization ids are
never stored. If `server_request_id` is present, provide it to support so the
local attempt can be correlated with the server request. Older backends may
omit the optional `X-Request-ID` header, in which case the field is `null`.

```json
{
  "schema": "ottto.upload_receipts.v1",
  "receipts": [
    {
      "uploaded_at": "2026-09-10T02:54:21Z",
      "outcome": "accepted",
      "http_status": 200,
      "server_request_id": "req-server-01HX",
      "retry_after_seconds": null,
      "source": "codex",
      "device_label": "Test Mac",
      "account_binding": "connected",
      "batch_item_count": 1,
      "accepted_count": 1,
      "accepted_entities": [
        {
          "source_session_id_hash": "7d96706e12ab",
          "snapshot_fingerprint_prefix": "abcdef012345",
          "occurrence_count": 1
        }
      ],
      "unchanged_entities": [],
      "conflict_entities": [],
      "rejected_entities": []
    }
  ],
  "ring_capacity": 500,
  "state_path_present": true
}
```

The private, owner-only receipt file may additionally retain content-free
request-specific ACK evidence after the existing validator succeeds. This
annotation contains full semantic fingerprints and body-witness hashes,
one-way session/destination identifiers, hashed head references, occurrence
counts, uploaded cache-patch presence, two numeric usage scalars and explicit
retained-coverage limits. It shares the existing ring's 500-receipt and 4 MiB limits and retains at most 50 entity records per receipt.
It is excluded from public receipt output, local-control responses and
diagnostics bundles. Raw head tokens, session ids, request bodies and
credentials are not retained.

An HTTP success receipt alone does not prove that a request-specific ACK
validated. Even a validated ACK does not prove that local checkpoint saving,
backend publication or customer-page freshness completed. Legacy count-only
responses and missing or truncated proof remain explicitly unproved; private
evidence is diagnostic and never authorizes delivery or a retry.

## Provider Requests

The daemon keeps a local log of every call it makes to OpenAI and Anthropic:
quota reads, sign-in and login-refresh runs of the provider CLIs, Codex cloud
task listing, Codex daily usage totals, and Verify smoke prompts. Use it to
count those calls per day and see why they ran:

```bash
ottto provider-requests
ottto provider-requests --json --since 24h
```

Each call is one JSON line in `provider-calls/YYYY-MM-DD.jsonl` (UTC day) in
the Ottto support directory, readable only by the user:

```json
{"v":1,"at":"2026-10-15T12:00:00Z","provider":"openai","kind":"codex_app_server_quota","trigger":"schedule","account":"01234567","result":"ok","duration_ms":1250,"basis":"subprocess_lower_bound","requests_at_least":2}
```

- `provider` is `openai`, `anthropic`, or `unknown` for a model request whose
  provider the daemon cannot tell (the Pi smoke prompt on Pi's default route).
- `trigger` is `schedule`, `explicit_refresh`, `older_app_compat`, `setup`,
  `startup` or `other`. A person's Verify is `setup`; the first status pass
  after the daemon starts is `startup`, and the first pass after the Mac wakes
  is `schedule`.
- `account` is the first 8 hex characters of the account identifier hash, or
  `unknown`.
- `result` is `ok`, `http_<status>`, `timeout`, `exit_<code>` or a short
  error class.
- `basis` is `observed` for an HTTP request the daemon made itself (one
  request), or `subprocess_lower_bound` for a provider CLI run, which makes at
  least `requests_at_least` requests the daemon cannot see. Requests count
  when sent, answered or not; `result` shows how the call ended. A Codex quota
  read through `codex app-server` that started counts two (a token refresh and
  a rate-limits read), or three with the detailed read, even when it fails or
  times out. A sign-in counts one once a code was submitted.

Lines never contain tokens, URLs, prompts, emails or provider responses. Days
older than 7 are deleted. A day holds at most 30,000 lines and 8 MiB, and the
directory at most 32 MiB; a day that reaches its bound ends with one
`log_full` line and the summary marks it. Logging is best effort: it never
fails a provider call, and a line it cannot write promptly is dropped.

## Common Diagnostics Flow

```bash
ottto status --json
ottto receipts --json --limit 20
ottto doctor --json
ottto diagnostics collect --json
```

If support requests an upload, rerun with the upload flags after the user has
approved the disclosure.
