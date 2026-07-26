# Session: Codex daily aggregates collector

**Date:** 2026-07-27 · **Change:**
`crates/ottto-service/src/provider_daily_reference.rs` (new),
`crates/ottto-service/src/snapshot_client.rs`,
`crates/ottto-service/src/agent_status.rs`, `lib.rs`, `main.rs`

The daemon half of "PR F" in the recorded provider-endpoints plan (product
repo, `docs/efforts/cloud-sessions-provider-endpoints-implementation-handoff.md`
§4.F), approved by the owner on 2026-07-26. The backend contract, storage, and
reconciliation read API landed first; this conforms to that contract exactly.

The framing is fixed: **verify Ottto against your provider's own numbers**. It
is an accuracy and self-audit capability, not cloud sessions and not
community-led. Ottto's modeled Codex cost does not track real consumption -
dollars per credit swung 19x across six days of modeled data and session count
came in 43% under the provider's own thread count - so a
`ottto computed | provider reported | delta` surface is the checkable answer.

## What it does

With a live versioned disclosure grant, the collector reads
`GET chatgpt.com/backend-api/wham/analytics/daily-workspace-usage-counts` with
the customer's own already-issued Codex credential, normalizes the answer
locally into `provider_daily_reference.v1` scalars, and posts them to
`POST /api/v1/provider-daily-reference/batches` over the existing relay-device
channel. The credential and the raw response body never leave the machine.

It ships **fully dark**, and that is the intended state.
`PROVIDER_DAILY_REFERENCE_ADMITTED_COLLECTOR_VERSIONS` is an empty code
constant on the server, so no build can upload until a separate reviewed
backend change admits its version. A client cannot self-approve a release.

## Wire conformance

The batch envelope emits exactly `schema_version` (`provider_daily_reference.v1`),
`source` (`codex`), `collector_id` (`provider_daily_reference`),
`collector_version` (`compiled_release_version()`), `installation_id` (the relay
device UUID), `grant_scope_fingerprint`, `account_fingerprint`, `grant_version`,
`provider_day_timezone` (`UTC`), `coverage_start`, `coverage_end`,
`collected_at`, `provider_data_refreshed_at`, `rows`.

Each row is one `(provider_day, surface, model)` grain carrying `credits_used`,
`uncached_input_tokens`, `cached_input_tokens`, `output_tokens`, `total_tokens`,
`thread_count`, `turn_count`.

Two contract rules that shape the code more than they look:

- **`null` is not `0`.** Every counter is `Option` and an absent one is omitted
  from the payload rather than sent as zero. Collapsing the two would
  manufacture a reconciliation delta out of a counter the provider simply did
  not report. `absent_counters_stay_absent_and_reported_zeros_are_preserved`
  pins both directions on one row that reports a real zero and omits another
  counter entirely.
- **Per-model rows carry no credits.** The provider returns `0.0` for
  `models[].credits`, which is not an attribution. Model rows carry tokens,
  threads and turns; the surface row carries the metered credits.

## The `client_id` map

| Provider `client_id` | Surface |
| --- | --- |
| `CODEX_WEB` | `codex_web` |
| `CODEX_DESKTOP_APP` | `codex_desktop_app` |
| `CODEX_SERVICE_EXEC` | `codex_service_exec` |
| `CODEX_WORK_DESKTOP` | `codex_work_desktop` |
| `CODEX_UNKNOWN_DEFAULT` | `codex_unknown_default` |
| anything else | `other` |

Matching is case-insensitive and trimmed. The daemon never invents a surface
value. `CODEX_UNKNOWN_DEFAULT` keeps its own slot rather than folding into
`other`, because "the provider could not attribute this" and "Ottto has never
seen this client id" are different facts and only the second one should move
when the provider ships a new surface.

Because several unrecognized ids collapse onto `other`, their rows are merged
before upload - the contract rejects a duplicate grain, and a merge that
treated absent as zero would defeat the `null`-is-not-`0` rule, so the merge
carries `None` through untouched.

Model ids are lowercased and narrowed to the contract's
`^(__all__|[a-z0-9][a-z0-9._-]{0,63})$` slug. A value that cannot begin with an
alphanumeric is **dropped, not coerced**: the surface total already carries the
numbers, so nothing comparable is lost, and inventing a slug would publish a
fabricated identifier. Dropped rows are counted and reported.

## Gating: five layers, all before a socket opens

1. **Sentinel** `<support>/codex-daily-aggregates-disabled`. Present means the
   endpoint is never contacted and the local cadence state is retired, with an
   info diagnostic saying so. Same directory mechanics as the Claude OAuth
   usage sentinel, and a fixed contract with the Companion toggle.
2. **Live consent** at the current epoch: status `enabled`, backend binding
   present, not server-revoked, and `server_policy_state == approved`. The
   policy enum defaults to `disabled`, so a binding written before the field
   existed can never read as approval.
3. **Consent is per build.** The server states the admitted `collector_version`
   and the daemon refuses to collect unless it equals its own release. A daemon
   upgrade therefore requires re-consent rather than silently inheriting it.
4. **Identity proof.** The live relay device id and the live Codex account id
   are hashed under the grant's own key and compared to the recorded
   fingerprints. Consent taken over account A can never upload account B's
   numbers under A's fingerprint.
5. **Circuit breaker, then cadence.**

Absent consent is the silent case - no diagnostic, no warning, and exactly one
local file read. Nothing below it (account, device, connection, destination
URL, credential, keychain) is touched.

The grant file persists fingerprints only. The raw installation id, the tenant
scopes and the provider account id are hashed under a per-installation random
32-byte HMAC key and never written to disk.

## Cadence

Day-grain data does not reward frequent polling. The gate is 6 h with a
deterministic ±15 min spread derived from the grant identity, giving a
5 h 45 m - 6 h 15 m band and roughly four reads per machine per day. The spread
is load-spreading across our own installs, not evasion: it is stable per
machine rather than redrawn per tick, and the request carries
`ottto/<version> (subscription-usage-reader; +https://ottto.net)` - the same
honest User-Agent as the Claude OAuth read, now shared from `agent_status.rs`
so one identity change moves both.

The supervisor ticks every 30 min and every tick is inert until all five gates
pass, so a grant created after boot activates without a daemon restart.

## Circuit breaker

Per-grant-epoch state next to the grant, keyed by the account and scope
fingerprints, the backend grant epoch, the endpoint, the User-Agent, and the
sentinel state. Three classes accumulate separately:

| Class | Trigger | Consecutive failures to open |
| --- | --- | --- |
| `auth_rejected` | 401/403 | 3 |
| `response_shape_changed` | unreadable body, no recognizable provider day, 400/404/410 | 3 |
| `rate_limited` | 429 | 5 |

Opening sets a 24 h cool-down, during which no request is made at all. It
resets on cool-down, on one clean answer, and on any change to the identity
above. Transport errors and 5xx are never counted - they say the network or the
vendor had a bad moment, not that we should stop asking.

An unreadable payload is deliberately a **shape failure, not an empty day**.
Uploading "no usage" for a payload we stopped understanding would read as the
customer having stopped working.

This is a parallel implementation of the PR #290 breaker rather than a shared
one: the Claude breaker is bound to that path's constants, file, account hash,
and diagnostics, and factoring it out would have meant refactoring a shipped
9k-line collector for no behavioural gain.

## Fail-closed admission

The expected steady state today is a `403` from our own backend, because no
collector version is admitted yet. That answer is typed
(`ProviderDailyReferenceUploadRejected`, distinct from a contract rejection),
reported at **info** severity as
`codex_daily_aggregates_collector_not_admitted`, and **never counted against
the circuit breaker** - the provider read succeeded, so treating the refusal as
a provider fault would eventually stop a healthy collector. A test drives five
consecutive refusals and asserts every failure counter is still zero.

A `409` is a stale consent epoch, which only re-consent can fix, so the cycle
stops instead of retrying.

## Windows and batching

`coverage_end` is the last **complete** UTC day - today is still accumulating,
and uploading it would publish a number that is knowably short. The lookback is
120 days, matching the provider's own retention and inside the contract's
200-day bound.

Rows are packed into contract-legal batches (≤1000 rows, ≤200 days), days are
never split, and batches go oldest first so each abuts the previous and the
backend's coverage envelope grows contiguously without ever being credited with
days it did not observe. An idle window still uploads an empty batch declaring
its coverage: a genuinely idle account is complete, not missing, and the
backend distinguishes the two. A single day that alone exceeds the row bound is
refused rather than truncated - a silently partial day is a manufactured delta.

## Content safety

`wire_payload_is_content_free` is the daemon-side counterpart to the backend's
must-not-persist key pinning. The backend proves no unexpected *key* can reach
storage; this proves no unexpected *value* can leave the machine. Every string
in an outgoing batch must be a fixed literal, an `hmac-sha256:` fingerprint, a
UUID, an ISO day, an RFC 3339 timestamp, a closed surface value, a bounded model
slug, or a decimal. It runs on every batch before upload, not only in tests.

`no_provider_free_text_survives_into_the_uploaded_batch` drives a provider
payload deliberately dense with workspace and client labels, a thread title, a
repository path, a prompt, and a raw account id, and asserts none of it appears
in the serialized batch. A companion test injects free text at every nesting
level and asserts the check rejects each one.

`the_capability_reaches_exactly_one_provider_route` scans this module's own
production source, comments stripped, for `wham/tasks`, `teleport-events`,
`/v1/sessions`, and `claude_code_shared_session_transcripts`. Content endpoints
are permanently out of scope for this capability, and the guard fails the build
rather than relying on review to notice.

## Tests

44 unit tests in `provider_daily_reference.rs`, all parallel-safe: every store
takes an explicit path and no test mutates process environment. Coverage:
the closed surface map and slug bounds; the must-not-persist proof and the
injected-free-text rejections; `null` versus `0`; per-model credits omission;
unknown-id merging and grain uniqueness; window and day-span arithmetic across
month, leap-year and year boundaries; batch packing bounds, contiguity and the
refusal case; consent lifecycle, epoch advancement, response mismatch, and
revoked-grant health; each gate proven with a reader and a transport that panic
if contacted; the cadence band and its stability; each breaker class at its own
threshold, class isolation, transient exemption, scoping and cool-down; the
not-admitted and epoch-conflict upload answers; the credential's account scope
surviving a token rotation; and the honest User-Agent.

`cargo test --workspace` is green (1016 service tests), as is the connector
workspace, `cargo fmt --all --check`, and
`cargo clippy --workspace --all-targets -- -D warnings`.

## Deliberately not in this change

- **The consent surface.** `enable`, `grant_create_request` and
  `bind_backend_grant` are public and tested, but nothing calls them yet: the
  control-socket and Companion disclosure UI are the next lane's work. Until
  then no grant can exist, which is the correct posture for an unadmitted
  collector.
- **A new backend telemetry path for diagnostics.** Cycle diagnostics are typed
  `AgentStatusDiagnostic` values, recorded in local grant health and logged, so
  wiring them to the snapshot later is mechanical. The backend already learns
  liveness and coverage from the batch itself.
- **The reconciliation view.** Frontend lane.
- Claude collectors, the statusLine path, and the Claude Desktop cookie
  collector are untouched.
