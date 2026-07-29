# Session: cadence, circuit breaker, and off-switch on the Claude OAuth usage read

**Date:** 2026-07-26 · **Change:** `crates/ottto-service/src/agent_status.rs`

Second half of the governance work on `GET api.anthropic.com/api/oauth/usage`,
after the honest User-Agent. The recorded provider-endpoints posture (product
repo, `docs/efforts/cloud-sessions-provider-endpoints-implementation-handoff.md`
§2) is: identify honestly, poll sparsely, circuit-break instead of adapting,
prefer sanctioned local surfaces. The User-Agent covered the first; this covers
the rest.

## Cadence: ~15 minutes to ~60

`CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS` went from `15 * 60` to `60 * 60`,
taking the measured cadence from ~96 fetches/day/machine to ~24. A deterministic
spread of +/- 5 minutes (`..._JITTER_SECONDS`) puts the effective gate in the
55-65 minute band.

The spread is load-spreading across our own installs - it stops every Ottto
machine from refreshing on the same wall-clock minute. It is not evasion and
hides nothing: the request carries
`ottto/<version> (subscription-usage-reader; +https://ottto.net)`, and a
timer-driven daemon is identifiable from its behaviour regardless of phase.

`claude_oauth_usage_fresh_age_seconds(seed)` derives the offset from a SHA-256
of the account identifier hash rather than a random draw, so a machine holds one
steady phase instead of jittering around every refresh. The same function backs
the `Fresh`/`Stale` label in `claude_oauth_usage_from_cache`, seeded from the
account the cache belongs to, so a payload served as fresh is never labelled
stale.

`CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS` (24 h) is unchanged and remains a
display fallback only. Account-keying of the cache (schema v3) is untouched.

## Circuit breaker

New persisted state, `<support>/claude-oauth-usage-breaker.json`
(`ClaudeOAuthUsageBreaker`), keyed by the same account hash as the usage cache
*and* by a fingerprint of the call's own configuration (endpoint, beta header,
User-Agent, sentinel state). Three failure classes accumulate separately:

| Class | Trigger | Consecutive failures to open |
| --- | --- | --- |
| `auth_rejected` | 401/403 (incl. OAuth scope errors) | 3 |
| `response_shape_changed` | unreadable 200 body, 200 with none of the expected quota fields, or 404/410 | 3 |
| `rate_limited` | 429 that outlives the retry-after backoff | 5 |

Transport errors and 5xx deliberately do not count: they say the user's network
or the vendor's servers had a bad moment, not that we should stop asking.

Opening sets a 24 h cool-down. While open the collector returns before the token
read and the request - no network call at all - and quota falls back to Claude
Code's own local statusLine surface. The breaker resets on cool-down expiry, on
one clean answer (`clear_claude_oauth_usage_breaker` on a successful parse:
the thresholds are about *consecutive* failures), on an account switch, and on
any configuration change.

The single-429 retry-after path is unchanged; the breaker only fires once 429s
outlive it.

## Alert path

Opening emits one `claude_oauth_usage_circuit_open` diagnostic
(`AgentDiagnosticSeverity::Warning`) on the transition, and re-emits it on each
later tick that skips the call while open. Diagnostics reach the backend by
riding the agent-status snapshot: `collect_claude_oauth_usage` now returns a
`ClaudeOAuthUsageOutcome` (result + diagnostics), the collector pushes them onto
`snapshot.diagnostics`, and `AgentStatusSnapshot::redacted_for_backend`
(`ottto-protocol`) maps diagnostics through `redact_diagnostic_for_backend`,
which preserves `code` and `message` and only strips the Companion-local
`account_label`/`scope`. That redacted snapshot is what
`snapshot_sync::upload_agent_status_snapshots` posts. A unit test pins the round
trip. No new telemetry channel.

## Off-switch sentinel

`<support>/claude-oauth-usage-network-disabled`, resolved through
`default_support_dir()`.
Present means the endpoint is never contacted; quota comes from statusLine only,
and an info diagnostic `claude_oauth_usage_network_disabled` says so. The check
runs ahead of the cache and the cached payload is removed from disk, because the
switch turns the data path off rather than just the socket. Absent (the default)
is unchanged behaviour. The filename is a fixed contract with the macOS
Companion toggle being built in a parallel lane.

## Tests

Ten unit tests in `agent_status.rs`: the jittered gate stays inside 55-65
minutes and is stable per account; each failure class opens at its own
threshold; classes do not pool; the cool-down closes it; breaker state is
account- and config-scoped and clearable; the alert fires once on the
transition and the open breaker short-circuits `collect_claude_oauth_usage`
before any network work; 5xx and transport errors are not counted; the sentinel
disables the read, emits its diagnostic, and retires the cache; both new
diagnostics survive `redacted_for_backend` intact.

## Deliberately unchanged

The honest User-Agent, the account-keying of the usage cache and statusLine
cache, and the statusLine-vs-network preference order (promoting statusLine to
default is a separate, deferred change).
