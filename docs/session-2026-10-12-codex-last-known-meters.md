# Codex failed usage probes: failure-only uploads, local last-known meters

When a Codex home's app-server probe failed (spawn error, JSON-RPC error, or
the 20-second deadline, for example before `initialize` was answered on a
heavily loaded machine), the home had no reading. Three things were wrong:

- the local status showed no meters for the account until the next successful
  read;
- a default home was uploaded as `status: available` with
  `codex_usage_probe_failed` and no identity hashes;
- the local source health said durable connections "need attention"
  (`secret_expired`) for a transient read failure.

## Who carries the last good reading

The server owns carry-forward: on a failed read it keeps its own last good
reading and clocks. The daemon therefore uploads a failed probe as a failure
only. The daemon's own last-known reading is for local display (the Mac app and
the CLI status) and is never uploaded.

## Upload shape of a failed probe

- Registered (managed) slot: the `codex_configured_account_unavailable`
  placeholder, unchanged: registered hashes, `degraded`, no windows, no
  balances.
- Default home: `degraded` (was `available`), with `codex_usage_probe_failed`
  as the stable code. It keeps the account and workspace hashes of the binding
  last validated at that home, but only while the home's current local
  credential still names the same account and workspace; otherwise it has no
  hashes, as before. With kept hashes the row is uploaded even when other
  accounts' rows are in the batch (unless a row already represents that
  account); before, it was sent only when the batch was otherwise empty.
- `AgentStatusSnapshot::redacted_for_backend`, the upload copy, strips from
  every Codex snapshot carrying `codex_usage_probe_failed` or
  `codex_configured_account_unavailable`:
  - every window marked `stale` (the placeholder `unsupported` window, when
    present, stays) and every credit balance;
  - `plan_type`, `subscription_product`, the plan observations and the
    subscription period (`subscription_period_start`,
    `subscription_period_end`, `subscription_period_last_checked_at`): on a
    failed read these come from the local credential, not from the provider.
  `billing_channel` stays: it is the registered route of the account, part of
  the identity the server files the row under, not a plan fact.
- A missing `codex` executable is not a transient failure: the local snapshot
  keeps its previous status and labels. Its upload is still a failed read by
  code (`codex_usage_probe_failed`), so it loses the same plan words and
  period fields.

Kept hashes never become transcript, session-attribution or live-meter
authority: the slot's binding stays empty and the account is marked low
confidence, which the current-login fallback of session attribution rejects.

## Local last-known reading

`agent_status::codex_last_known` keeps, in memory, the last fresh and bound
reading of each Codex account binding (account and workspace hashes, the same
key as the reset-grant cache). When a probe fails (`codex_usage_probe_failed`,
slot `identity_unknown` or `provider_unavailable`; a signed-in home has no
identity hashes without a reading):

- a registered slot's local status (`quota_snapshot`) shows that reading;
- the default home's local snapshot shows it, with the kept hashes.

The registered slot's `quota_snapshot.captured_at` is the time of the failed
poll; the time of the reading is each meter's own `observed_at`.

In both cases every window and balance is marked `freshness: stale`; values and
read clocks (`observed_at`, `grants_observed_at`, grants) are the original
reading's, never re-stamped. A reading older than 6 hours
(`LAST_KNOWN_MAX_AGE_SECS`) is not shown; Claude's display fallback is 24
hours, but a Codex reading's primary window is five hours.

One guard decides both paths (`codex_home_kept_binding`): the home was last
validated as that binding, and its current local credential still names the
same account and workspace. So a sign-out, or a re-login to another account
that was never validated, shows nothing. The credential's claim is read by a
binding-only helper (`codex_credential_claimed_binding`): it returns a key to
compare, never an identity, and takes no provider-authentication flag.
`validated_codex_identity` uses the same claim reading after its own
authentication check.

Limits:

- the claim needs unexpired local tokens. The app-server normally refreshes
  them during the same session that is failing, so in a long outage the
  default row can lose its hashes, and both paths their local reading, before
  the 6-hour cap. That is the conservative side;
- nothing is persisted: after a daemon restart a failure before any success
  shows nothing.

The stale marking is one helper, `mark_quota_meters_stale`, also used by the
Claude path (no Claude behavior change).

This updates the 2026-09-30 note on configured subscription availability only
for the local status. An uploaded placeholder still carries no meters, labels
or another identity's data.

## Health

A failed usage probe (other than a missing executable) is no longer a durable
connection that "needs attention", which the local status reported as
`secret_expired`. The Codex source health then carries
`codex_usage_read_retrying` and is shown as healthy with a warning: "Codex
usage check failed; retrying". A sign-out, identity mismatch or other real
connection problem still raises `codex_registered_slot_needs_attention*` as
before; a signed-in default home whose only problem is a failed probe still
counts as a working current login there. A signed-out or unconfirmed default
login keeps its own status and is never reported as a retrying read.

## Probe failure log line

Each failed app-server probe logs one line to the service log:

```
codex usage probe failed: at=<RFC 3339 UTC> stage=<initialize|account|quota|start|session> kind=<timeout|rpc_error|stdout_closed|read_failed|output_bound|start|request_failed|other> home=<12 hex> elapsed_ms=<n>
```

`stage` and `kind` come from the fixed producer text; `home` is a
domain-tagged SHA-256 digest of the Codex home path, cut to 12 hex. No path,
account or provider text is logged.

## Not changed, and follow-ups

Cadence, probe parallelism, retries and the 20-second deadline are unchanged.
Open follow-ups, for a separate decision:

- a repeated-failure threshold: a probe that keeps failing for a non-transient
  reason (the app-server cannot be started, a permanent RPC error) is reported
  as "retrying" with no escalation today;
- capping or staggering the parallel home probes, and retrying a timed-out
  `initialize` once.

## Tests

Synthetic, no provider calls.

- upload: a failed Codex snapshot with stale meters and plan words is uploaded
  with no stale window, no balance, no plan word, no plan observation and no
  subscription period, with its hashes, billing channel, status and failure
  code; a successful reading is uploaded as
  read; a failed-probe placeholder is meterless even when its binding has a
  recent reading;
- through the synthetic collector, a managed slot whose app-server ends before
  `initialize`: `identity_unknown`, its local status shows the stale reading
  with the original clocks, nothing past the cap, the uploaded placeholder has
  no meters; after its credential names another account, or is removed,
  nothing is shown;
- through the synthetic collector, a default home in the same case: `degraded`,
  validated hashes kept, stale reading local only, upload without meters or
  plan words; after its credential names another account, no hashes and
  nothing shown;
- the credential claim: equals the validated binding, is absent for an
  inconsistent credential, and an identity still needs provider
  authentication;
- a slot with no readable credential shows no reading;
- health: a failed probe gives `codex_usage_read_retrying` (healthy with a
  warning, problem code `unknown`), never `needs attention`; a real sign-out
  next to a failed default probe still needs attention with the current login
  available; signed-out and unconfirmed defaults are not hidden behind a
  retrying read; a missing executable is not transient;
- upload batch: a failed default with kept hashes is uploaded beside another
  account's row, not twice for the same account, and not without kept hashes;
- the store: stale marking, the cap, binding isolation, replacement and the
  64-binding eviction;
- the log line format and the stage and kind of every producer message.
