# Last-known Codex meters for a failed probe

When a Codex home's app-server probe failed (spawn error, JSON-RPC error, or
the 20-second deadline, for example before `initialize` was answered on a
heavily loaded machine), the home had no reading. Its registered account was
then uploaded as the `codex_configured_account_unavailable` placeholder with no
windows and no balances. One failed poll replaced the account's last good
meters until the next successful read. Claude slots already keep their last
reading, marked stale (`stale_local_claude_quota_snapshot`).

## Change

- `agent_status::codex_last_known` keeps, in memory, the last fresh and bound
  reading of each Codex account binding (account and workspace hashes, the
  same key as the reset-grant cache): its `quota_windows` and
  `credit_balances`, recorded when the slot's collection state is `fresh`.
- When a registered slot's placeholder is built because its probe failed
  (`codex_usage_probe_failed`, with the slot `identity_unknown` or
  `provider_unavailable`; a signed-in home has no identity hashes without a
  reading), and the slot's Codex home was last validated as that same binding,
  the placeholder carries that reading:
  - every window and balance is marked `freshness: stale`;
  - values and read clocks (`observed_at`, `grants_observed_at`, grants) are
    the original reading's, never re-stamped;
  - a reading older than 6 hours (`LAST_KNOWN_MAX_AGE_SECS`) is not sent, and
    the placeholder stays meterless as before.
- Unchanged: the placeholder's identity (registered hashes, unknown login
  state), status (`degraded`), collection method, capabilities, diagnostics
  and slot state. A sign-out, identity mismatch, or an answer without a failed
  probe carries nothing.
- No carry-forward across accounts: a reading is keyed by its binding, and a
  home whose last validated binding is another account gets nothing. Nothing is
  persisted; after a daemon restart a failure before any success sends the
  placeholder as before.
- The stale marking is one helper, `mark_quota_meters_stale`, now also used by
  the Claude path (no Claude behavior change).

## Default home

A failed probe on the default Codex home (no registered binding) used to send
`status: available` with `codex_usage_probe_failed`, no identity hashes and no
meters. Now:

- the snapshot is `degraded`; `codex_usage_probe_failed` stays the stable code;
- it keeps the account and workspace hashes of the binding last validated at
  that home, but only while the home's current local credential still names
  the same account and workspace (decoded as a consistency check, never as
  authentication); otherwise it has no hashes, as before;
- with kept hashes it carries that binding's last reading, marked stale, under
  the same 6-hour cap;
- the slot's binding stays empty: kept hashes never become transcript or
  live-meter authority.

A missing `codex` executable is not a transient failure: the snapshot keeps
its previous status and labels.

## Health

A failed usage probe (other than a missing executable) is no longer a durable
connection that "needs attention", which the local status reported as
`secret_expired`. The Codex source health then carries
`codex_usage_read_retrying` and is shown as healthy with a warning: "Codex
usage check failed; retrying". A sign-out, identity mismatch or other real
connection problem still raises `codex_registered_slot_needs_attention*` as
before; a default home whose only problem is a failed probe still counts as a
working current login there.

This updates the 2026-09-30 note on configured subscription availability: a
placeholder may now carry its own binding's last reading, marked stale. It
still never carries live meters, labels or another identity's data.

The cap is shorter than Claude's 24-hour display fallback because a Codex
reading's primary window is five hours.

## Probe failure log line

Each failed app-server probe now logs one line to the service log:

```
codex usage probe failed: at=<RFC 3339 UTC> stage=<initialize|account|quota|start|session> kind=<timeout|rpc_error|stdout_closed|read_failed|output_bound|start|request_failed|other> home=<12 hex> elapsed_ms=<n>
```

`stage` and `kind` come from the fixed producer text; `home` is a salted
SHA-256 digest of the Codex home path. No path, account or provider text is
logged.

## Not changed

Cadence, probe parallelism, retries and the 20-second deadline are unchanged.

## Tests

Synthetic, no provider calls. They run in CI; local test runs were paused on
the development machine for load.

- a fresh reading, then a failed probe for the same binding: the placeholder
  carries the reading with only freshness changed, and keeps its identity,
  status and diagnostics;
- a reading past the 6-hour cap: the placeholder is meterless as before; at
  the cap it is still sent;
- a different account: a home last read as another account, and a home that
  switched accounts after a reading, carry nothing;
- a sign-out, an answer without a failed probe, and a reading that was not
  fresh carry nothing;
- through the synthetic collector: a managed slot whose app-server ends
  before `initialize` is `identity_unknown` and its placeholder carries the
  stale reading; a default home in the same case is `degraded`, keeps its
  validated hashes and carries the stale reading, and after its credential
  names another account keeps no hashes and carries nothing;
- health: a failed probe gives `codex_usage_read_retrying` (healthy with a
  warning, problem code `unknown`), never `needs attention`; a real sign-out
  next to a failed default probe still needs attention with the current login
  available; a missing executable is not transient;
- the store: stale marking, the cap, binding isolation, replacement and the
  64-binding eviction;
- the log line format and the stage and kind of every producer message.
