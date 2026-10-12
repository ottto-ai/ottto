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
  (state `provider_unavailable` with `codex_usage_probe_failed`), and the
  slot's Codex home was last validated as that same binding, the placeholder
  carries that reading:
  - every window and balance is marked `freshness: stale`;
  - values and read clocks (`observed_at`, `grants_observed_at`, grants) are
    the original reading's, never re-stamped;
  - a reading older than 6 hours (`LAST_KNOWN_MAX_AGE_SECS`) is not sent, and
    the placeholder stays meterless as before.
- Unchanged: the placeholder's identity (registered hashes, unknown login
  state), status (`degraded`), collection method, capabilities, diagnostics
  and slot state. A sign-out, identity mismatch, unknown identity or an answer
  without usable meters carries nothing.
- No carry-forward across accounts: a reading is keyed by its binding, and a
  home whose last validated binding is another account gets nothing. Nothing is
  persisted; after a daemon restart a failure before any success sends the
  placeholder as before.
- The stale marking is one helper, `mark_quota_meters_stale`, now also used by
  the Claude path (no Claude behavior change).

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

Cadence, probe parallelism, retries, the 20-second deadline and health labels
(`codex_registered_slot_needs_attention*`) are unchanged.

## Tests

Synthetic, no provider calls:

- a fresh reading, then a failed probe for the same binding: the placeholder
  carries the reading with only freshness changed, and keeps its identity,
  status and diagnostics;
- a reading past the 6-hour cap: the placeholder is meterless as before; at
  the cap it is still sent;
- a different account: a home last read as another account, and a home that
  switched accounts after a reading, carry nothing;
- a sign-out, an answer without a failed probe, and a reading that was not
  fresh carry nothing;
- the store: stale marking, the cap, binding isolation, replacement and the
  64-binding eviction;
- the log line format and the stage and kind of every producer message.
