# ChatGPT workspace monthly credits

Codex app-server `account/rateLimits/read` exposes two distinct continuation
signals: flexible `credits` and a recurring workspace `individualLimit`.
`agent_status.rs` previously parsed only the former, so a Team plan whose weekly
window was exhausted appeared to have no remaining capacity even when the
workspace monthly pool was active.

The app-server and legacy `wham/usage` parsers now normalize
`individualLimit`/`individual_limit` into one display-safe credit balance:

- name: `workspace_monthly_credits`
- unit: `credits`
- used, quota, remaining, used percent, and reset timestamp
- safe spend-control, reached-limit, and limit-id metadata when present

This remains separate from flexible/purchased `credits`; downstream serving can
therefore render both without guessing provider semantics from the weekly
window. A snapshot containing only `individualLimit` now counts as usable rate
limit data, preventing the app-server selector from discarding it.

No raw provider response or credential is emitted. The existing setup-gated
status collector and upload boundary are unchanged.

`/backend-api/wham/analytics/daily-workspace-usage-counts` also required no new
implementation: it is already collected by `provider_daily_reference.rs` behind
its separate explicit, versioned provider-daily-reference consent and grant
flow. Keeping it there preserves the stricter account exclusion, bounded-day,
normalization, and upload policy instead of broadening routine quota status.

Focused Rust tests cover app-server parsing, snake-case legacy parsing, and a
monthly-only app-server snapshot.
