# Session 2026-10-03: `ottto apps` reflects paused Claude usage checks

## Problem

A connected Claude account had its usage checks paused after the provider
rejected its sign-in: its OAuth usage breaker was open, its managed slot was
`provider_unavailable`, and its readings were stale. The web showed "Checks
paused after sign-in rejection". `ottto apps --json` still reported the Claude
Code source as `state=healthy`, `grade=ok`, `problems=[]`, with
`agent_status.status=available`. The pause was visible only in diagnostics, so
the app and the web disagreed.

## What changed

`crates/ottto-service/src/agent_status.rs`:

- `claude_paused_usage_accounts` finds connected accounts whose usage checks
  are paused. An account counts when no slot for it is `fresh`, and a
  non-duplicate slot for it is either held back after a sign-in rejection
  (`claude_oauth_usage_auth_rejected`, `claude_oauth_usage_auth_backoff`, or an
  auth-flavoured `claude_oauth_usage_circuit_open`, on the slot or on the
  default login) or `provider_unavailable` with stale readings. Slot states
  that already raise the registered-slot attention path (for example
  `needs_login`) are left to that path, so an account is not reported twice.
- Review follow-up (AutoReview 01a10090): `fresh` alone is not proof that an
  account is served. The default login marks account-attributed status-line
  fallback readings `fresh`, and a held slot can look `fresh` while the shared
  cache is young. A slot now serves its account only when it is `fresh`
  through an eligible provider caller: no live hold for that caller, no open
  account-wide auth breaker, and no sign-in-rejection or breaker-suppression
  evidence on the slot. An eligible caller reusing its own young cache still
  serves, because it asks the provider on its normal cadence.
- The next automatic check comes from the account's breaker: the account-wide
  auth cool-down when it is open, otherwise the earliest live per-caller hold
  from #475. The breaker is read only, never written or reset.
- When any account is paused, the machine-local source-health copy gets one
  warning diagnostic `claude_usage_checks_paused`, for example: "Claude usage
  checks paused for one account after the provider rejected sign-in; next
  automatic check 2026-10-04T05:00:00Z. Last readings stay shown until then."
  The wording names accounts only, asks for no sign-in, and avoids the words
  that consumers read as a used-up plan ("quota", "limit"). The snapshots that
  are uploaded to the backend are unchanged, and `agent_status.status` stays
  `available` because the current login works.

`crates/ottto-service/src/lib.rs`:

- `source_health_from_agent_status` turns that diagnostic into
  `grade=warning` with one problem titled "Claude usage checks paused" (detail
  = the diagnostic text, `retryable=false`, no recommended action). The
  source state stays `healthy`.
- Canonical local health carries `blocking_reason=usage_checks_paused` and the
  detail as `clear_condition` on the still-`healthy` source. It adds no machine
  blocker, so overall health and the menubar header are unchanged.

`docs/claude-accounts.md` describes the behaviour.

## Compatibility

- No protocol enum changes. The problem uses the existing
  `StableProblemCode::Unknown` (`"unknown"` on the wire) and the existing
  `HealthGrade::Warning`, so older `ottto` CLIs, which decode
  `StableProblemCode` strictly, keep decoding the status. The Companion
  decodes `HealthProblem.code` as a string and `HealthGrade` strictly; both
  values are already known to it.
- `blocking_reason` is a free string in the canonical health contract. The
  backend reads it only for non-healthy sources, so a healthy source with this
  reason changes nothing there.
- No change to how often Ottto calls the provider, to breakers, holds, or
  upkeep.

## Tests and gates

- New unit tests in `agent_status.rs` (`usage_checks_paused_tests`): a paused
  account gets the plain-words diagnostic with the next check time; healthy
  accounts report nothing; an account still served by a fresh slot is not
  paused; duplicate slots and actionable states are skipped;
  `provider_unavailable` with stale readings counts without auth evidence (and
  not before the readings are stale); per-caller holds give the earliest next
  check; a default-login auth pause is attributed to its account, a
  response-shape circuit is not; several accounts are counted. Review follow-up tests: fallback-only `fresh`
  default with an open auth breaker is paused; a young shared cache on a held
  slot is paused (and serves again once the hold expires); a genuinely serving
  second credential keeps the account unpaused. The first two fail on
  ec93133f; the third passes there too and guards against over-reporting.
- New tests in `lib.rs`: a paused account gives the Claude Code source
  `healthy` + `warning` + one `unknown`-coded problem, canonical
  `blocking_reason=usage_checks_paused`, and no extra machine blocker; without
  the diagnostic the source stays `ok` with no problems; the diagnostic is
  ignored for other sources.
- Gates: `cargo test -p ottto-service`, `cargo clippy --workspace
  --all-targets --locked -- -D warnings`, `cargo fmt --all --check`, and the
  public repo manifest, export, contract, secret-scan and skeleton checks.
  Tests ran with a throwaway HOME and support dir and no agent CLIs on PATH.
