# Session 2026-10-03: one usage caller per Claude account, per-caller auth backoff

## Problem

One Claude account can be both the default `~/.claude` login and a registered
managed slot. Each collection pass then read the Claude OAuth usage endpoint
for that account with two different access tokens: the default login's token
(which Claude Code rotates on its own schedule) and the slot's token. Both
shared one per-account cache and one breaker. Three things went wrong:

- 401/403 responses counted into one account-wide streak, so rejections of
  the default login's token could open the breaker for the slot's healthy
  token, and the reverse.
- A 401/403 set no backoff. A rejected token was sent again on every tick,
  twice per tick for the double-caller account, so three strikes arrived
  within about two ticks.
- The breaker file did not record which credential failed, the HTTP status,
  or when. An incident could not be attributed afterwards.

## What changed

`crates/ottto-service/src/agent_status.rs`, `claude_upkeep.rs`:

- **One caller per account.** Before the default login is collected, the
  daemon works out which exact account + organization bindings a registered
  managed slot owns (`claude_slot_owned_usage_bindings`). A slot qualifies
  only when all of these hold: it is Ottto-managed, inside this pass's
  collection bound, not provisional or suppressed; its last pass was the
  binding's canonical anchor and ended `fresh` or `relogin_approaching`; and
  its config directory's identity file still names the same account and
  organization now; and its own credential has no live auth hold (a held
  slot can look `fresh` while the shared cache is young, but would not
  refresh it). For a qualifying binding the default login becomes
  `DefaultDeferredToSlot`: it serves the shared per-account cache (fresh or
  stale within the 24-hour bound) and never sends its own token. If any proof
  is missing the default login keeps calling as before. The default snapshot
  carries an info diagnostic
  `claude_oauth_usage_deferred_to_registered_slot`.
- **Auth failures belong to the caller.** A 401/403 updates only the failing
  caller's entry in the breaker's new `auth_callers` map. The default login
  is `default`; a slot is `slot-sha256:<opaque hash>`, a domain-separated
  hash of its slot id, so the raw slot id is never written to disk (files
  holding a raw `slot:<id>` key are rewritten on read). Each entry holds the
  consecutive count, last HTTP status, last failure time,
  and a backoff deadline. The backoff is 15 minutes, then 30, then the full
  24-hour cool-down once that caller reaches the existing threshold of 3. A
  held caller makes no provider request and reports
  `claude_oauth_usage_auth_backoff` (or, at the threshold, the existing
  `claude_oauth_usage_circuit_open` alert with unchanged wording) plus
  `claude_oauth_usage_check_suppressed`. Other callers for the same account
  are not held. Each entry also keeps the rejected credential's access-expiry
  metadata, never the token. When the caller's current credential reports a
  different expiry, for example after Claude Code rotated the default
  login's token, the hold is released and the streak starts over. The
  account-wide breaker classes for response shape and
  sustained 429 are unchanged; the account-wide auth class is no longer
  opened by current daemons.
- **Attribution fields.** Every 401/403 also writes `last_auth_failure`
  (caller key, HTTP status, local time) and emits a warning diagnostic
  `claude_oauth_usage_auth_rejected` with the status and the time. Uploaded
  messages name only the credential kind ("default Claude Code login" or
  "registered account slot"); slot ids, paths, and tokens never appear.
  Registered-slot local status keeps the status code through a fixed safe
  message.
- **Success.** A clean answer resets the account-wide counters and the
  answering caller's auth state. Another caller's streak is kept, held or
  not, because that answer came from a different credential; it ends only
  on that caller's own success, its credential refresh or rotation, or 24
  hours after its last rejection. With nothing left, the files are removed
  as before.
- **Upkeep.** When consented upkeep refreshes a slot's credential,
  `clear_claude_oauth_usage_auth_breaker` now takes the slot id and retires
  that slot's auth state. An account-wide auth verdict written by an older
  daemon is cleared too, but only its auth fields; other callers' entries
  stay.

## Compatibility

- The breaker file keeps `schema_version` 1. `auth_callers` and
  `last_auth_failure` are additive, default to empty, and are omitted when
  empty, so files without attribution round-trip unchanged. Older daemons
  ignore the new fields (no `deny_unknown_fields`); a test parses the new file
  with the pre-change field set.
- Downgrade: an older daemon that rewrites the breaker file (on any failure
  or success it records) drops `auth_callers` and `last_auth_failure`,
  because it does not know them. Per-caller holds then restart from zero and
  the older daemon's own account-wide breaker applies. This is acceptable.
- An account-wide auth breaker opened by an older daemon is still honoured
  until its cool-down, a clean answer, or upkeep clears it.
- New diagnostic codes are additive. Consumers that switch on codes ignore
  unknown ones; the circuit-open alert text is the same as before.

## Tests

Unit tests in `agent_status.rs` cover: per-caller streaks and backoff, the
bounded backoff schedule and stale-streak reset, a held caller making no
provider call, the one-time threshold alert with the existing wording,
success from one caller keeping another caller's hold, upkeep clearing only
the refreshed slot, the deferred default serving the shared cache without a
provider call, every proof the deferral requires, breaker file compatibility
in both directions, safe slot diagnostics keeping the HTTP status, and the new
diagnostics surviving backend upload redaction. Review follow-ups add tests
for: another caller's success keeping an expired-hold streak, a legacy auth
verdict clear keeping other callers' holds, opaque caller keys and raw-key
migration, no deferral to a held slot, and release of a rotated
credential's hold.
