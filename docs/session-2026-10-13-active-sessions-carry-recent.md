# Active sessions: keep recent sessions listed between scans

Codex account cards in the macOS Companion often showed no active sessions
while Claude cards showed many. Two daemon behaviors caused it.

## Cause

1. **The list was a per-scan delta.** `reconcile_active_sessions` listed only
   sessions whose transcript activity advanced in the current scan. A scan
   that read no new activity for a session dropped it, even when that session
   was active two minutes earlier. Claude Code sessions change constantly and
   scan quickly, so the list stayed full. Codex scans are slower and less
   frequent, so the list was often empty.
2. **Recency was judged on the scan start clock.** The finished scan passed
   `scan_started_at` as the reconciliation time. A session read later in a long
   scan had activity more than five minutes after that time. That activity was
   rejected as "future", and its watermark still advanced, so the next scan did
   not select it either. On one observed machine Codex scans took 12 to 26
   minutes, so live Codex sessions written during a scan were systematically
   missed.

## Change

- `active_sessions::reconcile_with_registrations` carries previously listed
  sessions this scan did not re-select while their `source_last_activity_at`
  is inside the same 15-minute window (and not more than five minutes ahead).
  Entry still requires advanced activity, so title-sidecar refreshes and
  historical backfill still do not create rows. Carried rows keep their
  attribution and Claude registration provenance from when they were selected.
- `changed_session_count` keeps its meaning: sessions advanced in this scan.
- New `active_sessions::clear_active_sessions` empties the list without
  carrying anything. The policy-tombstone and reconciliation-disabled paths in
  `snapshot_sync` use it.
- The finished scan passes the reconciliation-time clock instead of
  `scan_started_at`.
- `docs/session-surfaces.md` documents which sessions are listed.

No wire shape change.

## Not changed

The Companion attaches a Codex session to a card only when both the account
and workspace hashes match. Sessions observed during this investigation carried
both hashes, so attachment was not the cause.

Codex scans on the observed machine re-read nearly every rollout file each
cycle (acquisition reason `state_missing`), which makes them slow. That is a
separate scan-cost issue and is not addressed here.

## Tests

Synthetic only. `cargo fmt --check` and
`cargo clippy -p ottto-service --all-targets -D warnings` clean. Focused
`active_sessions` (33), `snapshot_sync` (195) and `claude_credit_pools` (55)
tests pass, including the new
`keeps_recent_sessions_listed_until_their_activity_leaves_the_window` and
`clearing_a_withdrawn_source_does_not_carry_recent_sessions`.
