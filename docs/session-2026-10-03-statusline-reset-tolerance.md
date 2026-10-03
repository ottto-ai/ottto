# Claude statusLine readings match OAuth windows within one second

**Date:** 2026-10-03
**Scope:** daemon quota source selection only; no wire or schema change

## Problem

Claude Code's statusLine reports fresh 5-hour and 7-day `rate_limits` after
every model reply. The daemon reads the OAuth usage endpoint far less often.
The rule that lets a newer statusLine reading replace the matching OAuth meter
required the two reset times to be exactly equal. OAuth resets carry
microseconds (`...T17:20:00.123456Z`); statusLine resets are whole epoch
seconds (`...T17:20:00Z`). The rule therefore almost never fired while the
OAuth read succeeded, and the fresher passive reading was discarded.

## Change

- Reset times (and the derived window start) now match within
  `CLAUDE_STATUSLINE_RESET_MATCH_TOLERANCE_SECONDS` (1 s). Distinct Claude
  windows are hours apart, so the tolerance cannot join two windows.
- A statusLine reading observed at or after its own reset never wins.
- Unchanged: exact account and organization proof, same window name, scope,
  duration, model, group and limit id; money-bearing OAuth meters are never
  replaced; the statusLine reading must be strictly newer than the OAuth one
  and not in the future.

## Tests

`prefer_newer_statusline_matches_whole_second_reset_against_microsecond_oauth_reset`
covers the winning case and these refusals: a reset 2 s or 60 s apart, an
older statusLine reading, a different account, and a reading taken after its
reset.
