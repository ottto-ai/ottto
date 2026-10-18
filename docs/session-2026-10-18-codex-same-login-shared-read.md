# Codex homes with the same login share one quota read

Date: 2026-10-18

## Problem

The default Codex home (`~/.codex`) and a managed account slot can hold the
same login: the same account and the same workspace. They share one quota,
but the daemon's quota schedule read each home on its own. The default home
was read every 5 minutes while Codex was in use, and the managed copy every
15 minutes, so the same quota was read about 370 times a day instead of about
290. An explicit Refresh read it twice as well.

## Change

`agent_status/codex_saved_quota.rs`:

- Homes are grouped by login. Two homes hold the same login only while both
  their saved readings and their current `auth.json` credentials name the
  same account and workspace, and the latest read of each did not fail. A home
  with an unknown login, a failed latest read, or a running daemon sign-in
  (already left off the schedule) is read on its own, as before.
- In a group, one home reads for all: the default home when it is a member,
  else the one with the lowest home key, so the reader stays the same from
  round to round. Its interval is 5 minutes when any member is in use, else
  15.
- The other members are read by themselves once every 24 hours
  (`SAME_LOGIN_KEEPALIVE_SECONDS`), so their own tokens stay refreshed and a
  login that died there shows up as that home's own failed read.
- An explicit Refresh reads each group once, with the same once-a-minute
  limit per home.
- A status read of a non-reader home serves the reader's reading when it is
  newer than the home's own (or the home has none to serve), after checking
  that both homes' current credentials and that reading name the same account
  and workspace and that the reader's latest read did not fail. Otherwise it
  serves the home's own saved copy. The home's own failed read is always
  served as such. These checks are local file reads; no provider call is
  needed to notice that a home switched account.

Unchanged: the 5 and 15 minute intervals, the one-minute re-read after a
login change, backoff and Retry-After handling, the sign-in exclusion and
credential baseline, the setup gate, the provider-call log (each real read
still logs once with its trigger), and the control protocol. The change only
removes reads; it adds none.

## Expected effect

With one default home and one managed slot on the same login, the slot is
read once a day instead of every 15 minutes: about 95 fewer `codex
app-server` runs (about 190 fewer provider requests) a day, and one read
instead of two per explicit Refresh.

## Tests

Unit tests in `codex_saved_quota.rs` with fake reads cover: one read per
interval for a shared login (5 minutes when either home is in use, 15 when
none) and the non-reader served the reader's windows, credits and reset
details; the same account in another workspace read on its own; a home that
switches account no longer sharing at once; a failed shared read putting the
other home back on its own schedule; a failed keep-alive read shown, not
hidden; the 24-hour keep-alive; one explicit-refresh read per group with the
rate limit unchanged; and a sign-in on either home ending the sharing without
serving another login's reading.
