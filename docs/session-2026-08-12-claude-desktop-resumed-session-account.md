# Claude Desktop resumed-session account attribution

Date: 2026-08-12

## Problem

Claude Desktop can retain the same resumed Claude Code session under an older
account bucket after the session continues under another account. Agent status
previously emitted only each account bucket's latest session. If the newer
account also owned a later different session, the older duplicate could become
the only exact plan observation for the resumed session.

Desktop numeric activity values are JavaScript millisecond epochs. They were
previously compared consistently but later treated as Unix seconds when
rendering `observed_at`, so the timestamp could not be represented.

## Resolution

The Desktop metadata scan now retains a bounded in-memory activity index for
each session in each account bucket. For a duplicated session ID, exactly one
newest timestamp wins the live session binding. Equal or missing timestamps
remain unattributed. Account-level observations remain available without the
losing exact session ID, and at most 64 resolved duplicate-session observations
are added, newest first.

Numeric timestamps are normalized to Unix seconds before comparison and
rendering. RFC 3339 timestamps retain their existing behavior.

This correction applies to live active-session account placement. It does not
rewrite historical usage attribution or relax the snapshot scanner's separate
cross-account conflict guard.

## Verification

- Newest duplicate account wins even when that account has a later different
  session.
- The losing account emits no exact binding for the duplicated session.
- Equal or missing timestamps fail closed.
- JavaScript millisecond and Unix-second inputs normalize to the same time.
- Full `ottto-service` test suite passes.
