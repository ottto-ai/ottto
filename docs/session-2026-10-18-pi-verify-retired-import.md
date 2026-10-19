# Pi Verify stops calling the retired import endpoint

Date: 2026-10-18

## Problem

The backend retired the direct Pi import endpoint (`POST /api/v1/pi/import-runs`).
An authenticated request now answers `410` with code `pi_ingest_not_available`
and stores nothing. Pi route Verify still built a multipart body from the new
smoke transcript and posted it there:

- Live Verify (API-key, gateway and service-account routes) treated the `410` as
  a generic backend rejection. The route failed with a message telling the user
  to sign in again, which was wrong: nothing about the session was invalid.
- Passive Verify (rotating subscription-OAuth routes) also uploaded recent
  transcripts. Its errors were logged and ignored, so the request was pure cost.

Both paths also issued a Pi relay token only to authorize that upload.

## Change

- Live Verify no longer issues a relay token, reads transcript bytes or posts
  anything to a Pi endpoint. After a successful smoke it keeps the held
  pre-smoke census result and polls setup verification exactly as before.
- Passive Verify keeps its read-only recent-file selection (presence and
  modification time only) as local route evidence and no longer uploads.
- The multipart builder, upload helpers, Pi import timeout and the
  upload-only byte caps are removed. Directory traversal caps, rooted
  `O_NOFOLLOW` opens and root identity checks are unchanged and still guard the
  census and recent-file selection.

No request reaches the retired endpoint, so no `410` handling is added.

## Result contract

No new codes or wire fields. A new local smoke session with no matching backend
usage settles as the existing `pi_local_only` Warning (verified from local
evidence, zero records seen). It never reports an upload. Smoke failures,
census failures, setup-verification backend errors (including authentication
failures and `telemetry_disabled_by_admin`) and the passive re-sign-in Warning
keep their existing results and messages.

## Validation

- A live-route Verify test runs a fake `pi` that writes a session, records every
  backend request, and asserts that only setup-verification `GET` polls are
  made (no Pi endpoint, no relay token) and that the route settles as
  `pi_local_only` without a sign-in message.
- Census, root replacement and symlink-swap tests now exercise the census and
  the rooted opener directly instead of the removed upload helpers.

## Limits

- Pi usage still reaches Ottto through the existing local session collection
  path, which this change does not touch. Verify does not prove that path
  delivered anything.
- This change does not depend on the backend retirement being deployed; it
  only removes a call that the backend no longer accepts.
