# Claude slots recover after a CLI token rotation

**Date:** 2026-10-03
**Scope:** daemon Claude slot collection and upkeep only; no wire or schema change

## Problem

On 2026-10-03 every managed Claude slot on one Mac stopped collecting within
minutes of each other, and the source reported `secret_expired`, although no
credential had expired. Claude Code 2.1.288 refreshed each slot's token inside
the daemon's per-pass `claude auth status --json`. The next `auth status`
exited 1 under the daemon's sanitized environment.

- `resolve_registered_claude_slot` mapped any non-zero `auth status` to
  `CredentialUnavailable`, even with a present, unexpired credential.
- `registered_claude_failure_status` saved that failure without the access or
  refresh deadline.
- On later passes `observe_registered_slot_upkeep` read the missing persisted
  deadline as `CredentialUnreadable`. It never re-read the slot, and it never
  handed a truly expired login to the refresh worker.

## Change

- Upkeep: when the persisted access deadline is missing, re-read the slot's
  own credential metadata, using the same secret-free projection the worker
  uses. Valid access proceeds to collection as `NotRequired`. Expired access
  goes to the refresh worker. Unreadable metadata keeps `CredentialUnreadable`.
- A failed probe keeps the last-known, still-unexpired access and refresh
  deadlines, taken from the upkeep observation or the previous collection.
  A deadline that has already passed is not kept.
- A non-zero `auth status` when the slot's credential, read after the
  command, has an access token and an unexpired deadline is the new transient
  `ProbeFailed` (collection state `probe_failed`, retried next pass). It does
  not raise the needs-attention warning. A missing CLI, a signed-out status or
  an expired credential still reports `CredentialUnavailable`. Usage breaker,
  auth holds and Retry-After are untouched.

## Single refresher

The daemon never calls the OAuth token endpoint and never holds a refresh
token; it keeps only a has-refresh-token bit. Only Claude Code CLI processes
refresh: `auth status` from the collector and `doctor` from the worker. The
CLI serializes rotation on its own `.oauth_refresh.lock` per config dir. The
daemon also keeps the two paths apart. The collector runs `auth status` only
while access is valid or its deadline is unknown. The worker is queued only
after expiry, at most once per slot, and while it is queued the collector does
not proceed. The worker re-reads keychain metadata before and after `doctor`.
No lock change was needed.

## Not changed

- `StableProblemCode::SecretExpired` is a protocol enum. Renaming it would
  change the wire contract, so it is left as is. With this fix, transient
  failures no longer reach it.
- Why `auth status` exits 1 under the sanitized environment right after a
  rotation is not reproduced here, because reproducing it needs a real
  logged-in slot.
- A retired duplicate slot that records `needs_login` on every pass without
  backoff is log noise and out of scope.

## Tests

- `missing_persisted_deadline_rereads_live_metadata_instead_of_latching`
- `missing_persisted_deadline_with_expired_live_access_hands_refresh_to_one_worker`
- `missing_persisted_deadline_and_unreadable_live_metadata_stays_unreadable`
- `persisted_deadline_skips_the_live_metadata_read`
- `production_worker_queue_admits_one_refresher_per_slot`
- `failed_auth_status_with_valid_credential_is_a_transient_probe_failure`
- `failed_auth_status_with_expired_credential_stays_credential_unavailable`
- `registered_failure_status_keeps_last_known_unexpired_deadlines`

Four of these fail with the fixes reverted.
