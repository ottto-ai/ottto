# Claude slots signed out by Claude Code report "reconnect" truthfully

**Date:** 2026-10-03
**Scope:** daemon Claude slot collection and upkeep only; no wire or schema change

## Problem

On 2026-10-03 every managed Claude slot on one Mac, plus the default
`~/.claude` login, stopped collecting within about four hours. The source
reported `secret_expired`. No credential had expired.

**What happened.** The slot's own keychain item was still present, but
Claude Code had blanked it: `accessToken` and `refreshToken` were empty strings
and `expiresAt` was 0. Claude Code writes exactly that shape when the token
endpoint rejects a refresh with `invalid_grant`. The CLI events for this are
`tengu_oauth_refresh_token_marked_dead_invalid_grant` and
`tengu_oauth_refresh_token_cleared_on_disk`. Each slot hit it on its first
refresh after Claude Code 2.1.288 was installed; the refresh ran inside the
daemon's `claude auth status --json`. After that, `auth status` correctly
reports `loggedIn: false` and exits 1.

**Cause of the rejection: unproven.** It is either a 2.1.288 regression in
token rotation or save, or a server-side revocation of these refresh tokens.
Telling them apart needs a provider refresh call, which was not made here.
Either way, only a reconnect or an official `claude /login` restores the slot.

**How the daemon handled it:**

- `resolve_registered_claude_slot` kept spawning `auth status` every pass.
- It mapped every non-zero exit to `CredentialUnavailable`, even when the
  credential was present and unexpired.
- `registered_claude_failure_status` saved that failure without the access or
  refresh deadline.
- On later passes `observe_registered_slot_upkeep` read the missing persisted
  deadline as `CredentialUnreadable`. It never re-read the slot, and it never
  handed a truly expired login to the refresh worker.

## Change

- **Signed out by Claude Code.** A credential item that is present, with both
  token strings empty and `expiresAt` 0, is detected from the stored item
  alone. It is never logged, and no CLI is spawned.
  - The slot becomes `needs_login` ("Claude Code signed this connection out
    after its sign-in was rejected; reconnect to resume").
  - Neither `claude auth status` nor `claude doctor` runs for it.
  - Each pass costs one keychain metadata read. When the item carries tokens
    again, after a reconnect or `claude /login`, the slot resumes on its own.
  - Stale deadlines from before the wipe are not carried forward.
- **Missing deadline.** When the persisted access deadline is missing, upkeep
  re-reads the slot's own metadata (the same secret-free projection the worker
  uses). Valid access proceeds as `NotRequired`. Expired access goes to the
  refresh worker. Unreadable metadata keeps `CredentialUnreadable`.
- **Kept deadlines.** A failed probe keeps the last-known, still-unexpired
  access and refresh deadlines. A deadline that has already passed is not kept.
- **Transient failure.** A non-zero `auth status` when the credential, read
  after the command, has a non-empty access token and an unexpired deadline is
  the new transient `ProbeFailed`. It is retried next pass and raises no
  needs-attention warning.
  - An explicit `loggedIn: false`, a missing CLI or an expired credential
    still reports `CredentialUnavailable`.
  - Usage breaker, auth holds and Retry-After are untouched.

## Single refresher

The daemon never calls the OAuth token endpoint and never holds a refresh
token; it keeps only a has-refresh-token bit. Only Claude Code CLI processes
refresh: `auth status` from the collector and `doctor` from the worker. The
CLI serializes rotation on its own `.oauth_refresh.lock` per config dir.

The daemon also keeps the two paths apart:

- The collector runs `auth status` only while access is valid or its deadline
  is unknown.
- The worker is queued only after expiry, at most once per slot. While it is
  queued, the collector does not proceed.
- The worker re-reads keychain metadata before and after `doctor`.

No lock change was needed.

## Not changed

- `StableProblemCode::SecretExpired` is a protocol enum, so renaming it would
  change the wire contract. The per-slot state is `needs_login`. Transient
  failures no longer reach `SecretExpired`.
- A retired duplicate slot that records `needs_login` on every pass without
  backoff is log noise and out of scope.

## Tests

- `cli_cleared_credential_is_signed_out_without_spawning_auth_status_until_rewritten`
- `cli_cleared_credential_needs_login_without_worker_or_collection`
- `needs_login_slot_resumes_once_the_stored_item_carries_tokens_again`
- `missing_persisted_deadline_rereads_live_metadata_instead_of_latching`
- `missing_persisted_deadline_with_expired_live_access_hands_refresh_to_one_worker`
- `missing_persisted_deadline_and_unreadable_live_metadata_stays_unreadable`
- `persisted_deadline_skips_the_live_metadata_read`
- `production_worker_queue_admits_one_refresher_per_slot`
- `failed_auth_status_with_valid_credential_is_a_transient_probe_failure`
- `failed_auth_status_with_expired_credential_stays_credential_unavailable`
- `failed_auth_status_reporting_signed_out_stays_credential_unavailable`
- `registered_failure_status_keeps_last_known_unexpired_deadlines`

Eight of these fail with the fixes reverted.
