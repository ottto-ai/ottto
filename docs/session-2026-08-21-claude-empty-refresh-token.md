# Claude empty refresh token requires login

Date: 2026-08-21

## Production finding

Final two-account acceptance on macOS 0.1.116 found one registered custom
Claude slot with an expired access deadline, an empty access token, an empty
refresh token, and a still-future `refreshTokenExpiresAt` value. Claude's
non-inference `auth status` command reported that exact slot as signed out.

The background-upkeep scheduler previously treated the retained future deadline
as proof that the slot was refreshable. It repeatedly ran the vendor's
non-inference `claude doctor` command and entered durable exponential backoff,
even though no refresh grant remained.

## Fix

Credential parsing now projects one secret-free Boolean: whether a non-empty
refresh token is present. The token itself is never retained by upkeep,
serialized, logged, or returned. Once access is expired, a missing refresh
grant produces `needs_login` immediately, starts no doctor process, and creates
no retry witness. A still-valid access token remains usable until its expiry.

The user-owned recovery flow is unchanged: Companion opens the exact registered
`CLAUDE_CONFIG_DIR` command and the customer completes Claude Code's official
`/login`. Ottto never enters credentials or performs OAuth lifecycle work.

## Validation

- Parser regression covers Claude's signed-out shape: empty token strings with
  a stale future refresh deadline.
- Upkeep regression proves the state is `needs_login`, the doctor runner is not
  called, and no backoff file is written.
- Existing consent, off-switch, refresh-deadline, and successful-refresh tests
  remain the surrounding contract.
