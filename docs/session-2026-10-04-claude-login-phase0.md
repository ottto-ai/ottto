# Claude logins: no Ottto-caused sign-outs (Phase 0)

**Date:** 2026-10-04
**Scope:** daemon Claude login state, upkeep and every Claude CLI spawn; no
wire field or protocol enum change

## Problem

Short Claude Code commands that the daemon ran signed users out. A command that
starts near or after the access token's expiry starts a token refresh. If it
exits, or is killed, before the rotated token is saved, the refresh token is
spent; the next run gets `invalid_grant` and Claude Code blanks the login
(anthropics/claude-code issue 95822). The daemon ran such commands all the time:

- `claude auth status --json` for the default login and every registered slot,
  on every status pass;
- `claude doctor` as consented post-expiry upkeep;
- `claude -p /context`, killed at its timeout;
- the Verify smoke prompt, killed at its timeout.

## Change

- **Login state from local metadata.** `auth status` read only the stored
  token's presence and scopes, the stored plan and the `.claude.json` account.
  The daemon now reads those directly: `.claude.json`, the stored credential,
  `.claude.json` again. The plan comes from the credential's
  `subscriptionType`, refined by the existing `.claude.json` rules. A keychain
  failure or a malformed item fails closed (`probe_failed`); a missing item is
  not signed in; a missing or lapsed refresh grant is `needs_login`.
- **`doctor` upkeep off.** Nothing is queued and the production process runner
  never spawns. Consent and the upkeep state file are kept for a later phase.
- **One spawn gate** (`crates/ottto-service/src/claude_spawn_gate.rs`). It is
  the only code that may build a `claude` `Command`, with an exact argv
  allowlist: `--version`; `auth login --claudeai` in a managed root;
  `-p /context --output-format json [--strict-mcp-config]`; the smoke argv.
  A credential-using spawn re-reads its login right before the spawn and is
  refused unless the access token stays valid for 5 min (Claude Code's refresh
  window) + 10 min + the command's runtime. Failed reads, missing deadlines,
  deadlines more than 24 h out, a fresh `.oauth_refresh.lock` and the usage
  off-switch also refuse. Children run on monotonic and wall-clock deadlines.
  A source-scan test fails on any Claude spawn pattern outside the gate.
- **Paused, then auto-resume.** An access token that lapsed while its refresh
  grant is alive is paused: `refresh_due` + upkeep `upkeep_disabled`
  (quota access `paused`), the last reading kept stale. Never
  `stale_access_token`. Every pass re-reads the credential, so when Claude Code
  refreshes the login the same pass collects again. The #479 identity gates
  still run first.
- **No expired-token usage requests.** A token expired by the local clock (or
  within 60 s) is never sent to `/api/oauth/usage`; the last reading is served
  stale under `claude_oauth_usage_check_suppressed`.
- **MCP.** A user MCP server that would run the Claude Code CLI is reported
  unreachable and never spawned.

## Cost and open decision

A managed-only account has live limits for about 8 hours after each browser
sign-in, then its reading ages. An account that is also the default login is
read through the default credential instead. Q-A (quiet "Paused" vs a louder
"Sign in again") is open; the quiet default is behind
`claude_upkeep::PAUSED_EXPIRED_SLOT_ASKS_FOR_SIGN_IN`.

## Tests

Gate boundaries with a fake clock; argv allowlist; target environment; source
scan; status passes across the expiry boundary with a logging fake `claude`
and fake `security` (only `--version` runs, one keychain read per login per
pass); paused presentation; auto-resume; identity mismatch stays; expired
default makes no request; default takes over from a paused slot; `/context`
and Verify refusals; MCP refusal; local-metadata account equals the old
`auth status` account for Max 20x and Team Premium. Provider requests are
forbidden in these tests.
