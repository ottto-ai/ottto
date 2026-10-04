# Claude logins: no Ottto-caused sign-outs, plus one safe background refresh

**Date:** 2026-10-04
**Scope:** daemon Claude login state, upkeep, short Claude runs and a new
background refresher; no wire field or protocol enum change

## Problem

Short Claude Code commands that the daemon ran signed users out. A command that
starts near or after the access token's expiry starts a token refresh. If it
exits, or is killed, before the rotated token is saved, the refresh token is
spent; the next run gets `invalid_grant` and Claude Code blanks the login
(anthropics/claude-code issue 95822). The daemon ran `claude auth status` on
every pass, `claude doctor` as upkeep, and the killable `-p /context` read and
Verify smoke.

## Change (re-scoped with Ron, 2026-10-04)

- **Login state from local metadata.** No `claude auth status`. `.claude.json`
  (identity: email, organization), the stored credential (deadlines, token
  presence, scopes, plan from `subscriptionType`), `.claude.json` again. A
  keychain failure, a missing `security` tool or a malformed item fails closed;
  a missing item is not signed in; a missing or lapsed refresh grant is
  `needs_login`. #478/#479 states and auto-resume are kept. Default-login
  precedence follows Claude Code: Bedrock/Vertex, `ANTHROPIC_AUTH_TOKEN`,
  `apiKeyHelper`, an approved `ANTHROPIC_API_KEY`, and a stored Console API key
  (only without OAuth).
- **`doctor` upkeep off.**
- **Quiet window** (`claude_spawn_gate.rs`): the `-p /context` read and the
  Verify smoke do not start from 15 minutes before access expiry until a new
  expiry is confirmed, nor while expired, on a failed read, or while Claude
  Code holds its refresh lock.
- **Background refresher** (`claude_refresher.rs`, "Keep my Claude accounts
  signed in" = `background_upkeep_consent`, on by default until chosen): per
  registered slot and the default login, one
  `claude -p /usage --no-session-persistence --strict-mcp-config` when the
  access token is within 5 minutes of expiry or expired; empty cwd, own process
  group, Mac kept awake (`caffeinate -i -w`), never killed (reported after
  120 s), success only when `expiresAt` advances (keychain `mdat` logged).
  Failure or blanking: no retry for that credential, the slot asks to sign in
  again; a new credential clears it.
- **Lifetime warnings** 3 days and 1 day before `refreshTokenExpiresAt`, on
  the existing `relogin_approaching` diagnostic.
- **No expired-token usage requests.**

All three CLI flags (`/usage` with `supportsNonInteractive`,
`--no-session-persistence`, `--strict-mcp-config`) were verified in Claude
Code 2.1.288's source; the real CLI was not run.

## Dropped (earlier review rounds)

MCP credential isolation, hook disabling, process-group kills of short runs,
the opaque-executable structure and the strict-MCP `/context`. MCP probes and
`/context` are back to master behaviour apart from the quiet window.
