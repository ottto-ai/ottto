# Session: stamp account identity on served Claude quota windows

**Date:** 2026-07-27 · **Change:** `crates/ottto-service/src/agent_status.rs`

0.1.97 keyed the Claude OAuth usage cache by account (#285) and attributed the
statusLine cache (#287), but the windows the daemon actually uploads still
carried no identity: `AgentQuotaWindow.account_identifier_hash` existed on the
wire (and the backend has accepted it since the Desktop-usage opt-in work) yet
every Claude quota window and credit balance shipped with the field absent -
`scope: account` with no account named. The backend's per-account serve path
(product PR #3380) cannot fan out what the daemon never sends.

Changes:

- `collect_claude_status` resolves the CLI `oauthAccount` once and derives both
  the account hash (existing `ottto-core` preference order) and an organization
  hash; the same resolution now scopes the OAuth cache read, gates the
  statusLine serve, and stamps the wire - the three can no longer disagree.
- `collect_claude_oauth_usage` takes the resolved identity and stamps every
  served window and credit balance at one boundary, covering fresh fetches and
  every cache/429/transport fallback alike (the cache is discarded rather than
  served when it belongs to another account, so one stamp is sufficient).
- statusLine-served windows are stamped from the v2 cache's
  `observed_under_account_identifier_hash` - the CLI writer's observation, not
  a serve-time guess.
- An unresolved account stamps nothing: unknown serves as unknown, never as a
  guessed identity (unit-tested as a negative control).

Deliberately unchanged: cache schema (v3 reads fine - stamping happens at
serve, not in the cache), the statusLine fail-closed attribution gate from
#287, and the Desktop plan-observation path, which already stamped identity.

Companion work in the product repo: hash-first history-lane attribution
(W4-a) so a stamped window can never inherit the snapshot account's profile by
label fallback. Effort:
`docs/efforts/state/cross-account-quota-attribution.md` (product repo).
