# Session: Resolve Claude Code statusLine Quota Per Session

Date: 2026-07-29

## Problem

Claude Code renders a statusLine by piping JSON payloads into a single machine-global wrapper that calls `ottto claude-code-statusline`. The payload contains `session_id`, `cwd`, `transcript_path`, model, and rate-limits data, but names NO account.

The wrapper stamps the cache with the account the local Claude CLI credential names (via `~/.claude.json` oauthAccount). However, EVERY Claude Code surface on the machine pipes into that same wrapper: the terminal CLI AND the Claude Desktop app's "Code" tab.

On a two-account machine (e.g., personal Max + work Team credential), the Desktop app's Code tab might be rendering under the Max account while the CLI credential names Team. The writer stamps Team, but the numbers come from Max. The service sees a matching write-time account AND another account observable on the machine, so it refuses to serve the sample — "safe but useless" fail-closed behavior.

## Resolution Order (Write Time)

The resolution chain attempts to prove which account ACTUALLY owns a session:

1. **session_store** - Parse `session_id` from the payload, scan the Desktop session store at `~/Library/Application Support/Claude/claude-code-sessions/<accountUuid>/<organizationUuid>/local_<sessionId>.json`, and find a leaf whose `cliSessionId` equals the payload's `session_id`. Hash the owning `<accountUuid>` using `billing_identity_hash("anthropic", "account", uuid)`. If multiple leaves match (a session resumed under another account):
   - Tie-break 1: Prefer `isArchived == false`.
   - Tie-break 2: Prefer greater `lastActivityAt`.
   - If still ambiguous, mark as `ambiguous` (unresolvable).

2. **config_dir** - Only on a store MISS and only when `CLAUDE_CODE_ENTRYPOINT=cli` or `CLAUDE_CODE_ENTRYPOINT=*vscode*` (terminal/IDE sessions). Use the current CLI credential hash from `claude_cli_account_identifier_hash()`.

3. **unknown** - Store miss with non-CLI entrypoint, unparseable payload, empty hash, or any other unresolvable state.

Record the method alongside the hash in the cache.

## Memoization (Performance)

Renders fire on a ~300 ms debounce + 60-second timer; each is a fresh short-lived process. Scanning ~375 Desktop session files per render is unacceptable.

Memoize resolution across renders:
- Key: SHA-256(session_id), not raw session_id (privacy).
- Value: {account_hash, method, timestamp}.
- Cap: 64 entries, evict oldest on overflow.
- File: `ottto-code-resolution-memo.json` in support dir.

Privacy invariant: the memo NEVER contains raw `session_id`, `cwd`, or `transcript_path`.

## Schema Bump

Bump `CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION` from 2 to 3 only. Context-window caches stay at v1 (they carry no per-account numbers).

Add field `observed_under_account_method` to the cache struct, recording the resolution method as a string: `"session_store" | "config_dir" | "ambiguous" | "unknown"`.

v2 caches (method field absent) are treated as unresolved and refused on read.

## Service Read Path

Update `claude_statusline_attribution_failure` to accept the method field:

- **session_store** -> SERVE. The store proved which account owns the session.
- **config_dir** -> SERVE if hash matches the current credential holder; refuse as `CredentialReplaced` if it differs.
- **ambiguous** -> Refuse as `MultipleAccounts`.
- **unknown** -> Refuse as `AccountUnknown`.
- v2 cache (empty method) -> Refuse as `AccountUnknown`.

The entire point: relaxation is method-gated. Do NOT refuse merely because multiple accounts are observable if the method proves ownership.

## Safety Invariant

**A sample is served ONLY under an account proven for that render.** Unproven
resolution yields the same behavior as today: fail-closed, typed diagnostic,
`unsupported_quota_window("usage")`.

Be precise about what is and is not established. The `session_id` ->
`cliSessionId` join has been verified against the store at rest (369 of 373
leaf files carry `cliSessionId`; Desktop-hosted sessions are present and
terminal sessions are absent), and it has **never been observed on a live
Desktop "Code" tab render** - not "observed and found reliable", simply never
observed, because that surface did not render a status line during 4.5 hours of
armed capture. This change does not depend on that gap being closed: a join
that misses resolves to `unknown`, which is byte-identical to today's
fail-closed behavior. Confirming it would tell us how much coverage the
`session_store` method actually buys, not whether it is safe.

There is no fallback to the credential holder. An unresolved sample carries no
account at all, so a reader that trusted the hash without checking the method
still cannot misattribute.

## Test Coverage

- Core: store hit resolves to `session_store` and is memoized (proven by
  deleting the store and resolving again); a mirrored session prefers the live
  claim, then the newest `lastActivityAt`; a mirrored session with no
  discriminator resolves `ambiguous` with an empty hash; a terminal render
  resolves `config_dir` only with a CLI entrypoint, and a store miss without one
  resolves `unknown` carrying no account; the cache and the memo hold no raw
  session id, cwd or transcript path.
- Service: `session_store` serves despite other accounts; `config_dir` serves
  when the hash matches despite others; `config_dir` refuses on hash mismatch;
  `ambiguous` refuses; `unknown` refuses; a v2 cache refuses.
- Negative control: the same render resolved via the store yields the hosting
  account while the credential holder yields a different one, asserted
  `assert_ne!`. If those ever matched, the resolver would be decorative and
  every attribution test here would pass anyway.
