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

**A sample is served ONLY under an account proven for that render.** Unproven resolution yields the same behavior as today: fail-closed, typed diagnostic, `unsupported_quota_window("usage")`. The new window-open (session_store serving) is safe because the store join has never been observed to fail on live Desktop "Code" tab renders — an unproven join simply yields `unknown`, i.e., today's behavior.

## Test Coverage

- Core: store hit resolves to `session_store`, memo prevents rescan, multi-account tie-breaks work, privacy holds.
- Service: `session_store` serves despite other accounts; `config_dir` serves when hash matches despite others; `config_dir` refuses on hash mismatch; `ambiguous` refuses; `unknown` refuses; v2 cache refuses.
- Negative control: stub resolver to always return `config_dir`, verify that the test FAILS attribution when hash differs — proof that method-gated logic is load-bearing.
