# Claude OAuth usage cache is keyed by account

The Claude Code OAuth usage cache (`claude-code-oauth-usage-cache.json` in the
support directory) held no account identifier of any kind. It lives at one
machine-global path, while the Claude Code CLI credential store holds exactly
one account: `/login` as a second account overwrites the first, and
`~/.claude.json` `oauthAccount` switches with it. Quota therefore came from the
cache, written under whichever account was active at write time, while account
identity came from the current login. The two could disagree.

`ClaudeOAuthUsageCache` now carries `account_identifier_hash` -- the same
`billing_identity_hash` this collector uses elsewhere, derived from
`oauthAccount` `accountUuid`, falling back to `organizationUuid` then
`emailAddress`. Every cache read is scoped to the account that owns the
credential right now, and a cache belonging to a different account is discarded
rather than served. This mirrors `ClaudeDesktopWebUsageCache`, which already
keys the Claude Desktop usage cache by account hash.

The schema version moves 2 -> 3. Version-2 caches carry no account identity, so
they are discarded wholesale on upgrade rather than adopted by whoever happens
to be logged in, the same precedent version 1 set. The first tick after upgrade
therefore refetches; if that one request meets a 429 there is briefly no cached
quota to fall back on, which is the intended trade for never attributing an
unidentified payload to an account.

The discriminator is deliberately not a hash of the access token. The token
rotates on refresh while the account does not, so a token fingerprint would
discard a valid same-account cache on every rotation: extra requests to an
endpoint that rate-limits, and no cache left to fall back on when it answers
429. `oauthAccount` is rewritten by Claude Code itself on every profile refresh,
so it tracks the credential without inheriting its rotation.

Two empty hashes match. If the local account metadata named no account when the
cache was written and still names none now, nothing observable changed;
refusing there would drop every cache hit on such machines and turn each status
tick into another request to a rate-limited endpoint.

## Exposure this closes

- Normal path: the cache is served untouched while younger than
  `CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS` (15 min), so cross-account
  contamination self-corrected within 15 minutes.
- Failure path: on 429 or a transport error the collector falls back to the
  cache up to `CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS` (24 h). 429s on this
  endpoint are routine, so contamination could persist for up to a day. This is
  the path that mattered most, and it now discards a foreign cache instead of
  serving it -- another account's numbers are worse than no numbers.
- `CLAUDE_OAUTH_USAGE_REFRESH_SECONDS` (5 min) is a post-429 backoff floor, not
  a poll timer, and is unchanged.

On the 429 arm the discarded cache is not merely skipped: `unwrap_or` replaces
it with an empty cache for the current account, and the write-back clears the
previous account's payload off disk instead of leaving it to be reconsidered on
the next tick.

## Live evidence (2026-07-26, Ottto 0.1.96, macOS)

Reproduced and then observed self-correcting on the 15-minute refresh.

- Account A (`claude_max`, Max 20x): `/api/oauth/usage` returned five_hour 13%,
  seven_day 41% with `resets_at 2026-08-01T04:59:59Z`, weekly_scoped 18%.
- After `/login` as account B (`claude_team`, seat tier `team_tier_1`): the same
  endpoint returned five_hour 27%, seven_day 15% with
  `resets_at 2026-07-31T14:00:00Z`, weekly_scoped 5%.
- The daemon cache at that moment still held session 28% / weekly 44% /
  weekly_scoped 18% with `weekly.resets_at = 2026-08-01T05:00:00Z` -- account
  A's reset boundary while account B held the credential. The differing reset
  timestamps make the misattribution unambiguous.
- The measured refresh delta was exactly 900 s, after which the cache matched
  account B (weekly 15%, weekly_scoped 5%,
  `resets_at 2026-07-31T14:00:00Z`).

Personal Max plus work Team on one machine is a common setup, which is what
made this worth closing rather than documenting.

## Tests

`crates/ottto-service/src/agent_status.rs`:

- `claude_oauth_usage_cache_is_not_served_across_accounts` -- writes a cache
  under account A through the real support-directory path, asserts A still
  reads it, asserts account B does not, asserts an unidentifiable credential
  does not, and repeats the assertion for the 429 fallback expression including
  the write-back that clears A's payload.
- `claude_oauth_usage_cache_account_match_is_exact_both_ways` -- match matrix,
  including both empty-hash directions.
- `claude_oauth_account_identifier_hash_prefers_account_uuid` -- preference
  order, and that two accounts inside one organization still separate.
- `claude_oauth_usage_cache_discards_v2_schema` -- upgrade discards.

Negative control: stubbing the account guard to always match fails both
regression tests (`cache written under account A was served to account B`).
