# Claude statusLine rate-limit cache is attributed, not just keyed

Sibling of [the OAuth usage cache fix](session-2026-07-26-claude-oauth-usage-cache-account-key.md),
which landed scoped to `claude-code-oauth-usage-cache.json`. The statusLine
rate-limit cache (`claude-code-rate-limits.json` in the support directory) had
the same missing account identifier, but not the same bug, and copying that fix
verbatim would have made things worse rather than better.

## What statusLine actually is

`statusLine` is a Claude **Code** mechanism, not a "Claude Desktop" feature. It
is configured once in `~/.claude/settings.json` (`statusLine.command`, pointing
at Ottto's wrapper in the support directory) and is invoked by *whichever*
Claude Code surface renders: the terminal CLI **and** the Claude Desktop app's
"Code" tab read that same settings file and pipe to that same wrapper. The
`rate_limits` in each render belong to the account *that* surface is
authenticated as.

The payload names no account. It carries `model`, `cwd`, `transcript_path`,
`rate_limits`, `context_window`, `session_id`, `version`, and `cost` -- and the
ingest deliberately keeps none of the first two. So on a machine with two Claude
accounts (a personal Max in the Desktop app, a work Team seat in the terminal
CLI) every render overwrites one shared, un-keyed file, and the cache silently
reflects whichever surface rendered last while the collector stamps it onto
whatever account it separately resolved.

Reproduced live 2026-07-26 on Ottto 0.1.96: with the terminal CLI on the Team
account (live `seven_day` 18 %, reset boundary `2026-07-31T14:00Z`), the cache
held `seven_day` 44 % with reset boundary `2026-08-01T05:00Z` -- the Max
(Desktop) account's window. The differing reset instants, 15 hours apart, are
the unambiguous tell; used-percentages alone could have been a staleness
artifact.

## Why account-keying alone is not the fix

For the OAuth usage cache the daemon fetches the numbers itself, so the account
that wrote them is provable and exact-match keying is a complete fix. Here the
writer is a hook fired by an arbitrary surface, so a write-time stamp records
only *which credential was visible at the time* -- which, during the repro
above, was the Team account both when the sample was written and when it was
read, while the numbers belonged to the Max account. Keying alone would have
matched, served, and laundered a wrong attribution into a confident one.

Proof needs both halves:

1. **Account key.** `ClaudeStatusLineRateLimitCache` now carries
   `observed_under_account_identifier_hash`, stamped by the CLI writer from
   `~/.claude.json` `oauthAccount`. Discard-on-mismatch at read time closes the
   `/login` account-switch hole -- the identical defect the OAuth fix closes.
   The field is named for what it means: the credential visible at write time,
   not the owner of the numbers.
2. **Ambiguity gate.** The service refuses to serve when any *other* Claude
   account is observable on the machine. Claude Desktop plan observations
   already carry `account_identifier_hash`, derived from the plaintext
   `lastKnownAccountUuid` with no decrypt and no network call, so "is there a
   second Claude account here?" is answerable today.

Only when both hold is the sample provably the current account's. Otherwise the
collector falls through to the existing typed
`unsupported_quota_window("usage")` state with an explicit capability message
and diagnostic -- `credential_replaced`, `multiple_accounts`, or
`account_unknown` -- rather than rendering another account's numbers. On a
two-account machine that means no statusLine quota at all, which is the correct
answer until a real attribution key exists.

Unlike the OAuth cache, two empty hashes do **not** match here. There the
allowance exists because an unidentifiable machine would otherwise lose every
cache hit against a rate-limiting endpoint; statusLine costs nothing to
re-observe on the next render, so refusing is free.

The shared hashing now lives in `ottto-core::claude_account`
(`billing_identity_hash`, `claude_account_identifier_hash`) because the CLI
writer and the service reader must produce byte-identical hashes. Two
implementations of one preference order would drift silently: a divergence
reads as "foreign cache", so quota would quietly disappear rather than fail
loudly. `ottto-service` now calls into core instead of keeping its own copy.

## Schema version

The rate-limit cache gets its own constant,
`CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION`, moved 1 -> 2. Version-1
caches carry no account identity, so they are discarded on upgrade rather than
adopted by whoever is signed in now.

The split from `CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION` is the point: that
constant is shared with the context-window cache and its 120-sample history,
neither of which holds per-account numbers. Bumping one shared value would have
thrown that history away as collateral damage for an unrelated fix.

## Not the answer, only the safe interim

This gate makes a wrong attribution impossible; it does not make a right one
possible. The open question is whether anything at statusLine invocation time
can name the account of the surface that rendered -- an environment variable, a
per-surface config dir, the `session_id`, or the provenance of the transcript
path. Until that is answered, a two-account machine legitimately gets no
statusLine quota, and promoting statusLine to the *default* Claude quota source
must stay gated: as a default on such a machine it would make the wrong-account
bug more prominent, not less.

## Boundaries kept

- No credential was decrypted and no content or transcript endpoint was touched.
- The cache keeps its closed scalar-struct shape. The added field is an opaque
  hash; the must-not-persist test still asserts no path, transcript reference,
  session identifier, or address reaches the serialized cache.
- Desktop plan observations are now computed once per status tick and shared
  between the attribution gate and the snapshot, rather than scanning the
  session buckets twice.

## Verification

- `cargo test --workspace`: 908 service + 71 core + 80 CLI tests pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- New coverage: attribution matrix (same account, replaced credential, unknown
  account, second account present), end-to-end refusal against a written cache,
  version-1 discard, and a guard that the context-window history survives the
  rate-limit version bump.
