# Retire Claude Desktop browser-session usage collection

**Date:** 2026-07-29 · **Change:**
`crates/ottto-service/src/agent_status.rs`,
`crates/ottto-service/src/control.rs`, `crates/ottto-protocol/src/lib.rs`,
`crates/ottto-cli/src/main.rs`, and the Claude Code connector package

## Claude Desktop browser-session collector

The product owner decided on 2026-07-26 and approved deletion on 2026-07-29.
The dormant, default-off collector recovered Claude Desktop browser-session
credentials from the app's Chromium cookie database and macOS Keychain, then
called a private Claude web endpoint while presenting browser identity headers.
Anthropic's support policy names tools that misrepresent their identity to
Anthropic's servers as enforceable. That identity mismatch plus credential
decryption made this collector the daemon's highest compliance-risk provider
surface.

The collector is deleted completely:

- the Claude web usage request, response normalization, rate-limit handling,
  retry gate, and normalized cache;
- the Chromium SQLite cookie read, `v10` AES-CBC decryption, host binding,
  PBKDF2 key derivation, and Keychain lookup;
- the opt-in sentinel, getter/setter, and
  `claude_desktop_web_usage_preference` local-control command;
- the browser User-Agent and web-only Origin, Referer, Cookie, and
  `anthropic-client-platform` headers;
- the `desktop_quota_status` connector manifest, fixture, registry entry,
  collector-only structs/constants/tests, and crypto-only crate dependencies.

The local-control command was companion-app-facing. The macOS app must remove
any remaining call to `claude_desktop_web_usage_preference`; newer daemons no
longer recognize it.

The deletion deliberately preserves all credential-free Claude Desktop
identity and metadata reads:

- `~/Library/Application Support/Claude/config.json`
  `lastKnownAccountUuid`;
- bounded `claude-code-sessions` and `local-agent-mode-sessions` metadata used
  for identity, organization/session-bucket attribution, and display-safe
  labels.

No release ordering gate applies to this deletion.

## ChatGPT subscription period last-checked evidence

`parse_codex_id_token_account` now reads
`chatgpt_subscription_last_checked` from the same
`https://api.openai.com/auth` claim object that supplies the ChatGPT plan and
active-period boundaries. It emits the provider-neutral optional wire field:

```text
subscription_period_last_checked_at: Option<Rfc3339Timestamp>
```

The field uses `#[serde(default, skip_serializing_if = "Option::is_none")]`, so
payloads are unchanged when the claim is absent. Parsing deliberately reuses
the period-boundary rules: numeric epoch seconds, numeric-string epoch seconds,
and RFC3339 strings are accepted and normalized to UTC; epoch values are
sanity-bounded to roughly 2015-2100 so milliseconds cannot become a distant
future date. Malformed, null, nested, and out-of-range values are absent. No
failure path substitutes the current time.

`merge_codex_accounts` explicitly carries
`subscription_period_last_checked_at` and preserves known evidence when a
later probe omits it. This is required because that function rebuilds
`AgentAccountStatus` field by field and would otherwise silently discard the
new value.

The timestamp makes an expired `subscription_period_end` interpretable. A
last-check after the end means the provider re-verified after the period
expired, so the subscription lapsed. A last-check before the end means only
that the cached token evidence is stale.

### Release gate

Merging to `main` is safe, but the stable release carrying
`subscription_period_last_checked_at` must not ship until the parallel product
repository backend PR declaring that field is both merged and deployed. The
agent-status accept model uses `extra="forbid"`; sending the field to an older
backend returns 422 for the entire snapshot batch. This gate applies only to
the new field, not to the collector deletion.

## Validation

- Team and Pro `id_token` fixtures cover epoch and RFC3339 values, absent
  claims, malformed/out-of-range shapes, one-sided reporting, and the
  no-account early return.
- Merge coverage pins both initial carry and preservation through a later
  silent probe.
- Serialization coverage pins omission when absent.
- `cargo fmt --all -- --check`: clean.
- `cargo test --workspace`: 1,259 passed, 0 failed, 3 ignored on the final tree
  after merging the current `origin/main`.
- `cargo clippy --workspace --all-targets`: clean.
- `scripts/public_repo_manifest_check.sh`: clean after final manifest
  regeneration.
- `cargo fmt --all -- --check`: clean.
- `cargo test --workspace`: 1,257 passed, 0 failed, 3 ignored.
- `cargo clippy --workspace --all-targets`: clean.
