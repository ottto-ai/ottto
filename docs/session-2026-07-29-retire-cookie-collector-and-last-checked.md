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
