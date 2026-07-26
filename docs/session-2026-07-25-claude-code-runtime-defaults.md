# Claude Code display-safe runtime defaults

The daemon captured `AgentRuntimeDefaults` for Codex only, so the Configuration
surface could name Codex's real config file and never Claude Code's. Claude
Code's status collector now resolves the same display-safe defaults from the
local settings chain and attaches them with `provenance: config_file`.

Precedence follows Claude Code's own order, lowest first: `~/.claude/settings.json`,
then `~/.claude/settings.local.json`, then the macOS managed-policy file under
`/Library/Application Support/ClaudeCode/managed-settings.json`. Each readable
file overwrites only the keys it sets, so a managed policy wins outright for the
keys it pins while a lower scope still supplies the rest. Project-scoped
`.claude/settings*.json` files stay out of scope: the daemon has no single
project cwd, and a checked-out repository's settings are not a machine default.

`model` becomes `model`. `effortLevel` becomes `reasoning_effort`.
`permissions.defaultMode` becomes
`approval_policy`, canonicalizing the `manual` alias to `default`.
`fastMode` becomes `fast_mode_enabled`, with `fastModePerSessionOptIn: true`
forcing the durable default to off because Fast then never persists across
sessions — the same shape as Codex's `fast_default_opt_out` override.
`sandbox.enabled` plus `sandbox.autoAllowBashIfSandboxed` become `sandbox_mode`
(`disabled`, `auto_allow`, or `regular_permissions`); an unset `sandbox.enabled`
stays quiet rather than inferring a mode from the auto-allow flag alone.
`selector_context` carries the resolved value per field and `selector_sources`
carries the `claude_code.<scope>.<json key path>` provenance of the file that
won, so the UI can name the file each value came from.

`effortLevel` is durable: `/effort` writes it into the settings file and
`low`/`medium`/`high`/`xhigh` persist across sessions, so it is a real machine
default and maps to `reasoning_effort`. The value is forwarded exactly as
configured rather than normalized against a known-value list, because the
Configuration surface's contract is to show what the config file says; `max` is
session-only in Claude Code unless the environment sets it, but a settings file
that says `max` is still saying `max`. An absent `effortLevel` leaves
`reasoning_effort` unset — Claude Code's own default is not ours to invent.
Environment variables are never read, so `CLAUDE_CODE_EFFORT_LEVEL` cannot enter
through this path.

The Codex-shaped `service_tier`, `speed_mode`, and `priority_enabled` fields stay
unset, because Claude Code's settings carry no equivalent.

`model` and `effortLevel` are in Claude Code's official settings reference.
`permissions.defaultMode`, `sandbox.enabled`, and
`sandbox.autoAllowBashIfSandboxed` are documented in the permission-mode and
sandboxing guides but are not listed in that reference, so they are mapped
best-effort: when absent, nothing is emitted for the field.

Redaction is allowlist-shaped rather than filter-shaped: only the named
keys are read, so `env`, `apiKeyHelper`, `statusLine`, `permissions.allow`/`ask`/
`deny`, `sandbox.filesystem`, and `sandbox.credentials` are never touched and
cannot ride along. Free-form config text additionally has to survive a scalar
guard that rejects anything long, quoted, whitespace-bearing, path-like, or
URL-like, and `permissions.defaultMode` is matched against a known-value list.
`bypassPermissions` is dropped rather than uploaded: it is a local safety
posture, not a cost-relevant default. The protocol's existing
`redacted_for_backend` guard remains the second line of defence.

Absence is reported honestly instead of as an empty struct. Settings that parse
cleanly but configure none of the mapped keys yield no defaults plus an
unsupported `runtime_defaults` capability and a
`claude_runtime_defaults_not_configured` diagnostic. No readable settings file at
all yields `claude_runtime_defaults_unreadable`, so the UI can distinguish "you
have not configured anything" from "we could not read it".

Validation:

- fixture settings file mapping model, effort level, permission mode, fast mode,
  and sandbox;
- managed-over-local-over-user precedence per key, including a key only the
  lowest scope sets, and local-over-user precedence for `effortLevel`;
- per-session Fast opt-in resolving to a durable default of off;
- `effortLevel` forwarded verbatim, including `max`;
- unsafe `effortLevel` values (path-shaped, non-string) rejected while a sibling
  key still resolves;
- `reasoning_effort` unset when `effortLevel` is absent, even alongside
  `alwaysThinkingEnabled` and a `MAX_THINKING_TOKENS` env entry;
- nothing-configured and unreadable outcomes kept apart from each other;
- redaction case proving paths, secrets, permission rules, and
  `bypassPermissions` never reach `selector_context`/`selector_sources`;
- path-shaped `model` value rejected while a sibling key still resolves;
- backend-facing `redacted_for_backend` round trip over the emitted defaults.

Reaching production needs a macOS stable release carrying this daemon plus a
`public_runtime_pin.json` bump on the server side. Both are owner-gated and are
not part of this change.
