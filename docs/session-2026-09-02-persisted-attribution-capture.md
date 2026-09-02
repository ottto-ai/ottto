# Claude attribution capture survives an upgrade

## Problem

Claude Code per-turn work attribution (`attributionAgent` and its four
siblings) is a local opt-IN, and the only way to opt in was the process
environment variable `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE`. For a daemon started by
launchd that means the LaunchAgent plist's `EnvironmentVariables` — and that
plist is not the operator's to keep.

`brew upgrade ottto` regenerates `~/Library/LaunchAgents/net.ottto.service.plist`
from the formula's `service` block, which emits `PATH` and nothing else. An
operator-set `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE=on` is therefore erased on every
upgrade, and `brew services restart` reloads the regenerated plist for the same
result. Capture silently reverts to its default OFF.

Nothing anywhere said so. There was no persisted setting to fall back to, no
command that reported the current answer, and no log line at startup. The only
symptom is attribution fields quietly missing from later snapshots — a symptom
that looks exactly like "no subagents ran".

## Change

One persisted setting, one resolution order, one startup line, one command.

### Resolution order

`OTTTO_CLAUDE_ATTRIBUTION_CAPTURE` (explicit override) → persisted setting →
default OFF.

The environment stays at the top so a one-shot
`OTTTO_CLAUDE_ATTRIBUTION_CAPTURE=on ottto-service serve` still wins and no
existing operator habit changes. **The default is unchanged and stays OFF**;
this change only adds a durable step between the override and the default.

`ottto_core::resolve_claude_attribution_capture` owns the order, and both the
daemon and the CLI call it, so there is one implementation to be wrong.

Environment parsing is byte-for-byte what it was: `on`/`1`/`true`/`yes`/
`enabled` (trimmed, case-insensitive) is on, and anything else — including a
word nobody recognizes — is off.

A PERSISTED value is held to a stricter rule: it must be an explicit word in
either direction (`on`/`1`/`true`/`yes`/`enabled`, or `off`/`0`/`false`/`no`/
`disabled`). An unrecognized word is not silently read as "off"; there is no
operator intent in it to honor, so it resolves to `persisted_invalid` and the
built-in default applies. Both answers are `false` today. The difference is
what the source says out loud, and what happens the day the default moves.

### Where it lives

`~/Library/Application Support/Ottto/settings.json`, alongside `account.json`,
`connection.json`, `device.json`, and `machine.json`, written by the same
`0600`-from-creation atomic writer through a `FileSettingsStore` that mirrors
`FileConnectionStore` exactly. No new configuration family and no second file:
the per-user support directory is the one place `brew` never rewrites.

Values are stored as RAW strings, not typed booleans. A word this build does
not recognize must degrade to "invalid, use the default" for that one setting
rather than making the whole file unparseable and taking every other setting
down with it.

### Reading it

`claude_attribution_capture_enabled` is called per transcript LINE, so the
resolved answer is TTL-cached for 60 s behind a `OnceLock<Mutex<..>>`, the same
refresh idiom `launch_events.rs` already uses. That keeps the file off the
per-line path, and it also means a running daemon picks up an `ottto config set`
within a minute instead of at the next restart.

The daemon never writes `settings.json`; only an explicit operator command
does.

A missing, unreadable, or corrupt file resolves to the default OFF and never
stops collection (`FileSettingsStore::load_lenient`). The operator-facing error
belongs to the CLI, which uses the strict `load` and reports the parse failure
with a non-zero exit.

### Saying it

The daemon logs one line at startup, before it spawns any relay:

```
Claude attribution capture disabled (source: default)
```

Source is one of `environment`, `persisted`, `persisted_invalid`, `default`.
No values, no paths, no secrets.

### Operator commands

```bash
ottto config show --json
ottto config set --setting claude-attribution-capture --value on --json
ottto config set --setting claude-attribution-capture --value off --json
```

`config` is local: it reads and writes one file and never touches the control
socket, so it works with the daemon stopped. `--watch` is refused for it —
there is no daemon round trip to stream progress for.

The JSON field is named `resolved_in_this_process` on purpose. The CLI resolves
the order against ITS OWN environment, which is the operator's shell, not the
daemon's. Only `persisted_value` is shared ground between the two; the daemon's
own answer is the startup log line. The human view says the same thing, and
warns explicitly when the shell carries an override:

```
settings file: /Users/<user>/Library/Application Support/Ottto/settings.json
claude-attribution-capture: on (source: persisted)
```

## Verification

- `cargo fmt --all --check`
- `cargo test --workspace --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings` on both
  1.88.0 and 1.97.0
- New coverage: the order resolves env-over-persisted-over-default in both
  directions; environment parsing is asserted unchanged against the exact
  historical token list plus unrecognized input; every recognized persisted
  word in both directions; a malformed persisted word is `persisted_invalid`
  and off; `settings.json` round-trips at `0600` and omits an unset setting
  entirely; a corrupt file is an error for the CLI and the empty settings for
  the daemon; the daemon-side reader honors the persisted value with the
  environment silent, which is the regenerated-plist case; an unusable settings
  file never turns capture on; the frozen `config show` JSON contract; `set`
  persists and re-reads identically from a cold read; an override is reported
  without losing the persisted value; `--watch` is refused.
- Negative control: the resolution order was inverted so persisted was checked
  before the environment. Three tests failed across all three layers —
  `claude_attribution_capture_environment_beats_persisted` (core),
  `claude_attribution_capture_reads_the_persisted_setting_when_the_environment_is_silent`
  (daemon), and
  `config_json_shows_an_environment_override_without_losing_the_persisted_value`
  (CLI) — and passed again once the order was restored.

## Not in this change

- The default. Turning capture on for everyone is a product decision, not a
  persistence fix.
- Preserving unknown keys across a save. `LocalSettings` drops fields it does
  not know, so an older build that runs `config set` would discard a newer
  build's settings. With one setting there is nothing to lose yet; a
  `#[serde(flatten)]` catch-all is the fix when a second one lands.
- Any change to the Homebrew formula's `service` block. Persisting the setting
  outside the plist is the durable answer; making the formula emit the variable
  would only move the same fragility.
