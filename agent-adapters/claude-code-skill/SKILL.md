---
name: ottto
description: Manage the Ottto local platform lifecycle from Claude Code with the public JSON ottto CLI. Use when asked to install or start Ottto, connect an account, set up or verify apps, run doctor/fix, update, uninstall, or collect redacted diagnostics.
---

# Ottto Local Lifecycle For Claude Code

Use this project skill from Claude Code as `/ottto` or when the user asks for
Ottto local setup, verification, repair, diagnostics, update, or uninstall work.
This mirrors the Codex `ottto` lifecycle skill while following Claude Code's
project skill format.

This v1 skill intentionally defines no `allowed-tools`, no `hooks`, and no
monitor setup. Use Claude Code's normal permission model. Do not create or edit
Claude Code hooks, status-line monitors, or local settings as a shortcut.

## Required Interface

Use the installed Rust `ottto` CLI. It is the stable developer, support, CI, and
AI-agent surface over the per-user `ottto-service` daemon.

Always pass `--json` for output you consume. `--json --watch` emits compact
NDJSON progress events plus one final event; do not treat it as one JSON object.

Do not parse human output, directly edit `~/.claude/settings.json`, inspect
Anthropic credentials or browser cookies, call private Anthropic endpoints, call
the retired `tools/ottto-companion` path, or bypass browser/setup authority.

Supported public app values are `codex`, `claude-code`, and `pi`. For a user
asking about "Claude Code setup", default to `--app claude-code`; use other apps
only when the user asks for whole-machine or cross-app Ottto work.

## Install And Baseline Status

Check for the CLI first:

```bash
command -v ottto
```

If `ottto` is missing, do not emulate local platform behavior. For trusted
internal repo QA only, and only when the user has approved an internal dev
package, install the dev runtime from the checked-in manifest:

```bash
tools/ottto-local-platform/scripts/macos_dev_install.sh \
  --manifest tools/ottto-local-platform/dist/macos/release-manifest.json \
  --bootstrap-launch-agent
```

For customer or stable-channel installs, use the published Ottto installer or
Homebrew instructions for the active release channel.

Start with:

```bash
ottto status --json
ottto account --json
ottto apps --json
```

Refresh when current app state matters:

```bash
ottto status --refresh-agent-status --json
ottto apps detect --json
ottto apps status --app claude-code --json
```

Common exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Invalid request or arguments |
| `10` | Daemon unavailable |
| `11` | Local daemon authentication failed |
| `12` | Local app client is not trusted |
| `13` | This Mac is connected to another Ottto account and needs reset |
| `14` | Backend unreachable |
| `15` | Backend rejected the request |
| `16` | Backend unavailable |
| `17` | Backend response was unexpected |
| `20` | App/source unsupported |
| `21` | App/source not found |
| `30` | Repair is locked by another local operation |
| `40` | Network unavailable |
| `50` | Permission denied |
| `60` | Setup needs user or browser action |
| `61` | Setup timed out |
| `70` | Internal error |

Inspect both JSON payloads and exit codes. Setup can return a parseable payload
with a nonzero exit code.

## Account And Setup

Use setup when connecting the Mac from the Apps page:

```bash
ottto setup --json
ottto setup --json --no-browser --no-wait
ottto setup --claim-code <code> --json
```

Use login for sign-in or account reconnect:

```bash
ottto login --json
ottto login --json --no-browser --no-wait
ottto account --json
```

Default setup/login opens the browser and waits up to the command timeout. In a
headless Claude Code flow, use `--no-browser --no-wait`, then surface the JSON
`claim_url` or `claim_code` to the user. Exit code `60` means browser/user
action is still needed; exit code `61` means the wait timed out.

Logout is cloud-first:

```bash
ottto logout --json
```

Use local-only cleanup only as the explicit emergency path after the CLI says
cloud disconnect cannot complete or the user approves it:

```bash
ottto logout --local-only --json
```

## Verify And Repair Claude Code

Prefer these commands for the Claude Code app:

```bash
ottto apps status --app claude-code --json
ottto verify --app claude-code --json
ottto verify --repair --app claude-code --json
ottto doctor --json
ottto fix --app claude-code --json
```

Run `doctor` before `fix` when diagnosing. Plain verify is read-only and reports
config drift; `verify --repair` may repair only daemon-owned WriteConfig drift.
Apply repair only through daemon-approved commands; do not write telemetry
environment variables, Claude settings, status-line config, or local auth files
directly.

Repair JSON includes plan `authority` and per-action `approval`. Treat terminal
repair as allowed only when `authority.mode` is `server_backed_setup_action`,
`authority.terminal_approval_allowed` is `true`, and mutating actions report
terminal or no approval with setup-safe server-backed metadata. If
`authority.browser_approval_required` is `true`, an action has `approval.surface`
set to `browser`, the account/setup binding is stale, or the repair touches
credential or auth-adjacent material, present the browser/setup next action and
stop.

## Diagnostics, Update, And Uninstall

Collect local redacted diagnostics:

```bash
ottto diagnostics collect --json
```

Upload diagnostics only after explicit user approval, retention disclosure
acceptance, and either an active login or a support claim:

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

Check updates before applying:

```bash
ottto update check --json
ottto update --json
```

Only uninstall after the user asks for removal:

```bash
ottto uninstall --json
```

## Reporting

Report the command family, exit code, high-level JSON status, and next action.
Prefer concise summaries over full payloads, and keep secrets, raw local paths,
prompts, account IDs, machine IDs, credential material, and command output out
of chat.
