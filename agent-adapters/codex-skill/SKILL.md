---
name: ottto
description: Manage the Ottto local platform lifecycle with the public JSON ottto CLI. Use when Codex needs to install or start the local runtime, connect an account, set up apps, check status, verify telemetry, run doctor/fix, update, uninstall, or collect redacted diagnostics.
---

# Ottto Local Lifecycle

Use this skill for Codex-managed Ottto local platform work on macOS. The skill
is intentionally thin: local behavior belongs to `ottto-service`, and agents
should drive it through the public `ottto` CLI contract.

## Required Interface

Use the installed Rust `ottto` CLI. It is the stable developer, support, CI, and
AI-agent surface over the per-user `ottto-service` daemon.

Always pass `--json` for output you consume. `--json --watch` emits compact
NDJSON progress events plus one final event; do not treat it as one JSON object.

Do not parse human output, directly edit Codex/Claude/Pi config files, inspect
browser cookies or OAuth credentials, call the retired `tools/ottto-companion`
path, or bypass browser/setup authority.

Supported public app values are `codex`, `claude-code`, and `pi`. Prefer public
`--app` commands. Use `--source` only when explicitly testing lower-level source
compatibility.

## Install And Start

Check for the CLI first:

```bash
command -v ottto
```

If `ottto` is missing, do not emulate local platform behavior. For trusted
internal repo QA only, install the dev package from the checked-in manifest:

```bash
tools/ottto-local-platform/scripts/macos_dev_install.sh \
  --manifest tools/ottto-local-platform/dist/macos/release-manifest.json \
  --bootstrap-launch-agent
```

For customer or stable-channel installs, use the published Ottto installer or
Homebrew instructions for the active release channel. Do not install a dev
package on a customer Mac unless the user explicitly asks for internal QA.

After install or start, verify daemon reachability:

```bash
ottto status --json
```

By default, the CLI may kickstart the standard per-user service. Use
`--no-autostart` only when testing daemon-unavailable behavior or a custom
socket.

## Baseline Status

Use these commands for the first read:

```bash
ottto status --json
ottto account --json
ottto apps --json
```

Refresh app discovery only when current state matters:

```bash
ottto status --refresh-agent-status --json
ottto apps detect --json
ottto apps status --app codex --json
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

Agents must inspect both JSON payloads and exit codes. Setup can return a
parseable payload with a nonzero exit code.

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

Default setup/login opens the browser and waits up to the command timeout. For a
headless agent flow, use `--no-browser --no-wait`, then surface the JSON
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

## Verify Apps

Verify an app through `ottto-service` and the setup-run/backend-token path:

```bash
ottto verify --app codex --json
ottto verify --app claude-code --json
ottto verify --app pi --json
ottto verify --repair --app codex --json
```

If the app is missing, unsupported, stale, or waiting for browser approval,
report the JSON status and next action. Plain verify is read-only and reports
config drift. `verify --repair` is limited to daemon-owned WriteConfig repair
for Codex and Claude Code; do not hand-edit local app config as a shortcut.

## Doctor And Fix

Run doctor first for read-only health:

```bash
ottto doctor --json
```

Apply repair only through the daemon-approved command:

```bash
ottto fix --app codex --json
ottto fix --app claude-code --json
ottto fix --app pi --json
```

Repair JSON includes plan `authority` and per-action `approval`. Treat terminal
repair as allowed only when `authority.mode` is `server_backed_setup_action`,
`authority.terminal_approval_allowed` is `true`, and mutating actions report
terminal or no approval with setup-safe server-backed metadata. If
`authority.browser_approval_required` is `true`, an action has `approval.surface`
set to `browser`, the account/setup binding is stale, or the repair touches
credential or auth-adjacent material, present the browser/setup next action and
stop. Do not bypass that boundary with direct file writes or secret handling.

## Diagnostics

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

Summarize diagnostics in final responses unless the user asks for exact JSON.
Keep secrets, raw local paths, prompts, IDs, and command output out of chat.

## Update And Uninstall

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

When reporting results, include the command family, exit code, high-level JSON
status, and next action. Prefer concise summaries over full payloads, and call
out any browser/user action that remains.
