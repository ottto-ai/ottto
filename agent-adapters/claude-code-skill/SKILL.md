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
package with a generated release manifest in this public-shaped checkout,
install the dev runtime through the public macOS dev installer script:

```bash
scripts/macos_dev_install.sh \
  --manifest dist/macos/release-manifest.json \
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

## Cloud Connectors

When the user asks to connect Amazon Bedrock billing, run:

```bash
ottto cloud connect --source bedrock --json --watch
```

The user's request authorizes creating the AWS stack. Use their AWS CLI
sign-in and add `--profile NAME` if they use one. The stack creates one
read-only role. Add `--metrics` only if they ask for CloudWatch usage numbers
and `--reconnect` only if they ask to replace an existing connection.

When `approval_required` appears, tell the user where to approve, using
`detail.where` and `detail.browser_url` when present. The user approves in
the Ottto app with Touch ID or in the browser with their passkey.

Follow the final `next_action`:

- `use_web` or `approve_in_browser` → Share `connect_url`.
- `set_up_on_mac` → Ask the user to open Ottto Settings and set up command-line connect.
- `fix_aws_sign_in` → Ask the user to sign in to AWS and then run `resume.argv`.
- `run_again` → Run `resume.argv` when the user is ready. Keep its
  `--request-id`: it resumes the same attempt instead of creating a new stack.
- `restart` → Explain the change and ask before replacing the open setup.
- For other actions, relay `message`.

Show `cleanup.argv` when present; it appears only for a stack whose attempt
Ottto ended without saving. Run it only if the user asks. When `cleanup` has
`settle_argv` instead, the attempt may still be saving: run that cancel command
before suggesting any cleanup. If the outcome is unclear, run `status_argv`.
Use `ottto cloud status --source bedrock --json` to find an attempt,
`ottto cloud status --attempt ID --json` to read it, and
`ottto cloud cancel --attempt ID --json` if the user asks to cancel.

Google Vertex AI setup starts at <https://app.ottto.net/connections>.
Keep AWS keys, session tokens, setup links, paste codes and Mac setup codes
out of chat and agent tools.

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

Do not ask users to paste support claims into public issues or chat. Support
claims authorize diagnostics upload only and must not appear in returned JSON or
uploaded bundle content; report only whether a support claim was provided.

Check updates before applying:

```bash
ottto update check --json
ottto update --json
```

Only uninstall after the user asks for removal:

```bash
ottto uninstall --confirm --json
```

## Reporting

Report the command family, exit code, high-level JSON status, and next action.
Prefer concise summaries over full payloads, and keep secrets, raw local paths,
prompts, account IDs, machine IDs, credential material, and command output out
of chat.
