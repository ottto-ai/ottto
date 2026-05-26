# Setup

Setup connects this Mac to an Ottto account and prepares local app sources such
as Codex, Claude Code, and Pi.

## Browser Setup

Default setup opens a browser claim and waits for approval:

```bash
ottto setup --json
```

If setup completes, exit code `0` means the Mac is connected. If setup needs
browser or user action, the CLI can still return a parseable JSON payload with a
nonzero exit code.

## Headless Setup

Agents and SSH sessions should skip browser auto-open and return the claim
payload immediately:

```bash
ottto setup --json --no-browser --no-wait
```

Show the returned `claim_url` or `claim_code` to the user. Exit code `60` means
browser or user action is required. Exit code `61` means a wait timed out.

If the Apps page gives a claim code:

```bash
ottto setup --claim-code <code> --json
```

## Account Commands

Use login for reconnect or sign-in:

```bash
ottto login --json
ottto login --json --no-browser --no-wait
ottto account --json
```

Logout disconnects cloud state before local cleanup:

```bash
ottto logout --json
```

Use local-only logout only as an explicit emergency cleanup path after cloud
disconnect cannot complete or the user asks for it:

```bash
ottto logout --local-only --json
```

## App Status And Verification

Refresh all supported app statuses:

```bash
ottto apps detect --json
```

Check or verify one app:

```bash
ottto apps status --app codex --json
ottto apps status --app claude-code --json
ottto verify --app codex --json
ottto verify --app claude-code --json
ottto verify --repair --app codex --json
```

Plain verify is read-only and returns `config` state with a `sha256:`
fingerprint plus drift details. `verify --repair` is limited to daemon-owned
WriteConfig repair for Codex and Claude Code; Pi keeps its existing verification
flow and has no config patching. Do not hand-edit local Codex, Claude Code, or
Pi config as a setup shortcut.

## Stable Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success or setup complete |
| `2` | Invalid request or arguments |
| `10` | `ottto-service` unavailable |
| `14` | Backend unreachable |
| `16` | Backend unavailable |
| `50` | Permission denied |
| `60` | Setup needs user or browser action |
| `61` | Setup timed out |
| `70` | Internal error |
