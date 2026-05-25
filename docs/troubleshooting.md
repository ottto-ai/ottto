# Troubleshooting

Start with machine-readable status:

```bash
ottto status --json
ottto doctor --json
```

Do not parse human summaries. Use JSON status, error codes, and next-action
fields.

## Common Exit Codes

| Code | Meaning | First response |
| --- | --- | --- |
| `10` | `ottto-service` unavailable | Let CLI autostart once, then check install owner service state. |
| `11` | Local daemon authentication failed | Reinstall or repair local control token through the install owner. |
| `13` | Connected to another account | Ask the user before reset or logout. |
| `14` | Backend unreachable | Check network and retry. |
| `16` | Backend unavailable | Wait and retry; do not clear local credentials. |
| `30` | Repair locked | Wait for the active local operation to finish. |
| `50` | Permission denied | Check macOS permissions and app trust. |
| `60` | Browser/user action needed | Open or share the claim URL/code. |
| `61` | Setup timed out | Rerun setup or use headless setup with claim URL/code. |

## Setup Stuck Waiting

```bash
ottto setup --json --no-browser --no-wait
```

Share the returned claim URL or code with the user. If browser approval already
happened, run:

```bash
ottto status --refresh-agent-status --json
ottto apps detect --json
```

## App Needs Repair

For Claude Code:

```bash
ottto doctor --json
ottto fix --app claude-code --json
ottto verify --app claude-code --json
```

For Codex:

```bash
ottto doctor --json
ottto fix --app codex --json
ottto verify --app codex --json
```

If repair JSON requires browser approval, do not edit config files directly.
Present the browser/setup next action.

## Local Relay Port Conflict

The default local OTLP relay listens on `127.0.0.1:43119`. If another macOS
user account or stale Ottto service already owns that port, `ottto-service`
binds a deterministic per-user fallback port and reports the active endpoint in
`ottto status --json`.

Run the app repair flow after a fallback bind so Codex or Claude Code settings
are rewritten to the active endpoint:

```bash
ottto fix --app codex --json
ottto verify --app codex --json
```

If the stale service belongs to a test user or old login session, also remove
that user's `net.ottto.service` LaunchAgent through the normal macOS account or
install-owner path. Do not kill another user's process unless you own that test
account and have confirmed it is not the active customer install.

## Account Disconnect Problems

Use cloud-first logout:

```bash
ottto logout --json
```

If the backend is unavailable or rejects a stale binding, the CLI should keep
local credentials and point to the explicit emergency path:

```bash
ottto logout --local-only --json
```

Use local-only cleanup only after the user accepts that cloud disconnect did not
complete.

## Support Bundle

```bash
ottto diagnostics collect --json
```

Upload only with explicit approval and retention disclosure acceptance.
