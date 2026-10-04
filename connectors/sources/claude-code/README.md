# Claude Code Source Package

Claude Code remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back local enriched usage, live telemetry setup, and documented status-line quota evidence.

Collectors:

- `local_sessions`: reads local Claude Code project JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry environment/settings capability.
- `quota_status`: existing Claude Code subscription quota from documented status-line evidence or Claude Code OAuth.
- `identity_probe`: derives the Claude Code login from local metadata (`.claude.json` and the stored Claude Code credential's deadlines, token presence, scopes and plan) without running any Claude command, reads `~/.claude/settings.json` env values, and reads narrow Claude Desktop app-managed metadata (`config.json`, `claude-code-sessions/local_*.json`, and `local-agent-mode-sessions/local_*.json`) to surface per-machine CLI/Desktop identity for observation-time billing attribution. Never stores, logs or uploads token bytes; never reads browser state, prompts, responses, or audit logs.

The daemon keeps Claude logins signed in with one waiting background refresh per login near access expiry, and its other short Claude runs wait out a 15-minute quiet window before expiry. See `POLICY.md`.

Raw prompts, responses, tool output, command output, local paths, cookies, and provider credentials must not be uploaded by these collectors.
