# Claude Code Source Package

Claude Code remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back local enriched usage, live telemetry setup, and documented status-line quota evidence.

Collectors:

- `local_sessions`: reads local Claude Code project JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry environment/settings capability.
- `quota_status`: existing Claude Code subscription quota from documented status-line evidence or Claude Code OAuth.
- `desktop_quota_status`: setup-gated Claude Desktop quota. It decrypts `sessionKey` and `lastActiveOrg` in memory, polls the active organization's usage endpoint at most every five minutes, and persists only normalized quota values.
- `identity_probe`: subprocesses `claude auth status --json`, reads `~/.claude/settings.json` env values, and reads narrow Claude Desktop app-managed metadata (`config.json`, `claude-code-sessions/local_*.json`, and `local-agent-mode-sessions/local_*.json`) to surface per-machine CLI/Desktop identity for observation-time billing attribution. Never reads token bytes, Keychain items, browser state, prompts, responses, or audit logs.

Raw prompts, responses, tool output, command output, local paths, cookies, and provider credentials must not be uploaded by these collectors. Claude Desktop cookie and Keychain bytes must not be stored by Ottto.
