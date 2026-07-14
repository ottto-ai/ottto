# Claude Code Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it uploads aggregate usage and metadata only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` keeps the existing Claude Code status-line/OAuth behavior.
- `desktop_quota_status` requires explicit setup and owns the Claude Desktop local-session path described below.
- `identity_probe` defaults on; it subprocesses `claude auth status --json`, reads `~/.claude/settings.json` env values, and may read the narrow Claude Desktop app-managed metadata paths listed below. Never reads token bytes or Keychain items.

## Documented Surfaces

- Claude Code project JSONL files may be read locally for aggregate usage snapshots.
- Managed telemetry environment/settings may be inspected or written only through the live telemetry setup path.
- The documented status-line `rate_limits` payload may be used for quota evidence when the Ottto wrapper is enabled.
- When the user explicitly enables Claude Desktop usage in Ottto Settings, `desktop_quota_status` may read the encrypted `sessionKey` and `lastActiveOrg` rows from Claude Desktop's per-user `Cookies` database and request its `Claude Safe Storage` decryption secret from macOS Keychain. The cookie and decryption secret stay in process memory only and must never be logged, uploaded, or persisted by Ottto.
- The enabled Desktop path may call `GET https://claude.ai/api/organizations/{org_id}/usage` no more than once every five minutes. Persist only normalized quota/credit fields and a hashed organization identifier in Ottto's local cache.
- The documented `claude auth status --json` CLI may be subprocessed by `identity_probe` to read `apiProvider`, `authMethod`, `subscriptionType`, `email`, and `orgId` fields. Email and orgId are hashed before emit; raw values never leave the machine.
- `~/.claude/settings.json` may be read for `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`, and similar gateway env values when a Vertex/Bedrock novelty trigger fires. Read-only.
- Claude Desktop app-managed metadata may be read only from:
  - `~/Library/Application Support/Claude/config.json` for `lastKnownAccountUuid`.
  - `~/Library/Application Support/Claude/claude-code-sessions/<account>/<org>/local_*.json` for bounded session recency, org-bucket, and CLI session-id metadata.
  - `~/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<org>/local_*.json` for display-safe account email/name, org/workspace label, plan label if present, recency, and CLI session-id metadata.
  These files may be used to distinguish Claude Desktop Code from Claude CLI when the active Desktop account/org differs from the CLI login. Prompt, response, system prompt, cwd, and tool/audit fields in those files must not be uploaded.

## Undocumented Surfaces

- Do not scrape `/status` or `/usage` UI. The only approved browser-session exception is the setup-gated Claude Desktop `sessionKey` usage request above; do not generalize it to other cookies, endpoints, browser profiles, or account data.
- Do not proxy Claude traffic.
- Do not infer plan, speed, or billing selectors from undocumented UI state.
- `identity_probe` must never access Anthropic Keychain items (`Claude Code-credentials`) or read `~/.claude/.credentials.json`. Token bytes are never read, stored, transmitted, or logged.
- `identity_probe` does not enumerate `~/Library/Containers/`, browser profiles, Keychain, or broad `/Library/Application Support` paths. The only Application Support exception is the narrow per-user Claude Desktop metadata allowlist above.

## Local-Only Behavior

- Project files and local paths stay on the machine; uploads use aggregate usage, hashed workspace/session identifiers, and collector-health metadata.
- Wrapper status collection must keep status-line evidence bounded to documented JSON fields.
- Claude Desktop credential material stays in memory only. The local cache contains normalized quota/credit values, timestamps, and a hashed organization identifier—never a cookie, Keychain secret, or raw API response.

## Upload Boundaries

- Do not upload raw Claude Code prompts, responses, command output, tool output, or local file paths.
- Keep Claude selector context names stable, especially `speed`, `speed_mode`, `service_tier`, `batch_mode`, and residency selectors.
