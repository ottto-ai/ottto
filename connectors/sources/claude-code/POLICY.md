# Claude Code Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it uploads aggregate usage and metadata only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` keeps the existing Claude Code status-line/OAuth behavior.
- `identity_probe` defaults on; it derives the Claude Code login from local metadata (see "Login state and the Claude CLI spawn gate" below) and never runs `claude auth status`. It reads `~/.claude/settings.json` env values and may read the narrow Claude Desktop app-managed metadata paths listed below.

## Documented Surfaces

- Claude Code project JSONL files may be read locally for aggregate usage snapshots.
- Managed telemetry environment/settings may be inspected or written only through the live telemetry setup path.
- The documented status-line `rate_limits` payload may be used for quota evidence when the Ottto wrapper is enabled.
- `identity_probe` reads the same fields `claude auth status --json` printed, from their local sources: `email`, `organizationUuid` and `organizationName` from `.claude.json` `oauthAccount`, and `subscriptionType`, token presence, deadlines and scopes from the stored Claude Code credential. Email never leaves the machine. The organization id leaves the machine only as the raw `organization_id` of the agent-status account block and plan observations, next to its hash.

## Login state and the Claude CLI spawn gate

- The daemon never runs `claude auth status` or `claude doctor`. A short Claude Code command that starts near or after access expiry can begin a token refresh and exit before the rotated token is saved, which signs the login out (anthropics/claude-code#95822).
- Login state comes from `.claude.json`, then the stored credential (the `Claude Code-credentials[-<hash>]` Keychain item read with `security find-generic-password -w`, or `<config>/.credentials.json`), then `.claude.json` again. The credential passes into daemon memory only: the access token is used solely for the documented subscription usage request and is never sent once it is locally expired; the refresh token is checked for presence and never used. Nothing from the item is stored, logged or uploaded. A failed or unavailable Keychain read fails closed.
- Every daemon spawn of the Claude Code CLI goes through one gate with an exact argv allowlist: `--version`; `auth login --claudeai` in an Ottto-managed auth root; `-p /context --output-format json --strict-mcp-config --settings {"disableAllHooks":true}`; and the Verify smoke prompt with the same two switches. The credential-using commands re-read the login immediately before spawning and are refused unless the access token stays valid for Claude Code's 5-minute refresh window, a 10-minute margin and the command's runtime. They start no user MCP servers and no hooks, their credential environment is pinned to exactly the admitted login, and they run in their own process group.
- Every MCP server the inventory probes runs credential-isolated (empty per-probe `CLAUDE_CONFIG_DIR` and `CLAUDE_SECURESTORAGE_CONFIG_DIR`, no credential variables), so a Claude Code started beneath it cannot reach a real login. As defence in depth, servers recognised as Claude Code itself are not started and are reported with a `skipped_reason`.
- `~/.claude/settings.json` may be read for `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`, and similar gateway env values when a Vertex/Bedrock novelty trigger fires. Read-only.
- Claude Desktop app-managed metadata may be read only from:
  - `~/Library/Application Support/Claude/config.json` for `lastKnownAccountUuid`.
  - `~/Library/Application Support/Claude/claude-code-sessions/<account>/<org>/local_*.json` for bounded session recency, org-bucket, and CLI session-id metadata.
  - `~/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<org>/local_*.json` for display-safe account email/name, org/workspace label, plan label if present, recency, and CLI session-id metadata.
  These files may be used to distinguish Claude Desktop Code from Claude CLI when the active Desktop account/org differs from the CLI login. Prompt, response, system prompt, cwd, and tool/audit fields in those files must not be uploaded.

## Undocumented Surfaces

- Do not scrape `/status` or `/usage` UI, browser sessions, cookies, endpoints, browser profiles, or account pages.
- Do not proxy Claude traffic.
- Do not infer plan, speed, or billing selectors from undocumented UI state.
- Token bytes are never stored, transmitted (except the access token to the documented usage request), or logged; the refresh token is never used.
- `identity_probe` does not enumerate `~/Library/Containers/`, browser profiles, Keychain, or broad `/Library/Application Support` paths. The only Application Support exception is the narrow per-user Claude Desktop metadata allowlist above.

## Local-Only Behavior

- Project files and local paths stay on the machine; uploads use aggregate usage, hashed workspace/session identifiers, and collector-health metadata.
- Wrapper status collection must keep status-line evidence bounded to documented JSON fields.

## Upload Boundaries

- Do not upload raw Claude Code prompts, responses, command output, tool output, or local file paths.
- Keep Claude selector context names stable, especially `speed`, `speed_mode`, `service_tier`, `batch_mode`, and residency selectors.
