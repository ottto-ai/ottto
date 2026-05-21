# Agent Adapters

Ottto public v1 exposes agent integrations as thin workflow instructions over
the stable `ottto --json` CLI. Agent adapters help an agent discover the right
commands, but `ottto-service` remains the runtime owner for setup, repair,
diagnostics, update, uninstall, local state, and approval boundaries.

## Supported V1 Adapters

- Codex uses the exported `agent-adapters/codex-skill/` skill.
- Claude Code uses the exported `agent-adapters/claude-code-skill/` skill.
- Pi is supported through the same public CLI app value, `--app pi`, and public
  examples. It does not need a separate v1 adapter package.

Every adapter must:

- consume machine-readable `ottto --json` output instead of human text
- use public `--app` commands where available
- preserve browser-claim-first setup and browser-required repair boundaries
- avoid direct edits to agent config, credentials, cookies, hooks, status-line
  monitors, or local source files
- summarize redacted status facts instead of pasting raw diagnostics payloads

## MCP Decision

The MCP adapter is intentionally deferred for public v1. An MCP server can be
added later only if it wraps the stable CLI or local-control protocol, keeps
the same explicit user approval boundaries, and improves real setup or support
workflows beyond what the CLI and skills already provide.

An MCP adapter must not own setup authority, repair authority, diagnostics
upload authority, update ownership, local credential access, or source
collection policy. It must also ship with contract tests that prove it cannot
bypass browser approval, terminal-approval limits, diagnostics upload consent,
or install-owner routing.

Until that evidence exists, the public export must not include an MCP server,
MCP plugin, MCP tool registry, or MCP-specific setup path. Agents should use the
Codex skill, Claude Code skill, or the JSON CLI examples instead.
