# Ottto Local Platform Public Docs

These docs are the public entrypoint for installing, setting up, verifying, and
supporting the Ottto local platform on macOS. They assume a released `ottto`
CLI and `ottto-service` daemon, not private development scripts.

## Start Here

- [Install](install.md): install owners, service start, update, and uninstall.
- [Setup](setup.md): browser setup, headless setup, account commands, and app
  verification.
- [Privacy](privacy.md): local data boundaries, telemetry modes, redaction, and
  opt-out behavior.
- [Diagnostics](diagnostics.md): local-only diagnostics and approved support
  uploads.
- [Support Runbook](support.md): public-safe triage, diagnostics, escalation,
  and closeout support-readiness checks.
- [Connector Contribution](connectors.md): source package and collector
  manifest expectations.
- [Cloud Connectors](cloud-connectors.md): safe planning, keyless registration,
  testing, status, and explicit sync through the local daemon.
- [Agent Adapters](agent-adapters.md): Codex and Claude Code lifecycle adapter
  boundaries, Pi CLI usage, and the public-v1 MCP deferral.
- [Active Session Surfaces](session-surfaces.md): canonical Desktop, CLI,
  exec, and SDK provenance in local active-session status.
- [Claude Accounts](claude-accounts.md): default and registered credential
  slots, full-meter identity gates, partial statusLine data, and local failure
  isolation.
- [Codex Accounts](codex-accounts.md): additive default and durable
  connections, exact user/workspace validation, quota collection, and
  duplicate prevention.
- [Release Verification](release-verification.md): checksums, signing,
  notarization, SBOM, and provenance checks.
- [Troubleshooting](troubleshooting.md): common exit codes and recovery steps.
- [Examples](examples.md): copy-ready JSON workflows for agents and support.

## Automation Contract

Automation should consume only `ottto --json` output. Human summaries are for
people and are not a parsing contract.

`--json --watch` emits newline-delimited JSON progress events and a final event;
plain `--json` emits one final JSON object.

## Public Surface

Customer-facing commands use app language:

```bash
ottto apps --json
ottto context --json
ottto apps detect --json
ottto apps status --app codex --json
ottto setup --json
ottto verify --app claude-code --json
ottto verify --repair --app claude-code --json
ottto fix --app claude-code --json
ottto config show --json
ottto diagnostics collect --json
```

`ottto config` reads and writes `settings.json` in the per-user support
directory. Settings persisted there survive `brew upgrade` and
`brew services restart`, which regenerate the LaunchAgent plist and drop any
environment variables set on it. A matching environment variable still
overrides the persisted value for the process that carries it.

Lower-level source nouns can still appear in protocol payloads and compatibility
options, but public docs should prefer `apps` and `--app`.
