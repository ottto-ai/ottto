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
- [Agent Adapters](agent-adapters.md): Codex and Claude Code lifecycle adapter
  boundaries, Pi CLI usage, and the public-v1 MCP deferral.
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
ottto apps detect --json
ottto apps status --app codex --json
ottto setup --json
ottto verify --app claude-code --json
ottto fix --app claude-code --json
ottto diagnostics collect --json
```

Lower-level source nouns can still appear in protocol payloads and compatibility
options, but public docs should prefer `apps` and `--app`.
