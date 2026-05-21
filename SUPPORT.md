# Support

Use public issues or discussions for reproducible bugs, documentation fixes,
feature requests, connector package questions, and local development help once
the public repository is available.

For account, billing, private organization, or security-sensitive help, contact
Ottto support through the product support channel. Report vulnerabilities to
security@ottto.net instead of opening a public issue.

For public-safe triage, diagnostics, escalation, update, rollback, and launch
closeout expectations, use the public support runbook in
[`docs/support.md`](docs/support.md).

## What To Include

- Ottto version and installation method.
- macOS version and architecture.
- The command you ran and the redacted error output.
- Whether the issue affects setup, status, verify, doctor, fix, diagnostics,
  update, uninstall, or connector manifests.
- Redacted diagnostics from `ottto diagnostics collect` when relevant.

## Do Not Include

- Passwords, cookies, API keys, tokens, setup-run secrets, support claims, or
  raw credentials.
- Raw prompts, raw model output, customer data, or private repository material.
- Full local filesystem paths unless a maintainer explicitly asks for a
  redacted path shape.

## Support Boundaries

The public project supports the Ottto CLI, local service, installer/release
tooling, public connector SDK/testkit, source-package manifests, public schemas,
docs, and thin agent adapters. It does not provide support for third-party
agents, provider accounts, private Ottto backend operations, or unsupported
local modifications except where they expose a bug in the public Ottto surface.
