# Support

Pick the channel that fits your question. Public channels are visible to
everyone, so keep account details and anything private out of them.

| You need help with | Go to |
| --- | --- |
| Installing, setting up, or troubleshooting Ottto | [The docs](docs/README.md) |
| A reproducible bug or a feature idea | [GitHub issues](https://github.com/ottto-ai/ottto/issues/new/choose) |
| Your account, billing, organization, or anything private | [support@ottto.net](mailto:support@ottto.net) |
| A security vulnerability | [Private report on GitHub](https://github.com/ottto-ai/ottto/security/advisories/new), or [security@ottto.net](mailto:security@ottto.net); see [SECURITY.md](SECURITY.md) |
| A code of conduct concern | [conduct@ottto.net](mailto:conduct@ottto.net); see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |

Never report a security problem in a public issue.

## 1. Start With The Docs

- [Install](docs/install.md), [Setup](docs/setup.md), and
  [Troubleshooting](docs/troubleshooting.md) cover the most common problems.
- `ottto doctor --json` checks your local setup and names the next action.
- For public-safe triage, diagnostics, escalation, update, and rollback
  expectations, use the support runbook in [`docs/support.md`](docs/support.md).

## 2. Bugs And Feature Requests: GitHub Issues

- Use the [issue forms](https://github.com/ottto-ai/ottto/issues/new/choose).
  Search [existing issues](https://github.com/ottto-ai/ottto/issues) first and
  add to a matching one instead of opening a duplicate.
- Issues are public: follow [What To Include](#what-to-include) and
  [Do Not Include](#do-not-include) below.
- Feature requests start as an issue so the change can be discussed before
  anyone writes code. See [CONTRIBUTING.md](CONTRIBUTING.md).

## 3. Account, Billing, And Private Help: support@ottto.net

Email [support@ottto.net](mailto:support@ottto.net) for anything tied to your
Ottto account or organization: billing and subscriptions, sign-in and setup
claims, support claims for diagnostics uploads, data and privacy requests, or a
problem you cannot describe without private details. This is the only channel
where we handle account data.

## What To Include

- Ottto version and installation method.
- macOS version and architecture.
- The command you ran and the redacted error output.
- Whether the issue affects setup, status, verify, doctor, fix, diagnostics,
  update, uninstall, or connector manifests.
- From `ottto diagnostics collect --json`, only a short summary: the command
  family, exit code, high-level status, support bundle state, redaction
  summary, and next action. Do not attach raw diagnostics JSON or bundles to a
  public issue; if a maintainer needs more, arrange it privately through
  [support@ottto.net](mailto:support@ottto.net).

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

Only the latest stable release is supported. If you are on an older version,
update first and check whether the problem remains.

Maintainers aim to give a first response to new issues within 5 working days.
That is a target, not a guarantee, and there is no promised time to a fix.
