# Security Policy

## Supported Versions

Security updates are provided for the latest stable public release of Ottto.
Preview, development, and unreleased builds are supported for coordinated
testing only and may be replaced instead of patched.

## Reporting Vulnerabilities

Report suspected vulnerabilities to security@ottto.net. Do not include raw
secrets, authentication tokens, API keys, private prompts, private output, or
customer data in the initial report.

Include:

- The affected Ottto version and installation method.
- The operating system and architecture.
- A concise description of the impact.
- Minimal reproduction steps that do not expose third-party secrets.
- Any relevant redacted diagnostics produced by `ottto diagnostics collect`.

We will acknowledge valid reports as quickly as practical, coordinate on a
fix and disclosure plan, and credit reporters when requested and appropriate.

## Scope

In scope:

- The public Ottto CLI, local service, public connector SDK/testkit, installer
  scripts, release metadata, and documented agent adapters.
- Security boundaries for local setup, local repair authority, diagnostics
  redaction, release verification, and update trust.

Out of scope:

- Social engineering, denial-of-service testing, physical access attacks, and
  issues in third-party services not caused by Ottto.
- Reports that depend on collecting or publishing raw customer data, prompts,
  outputs, credentials, cookies, or tokens.

## Safe Testing

Use your own accounts and local machines. Do not access, modify, or exfiltrate
data that is not yours. Stop testing and report the issue if you encounter
private data, secrets, or account access that you did not explicitly create.
