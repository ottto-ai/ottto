# Security Policy

Thank you for helping keep Ottto and its users safe. This policy covers the code
in this repository: the `ottto` CLI, the `ottto-service` local service, the
connector SDK/testkit, installers, and release tooling.

## Reporting a Vulnerability

Please report vulnerabilities privately. Do not open a public issue or pull
request about them, and keep the details private for the period described in
[Coordinated Disclosure](#coordinated-disclosure).

1. **Preferred: GitHub private vulnerability reporting.** Open
   <https://github.com/ottto-ai/ottto/security/advisories/new>, or go to the
   repository's **Security** tab and choose **Report a vulnerability**. The
   report stays private between you and the maintainers.
2. **If you cannot use GitHub:** email
   [security@ottto.net](mailto:security@ottto.net).

Do not include raw secrets, authentication tokens, API keys, private prompts,
private output, or customer data in the initial report.

Include:

- The affected Ottto version and installation method (the `current_version`
  and `channel` from `ottto update check --json`, and Homebrew, Ottto.app, or
  the hosted installer).
- The operating system and architecture.
- A concise description of the impact.
- Minimal reproduction steps that do not expose third-party secrets.
- Any relevant redacted diagnostics produced by `ottto diagnostics collect`.
- Whether you used AI tools to find the issue or to write the report. Reports
  must describe a problem you have reproduced yourself.

## What To Expect

- **Acknowledgement within 7 days**, usually sooner.
- We then confirm the issue, ask for more information, or explain why we do not
  consider it a vulnerability.
- While the report is open, we keep you informed of progress and work out the
  fix and the disclosure date with you.
- If you have had no acknowledgement after 7 days, email
  [security@ottto.net](mailto:security@ottto.net) with "Follow-up" in the
  subject and a link to your report.

## Coordinated Disclosure

- Please keep technical details private until we publish a fix or an advisory,
  or until 90 calendar days after you first reported the issue, whichever comes
  first. The 90 days run from your report, even if we have not acknowledged it,
  fixed it, or published an advisory by then.
- We can agree on a different date together: earlier, for example if the issue
  is being actively exploited, or later for a complex fix. Please tell us before
  you publish.
- For a confirmed vulnerability that affects a released version, we publish a
  GitHub Security Advisory in this repository and request a CVE ID through
  GitHub when one is warranted.
- We credit reporters in the advisory unless they ask us not to.
- The advisory names the affected versions and, once one exists, the fixed
  version. If no fix is available yet, the advisory says so and describes known
  mitigations. Homebrew users update with
  `brew update && brew upgrade ottto && brew services restart ottto`.

## Supported Versions

Security updates are provided for the latest stable public release of Ottto.
Preview, development, and unreleased builds are supported for coordinated
testing only and may be replaced instead of patched.

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
- Ottto's hosted web app and API. This policy, including its Safe Harbor, does
  not authorize testing them. If you come across a vulnerability in them,
  report it privately to [security@ottto.net](mailto:security@ottto.net).

## Safe Testing

Use your own accounts and local machines. Do not access, modify, or exfiltrate
data that is not yours. Stop testing and report the issue if you encounter
private data, secrets, or account access that you did not explicitly create.

## Safe Harbor

We will consider your security research to be authorized if you make a good
faith effort to comply with this policy during your security research. If
research within this policy's scope would otherwise break a restriction in
Ottto's [Terms of Service](https://app.ottto.net/terms), such as its
"Restrictions" or "Acceptable use" rules, we waive that restriction for that
research, and you do not need to contact us before you start. We will not sue
you for attempting to circumvent the technological safeguards we have put in
place to protect the applications in scope. If a third party takes legal action
against you for activities carried out in accordance with this policy, we will
make this authorization known.

For inadvertent, good-faith violations of this policy, we will not take civil
action or file a report with law enforcement, unless the law requires us to
report. Before doing anything that may be inconsistent with or unaddressed by
this policy, please contact us by submitting a report.

These permissions and commitments cover only research within this policy's
scope, and only rights and claims that Ottto controls. They do not authorize
testing third-party systems, such as the AI coding tools and providers that
Ottto reads from, and they do not bind third parties or public authorities;
their own terms still apply to you. Nothing in this policy prevents Ottto from
making a disclosure that the law requires.

This section is adapted from the [disclose.io](https://disclose.io) Simple Safe
Harbor text (CC0 1.0).

## No Bug Bounty

Ottto does not run a bug bounty program and does not pay for vulnerability
reports. We are grateful for responsible reports and credit reporters as
described above.
