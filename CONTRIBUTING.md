# Contributing

Thanks for helping improve Ottto. This repository holds the `ottto` CLI, the
`ottto-service` local service, and the source packages that teach Ottto to read
each coding agent's local data.

## Find Your Path

- **Fix a typo or a doc:** edit the file on GitHub and open a pull request. No
  issue or local setup needed.
- **Fix a bug:** open a pull request with a reproduction, and link the issue if
  there is one. Issues labeled `good first issue` and `help wanted` are open to
  anyone; say in a comment that you are taking one.
- **Add a feature, support a new agent, or change CLI output:** open an issue
  first (see [Open An Issue First](#open-an-issue-first)).
- **Report a bug:** use the [issue forms](https://github.com/ottto-ai/ottto/issues/new/choose).
- **Report a vulnerability:** privately, as described in
  [SECURITY.md](SECURITY.md), never in a public issue or pull request.
- **Report harassment or other conduct problems:** email
  [conduct@ottto.net](mailto:conduct@ottto.net).
- **Get help using Ottto:** see [SUPPORT.md](SUPPORT.md).
- **Review and test** open pull requests, or confirm and narrow down bug reports.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Open An Issue First

For a new feature, a behavior change, support for a new agent or data source,
or any change to CLI output, protocol models, or schemas, open an issue before
you write code and wait for a maintainer to agree on the approach. This saves
you from building something we cannot merge.

You can go straight to a pull request for a bug fix with a clear reproduction,
a documentation fix, or a small test improvement.

## What We Are Unlikely To Merge

- Features, behavior changes, or new agents not agreed in an issue first.
- Changes to how usage, cost, or pricing is calculated without agreed tests.
- Changes that weaken privacy defaults, redaction, or diagnostics boundaries.
- Changes to signing, notarization, release publishing, or update trust from
  outside contributors. Report problems there in an issue, or privately if they
  are security-sensitive.
- Large refactors, formatting-only sweeps, or new dependencies without a
  concrete need.

## Development Setup

Ottto builds on macOS 14 or later on Apple silicon; the portable crates also
build and test on Linux. The Rust toolchain, with rustfmt and Clippy, is
pinned in `rust-toolchain.toml`; rustup uses it automatically in this checkout.

Prerequisites, the two Cargo workspaces, the checks to run, and Linux notes are
in [docs/development.md](docs/development.md). Run the smallest set of checks
for what you changed; CI runs the full suite on your pull request.

## After You Open A Pull Request

Mark the pull request ready for review; drafts run no CI. For your first pull
request, a maintainer may need to approve the CI run. Linux checks run on every
push. The macOS checks run only in the merge queue, after a maintainer approves
and queues your pull request; if they fail there, we will tell you what broke
or fix it with you.

## Pull Request Expectations

- **Keep it focused**: one topic per pull request. Separate mechanical
  refactoring from behavior changes.
- **Write a plain, descriptive title.** Pull requests are squash-merged and the
  title becomes the commit subject on `main`. Use the conventional form
  `type(scope): summary`, for example
  `fix(cli): report the install owner in status JSON`.
- **Describe what and why**, link the issue, and list the checks you ran. The
  [pull request template](.github/pull_request_template.md) has the sections.
- **Rust changes need a `Reuse:` line** in the description: what you searched
  for and which existing code you reused or extended. CI also rejects new
  crate- or module-level `#![allow(...)]` and needs a reason on every lint
  suppression. CI reads the description from the last push, so push a commit
  after editing it.
- **Update tests and docs** when behavior, CLI contracts, schemas, connector
  manifests, release metadata, or support workflows change. Add regression
  tests for changed decisions.
- **Put lasting design in `docs/` or a crate's `ARCHITECTURE.md`.** Dated
  session, review, or rollout notes do not belong in this repository.
- **No private material**: follow the checklist in the pull request template.
  Share diagnostics only as the short summary described in
  [SUPPORT.md](SUPPORT.md#what-to-include), never as raw JSON or bundles.
- **Respond to review** by pushing new commits; there is no need to squash or
  force-push during review.

## CLI And Protocol Contracts

The visible CLI help, JSON output, NDJSON watch output, stable exit codes, and
local-control protocol models are compatibility contracts. Update fixtures and
contract tests in the same pull request as any intentional contract change.

## Supporting A New Agent Or Data Source

Open an issue first: name the agent, where it keeps its local data, and whether
reading that data needs credentials. Support usually comes in two parts, often
as separate pull requests:

1. A source package under `connectors/sources/<agent>/` (`source.toml`,
   collector manifests, synthetic fixtures). Copy the shape of `claude-code`,
   `codex`, or `pi`, and see [connectors/README.md](connectors/README.md) and
   [docs/connectors.md](docs/connectors.md). Check it with the connector
   testkit command in [docs/development.md](docs/development.md).
2. Service code in `crates/ottto-service` that reads the data; existing readers
   live in `src/snapshots/sources/`. Read
   [its ARCHITECTURE.md](crates/ottto-service/ARCHITECTURE.md) first.

Collectors that read credentials, inspect sensitive local state, or call
undocumented services stay off by default until a maintainer has reviewed their
risk. Maintainers regenerate `connectors/registry.generated.json`; say in your
pull request when it needs regenerating.

## AI-Assisted Contributions

AI tools are welcome. You own what you submit:

- Understand every change and be able to explain it without asking the tool
  again.
- Verify the change with the relevant checks or CI results, and confirm the
  behavior yourself.
- Say in the pull request if AI wrote a substantial part of it, and which tool.
  Small completions need no note.
- Write issues, pull request descriptions, and review replies in your own
  words. Using a tool to translate or polish your text is fine.
- Every issue and pull request needs a human author who owns it and answers
  review. We close submissions an agent sent on its own.

Maintainers use AI coding agents too. Their changes pass the same CI and merge
queue, and a maintainer is accountable for everything merged and released.

## Maintainers, Decisions, And Response Times

Ottto's maintainers review and merge all changes and make the final call on
scope and design after discussion in issues. If the project gains more
maintainers, we will document how that works.

We aim to reply to new issues and pull requests within 5 working days. We do
not promise merge dates. We may close a pull request after 30 days without a
reply from its author; reopen it when you come back.

## Contribution License

Unless you state otherwise in writing, a contribution you submit for inclusion
in Ottto is licensed under the license of the file it changes. Most files use
the Apache License, Version 2.0; [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) uses
CC BY-SA 4.0. Only submit work you have the right to submit. We do not require
a contributor license agreement.

## For Maintainers

Review, merge, and merge-queue steps for people with write access are in
[AGENTS.md](AGENTS.md#checks-and-tools). Outside pull requests follow the same
path: a maintainer reviews, runs `scripts/pr_merge_when_mac_green.sh`, and sees
the pull request through the merge queue.
