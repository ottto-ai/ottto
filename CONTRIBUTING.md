# Contributing

Thanks for contributing to Ottto. This repository owns the public local
runtime, CLI, local service, installer/release tooling, connector SDK/testkit,
first-party source packages, manifest schemas, public docs, and thin agent
adapters.

## Before Opening A Pull Request

- Keep changes scoped to the public local-platform surface.
- Do not include secrets, tokens, cookies, raw credentials, raw prompts, raw
  model output, customer data, private planning docs, or local filesystem paths.
- Keep public docs standalone; they must not require private repository context.
- Update tests and docs when behavior, CLI contracts, schemas, connector
  manifests, release metadata, or support workflows change.
- A pull request that changes Rust code carries a `Reuse:` line in its
  description: what you searched for and which existing code you reused or
  extended. Do not add `allow(dead_code)`, `allow(unused...)`, a blanket
  `#![allow(...)]` or `cfg_attr(not(test), allow(...))`; a needed suppression is
  `#[expect(<lint>, reason = "...")]` on the smallest item. The Linux clippy step
  checks both (`scripts/lint_ratchet.sh`); after fixing the description, push a
  commit, because a re-run reads the original one.

## Local Checks

Run the smallest relevant checks first: `cargo fmt --check`, checks or tests of
the one crate you changed (`cargo test -p <crate>`), `jq empty` on changed JSON.
Full-workspace builds and tests run in GitHub CI, not locally: push a branch and
run the free Linux lane (`gh workflow run linux-tests.yml --ref <branch>`), or
open the pull request. A local full-workspace build takes several GB of memory
and every core for minutes, on a machine other agents may share.

Release, installer, and supply-chain changes must also run their targeted
script tests and dry-run gates before review.

For substantive PRs, the implementing agent runs the local
[AutoReview workflow](agent-adapters/autoreview/SKILL.md) after relevant tests:
`scripts/autoreview --change-id pr-123`. Before a PR exists, use the feature branch
name and keep that identity through closeout. Review is invoked by the agent;
it is not scheduled or enforced by GitHub. The default is one discovery review
and, after accepted fixes, one focused verification within 24 hours. Existing
Cargo, native and public-surface checks remain required; review does not replace
them. Small prose, cosmetic or purely mechanical changes may skip with a reason.

## Merging

Merge only with `scripts/pr_merge_when_mac_green.sh <pr>`. It marks a draft
ready, waits until the Public CI (`ci.yml`) checks of the pull-request run on the
PR's head commit passed (Linux `Public surface checks`, `Rust advisory audit` and
`Dependency review`; the macOS `Rust contracts` job is skipped on pull requests
and runs in the merge queue), and then enqueues exactly that head; other checks
are informational. `main`'s ruleset requires `Rust contracts`, `Public surface
checks` and `Rust advisory audit` in the merge queue. For macOS evidence before
enqueueing, run `gh workflow run ci.yml --ref <branch>` once. The script refuses a PR with
merge conflicts: rebase onto `main` and push first. `gh pr checks` exit 0 is not
evidence, no Linux job stands in for the macOS `Rust contracts` job, and a
manually started (`workflow_dispatch`) run tests the branch head, not the merge
with `main`.

`main` has a merge queue: the guard enqueues the PR and waits for the merge (default timeout 2 h; rerunning it for a queued PR resumes the wait). The queue retests the PR on top of `main` and the PRs ahead of it, including the macOS `Rust contracts` job; a PR that fails there is removed (exit 4, with the failing run): fix it, push and rerun the guard.

Authors with write access merge their own pull request once its review is
complete, its pull-request checks passed on the final head and it is mergeable. No
separate merge window, merge slot or extra approval is required. Wait only for a
real dependency or conflict with other open work, an explicit dated hold, or an
announced release freeze.

## Credential Store Tests

Service and CLI dev-dependencies enable core's `test-secret-store` feature.
It keeps test harnesses away from the host Keychain, even when fixture environment
overrides are absent. Core unit tests use the same isolation. Prefer scoped file
fixtures and clean them up; the fallback is a fresh private process-local temporary
directory. Never enable this feature for installed runtime binaries.

## CLI And Protocol Contracts

The visible CLI help, JSON output, NDJSON watch output, stable exit codes, and
local-control protocol models are compatibility contracts. Update fixtures and
contract tests in the same pull request as any intentional contract change.

## Source And Collector Packages

Source and collector manifests must pass the public schemas and Rust testkit.
Collectors that read credentials, inspect sensitive local state, or call
undocumented services must remain off by default until their governance and risk
classification are reviewed.

## Contribution License

Unless you state otherwise in writing, contributions submitted for inclusion in
Ottto are licensed under the Apache License, Version 2.0.
