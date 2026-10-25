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

## Local Checks

Run the smallest relevant checks first. For broad changes, run:

```bash
cargo fmt --check
cargo test
cargo test --manifest-path crates/Cargo.toml -p ottto-connector-testkit --test first_party_sources
jq empty connectors/registry.generated.json schemas/*.schema.json
bash scripts/public_repo_export_check.sh
```

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
ready, waits until the four Public CI (`ci.yml`) checks of the pull-request run
on the PR's head commit passed (macOS `Rust contracts`; Linux `Public surface
checks`, `Rust advisory audit` and `Dependency review`), and then squash-merges
exactly that head (`--match-head-commit`); other checks are informational.
`main`'s ruleset also requires `Rust contracts`. The script refuses a PR with
merge conflicts: rebase onto `main` and push first. `gh pr checks` exit 0 is not
evidence, no Linux job stands in for the macOS `Rust contracts` job, and a
manually started (`workflow_dispatch`) run tests the branch head, not the merge
with `main`.

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
