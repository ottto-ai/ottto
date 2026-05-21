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
