# Development Guide

How to build and check Ottto locally. Start with
[CONTRIBUTING.md](../CONTRIBUTING.md) for how contributions work. Coding agents
working in this repository also follow the execution rules in
[AGENTS.md](../AGENTS.md).

## Prerequisites

- **macOS 14 or later on Apple silicon** for the full build and for anything
  that touches native macOS behavior (Keychain, launchd, app bundle, signing
  checks). The portable crates also build and test on Linux; see
  [Testing On Linux](#testing-on-linux).
- **Rust via rustup.** `rust-toolchain.toml` pins the Rust version and the
  `rustfmt` and `clippy` components, and CI uses the same file. rustup selects
  that toolchain automatically in this checkout; if it is not installed yet,
  run `rustup toolchain install` once from the repository root.
- Xcode Command Line Tools (`xcode-select --install`) on macOS.
- `jq` for schema and registry checks, `python3` for repository scripts, and
  `shellcheck` 0.11.0 if you change shell scripts.

## Two Workspaces

- The root `Cargo.toml` workspace holds the runtime: `ottto-cli`,
  `ottto-service`, `ottto-core`, and `ottto-protocol`.
- `crates/Cargo.toml` is a separate workspace for the connector SDK and
  testkit (`ottto-connector-sdk`, `ottto-connector-testkit`). Pass
  `--manifest-path crates/Cargo.toml` to work on it.

Check both only when your change affects both. Before changing
`crates/ottto-service`, read
[its ARCHITECTURE.md](../crates/ottto-service/ARCHITECTURE.md).

## Checks You Can Run

Run the smallest relevant set for what you changed. CI runs the full suite on
your pull request, and its results count as validation, so you do not need to
build or test the whole workspace locally; a full-workspace build needs several
GB of memory and takes minutes.

```bash
# Formatting (both workspaces)
cargo fmt --all --check
cargo fmt --manifest-path crates/Cargo.toml --all --check

# Lints for the crate you changed
cargo clippy -p <crate> --all-targets --locked -- -D warnings

# Tests for the crate you changed
cargo test -p <crate> --locked

# Connector packages: manifest and fixture contracts
cargo test --manifest-path crates/Cargo.toml -p ottto-connector-testkit --test first_party_sources --locked

# Schemas and the generated connector registry
jq empty connectors/registry.generated.json schemas/*.schema.json

# Public export check (private paths, secret-like content, export roots)
bash scripts/public_repo_export_check.sh

# Shell scripts you changed
shellcheck scripts/<script>.sh
```

For the connector SDK and testkit crates, add
`--manifest-path crates/Cargo.toml` to the clippy and test commands.

Release, installer, and supply-chain changes must also run the targeted
`scripts/test_*.sh` test for the script they change.

## Testing On Linux

Linux CI installs `libsqlite3-dev` and `zsh` and points `TMPDIR` at a private
(`0700`) directory reached through a symlink, because credential-path checks
reject world-writable ancestors such as `/tmp`. Do the same if you run tests on
Linux. Native macOS APIs and `cfg(target_os = "macos")` tests only run on a Mac.

## Tests And The Keychain

Service and CLI dev-dependencies enable core's `test-secret-store` feature. It
keeps test harnesses away from the host Keychain, even when fixture environment
overrides are absent. Core unit tests use the same isolation. Prefer scoped
file fixtures and clean them up; the fallback is a fresh private process-local
temporary directory. Never enable this feature for installed runtime binaries.

Use synthetic fixtures, never live credentials or provider accounts.

## What CI Runs

CI does not run on draft pull requests. On a pull request that is ready for
review, it runs on Linux:

- `Rust format (Linux)` and `Rust tests (Linux)`: formatting, Clippy with
  `-D warnings`, and the runtime and connector test suites;
- `Public surface checks`: schemas, the connector registry, shellcheck,
  repository script tests, and the public export and secret checks;
- `Rust advisory audit` and `Dependency review`.

The macOS job, `Rust contracts`, does not run on pull requests. It runs in the
merge queue, which retests each queued pull request on top of `main`. The exact
commands are in [.github/workflows/ci.yml](../.github/workflows/ci.yml) and
[.github/workflows/linux-tests.yml](../.github/workflows/linux-tests.yml).
