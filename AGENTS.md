# Working in Ottto

- Follow [CONTRIBUTING.md](CONTRIBUTING.md). The root Cargo workspace owns
  runtime/CLI/protocol; `crates/Cargo.toml` owns connector SDK/testkit. Check both
  only when the change affects both.
- Make small, cohesive changes. Read callers and state ownership first; separate
  mechanical refactoring from behavior changes. Use private modules and narrow
  interfaces; preserve public paths. File length alone does not justify a split.
- Preserve CLI/wire contracts, canonical bytes/hashes, persisted formats, and
  account attribution. Preserve lock and side-effect ordering, credential/privacy
  protections, and checkpoint/receipt/retry/recovery semantics unless the task
  explicitly changes them. Keep manifests and lockfiles unchanged unless needed.
- Before consolidating similar code, compare preconditions and failure handling.
  Repeated boundary checks and distinct settlement outcomes may be intentional.
- Coordinate with existing owners before editing shared files. For authorized
  parallel work, use disjoint ownership and one integration owner. Preserve
  unrelated working-tree changes.

# Checks and tools

- Use existing Cargo tooling and CI. Establish an affected baseline once, run
  compile/focused tests per code patch, then existing formatting, Clippy, and
  changed-crate tests at integration. See [.github/workflows/ci.yml](.github/workflows/ci.yml)
  for exact commands. Report failures and concrete unverified limits.
- Add regression tests for changed decisions, not tests that mirror unchanged
  code. Preserve test discovery, fixtures, platform gates, and environment
  isolation when moving tests. Update source-path validators without weakening them.
- Locally, check and test only the crates you changed (`cargo check|test -p <crate>`).
  Full-workspace `cargo build`/`cargo test` runs only in GitHub CI: push a PR and
  read its result. Coordinate heavy local builds.
- CI runs on pull requests. Push to the PR branch; do not also start Public CI by
  hand on a branch whose PR is open and mergeable. GitHub starts no pull-request
  run while a PR has merge conflicts (`gh pr view <n> --json mergeable`): rebase
  onto `main` and push. Start Public CI by hand (`workflow_dispatch`) only for a
  `main` commit with no push run, a branch with no PR (for example a red-test
  proof), or a dispatch-only job the branch adds; one run per head, and never
  restart a run because it is queued. Do not put `[skip ci]` in PR commits. Merge
  only after a green pull-request run on the final head.
- Merge only with `scripts/pr_merge_when_mac_green.sh <pr>`. It marks a draft
  ready, waits until the four `ci.yml` checks of the pull-request run on the PR's
  head commit pass (macOS `Rust contracts`; Linux `Public surface checks`, `Rust
  advisory audit`, `Dependency review`), and squash-merges exactly that head.
  `main`'s ruleset also requires `Rust contracts`. `gh pr checks` exit 0 is not
  evidence, and no Linux job stands in for the macOS `Rust contracts` job.
- The author merges its own reviewed, green, mergeable PR; no merge window, slot
  or extra approval is needed. Wait only for a real dependency or conflict, an
  explicit dated hold, or an announced release freeze.
- Use macOS for native behavior. Use synthetic fixtures rather than live
  credentials or provider accounts.
- No additional skill, dependency, coverage quota, report, or validation gate is
  required merely for refactoring. Use extra tooling only for a concrete need.
- Before handing off or merging substantive changes, the implementing agent runs
  the local [AutoReview workflow](agent-adapters/autoreview/SKILL.md) after relevant
  tests. Use one stable PR/task identity, standard review for ordinary behavior and
  strict for sensitive invariants. Cosmetic or purely mechanical changes may skip
  with a concrete reason; report skipped/unavailable review honestly.

# Public export

- Keep public files standalone and free of secrets, customer data, private repo
  references, and operator paths. Follow the contribution/export tooling already
  in this repo.
- New root export files need `public-export/roots.txt` and `public-export/path-map.tsv`
  entries. `PUBLIC_EXPORT_MANIFEST.json` is derived from the commit tree
  (`scripts/public_repo_manifest.sh --facts`); never commit it, and resolve a
  conflict on it with `git rm PUBLIC_EXPORT_MANIFEST.json`. Run relevant
  export/contract checks when their inputs change.
