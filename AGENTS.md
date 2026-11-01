# Working in Ottto

- Follow [CONTRIBUTING.md](CONTRIBUTING.md). The root Cargo workspace owns
  runtime/CLI/protocol; `crates/Cargo.toml` owns connector SDK/testkit. Check both
  only when the change affects both.
- Daemon (`crates/ottto-service`) work: read [its ARCHITECTURE.md](crates/ottto-service/ARCHITECTURE.md) first.
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
- Iterate on CI, not on the local machine. A local `cargo check -p ottto-service`
  takes several GB of memory and every core for minutes, and many agents may
  share one machine. For compile and test feedback, push a branch and run the
  free Linux lane on it: `gh workflow run linux-tests.yml --ref <branch>`, then
  read `Rust tests (Linux)`. Pull-request runs use no macOS runner either: the
  macOS `Rust contracts` job runs only in the merge queue, on manual dispatch and
  in the daily `main` cache refresh. Build locally only when
  no CI path works: one changed crate, one build at a time, on an idle machine,
  and say why in your report. Linux unit-test builds also run the heap-layout
  (`layout_supported()`) paths; macOS APIs, tools and `cfg(target_os = "macos")`
  tests still run only on the Mac. A Linux green is fast feedback, not Mac evidence;
  the macOS `Rust contracts` job in the merge queue stays the merge gate.
- CI runs on ready pull requests. Draft pushes start no jobs; marking the PR
  ready (the merge guard does) starts both workflows. For feedback on a draft,
  dispatch `linux-tests.yml` on its branch. Do not also start Public CI by
  hand on a branch whose ready PR is open and mergeable. GitHub starts no pull-request
  run while a PR has merge conflicts (`gh pr view <n> --json mergeable`): rebase
  onto `main` and push. Start Public CI by hand (`workflow_dispatch`) only for a
  `main` commit with no push run, a branch with no PR (for example a red-test
  proof), a dispatch-only job the branch adds, or macOS evidence before you
  enqueue a change with macOS-only risk (native code, clippy `-D warnings`,
  macOS-only tests, `scripts/mac_batch.py detect` exit 10): `gh workflow run ci.yml
  --ref <branch>`. Every macOS dispatch (full, `rust_test_filter` partial or
  `money_equivalence`) runs once per head and only after `Rust tests (Linux)` is
  green on that head; never restart a run because it is queued. Do not put `[skip ci]` in PR commits. Merge
  only after a green pull-request run on the final head.
- Several PRs waiting for macOS evidence share one run:
  `scripts/mac_batch.py plan <pr> <pr>...` merges their heads onto `main` in
  memory and names conflicting pairs; `dispatch --gate <script>` pushes a
  temporary `mac-batch/*` branch and starts one `ci.yml` run after the gate says
  go; `report --run <id> --delete-branch` maps failing tests to PRs, and also
  reads a merge-queue run (a train PR's members are its `train: merge #<n>`
  commits). `detect <pr>`
  tells from the diff alone whether a PR needs macOS evidence (exit 10).
- Merge only with `scripts/pr_merge_when_mac_green.sh <pr>`. It marks a draft
  ready, waits until the pull-request checks on the PR's head commit pass
  (`ci.yml`: `Public surface checks`, `Rust advisory audit`, `Dependency review`,
  with macOS `Rust contracts` skipped on pull requests; `linux-tests.yml`: `Rust
  tests (Linux)`, `Rust format (Linux)`), and enqueues
  exactly that head. `main`'s ruleset requires `Rust contracts`, `Public surface
  checks` and `Rust advisory audit` in the merge queue. `gh pr checks` exit 0 is
  not evidence, and no Linux job stands in for the macOS `Rust contracts` job.
- `main` has a merge queue: the guard enqueues the PR and waits for the merge (default timeout 2 h; rerunning it for a queued PR resumes the wait). The queue retests the PR on top of `main` and the PRs ahead of it, including the macOS `Rust contracts` job; a PR that fails there is removed (exit 4, with the failing run): fix it, push and rerun the guard.
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
