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
  affected-workspace tests at integration. See [.github/workflows/ci.yml](.github/workflows/ci.yml)
  for exact commands. Report failures and concrete unverified limits.
- Add regression tests for changed decisions, not tests that mirror unchanged
  code. Preserve test discovery, fixtures, platform gates, and environment
  isolation when moving tests. Update source-path validators without weakening them.
- Coordinate heavy builds; use macOS for native behavior. Use synthetic fixtures
  rather than live credentials or provider accounts.
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
  entries. Regenerate `PUBLIC_EXPORT_MANIFEST.json` from the intended clean,
  Git-tracked export inventory; never include unrelated local files. Run relevant
  export/contract checks when their inputs change.
