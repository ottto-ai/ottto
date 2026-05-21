# Public Export Gate

This directory defines the local-platform files that are safe to export into
the future public `ottto` repository and the checks that must pass before any
public commit.

The current private monorepo remains the temporary source until the public repo
is reachable. This gate does not create a second runtime source of truth; it
makes the cutover explicit and repeatable.

## Files

- `roots.txt`: tracked files or directories that belong in the public local
  platform export, including public GitHub Actions/Dependabot files,
  Apache-2.0 license/NOTICE/policy files, runtime crates, connector SDK/testkit
  crates, first-party source packages, registry, and public schemas.
- `path-map.tsv`: private monorepo path prefixes and their public repository
  destinations.
- `rewrite-rules.tsv`: known private-repo references that must be rewritten
  during export, such as release attestation repository names.
- `deny-patterns.tsv`: path and content patterns that fail the export check.

Run the export check in no-rewrite mode before bootstrap:

```bash
tools/ottto-local-platform/scripts/public_repo_export_check.sh \
  --require-no-rewrites
```

Generate a root-shaped public repository staging tree:

```bash
tools/ottto-local-platform/scripts/public_repo_export_bundle.sh --force
```

Verify the staged manifest inventory:

```bash
tools/ottto-local-platform/scripts/public_repo_manifest_check.sh \
  --staged-output tools/ottto-local-platform/dist/public-export/ottto
```

Check the staged public repository shape:

```bash
PUBLIC_SKELETON_REPO_ROOT=tools/ottto-local-platform/dist/public-export/ottto \
  tools/ottto-local-platform/scripts/public_repo_skeleton_check.sh
```

Run the pre-public secret scan:

```bash
tools/ottto-local-platform/scripts/public_repo_secret_scan.sh \
  --staged-output tools/ottto-local-platform/dist/public-export/ottto
```

Run the exported public-surface CI smoke:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
tools/ottto-local-platform/scripts/public_repo_surface_ci.sh \
  --staged-output tools/ottto-local-platform/dist/public-export/ottto
```

Plan the public repository bootstrap against a clean target checkout:

```bash
tools/ottto-local-platform/scripts/public_repo_bootstrap_plan.sh \
  --target-dir ../ottto \
  --report public-bootstrap-plan.json
```

The bootstrap plan builds and verifies the bundle, checks that the target is a
clean git repository root outside the private source tree, rejects
private-monorepo-shaped target paths, and prints add/change/delete counts
without mutating the target. The optional report records the source commit,
bundle manifest facts, target safety gates, bundle checks, and relative file
changes without absolute local filesystem paths. Manifest facts include the
per-file record count and deterministic content digest. After reviewing the dry
run, apply the same verified bundle explicitly:

```bash
tools/ottto-local-platform/scripts/public_repo_bootstrap_plan.sh \
  --target-dir ../ottto \
  --report public-bootstrap-apply.json \
  --apply
```

Run the target closeout gate before committing the applied public checkout:

```bash
../ottto/scripts/public_repo_cutover_closeout.sh \
  --target-dir ../ottto \
  --source-repo-root . \
  --bootstrap-report public-bootstrap-apply.json \
  --report public-cutover-closeout.json
```

The bundle defaults to `tools/ottto-local-platform/dist/public-export/ottto`.
It first runs the export check, copies only tracked root files, maps
`tools/ottto-local-platform/` to the public repository root, maps public-root
CI/dependency and policy files to repository root, keeps `connectors/`,
`schemas/`, and connector helper crates in their public paths, maps agent
skills under `agent-adapters/`, refuses rewrite-required source by default, writes a
`PUBLIC_EXPORT_MANIFEST.json` with per-file SHA-256, size, mode, executable-bit
metadata, and a deterministic `content_sha256`, then scans the staged output
for denied paths or content before replacing the output directory.

The check uses `git ls-files`, so untracked build outputs under `dist/` or
`target/` are ignored. It fails when an export root has no tracked files, when a
candidate path is outside the approved public surface, or when candidate
content contains private paths, private docs links, raw tokens, key material, or
secret-like values. Known private-repo references listed in
`rewrite-rules.tsv` are reported as rewrite-required by the plain check and
fail when `--require-no-rewrites` is passed. The bundle passes that stricter
mode by default; `--allow-rewrites` exists only for legacy/test fixtures.

After bundling, run `scripts/public_repo_skeleton_check.sh` against the staged
tree and `scripts/public_repo_manifest_check.sh --staged-output ...` against
the same root. The skeleton gate verifies the public root has the expected
runtime crates, connector SDK/testkit workspace, connector packages, schemas,
public docs, the public support runbook, fixtures, release/install tooling,
policy files, GitHub Actions/Dependabot files, and Codex/Claude Code agent
adapters, while rejecting private monorepo root paths. The manifest gate verifies that
`PUBLIC_EXPORT_MANIFEST.json` matches every staged non-manifest file and
rejects drift, missing files, extra files, symlinks, mode changes, executable
bit changes, and content hash changes. Run
`scripts/public_repo_contract_check.sh --staged-output ... --private-repo-root ...`
to verify public CLI, protocol, setup, redaction, release, connector, and
private consumer contracts. With a private root, the contract check also
requires `backend/app/domain/local_platform/public_runtime_pin.json` to match
the staged public manifest digest and file counts. After the public repository
is the runtime authority, add `--require-public-authority`; the private pin must
then use `authority_state: public_repo_commit`, record the `ottto-ai/ottto`
commit and `PUBLIC_EXPORT_MANIFEST.json` digest, and the checked public root
must be a clean git checkout at that commit. Then run
`scripts/public_repo_secret_scan.sh --staged-output ...` before any public
commit. That preflight scans current tracked export candidates, historical
blobs for paths under export roots, and the root-shaped staged bundle for
private paths and secret-like content. The expected public-v1 source state is
zero rewrite-required references; the rewrite rules remain a guardrail for
legacy or newly introduced private repository names, not a normal cutover
dependency.
Run `scripts/public_repo_surface_ci.sh --staged-output ...` when you need the
closest local substitute for the future public repository's `public-surface`
GitHub Actions job. The smoke copies the bundle into a temporary git checkout,
runs schema/registry validation, shellcheck, export tests, release/installer
dry-run tests, manifest/skeleton, secret-scan, contract checks, and verifies a
self-exported bundle from that temporary checkout. The staged copy intentionally
excludes any source `.git` metadata so the same smoke can validate a real public
checkout through `--staged-output`.
Finally, run `scripts/public_repo_bootstrap_plan.sh --target-dir <public-checkout>`
to review the target diff before applying the generated bundle, and pass
`--report <path>` to preserve machine-readable cutover evidence. The target
checkout must have `origin` bound to `ottto-ai/ottto`; the report stores only
normalized remote facts, not the raw remote URL. Apply mode reruns manifest,
skeleton, secret-scan, and contract checks against the target checkout after
files are copied and marks those post-apply checks in the report. Then run
`scripts/public_repo_cutover_closeout.sh --target-dir <public-checkout>` with
the apply report before the first public commit. The closeout gate checks the
applied target manifest, skeleton, secret scan, public/private contracts, and
public-surface CI smoke, verifies the bootstrap report branch/head plus
remote/digest/counts, records whether private source history and private
consumer contracts were in scope, and writes a path-safe `ready_to_commit`
evidence report.

## Export Rules

- Export only public-root GitHub Actions/Dependabot files, root
  license/NOTICE/policy files, local runtime, public docs, installer/release
  tooling, connector SDK/testkit crates, source packages, manifest schemas,
  fixtures, and the thin Codex/Claude lifecycle skills.
- The root `README.md` must explain the public v1 install promise, supported
  install owners, first smoke commands, privacy defaults, and private-code
  boundary without requiring private repository context.
- `docs/support.md` must carry the public-safe support runbook for triage,
  diagnostics, escalation, data boundaries, and final public-v1 closeout
  support readiness.
- The public staging tree is root-shaped: `Cargo.toml`, `crates/`, `docs/`,
  `connectors/`, `schemas/`, `release/`, and `scripts/` live at the repository
  root; lifecycle skills live under `agent-adapters/`.
- Do not export private backend, frontend, infrastructure, production
  operations, AI KB, session notes, or planning boards.
- Private monorepo workflows under repository-root `.github/` are excluded
  because they are not export roots. Public repository CI must be authored under
  `tools/ottto-local-platform/public-root/.github/`.
- Do not rely on export-time rewrites for public-v1 source. Fix private
  repository references in source before publishing to `ottto`; keep rewrite
  rules only as a regression guard.
- Verify `PUBLIC_EXPORT_MANIFEST.json` with `public_repo_manifest_check.sh`
  before bootstrap and after applying the bundle to a clean public checkout.
- Run `public_repo_bootstrap_plan.sh` only against a public checkout whose
  `origin` remote resolves to `ottto-ai/ottto`; bootstrap reports store the
  normalized repository binding instead of the raw remote URL.
- Keep the private runtime pin in
  `backend/app/domain/local_platform/public_runtime_pin.json` synchronized with
  the public manifest digest that private backend/frontend consumers are tested
  against. Before public cutover this pin may use
  `authority_state: pre_public_repo_export`. After public cutover it must use
  `authority_state: public_repo_commit` plus a matching public checkout commit,
  and `public_repo_contract_check.sh --require-public-authority` must pass.
- Run `public_repo_cutover_closeout.sh` only from an applied public checkout
  whose `origin` remote resolves to `ottto-ai/ottto`; the closeout report stores
  a normalized repository binding instead of the raw remote URL and verifies the
  bootstrap report recorded the same target branch, pre-apply head, and remote
  binding. Final public-v1 closeout also requires the closeout report to prove
  it ran with `--source-repo-root` so private source history scanning and
  private backend/frontend consumer contract checks were in scope.
- Run `public_repo_surface_ci.sh` in the root-shaped public checkout, or with
  `--staged-output` against a generated bundle, before relying on public CI.
  Keep `cargo` available on `PATH` because the SBOM dry-run uses
  `cargo metadata`.
- Run `public_repo_cutover_closeout.sh` against the applied public checkout
  before committing or enabling branch protection; preserve its path-safe JSON
  report with the bootstrap apply report.
- Run the export secret scan before moving Git history or pushing a public
  branch, then run any host-side secret scanning required by the public GitHub
  organization before promotion.
