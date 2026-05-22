# Ottto Local Platform

This is the clean-slate local runtime for customer machines. It is the target
production path for the daemon, CLI, macOS app, agent skill, and `/apps`
integration. The retired Python companion implementation has been removed from
the production repository path.

## Public V1 Promise

The public `ottto` repository is intended to be enough for an external
developer, support engineer, CI job, or coding agent to install, set up, verify,
repair, diagnose, update, and uninstall Ottto without private repository
knowledge.

Stable releases are distributed through the install owners advertised by the
release manifest:

- Homebrew tap: installs `ottto`, installs `ottto-service`, and owns
  `brew services start ottto`.
- Hosted native installer: downloads and verifies a signed, notarized DMG or
  PKG without installing mutable shell-managed payloads.
- GitHub Releases and release notes: publish immutable manifest-backed
  artifacts, checksums, SBOM/provenance metadata, and rollback instructions.
- Signed `Ottto.app`: provides the native app path while staying aligned with
  the same `ottto-service` runtime and release manifest.

Final public-v1 closeout verifies that the public repository resolves as
`ottto-ai/ottto`, uses `main` as its default branch, and has that public `main`
branch head bound to the launch runtime commit. It also verifies that the exact
stable GitHub Release is non-draft, non-prerelease, has `targetCommitish`
bound to either `main` or the launch runtime commit, and contains only
canonical tag-scoped download assets for `release-manifest.json`, every stable
manifest artifact, and the CycloneDX SBOM before
`stable_release_published` can pass.
The same closeout requires a redacted public `Public CI` push-run report from
the public runtime commit whose public run URL matches the reported run ID,
with a unique workflow job inventory, canonical public GitHub job URLs for that
run, and the reviewed runtime, public-surface, and advisory jobs green.
The public repo, release, CI, and final closeout `checked_at` fields plus
GitHub release/CI timestamps must be parseable ISO-8601 UTC timestamps, so
reviewed evidence cannot carry ambiguous local time strings. Release and CI
access reports also require `checked_at` to be at or after the reported GitHub
event, and final closeout requires its `checked_at` to be at or after each
component access report.

Stable preflight also requires a passing, redacted internal stable-candidate RC
evidence record from a `stable-candidate` manifest built from the same commit,
so stable publication cannot skip candidate artifact trust, installer, setup,
diagnostics, update, rollback, and static install-owner checks. The
stable-candidate RC gate rejects candidate macOS artifacts that are not marked
signed, notarized, and Gatekeeper-assessed, and its evidence skeleton requires
explicit signature, notarization, Gatekeeper, and local-runtime pass/fail facts
bound to `ottto-service`, `net.ottto.service`, protocol v11, the
stable-candidate version/channel, and candidate release-manifest SHA-256.
Stable closeout then requires clean-machine evidence for each advertised install
owner, including setup, app detection, Codex verify/fix, diagnostics, logout,
update/upgrade, uninstall, reinstall, post-reinstall status, and owner-specific
trust checks before `latest` can be treated as externally ready. Each owner
entry must also bind the installed local runtime to `ottto-service`,
`net.ottto.service`, protocol v11, the exact stable version/channel, install
owner, and release-manifest SHA-256. The closeout gate rejects extra required
install owners and unknown per-owner check names so the matrix cannot pass with
unreviewed launch evidence.

Setup is browser-claim-first. The CLI never collects an Ottto password in the
terminal. Agents and headless sessions use `--json --no-browser --no-wait`,
show the returned claim URL or claim code to the user, and resume through the
same daemon-owned setup flow.

The first public smoke commands are:

```bash
ottto status --json
ottto setup --json
ottto apps detect --json
ottto verify --app codex --json
ottto doctor --json
ottto fix --app codex --json
ottto diagnostics collect --json
ottto update check --json
```

Privacy defaults are part of the product contract. Local usage sync starts only
after claim approval, uses a six-month default backfill capped at 1000 files per
app/source, and must not upload raw prompts, raw output, absolute local paths,
cookies, credentials, or secret material. Live telemetry is source-level
opt-in, diagnostics upload is explicit-approval-only, and risky collectors are
excluded from default v1.

This public repository owns the local runtime, installer/release tooling,
public docs, tests, redaction, diagnostics, agent adapters, connector
SDK/testkit, manifest schemas, and safe first-party source packages. The cloud
application, backend, frontend, billing, auth, analytics, infrastructure,
private operations, and planning docs remain private.

## Crates

- `ottto-protocol`: stable JSON models shared by the daemon, CLI, app, agent
  skill, backend event ingestion, and web setup flows.
- `ottto-core`: platform-neutral local logic such as source health summaries,
  repair planning primitives, diagnostics redaction, and stable CLI errors.
- `ottto-service`: the per-user daemon and future local authenticated control
  API owner.
- `ottto-cli`: the `ottto` developer, support, CI, and AI-agent interface.

## Contract First

Every customer-facing local action should cross the typed protocol boundary:

- status
- setup
- doctor
- fix
- verify
- diagnostics collect
- update check
- uninstall

The SwiftUI app and agent skill should talk to `ottto-service` through this
protocol. The app must not shell out to the CLI for normal behavior, and the web
app must not duplicate local setup logic.

## Public Docs

External install, setup, privacy, diagnostics, support, connector,
release-verification, agent-adapter, troubleshooting, and JSON automation examples live in
[`docs/`](docs/README.md). These docs are written to stand alone in a public
repository or release package without private repo links.

## Public Export Gate

The future public `ottto` repository must be populated from the approved export
surface under this local-platform tree, not by copying arbitrary private
monorepo paths. The export manifest and checks live in
[`public-export/`](public-export/README.md). Run
`scripts/public_repo_export_check.sh --require-no-rewrites` before any public
repo bootstrap or runtime move; it verifies export roots, fails private paths
and secret-like content, and fails private repo references that would need to be
rewritten to the public repository name. Current release attestation defaults already name
`ottto-ai/ottto`, so the expected pre-bootstrap bundle output is
`rewrite-required references: 0`; any new rewrite-required release/runtime
reference is a regression to fix before cutover.
`scripts/public_repo_export_bundle.sh --force`
materializes the root-shaped public staging tree, including connector
SDK/testkit crates, first-party source packages, the generated connector
registry, public manifest schemas, public GitHub Actions and Dependabot
configuration, and root Apache-2.0 license, NOTICE, security, contribution,
conduct, support, and trademark policy files. The bundle refuses rewrite-required
source by default; `--allow-rewrites` is reserved for legacy/test fixtures. The generated manifest records
every staged non-manifest file with SHA-256, size, mode, and executable-bit
metadata plus a deterministic `content_sha256`; run
`scripts/public_repo_manifest_check.sh --staged-output dist/public-export/ottto`
to verify that inventory before bootstrap. The generated tree must also pass
`scripts/public_repo_skeleton_check.sh`, which verifies the public repo shape
for runtime crates, connectors, docs, release tooling, policies, CI, and agent
adapters before bootstrap, and
`scripts/public_repo_contract_check.sh --staged-output dist/public-export/ottto`,
which verifies the generated root-shaped tree still carries the public CLI
JSON/NDJSON fixtures, local-control protocol fixtures, generated connector
registry, manifest schemas, setup claim fixtures, diagnostics redaction
fixture, release manifest schema, and private backend/frontend consumer
assumptions. When `--private-repo-root` is supplied, the same gate also checks
the private runtime pin at
`backend/app/domain/local_platform/public_runtime_pin.json`, so private
consumers only validate against the pinned public manifest digest. Once the
public repo is the runtime authority, run the same contract gate with
`--require-public-authority`; it requires the private pin to name a
`public_repo_commit` and verifies that the checked public root is a clean git
checkout at that commit. Before any public commit or runtime move, run
`scripts/public_repo_secret_scan.sh --staged-output dist/public-export/ottto`
to scan current export candidates, candidate path history, and the generated
bundle for private paths and secret-like content.
Run `scripts/public_repo_surface_ci.sh --staged-output dist/public-export/ottto`
to copy the generated root-shaped bundle into a temporary git checkout and run
the same public-surface gate that the exported GitHub Actions workflow uses:
schema/registry validation, shellcheck, export tests, manifest/skeleton,
secret-scan, contract checks, release/installer dry-run tests, and a
self-exported bundle verification. This includes release manifest,
stable-candidate RC, stable preflight, stable closeout, stable QA template,
Homebrew, hosted installer, and CycloneDX SBOM generator tests.
The skeleton gate also requires `docs/support.md`, the public support runbook
covering redacted triage, diagnostics, escalation, data boundaries, and
public-v1 closeout readiness.
Use `scripts/public_repo_bootstrap_plan.sh --target-dir <clean-public-checkout> --report public-bootstrap-plan.json`
to build and verify the bundle, check that the target checkout is a clean git
root outside the private monorepo with `origin` bound to `ottto-ai/ottto`,
print a dry-run add/change/delete plan, and write a machine-readable report
without absolute local filesystem paths. Only pass `--apply` after reviewing
that plan; apply mode copies the verified bundle into the target checkout and
reruns the public manifest, skeleton, secret-scan, and contract gates against
the applied tree.
After apply, run
`scripts/public_repo_cutover_closeout.sh --target-dir <public-checkout> --source-repo-root <private-monorepo> --bootstrap-report public-bootstrap-apply.json --report public-cutover-closeout.json`
before committing or enabling branch protection in the public checkout. The
closeout gate verifies the target manifest, skeleton, secret scan, public/private
contracts, and public-surface CI smoke against the applied checkout, then writes
a path-safe JSON report with the target `origin` repository binding, git status,
manifest digest, bootstrap report branch/head plus remote/digest consistency,
private source history/consumer-contract scope, per-check results, and
`ready_to_commit=true`.

## CLI Contract

The public CLI is the developer, support, CI, and AI-agent surface over
`ottto-service`. Help text for visible commands and options is frozen by
`fixtures/cli/help-contract.txt` and the `ottto-cli` unit test
`cli_help_matches_frozen_contract`; update both intentionally when changing the
public command surface.

Codex lifecycle automation uses `.agents/skills/ottto/SKILL.md`, which stays
thin over this contract: it calls `ottto --json`, uses public `--app` commands,
and does not duplicate setup, repair, diagnostics, or install-owner logic.
Claude Code lifecycle automation uses `.claude/skills/ottto/SKILL.md`, the
project skill equivalent, with no hooks, status-line monitor ownership, or
preapproved tool grants in v1.

MCP is deliberately not a public-v1 adapter. `docs/agent-adapters.md` records
the deferral: any future MCP server must wrap the stable CLI/local protocol and
must not own setup, repair, diagnostics upload, update, credential, or source
collection authority.

Current locked commands:

```bash
ottto status --json
ottto status --json --watch
ottto status --refresh-agent-status --json
ottto apps --json
ottto apps detect --json
ottto apps status --app codex --json
ottto setup --json
ottto setup --json --no-browser --no-wait
ottto setup --json --timeout 300
ottto setup --claim-code <code> --json
ottto login --json
ottto login --json --no-browser --no-wait
ottto account --json
ottto logout --json
ottto logout --local-only --json
ottto doctor --json
ottto fix --app codex --json
ottto verify --app codex --json
ottto diagnostics collect --json
ottto diagnostics collect --upload --approve-upload --accept-retention-disclosure --support-claim <claim> --json
ottto update --json
ottto update check --json
ottto uninstall --json
```

Automation should pass `--json`; JSON mode prints one final JSON object and no
human summary text. `--json --watch` prints newline-delimited JSON progress
events followed by one final event with `ok`, `exit_code`, and either `payload`
or `error`; setup can return a payload with a nonzero `exit_code` when it needs
user action or times out. Setup opens a browser claim by default when no local
setup-run binding exists, prints the URL/code fallback in human mode, and waits
up to `--timeout` seconds for browser approval and setup progress before
returning exit code `61`. Agents and headless flows can pass `--no-browser` to
skip auto-open and `--no-wait` to return the fallback claim payload immediately
with exit code `60`. `--watch` without `--json` exits as `invalid_request`.
Human mode prints short summaries only and is not a parsing contract. All
commands call `ottto-service` through the local-control protocol except local
uninstall cleanup and the hidden Claude Code status-line helper.

Stable CLI exit codes are:

| Code | Meaning |
| --- | --- |
| `0` | Success or setup complete |
| `2` | Invalid request or arguments |
| `10` | `ottto-service` unavailable |
| `14` | Backend unreachable |
| `16` | Backend unavailable |
| `50` | Permission denied |
| `60` | Setup needs user or browser action |
| `61` | Setup timed out |
| `70` | Internal error |

Public command nouns use `apps` and `--app`. The lower-level
`agent-status --source <source>` and `--source` selectors remain available for
existing automation while protocol payloads continue to use `source` and
`SourceKind`.

## Current Phase

This workspace contains the Phase 1 protocol/core foundation and the first Phase
2 daemon control primitives:

- authenticated local daemon status access
- daemon-owned relay and source state
- daemon-owned repair locks
- repair-plan proposal skeletons with required approval-boundary metadata:
  setup-safe config repairs may use terminal approval only when tied to an
  active setup-run binding, credential/auth-adjacent actions require browser
  approval, disconnected or stale local account state is browser-only, and old
  repair payloads without authority/approval metadata fail deserialization
- typed diagnostics bundles with explicit redaction reports
- typed local control request/response envelopes
- persistent Unix-socket serving with `--once` smoke mode
- CLI-to-daemon Unix-socket requests for status, setup, login, account, logout,
  setup claim codes, doctor, repair, verify, diagnostics, and uninstall
- CLI autostart recovery that kickstarts the standard per-user LaunchAgent when
  the default socket is unavailable, while leaving custom sockets deterministic
- macOS LaunchAgent plist generation and launchctl install-plan construction
- 0600 file-backed local control-token storage for CLI/agent access, avoiding
  macOS Keychain prompts on normal local-control calls
- daemon-owned account binding with non-secret account metadata persisted to
  `~/Library/Application Support/Ottto/account.json`
- daemon-owned setup-run binding metadata persisted to
  `~/Library/Application Support/Ottto/connection.json`, allowing source
  verification to survive daemon restarts without exposing setup-run secrets to
  the app. The binding now persists the validated `api_base_url` from the
  `/apps` deep link so standalone Companion verify and setup-run polling keep
  talking to the same local or production backend that created the run; legacy
  binding files without the field default to the configured API base until the
  next setup deep link rewrites them.
- daemon-owned persistent machine identity in
  `~/Library/Application Support/Ottto/machine.json`, using a hashed macOS
  hardware UUID when available plus a generated installation id. Placeholder
  development ids are replaced on the next daemon startup.
- daemon-owned setup-run and relay-device secret storage in the
  `net.ottto.service` Keychain service, without exposing those secrets to the
  app. macOS Keychain operations are bounded by a timeout and mirrored to
  owner-only files under the Ottto support directory so dev/preview signature
  churn, unavailable Keychain access, or blocking Keychain calls do not strand
  verification after restart.
- native app auth commands: `auth_status`, `auth_start`, `auth_complete`, and
  `auth_reset`. Reset/logout is cloud-first by default: the daemon records a
  `local-client/disconnect` in Ottto before clearing local account, connection,
  and setup-run token state. `local_only=true` is reserved for emergency local
  cleanup when the backend cannot be reached or the website state is stale.
- native app account-state UX now treats browser login and local app binding as
  separate states: Verify returns a sign-in-specific message when no local
  account is bound, and the SwiftUI app keeps polling a pending browser claim so
  successful browser approval updates the local UI even if the deep link handoff
  is missed.
- real setup-run attach/resume for web-created `/apps` runs, including local
  Codex/Claude/Pi scan publication, setup-action polling, bounded smoke
  verification commands, and redacted setup JSON shared by Companion and the
  CLI fallback. A fresh deep link with `claim_code` reattaches the local
  binding to that run, while a mismatched `setup_run_id` without a claim code
  fails clearly instead of silently replacing the existing binding.
- setup-run answers from trusted native clients, currently used by Companion to
  skip or disable a failed source through the setup-run token without exposing
  browser credentials or setup secrets to the app.
- setup-run actions from trusted native clients, currently used by Companion to
  continue `ready_to_install` sources by queueing and executing local-client
  `install_source`/`verify_source` work through the daemon-owned setup-run token.
- setup-run install completion payloads use backend-safe metadata keys, so
  successful Codex or Claude setup completion is not rejected by the setup-run
  secret/header guard.
- backend setup calls are routed through typed local-control backend errors
  (`backend_unreachable`, `backend_rejected`, `backend_unavailable`, and
  `backend_response_unexpected`) with safe status/body excerpts, so CLI and
  Companion can distinguish network, rejection, service, and protocol failures.
- setup-run polling sends backend heartbeats before asking for work, refreshing
  the short setup-run token and clearing disconnected state while the daemon is
  alive.
- SMAppService-oriented LaunchAgent packaging metadata with the
  `net.ottto.service.xpc` Mach service name
- a real launchd-backed XPC listener for `ottto-service serve-xpc`; it also
  serves the default per-user CLI/agent Unix socket for app-bundled launches,
  and a supplied debug socket overrides that fallback path
- trusted native-app authorization that inspects the local peer process,
  validates the Companion executable path, and can enforce a Developer ID code
  requirement through `OTTTO_COMPANION_TEAM_ID` or
  `OTTTO_COMPANION_CODE_REQUIREMENT`
- a macOS packaging rehearsal script that builds the SwiftUI app bundle, embeds
  Rust CLI/daemon helpers, ad-hoc seals dev/preview bundles, writes a release
  manifest, and separates those internal builds from stable
  signed/notarized requirements
- a release gate that validates artifact presence, SHA-256 integrity, manifest
  shape, rollback metadata, macOS app bundle sealing, and stable-channel
  signing/notarization/Gatekeeper state
- a stable macOS preflight wrapper that blocks publish readiness unless the
  manifest is stable-only, artifact URLs and hashes match the rollback
  immutable prefix, Developer ID signing uses hardened runtime and timestamps,
  notarization profile access works, stapling validates, and Gatekeeper accepts
  the app/CLI/daemon artifacts. Dry-run mode validates non-secret manifest,
  rollback, and hash checks without requiring Apple credentials.
- a Homebrew formula generator that writes `Formula/ottto.rb` from the stable
  release manifest only after Homebrew is listed as a supported install owner
  and the CLI/daemon artifacts are immutable-prefix pinned, signed, notarized,
  Gatekeeper-assessed, and SHA-256 pinned. The generated formula installs the
  public CLI as `ottto`, installs the service executable as `ottto-service`,
  owns Homebrew launchd label `net.ottto.service`, starts with
  `brew services start ottto`, updates with
  `brew update && brew upgrade ottto`, and uninstalls with
  `brew services stop ottto && brew uninstall ottto`.
- a stable hosted native installer wrapper generator that writes
  `install-macos.sh` only from a stable manifest whose native macOS app artifact
  is HTTPS, immutable-prefix pinned, SHA-256 pinned, signed, notarized,
  Gatekeeper-assessed, and advertised for the `hosted_installer` owner. The
  wrapper verifies and opens the DMG or PKG; it does not install mutable shell
  payloads, clear quarantine, or bootstrap launchd jobs.
- a stable release closeout gate that validates redacted clean-machine QA
  evidence before stable `latest` promotion. The evidence must match the exact
  manifest version, commit, and SHA-256 and prove every advertised install owner
  passed its install, service, status, update, uninstall, and trust checks while
  binding that owner to the `ottto-service` runtime, `net.ottto.service`,
  protocol v11, stable channel/version, and release-manifest SHA-256.
- a CycloneDX SBOM generator plus release-manifest `supply_chain` contract for
  SLSA v1.2 Build Track provenance. Stable release gates require the SBOM URL
  and SHA-256 under the immutable prefix, verified SBOM attestation with
  predicate `https://cyclonedx.org/bom`, SLSA provenance predicate
  `https://slsa.dev/provenance/v1`, Build L2 or better, and subject coverage for
  every artifact plus `release-manifest.json` and the SBOM.
- a notarization helper that submits the generated macOS archives and updates
  manifest notarization flags only after Apple validation and local Gatekeeper
  assessment pass
- local and hosted preview installers that verify dev/preview artifacts,
  install the app and Rust helpers to user-scoped locations, clear quarantine
  for the explicit tester install path, and delegate LaunchAgent plist writing
  to `ottto-service`. Bootstrap replaces an already-loaded
  `net.ottto.service` job before loading the freshly written plist, so stale
  SMAppService registrations do not keep launchd pinned to an older bundled
  helper after an in-place dev app replacement. Hosted installer readiness
  checks wait for the daemon without invoking CLI autostart, and the native app
  skips bundled SMAppService registration while the installer-owned user
  LaunchAgent exists.
- an installed dev/preview E2E smoke that validates the app bundle, LaunchAgent,
  CLI-to-daemon protocol, real setup claim handoff when a claim is supplied,
  actionable Codex verification JSON, and diagnostics redaction
- a SwiftUI app flow that calls the daemon as a trusted local app client for
  account login, source verify/repair, and diagnostics collection without
  reading the daemon control token from Keychain. The native Companion keeps
  source rows compact and daemon-owned: brand marks, setup readiness, primary
  setup/verify/repair/skip actions, and disclosure details all render from the
  typed local-control status/setup/verify payloads instead of shelling out or
  scanning local files in SwiftUI.
- source verification that runs a bounded local smoke prompt, waits for delayed
  backend telemetry, uses the daemon-owned setup-run token to call the backend
  local-client verification endpoint, updates local source health, and reports
  verified/no-fresh-telemetry/reconnect-required/local-smoke-failure states
  instead of a placeholder pending result. Pi verification runs a real
  non-interactive `pi --print` prompt for every configured provider/model route
  from `~/.pi/agent/settings.json` plus the default route, falling back to
  `pi --list-models` when settings are unavailable. A Pi source is `verified`
  when every route passes, `warning` when at least one route passes and at least
  one route fails, and failed only when no route passes. Smoke diagnostics read
  both stderr and stdout through the same redaction/truncation path so CLIs that
  print authentication failures on stdout still produce actionable safe setup
  errors.
- built-in local OTLP relay support in `ottto-service` on `127.0.0.1:43119` for
  Claude Code and Codex: approved setup-run `install_source` actions register a
  telemetry device, store the relay secret locally, patch
  `~/.claude/settings.json` or `~/.codex/config.toml` with logs, metrics, and
  traces endpoints, expose `/healthz` for local readiness, and expose a narrow
  browser CORS `/control` endpoint for M3 `telemetry_control` enable/disable/status
  requests from the Apps page. The control endpoint returns the private-network
  CORS header required by Chromium for production `https://ottto.net` to reach
  the loopback daemon, while the frontend marks the request target as
  `loopback`. Claude Code setup also installs a local
  `statusLine` wrapper that preserves an existing status line command while
  feeding documented `rate_limits` fields into the local quota cache. The relay
  uses a source header to route shared-port payloads to source-scoped
  relay-token exchange before forwarding OTLP payloads to the setup run's
  persisted backend API base URL. Manual edits to the managed Ottto fence are
  rejected with `manual_fence_review_required`, leaving local keys in place
  until the user reviews the file instead of guessing at cleanup. Pi setup
  actions also register or merge the local telemetry device source grant so
  route-smoke session imports can issue Pi-scoped relay tokens, but they skip
  Codex/Claude OTLP config patching because Pi telemetry is imported from local
  session files. The local scan
  reports Pi as requiring install when the Pi CLI/session files are present but
  the device grant does not yet include `pi`.
- source-local snapshot parsing and background sync in `ottto-service` for Codex
  `~/.codex/sessions/**/*.jsonl`, Claude Code
  `~/.claude/projects/**/*.jsonl`, and Pi
  `~/.pi/agent/sessions/**/*.jsonl`, streamed line-by-line and reduced to safe
  usage/title/model/timestamp/selector hashes instead of response, tool output,
  command output, or raw local paths. The Codex parser version
  `codex_jsonl:v10` reads current `event_msg` title updates,
  `payload.info.total_token_usage` totals, and selector fields such as
  `service_tier`, `actual_service_tier`, `fast_mode`, `batch_mode`,
  `inference_geo`, `context_bucket`, and cache TTL aliases from direct or
  nested `selector_context` rows; if a Codex usage row lacks an observed
  selector, locald can use `~/.codex/config.toml` fast-mode settings or the
  explicit top-level or `[notice].fast_default_opt_out=true` standard-mode
  preference as a low-confidence current-default selector. It then fills
  missing titles from local Codex sidecars in this order:
  `~/.codex/session_index.jsonl` `thread_name`,
  `~/.codex/state_5.sqlite` `threads.title`, and finally a short, filtered
  first-user-prompt fallback. The fallback rejects setup/system text, AGENTS and
  environment blocks, pasted plans, command-looking text, raw ids, generic
  labels, and tool/function names such as `exec_command` or `write_stdin`.
  Claude Code parser version `claude_code_jsonl:v3` carries
  `message.usage.speed`, service tier, residency, batch, and context aliases
  into selector context. Pi parser version `pi_jsonl:v3` carries
  `ottto-selector` / `ottto.selector` custom entries and per-message selector
  aliases into subsequent assistant-message usage rows. Parser-versioned file
  fingerprints plus Codex sidecar/config metadata fingerprints force a reparse
  of recent files when title or selector sources change. The daemon starts the
  snapshot sync loop beside the local OTLP relay,
  uses source-scoped relay tokens and backend activity hints, scans the last
  six months by default with stricter backend windows allowed, caps each
  app/source at 1000 recent files, strips filtered session titles or path-free
  workspace labels before upload when the effective backend org/user activity
  hint disables them, uploads changed snapshots in schema-v4 batches, and
  reports collector status and cap-hit metadata without exposing local paths.
  Policy-disabled metadata uses a policy-scoped scan index so later re-enabling
  titles or labels can re-upload unchanged local files with the newly allowed
  display metadata. Per-model usage is grouped by `(model, selector_hash)`, so
  mixed fast and standard usage for one model is emitted as separate model-usage
  rows without duplicating canonical model records.
- adaptive per-source local snapshot cadence primitives: debounced file watches
  through `notify`, hot/warm/idle/cold/failing/disabled scheduler states,
  backend activity-hint polling, and a persisted scan index under
  `~/Library/Application Support/Ottto` whose backend-visible fields are hashes
- source-scoped relay snapshot client helpers for relay-token exchange, batch
  upload, collector status, and backend activity-hints, with missing relay
  device credentials logged as a safe local skip instead of leaking paths or
  secrets
- local protocol version 11 and local snapshot schema version 4 as clean
  cutovers. Local control requests must include `protocol_version: 11`, and
  backend local snapshot batch/status endpoints reject stale internal schema
  versions instead of compatibility-mapping them. Protocol v11 adds
  owner-aware update gates, manifest minimum-version/protocol metadata, and
  required repair-plan authority fields that distinguish server-backed
  setup-safe terminal approval from browser-required account, stale binding,
  and credential-rotation cases; old repair payloads without these fields are
  rejected at Rust and macOS app protocol boundaries.
  Protocol v10 adds explicit diagnostics
  upload approval fields, local-only default upload reports, support-claim
  authorization, and retention disclosure acceptance before any diagnostics
  upload attempt. Protocol v9 adds typed diagnostics bundles and explicit
  redaction reports for
  local/support/agent/setup/command output surfaces. Protocol v8
  added registry-backed source descriptor review tiers, maturity badges, and
  collector descriptors for Codex, Claude Code, and Pi
  without adding static `supported_platforms`; runtime availability remains
  represented by source operation state. Protocol v7 added display-safe billing
  identity hashes/evidence for accounts, model routes, plan observations, and
  Pi route verification results; protocol v6 added Pi route classifications,
  per-route smoke results, and source-level verification warnings while
  preserving protocol-v5 uninstall planning/execution and lifecycle
  diagnostics. `SourceHealth` carries daemon-owned source descriptors and
  repair backup metadata, `AgentStatusSnapshot` emits protocol-v4
  `quota_windows` instead of legacy `limits`.
  Each quota window carries `scope`, `freshness`, optional
  model/account label, reset time, percentage, and remaining/quota fields;
  `rate_limited` is an explicit state. Local snapshots can include optional
  user-approved `workspace_display_label` text while keeping the hashed
  workspace identity as the only default project key; org and user telemetry
  settings can independently disable title and workspace-label upload.
- display-safe agent status snapshots attached to `SourceHealth` for Codex,
  Claude Code, and Pi, including account, subscription, model, context,
  quota-window, credit-balance, capability-gap, and diagnostic fields where each
  local CLI exposes safe metadata. Codex OAuth usage collection is an explicit
  setup-gated collector because it reads the local Codex credential only inside
  `ottto-service` to call an undocumented ChatGPT usage endpoint, converts the
  returned primary and secondary windows into session/weekly quota windows with
  `started_at` and `resets_at`, and converts provider credits into display-safe
  balances without serializing access tokens. `SourceHealth` and
  `AgentStatusSnapshot` also carry
  `plan_observations` with last-seen, current marker, evidence method, optional
  session id, and normalized billing/model attribution so the backend can keep
  multiple known plans for one source/computer. Pi `--list-models` output is
  parsed as a provider table and exposed through structured
  `available_model_details` so OpenAI Codex, OpenAI API-key, Google Vertex
  Gemini, Google Gemini API-key, AWS Bedrock, Azure OpenAI, gateway, and unknown
  Pi model routes keep their provider, model provider, billing provider,
  billing channel, auth mode, source category, context/output size, thinking,
  image-support metadata, and optional local billing identity evidence instead
  of flattening to one unknown model list. Locald now prefers
  `$PI_CODING_AGENT_DIR/settings.json` or `~/.pi/agent/settings.json` for
  `defaultProvider`, `defaultModel`, `defaultThinkingLevel`, and
  `enabledModels`, reads `$PI_CODING_AGENT_DIR/auth.json` or
  `~/.pi/agent/auth.json` for display-safe account/project/credential
  fingerprints, and falls back to `pi --list-models` only when settings are
  unavailable.
- cached agent status in `ottto status --json`, explicit refresh through
  `ottto status --refresh-agent-status --json` or
  `ottto apps detect --json`, source-specific refresh through
  `ottto agent-status --source <source> --json` or
  `ottto apps status --app <app> --json`, and locald collectors that redact raw
  command output, secrets, and absolute local paths before backend publication.
  Background source snapshot sync is source-isolated: a scan or upload failure
  for one local app logs that source and continues with the remaining granted
  sources, so a broken Codex session scan cannot prevent Claude Code agent
  status from reaching the backend. Sync logs report phase-level safe causes
  such as agent-status upload, activity-hint request, local scan, or snapshot
  upload failure without exposing raw response bodies or local paths.
  Public CLI affordances use `apps` and `--app`; typed daemon protocol payloads
  keep `SourceHealth`, `SourceKind`, and `source` fields.
  Codex keeps `codex login status` as the local diagnostic source and can carry
  pasted or future structured `/status` evidence when available; Claude uses
  `claude auth status --json` as high-confidence account/plan evidence.
- diagnostics collection returns a protocol-owned `DiagnosticsBundle` with
  sectioned runtime/version/install/repair/security facts plus a
  `RedactionReport` and `DiagnosticsUploadReport`. Collection is local-only by
  default; `ottto diagnostics collect --upload` requires `--approve-upload`,
  `--accept-retention-disclosure`, and either an active Ottto login or
  `--support-claim <claim>`. The redaction report names covered surfaces
  (`diagnostics`, `support_output`, `agent_output`, `setup_error`, and
  `command_output`), protected categories (local paths, secret tokens, account
  identifiers, machine identifiers, raw prompts, and command output), redacted
  fields, and intentionally preserved fields.
- setup scan publication uses protocol-owned agent-status redaction: safe
  provider, auth, plan, billing, account email, confidence, and model-route
  metadata is kept, while raw account/org ids and labels, path-like diagnostics,
  and secret-shaped values are nulled before leaving the machine. Provider
  account hashes remain the stable grouping key when an email is unavailable.
- bounded local command execution resolves agent CLIs from launchd-safe macOS
  candidate paths including `~/.local/bin`, Homebrew, `/usr/local/bin`, and
  system directories in addition to the inherited `PATH`; daemon-launched
  status and smoke commands also receive that augmented `PATH` so
  `/usr/bin/env` shebangs can find interpreters such as `node` under launchd.
- setup and standalone verification use the persisted setup-run API base URL,
  run Pi smoke prompts for every configured provider/model route, record
  whether a local Pi session file was created for each route, filter backend
  verification by model/model-provider/billing-provider, and report route-level
  no-telemetry failures as command failure, no local session, local session not
  uploaded, or verification service unavailable.
- native update checks read the release manifest and report `current`,
  `update_available`, or `unknown` plus a separate gate of `current`,
  `soft_warn`, `hard_block`, or `unknown`. Ordinary stale versions are soft
  warnings; only below-min-supported versions or protocol-incompatible
  manifests hard block. The parser requires public-v1 update metadata and
  rollback metadata before trusting a manifest. Update instructions route
  through the detected install owner (Homebrew, hosted installer, app bundle,
  or unknown) so Ottto does not self-overwrite owner-managed files. The default
  manifest URL follows the local release channel, while
  `OTTTO_RELEASE_MANIFEST_URL` remains available for explicit operator tests.

The remaining production hardening work is live macOS lifecycle and release
execution: SMAppService packaging, reboot/startup validation, sleep/wake and
network-interruption soak, Developer ID signing, notarization, Gatekeeper
assessment, rollback, and support-runbook rehearsal.

Preview builds currently register the app-bundled LaunchAgent and use the typed
JSON command envelope over XPC. Native app requests are accepted only from a
trusted Companion process, using peer PID plus macOS code-signing/path
validation; CLI and agent requests still require the control token. Stable
customer distribution remains blocked until Developer ID signing, notarization,
and Gatekeeper assessment pass.
