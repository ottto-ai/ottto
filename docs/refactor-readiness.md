# Refactor readiness and review coverage

Review date: 2026-10-06. Inventory revision:
`35ef92cb5aa0dd5376c77f877717ec460c73fdcc`.

The initial architecture review scanned all 78 tracked Rust files (including
`build.rs`), counted file sizes and main inline test sections, inspected symbols
and selected cross-module references, and searched for repeated source blocks.
It did not read every production function or test. The baseline contains 446
tracked files, including 58 shell scripts and two native shims. Generated build
output and unrelated local IDE files are outside the review inventory.

The accompanying [coverage ledger](refactor-review-coverage.tsv) records every
baseline tracked path. `targeted reading` means selected implementation or test
sections were read; it does not mean the file was fully audited. `structural
scan` includes size/symbol/reference or duplicate-block inspection, without a
manual correctness review. `inventory only` means no substantive reading was
performed in the initial review. Complementary inspection is recorded separately
so it does not retroactively overstate the initial review.

## Current evidence

- Root runtime workspace: `cargo check --workspace --all-targets --locked`
  passed before instruction/documentation changes. This compiled test targets
  but did not run tests.
- Full runtime and connector test suites, behavioral coverage, Clippy baseline,
  native runtime behavior, and production restart behavior are not certified by
  the initial review.
- Many existing tests exercise real recovery and partial-failure scenarios.
  Their number and source-line volume do not establish behavioral coverage.
- No Rust implementation, native shim, dependency, live credential, or
  production configuration change is part of this preparation.

## Preparation before implementation

1. Agree the next useful slice with the daemon owner. Record its base revision,
   existing changes, and file ownership; use isolated checkouts for parallel edits.
2. Establish the affected workspace's existing baseline once. Per patch, run
   compile checks and the relevant existing tests. Run formatting, Clippy, and
   the full affected suite on the combined change using existing CI. Check the
   connector workspace when it or its contracts change, not for unrelated edits.
3. Read callers, side effects, and tests for the chosen slice. Preserve wire
   bytes/hashes, persisted formats, locks, account/cancellation ordering, and
   checkpoint/receipt semantics. Update source-path validators when needed.
4. Make small preparatory refactors where they help the next real change.
   Separate mechanical moves from intentional behavior fixes. Avoid a broad
   test-file shuffle while other owners are modifying the same modules.
5. For changed decisions, use an existing regression or add one focused check
   for the failure. Test discovery comparisons are useful for test extraction;
   native checks are useful for native changes. Do not exercise live credentials.

No new CI gate, mandatory report per patch, coverage percentage, plugin,
dependency, property-test suite, or release smoke cycle is a prerequisite.
Use additional validation only to resolve a concrete risk in the changed slice.

## Structural priorities

- `snapshots.rs`: split scanning/index state, wire types, provider parsing,
  identity/hashing, and Claude evidence reconciliation while retaining stable
  entry points.
- `agent_status.rs`: separate provider acquisition, credential/identity reads,
  cache/refresh ownership, and status projection.
- `control.rs`: retain command dispatch and move domain implementation into
  cohesive modules with narrow interfaces.
- `snapshot_sync.rs`: extract explicit preparation, upload, and settlement
  stages without changing authority checks or durability ordering.
- `claude_browser_auth.rs`: separate supervisor/process I/O, storage/locks,
  identity admission, and recovery. Preserve lifecycle semantics before
  considering a redesigned transition API.
- `claude_upkeep.rs`: document and separately evaluate retained dormant worker
  machinery; preserve compatibility readers during any eventual retirement.

No hard line-count targets, new generic framework, dependency upgrade, or
blanket visibility expansion is required.

## Complementary review candidates

The complementary review read 28 complete files and selected sections of 25
others, with exact ranges in the coverage ledger. Full text reading is not
execution-based verification. Other large concentrations include cloud sessions,
daily reference collection, core account slots, and CLI implementation.

1. **Keychain mirror failure:** `ottto-core/src/token_store.rs` loads an existing
   fallback file first, but a successful Keychain save ignores a mirror write
   failure. An old surviving mirror can therefore make later reads stale despite
   a reported successful save. Static conditional correctness candidate; no
   failure-injection reproduction was performed.
2. **Keychain timeout ownership:** receiver timeout does not stop the detached
   operation. A slow mutation can finish after its caller proceeds to fallback
   or another operation. Sequencing and stale-completion handling require
   targeted investigation before any behavior fix.
3. **IPC admission budgets:** Unix socket input has no visible body cap and its
   read deadline is checked on `WouldBlock`; continuously readable incomplete
   input deserves a bounded-input test. Unix/XPC worker admission also deserves
   review. Socket permissions, same-user XPC gating, and companion signing checks
   are existing protections; this is not a demonstrated authorization bypass.
4. **Connector rule parity:** SDK, JSON schemas, and the Python contract checker
   have differing credential/identity vocabularies and acceptance rules. The
   Rust first-party testkit is an additional stricter gate. Consolidate ownership
   or add parity checks; do not infer an actual secret leak from differing sets.
5. **Worker lifecycle:** agent-status startup installs a process-global owner
   before worker startup succeeds. Retry and panic cleanup paths need explicit
   tests and supervision review. This is a conditional failure-path concern.
6. **Public contributor workflow:** connector docs reference a backend generator
   absent from this public checkout, and a contract validator requires that
   wording. Resolve the supported generation workflow and its validator together.

These are separate audit/repair candidates, not reasons to silently change
behavior during module extraction. Most shell scripts, historical docs, unread
Rust sections, fixtures, dependency/MSRV behavior, and real native lifecycle
integration remain outside a detailed correctness audit.

## Status lifecycle follow-up — 7 October 2026

Synthetic failures reproduced the status-owner concern above: failed thread
startup left a stopped global owner installed, and acquisition/upload unwinds
left a lane busy. The status owner now gates acquisition until all three workers
spawn, joins partial workers on failure and leaves failed startup retryable.
Concurrent starts install one worker per source. Acquisition unwind releases
waiters with an error and retains last-good data without rewriting its timestamps;
upload unwind retains the exact body for the existing transport retry. Focused
regressions cover these paths alongside the original schedule/freshness tests.
Five-minute cadence, minute failure delay, manual coalescing and shutdown remain
unchanged. This repairs caught Rust unwinds, not aborts or indefinitely blocked
provider calls. It adds no scheduler or retry activation change. The audit
references elsewhere in this report describe the earlier baseline.

## Work priority and sequencing

This ranking is a proposed engineering order, not a claim that conditional
failures have occurred in production. Existing daemon work with demonstrated
usage, freshness, account-attribution, recovery, or resource failures should
retain priority. Coordinate this backlog with the daemon owner before assigning
overlapping files. No implementation is started by this report.

| Order | Finding/work | Evidence status | Smallest useful next step | Scheduling |
| --- | --- | --- | --- | --- |
| 1 | Keychain surviving stale mirror | Static conditional correctness path | Inject mirror-write failure with fake storage; decide authoritative save/load semantics | Investigate alongside current work in an isolated core lane |
| 2 | Keychain detached mutation after timeout | Static conditional ordering risk | Test delayed completion across save/delete; define per-account ownership | Same owner as mirror issue; behavior fix separate from extraction |
| 3 | Cloud CLI pipe drain after child exit/timeout | Static conditional deadline risk | Fake child/descendant retains stdout; prove collection lease finishes within budget | Follow bounded-work priorities if relevant to active source |
| 4 | Codex pending-open slot cleanup loses durable owner | Static conditional crash/cleanup risk | Simulate interrupted deletion; retain cleanup authority through restart | Account owner review before changing cleanup semantics |
| 5 | Agent-status startup/panic recovery | Static conditional lifecycle risk | Inject spawn/acquisition failure and verify waiters recover | Coordinate with quota/status owner |
| 6 | Unix/XPC request and worker admission | Code-verified missing application budgets; protected local surface | Bound input/worker admission using existing local patterns | After live failures; first prove concrete limits with synthetic input |
| 7 | Connector schema/SDK/Python parity | Confirmed differing acceptance rules | Align vocabularies or add one focused parity check | Independent connector lane, can run alongside daemon work |
| 8 | Installer generated shell literal handling | Static conditional standalone-input issue | Reject or quote shell metacharacters; test generated bytes without execution | Independent release lane; no release/installer run needed |
| 9 | Missing public connector generation workflow | Confirmed documentation/validator gap | Establish supported generator authority and update docs/checker together | Alongside next connector change |
| 10 | Repeated Claude compaction matching | Confirmed same-rule duplication | Compute matching once; preserve both derived outputs | Preparatory slice when touching compaction; avoid conflict with active owner |
| 11 | Repeated snapshot settlement filtering | Confirmed same-rule duplication | Share committable-index calculation, preserving distinct outcomes | Inside next upload/retry slice owned by current owner |
| 12 | Repeated cache and owner-only file writing | Confirmed mechanics duplication | Reuse a helper with explicit durability/best-effort semantics | Independent small slice after correctness rules are settled |
| 13 | Repeated Keychain CLI fallback | Confirmed mechanics duplication | Share low-level classification while preserving caller results | After Keychain behavior questions are resolved |
| 14 | Repeated query construction, route mapping, daemon initialization | Confirmed local repetition | Extract only mappings with identical semantics | Low urgency, opportunistic |
| 15 | Huge snapshots/status/control/sync/auth modules and crate root | Confirmed structural concentration | Extract one cohesive seam needed by an upcoming change; preserve facade | Incrementally after overlapping correctness work settles |
| 16 | Dormant upkeep execution machinery | Explicitly retained dormant path | Establish compatibility need; remove only obsolete execution pieces | After replacement/recovery behavior is understood |
| 17 | Architecture navigation and large inline test sections | Maintainability issue | Move tests with their owning feature; document actual boundaries | Alongside useful module extraction, not a repo-wide first phase |

Two smaller subprocess follow-ups fit after the cloud runner investigation:
`mcp_inventory.rs:665-690` can abandon an already-started child if handshake
thread creation fails, and its `read_line` lacks a byte budget;
`context_footprint.rs:455-469` waits for child exit before draining stdout, so
pipe-sized output can cause a false timeout. Keep these in the subprocess
ownership lane, ahead of cosmetic restructuring but below the primary findings.

Proposed delivery approach:

1. Keep current correctness/resource work moving. Confirm exact overlaps with
   the daemon owner; independently verify the narrow core/connector candidates.
2. Fix verified correctness candidates in small separate patches. Expected
   investigation size is usually hours to a day per narrow candidate; repair
   effort remains uncertain until a regression is established.
3. Use compaction and settlement consolidations as preparatory refactors in the
   next related slice. A selected mechanical extraction should normally be a
   fraction of a day to two engineer-days, depending on its dependency surface.
4. Split broader modules only where this reduces the next change's complexity.
   Do not schedule an undefined multi-week rewrite or mass test-file movement.

These are rough sizing ranges, not commitments or measured productivity. One
integration owner coordinates interfaces and combined checks. Reuse active
owners; parallelize disjoint core, connector, or quiet-module work. Code moves
must not happen underneath another owner's active patch.

## Additional focused audit

The additional auditor checked candidates against surrounding ownership, trust
controls, and existing tests. No live credentials, release actions, or broad
builds were used. Findings below are static unless explicitly stated otherwise.

- `crates/ottto-core/src/token_store.rs:173-214`: the fallback mirror is read
  first; Keychain save success ignores a failed mirror update. The condition
  requires an existing stale mirror whose replacement fails. No reproduction
  was run; do not certify current account failures from this path alone.
- `crates/ottto-core/src/token_store.rs:323-340`: timing out the receiver leaves
  its operation running. Slow completion can overlap later save/delete or
  rollback work; changing this requires a clear authority rule, not merely a
  different timeout.
- `crates/ottto-core/src/codex_account_slots.rs:663-689`: stopping a pending-open
  setup durably removes its slot reference before deleting the directory.
  Interrupted/failed cleanup can leave an unregistered credential-bearing root
  without the registered-slot tombstone recovery path. Review intended provider
  process behavior and cleanup guarantees before fixing.
- `crates/ottto-service/src/cloud_sessions.rs:2265-2300`: the CLI stdout reader
  is joined without a separate drain deadline after the direct child exits or
  is killed. A descendant retaining that pipe can block completion and keep the
  collector I/O lease live. The normal trusted CLI may not exercise this path;
  a fake-process regression is the appropriate next proof.
- `crates/ottto-service/src/agent_status_refresh.rs:176-277`: startup installs
  the global owner before all workers start, and panic/failure cleanup deserves
  a completion guard. Existing schedule tests do not certify restart/waiter
  recovery after those injected failures.
- `crates/ottto-service/src/unix_socket.rs:151-160,367-393` and
  `crates/ottto-service/src/xpc_mach.rs:92-98`: missing application admission
  budgets deserve bounded-input tests. Existing socket/XPC trust protections
  remain relevant. The macOS debug listener is restarted by `main.rs`; a worker
  spawn failure is not evidence that every control transport stays down.
- `scripts/hosted_native_installer.sh:77-82,197,454`: the helper's literal check
  excludes several characters but permits dollar/backtick expansion syntax;
  raw replacement into a double-quoted generated assignment can interpret it
  when that helper is later run. The normal package pipeline constructs the
  prefix; this is a standalone malformed/untrusted-input concern, not proof of
  release compromise.
- Connector parity and missing public generation workflow were reconfirmed.
  Additional stricter Rust fixture checks reduce exposure; inconsistent
  validators do not establish that any current fixture leaks secrets.

The auditor fully read six small files (including the instructions and report),
read all production code in `agent_status_refresh.rs`, and selectively reviewed
the other listed paths. It did not execute fault-injection tests. The exact pass
is recorded in the ledger's `additional_audit` column. Remaining gaps include
complete CLI/protocol review, full account-slot state machines, snapshot client
response/receipt handling, provider-daily semantics, MCP/context/session privacy
and attribution, most release scripts, and native execution-based verification.

The focused audit does not close all unread code ranges, historical docs,
release workflows, schema semantics, or native lifecycle behavior. Coverage is
recorded separately in the ledger rather than changing the original claims.

## Daemon owner review and final scheduling

The daemon North Star owner reviewed this report, the ledger, and surrounding
implementation for the principal lifecycle candidates. It independently
confirmed the ledger matches all 446 baseline paths with no omissions or
duplicates. The review was read-only, with no new agents or fault-injection runs.
It accepts the approach, with these scheduling and scope qualifications:

1. Continue current demonstrated scan/recovery, bounded retry, and Codex
   accounting work first. This candidate backlog is not a prerequisite for that
   work. Do not start a separate repository-wide cleanup effort.
2. Use the next available independent slot for one Keychain investigation
   covering mirror authority and detached timeout completion together. Then
   investigate the cloud/MCP/context subprocess family with separate repair
   patches. Allow roughly half to one engineer-day per focused investigation
   family; estimate repair only after reproduction, with release waits separate.
3. Review pending Codex cleanup with the account owner below observed ingestion
   failures. Integrate status lifecycle investigation after the current retry
   slice. Unix/XPC work should start with bounded-input/admission proof rather
   than transport redesign; establish actual XPC callback concurrency.
4. Connector parity and installer literal validation may run independently
   when capacity permits. Classify intentional vocabulary differences before
   alignment. Resolve public generation with the next connector contribution.
5. Integrate snapshot settlement preparation with the existing retry owner.
   Completed/conflicted branches repeat filtering but intentionally differ in
   completion and recovery handling: share the calculation, not the entire
   settlement outcome. Integrate Claude matching only when its owner touches
   that rule; preserve legacy/structured pairing, timestamps and metrics.
6. Defer generic writing/cache helpers, Keychain fallback consolidation, route
   repetition, dormant-path removal and test movement until relevant work needs
   them. Select a private module seam only when it makes an upcoming change easier.

The owner also flagged two important implementation pitfalls: returning an error
alone does not repair divergent Keychain/mirror replicas, and adding a mutex alone
may serialize obsolete detached work without correcting it. Decide authority and
stale-completion semantics explicitly. The existing Keychain comment and load
order disagree, so do not simply change code to match the comment. Similarly,
detaching a blocked pipe reader would hide a resource leak rather than establish
bounded completion; validate reader, child and collector-lease cleanup together.

These are relative scheduling recommendations, not calendar commitments or
authorization to start application changes. Current owners retain their work;
new investigations use available capacity without moving code beneath active
patches. No application implementation has begun in this preparation.

The owner subsequently approved the concise shared `AGENTS.md` as written:
41 lines, with exact check commands linked to existing CI instead of duplicated.
It confirmed no essential North Star invariant was missing and recommended no
backlog-specific additions. `CLAUDE.md` remains the single `@AGENTS.md` import.

## Rust guidance and optional skills

Primary guidance:

- [Rust Book: separating modules](https://doc.rust-lang.org/book/ch07-05-separating-modules-into-different-files.html)
- [Rust Reference: visibility and privacy](https://doc.rust-lang.org/reference/visibility-and-privacy.html)
- [Rust Book: test organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
- [Cargo: compatibility](https://doc.rust-lang.org/cargo/reference/semver.html)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Clippy usage](https://doc.rust-lang.org/clippy/usage.html)
- [Cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html)

These support private modules, narrow interfaces, stable paths/re-exports,
recoverable errors, and separate unit/integration tests. Choosing cohesive
ownership boundaries, sequential integration, and small refactor stages is
project engineering judgment rather than an official Rust size rule.

The expanded research inspected actual skill instructions rather than ranking
popularity. No stock skill is clearly a better fit than the concise repository
policy for this existing synchronous macOS daemon.

| Candidate | Useful capability | Fit limitation |
| --- | --- | --- |
| [Actionbook rust-refactor-helper](https://github.com/actionbook/rust-skills/blob/main/skills/rust-refactor-helper/SKILL.md) | Reference-aware rename/extract/move checklist | Requires specific callable LSP operations; installation does not supply them |
| [Apollo rust-best-practices](https://github.com/apollographql/skills/blob/main/skills/rust-best-practices/SKILL.md) | Rust ownership, error, and performance references | Broad style requirements and lint policies do not all fit existing code |
| [Jeffallan rust-engineer](https://github.com/Jeffallan/claude-skills/blob/main/skills/rust-engineer/SKILL.md) | Rust engineering reference | Trait hierarchy, error, async, documentation templates exceed mechanical-extraction needs |
| [GitHub refactor](https://github.com/github/awesome-copilot/blob/main/skills/refactor/SKILL.md) | Small-step workflow | Long generic checklist, OOP examples, hard function-size preference |
| [Matt Pocock codebase-design](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/SKILL.md) | Complexity-hiding interfaces | Vocabulary/design workflow adds overhead to already-scoped changes |
| [ECC rust-testing](https://github.com/affaan-m/everything-claude-code/blob/main/skills/rust-testing/SKILL.md) | Testing references | Prescribed mocking, coverage tooling, and percentage targets are unnecessary new gates |

Recommendation: use `AGENTS.md` and existing tools. Optionally invoke Actionbook's
helper for a specific mechanical operation only when compatible LSP tooling is
available. No additional skill or plugin was installed. A skill is agent context,
not a compiler rule: depending on host discovery and invocation, it can influence
Rust reviews, planning, manifests, tests, or documentation as well as `.rs` edits.
It does not automatically constrain itself to one file extension or alter the
application runtime.

The practical workflow follows these author sources:

- [Fowler: preparatory refactoring](https://martinfowler.com/articles/preparatory-refactoring-example.html): make the next useful change easier through a small structural change, keeping behavior changes separate.
- [Fowler: refactoring workflows](https://martinfowler.com/articles/workflowsOfRefactoring/fallback.html): improve the code as part of real development rather than requiring a repository-wide cleanup first.
- [Ousterhout: modular design](https://web.stanford.edu/~ouster/cgi-bin/cs190-winter18/lecture.php?topic=modularDesign): hide substantial complexity behind small interfaces; excessive tiny modules can also increase complexity.
- [rust-analyzer assists](https://rust-analyzer.github.io/book/assists.html): use actual rename/extraction tools where available, and review generated visibility/import changes.

No universal skill ranking is established by this comparison. The selection is
based on fit, tooling requirements, and instruction overhead for this project.

A subsequent comparison with established Rust projects did not justify more
mandatory instructions. [Tokio's contribution guide](https://github.com/tokio-rs/tokio/blob/master/docs/contributing/README.md)
links to focused workflow and test documentation;
[rust-analyzer's AGENTS.md](https://github.com/rust-lang/rust-analyzer/blob/master/AGENTS.md)
links to its shared AI policy. [ripgrep's policy](https://github.com/BurntSushi/ripgrep/blob/master/AI_POLICY.md)
and rust-analyzer emphasize contributor responsibility, with project-specific
restrictions that are not suitable to copy into this agent-operated repository.
The useful pattern is short entry-point guidance backed by existing documentation;
Ottto already follows it by linking CONTRIBUTING.md and CI. No additional rule,
plugin, or workflow gate was added from this comparison.

`CLAUDE.md` imports the shared instructions using `@AGENTS.md`, as documented in
[Claude Code's memory guide](https://code.claude.com/docs/en/memory#share-one-file-with-other-coding-tools).
The import is outside a code fence and resolves relative to `CLAUDE.md`. The
configuration is statically checked; loading it in an actual Claude session can
be verified with that session's memory/context display.

## Independent follow-up audit prompt

Read AGENTS.md and docs/refactor-readiness.md. Perform a read-only correctness,
architecture, and duplication audit of the repository areas outside the large
service modules already identified. Use refactor-review-coverage.tsv as the
initial inventory, not as proof of correctness. Prioritize ottto-core stores and
Keychain timeout/mirror behavior; CLI and protocol contracts; Unix socket/XPC and
native shims; collector scheduling/resource bounds; OTLP relay; connector SDK,
testkit, registry and JSON-schema/validator parity; installer, release,
public-export tooling and CI.

For each candidate, read callers and surrounding trust/ownership controls,
search relevant tests, and distinguish confirmed bugs, conditional risks, and
maintenance issues. Use isolated synthetic fixtures for reproductions. Do not
modify application code, production configuration, credentials, Keychain state,
provider accounts, or release assets. Do not run installers or destructive/live
tests. Report precise file/line evidence, practical impact, required conditions,
recommended scope, existing protections, and a suitable regression oracle.
Provide an exact ledger of fully read, partially read, automated-only, and
unreviewed files; explicitly list remaining gaps. Do not infer safety from
compilation, test counts, or file length. Keep intentional behavior fixes
separate from mechanical refactor proposals.
