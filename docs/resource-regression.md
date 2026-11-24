# Resource regression checks

**Resource regression (advisory)** runs on `ubuntu-latest` when a PR touching
`crates/ottto-service/**` is marked ready for review, nightly on main, and on
manual dispatch. It has no
merge-group trigger, required-check dependency or required-check ruleset entry.
A daemon PR includes a nonblank `Resource:` body line describing its evidence
and limitations; it may cite the id of a dispatched run on the PR branch. That
line never waives a failing budget.

The generated fixed-seed corpus has 12,000 Claude, 5,500 Codex and 500 Pi
transcripts, eight Codex homes and five homes with synthetic SQLite sidecars.
All files live in private temporary directories and are removed on fixture drop.
The exact 90/9/1% mix is 4KiB/64KiB/1MiB. MCP-shaped lines with made-up
names fill part of a fixed share's padding, so file sizes stay the same. Per
hundred Claude files: nine 64KiB Desktop-shaped sessions with 635 MCP names from
26 servers (32 tools in full in request 1, the rest deferred, instructions
deltas before and after response 1) and one 1MiB one with 739 names from 31
servers; six of these ten get some names after response 1. Ten 4KiB headless
sessions carry 58 connector names from 5 servers. Per hundred Codex files,
twenty list 19 deferred namespaces at start; per thousand, sixteen re-send the
block, eleven of them with a new namespace. Native acquisition, policy, exact ACK,
accepted fingerprint, state save and reload helpers seed the corpus. No live
provider input, auth material or generated transcript is checked in.

One shared virtual UTC/monotonic clock drives real cadence, account-switch
owners and native collection/census windows. Watcher hints transfer once into
the native traversal, which retains deferred work for cursor follow-up. The measured half-open window is `[0,7200)` seconds, with separate cold
seed and active-drain receipts. Cases cover quiet AC/Battery/Low Power/Unknown,
one active session per source with 2KiB appended each five minutes (including
real Codex SQLite WAL mutations through the existing external-provider WAL-image
helper, avoiding process-local writable SHM at the read path), one minute-30
native historical-replay reselect, and an account switch forcing an immediate pass.
Delivery context changes alone deliberately trigger no acquisition; the reselect
uses the native replay owner once at prepare, including its full scan-request
window, with its hydration counted. It must finish every generated Claude file exactly once and leave no
context debt. Metadata companions cover successful stderr login and the native
60-minute TTL. Tests use no sleeps or elapsed-time assertions.

## Linux work counters and baseline

`crates/ottto-service/src/snapshots/resource-baseline.json` is the single baseline
B. Its header pins the current-main production revision, generator seed and exact corpus manifest, and
explicitly lists Linux counters, source-specific counters, exclusions and the
separate macOS RC metric set. Each observed scenario/source/phase/hour count must
be at most `1.20 * B`, using exact integer comparison. Sidecar reuse is judged
by rate in the inverse direction, as the RC scorecard floors its reuse ratio: for
each Codex loader kind, `reused / (reused + reloaded)` must stay at least the
baseline rate `/ 1.20`, with both denominators positive. Fewer passes at the
same rate therefore pass; `reloaded.*` keeps the `1.20 * B` ceiling.
Baseline changes that loosen a bound require a reviewed PR. A missing
defined-platform counter, phase or source fails; an observed zero of a capped
counter remains zero. Source-specific sidecar fields apply to Codex only.
Quiet sidecar reuse additionally requires >=95% with a positive denominator for
each native loader kind.

Linux judges native/Full/Tail and guard read bytes from the actual page row,
parser consumption, physical decoded rows, existing save-work encoded bytes and
dirty rows, native child starts by kind, actual diagnostic formatter/writer
bytes including prefix/newline, and per-kind sidecar reload/reuse counts. The
save observer includes every existing `save_work` call in the measured pass.
The `encoded_bytes` fixture field records that tally's dirty-byte charge,
including row/key overhead. It is not exact serialized payload size. The log
counter covers the resource-diagnostic writer, excluding other stderr.
Counter scopes include native prepare, collection, ACK, save, and reload.

These are **logical work counters**. Native page read bytes exclude discovery,
failed plans, joins and sidecars; parser bytes have their narrower existing
meaning. This production revision has no sidecar byte tally or maintenance
`cache_write` page counter. The header excludes those absent metrics explicitly:
sidecar reload counts and encoded save bytes are the nearest existing counters.
These dirty-byte charges are not SQLite pages, WAL/checkpoint bytes or physical disk I/O.
No new production counters are introduced. `DiskBytes`/`proc_pid_rusage` are
macOS-only RC observations and are excluded from Linux budgets.

Regenerate in CI against the pinned current-main production plus these test
adapters: dispatch `resource-regression.yml` with `record_baseline=true`, download
the completed log, then run:

```sh
python3 scripts/resource_baseline.py --log calibration.log \
  --production-main <40-character-main-sha>
```

This imports exactly one counts-only receipt and preserves the reviewed header.
Review the resulting counts, corpus receipt, source/phase coverage and pinned
revision before committing B. A record-mode run skips the B comparison and is
**calibration only**. PR and nightly runs compare B by default. After updating B,
run the advisory workflow normally, normal Linux tests, then money equivalence
on the final head. The advisory bootstrap keeps a private symlinked TMPDIR
but needs no apt/zsh install: SQLite is bundled and metadata commands are Python stubs.
Resource tests are ignored in ordinary discovery and selected
explicitly, serially, without retries. The advisory build uses the ordinary
service test profile with the workspace's existing optimized dependencies, debug assertions and overflow checks. Two
Cargo jobs limit compile concurrency. That profile is pinned in B. It changes neither native
Mac nor money builds. Command wall time is CI overhead evidence. Calibration exceeded the initial
40-minute total estimate. The job takes 47-63 minutes on a normal runner and
one slow runner needed about 80, so the single advisory job allows 100 minutes. This
adds no resource-test execution or timeout change to required shards; it does
consume a Linux slot for substantially longer than the original estimate.
Keep the check advisory and review duration drift before promotion.

The off-pass replay uses the same native aggregation and formatter, flushing
each event in the replay. The paced-rewalk replay requests another native paced
pass after a quiet completed page. Both must breach their original resource
bounds; the CLI bypass and sidecar cache-loss replays use real native loaders.

## Native macOS PR QoS

The ignored `resource_native_ordinary_stage_qos` test uses native pthread QoS
inside native fixture prepare/page/finish on a scan-sized worker. Ordinary
stages must keep utility; stages explicitly requested as resident-paced must
keep background, and another source must retain utility. It checks restoration
on normal return, error and unwind. A test-only cycle-wide demotion must trip
the same ordinary-class predicate. These tests measure requested QoS, not core
placement. They use native acquisition/stage owners and the production paced-QoS
policy; the HTTP/control-plane cycle is outside this fixture's scope.

The native Mac PR runner invokes `scripts/resource_native_qos_pr.sh <PR-number>`.
It requires Darwin, a PR context and an exact PR-head match. Linux compiles and
type-checks the test, then explicitly excludes its module from execution. The test is ignored
by ordinary, scheduled and merge-group discovery and requires the runner's PR
binding; zero-match runs fail. No paid hosted Mac workflow is added. A Linux pass is not native Mac
evidence; record the native runner receipt separately.

## Stable candidate RC scorecard

`scripts/resource_scorecard.py <stable-candidate-rc-qa.json>` validates existing
RC evidence; `resource_soak` starts `not_run`. Both the RC gate and stable-release
binding validate a supplied scorecard. An absent scorecard or the template's
unfilled `not_run` placeholder is reported as absent and does not block release.
No stable release requires resource-soak evidence until the sampler ships;
a supplied incomplete or failing scorecard still fails validation.

Required: sampler_v6; two battery hours after 15 minutes startup exclusion;
>=99% coverage and <=2s gaps; one verified process instance, no restart;
candidate manifest/executable SHA binding; child-inclusive CPU; and previous
stable evidence bound by canonical SHA-256. Host, OS, architecture, power,
workload, duration and source input counts must match the comparator.

Absolute ceilings: 180 CPU seconds/hour, 100mW battery energy, 0.25GiB written/hour,
150MiB median footprint, 600MiB peak, and 60 seconds/hour above 500MiB. Every
adverse metric regression >20% also fails, including physical reads/writes,
wakeups, logs and children; reuse compares in the inverse direction. A zero
baseline uses an explicit absolute bound, otherwise any nonzero value fails.
Reads >3GiB/hour are an alarm. Missing/nonfinite/negative or mismatched evidence
fails. Supplied pass flags are not trusted.

Trial rest and active budgets (advisory, not checked by the validator yet):
the single 180 CPU seconds/hour and 100mW ceilings mix quiet hours with hours
that carry new work, so a daemon that keeps itself busy while nothing changes
can still pass. RC evidence also reports these trial budgets, split by hour
class, counting the whole daemon including children:

- **Rest hour** (no new provider input and no owed work at the hour start, and
  no first import or recovery during it): <=36 CPU seconds/hour (1% of one
  core) and <=25mW battery energy averaged over the hour.
- **Active hour** (any other awake hour): the existing 180 CPU seconds/hour and
  100mW ceilings.
- Memory keeps the existing 150MiB median footprint and 600MiB peak, judged on
  measured rest and peak, including any state kept between passes.

Report first-import and recovery hours separately rather than in either class.
Promote a trial budget to an absolute ceiling only after matched RC evidence
shows it is met with unchanged delivery freshness.

The validator consumes reviewed aggregates; it neither runs the real Mac soak
nor independently verifies live process identity. Verify candidate PID/start/
digest and previous-stable provenance before producing evidence. Keep raw
sampler/provider data local; publish aggregates only.
