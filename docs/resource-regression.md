# Resource regression checks

**Resource regression (advisory)** runs on `ubuntu-latest` for pull requests
that touch `crates/ottto-service/**`, nightly, and manual dispatch. It has no
merge-group trigger, required-check dependency or required-check ruleset entry.
A daemon PR includes a nonblank `Resource:` body line describing its evidence
and limitations. That line never waives a failing budget.

The generated fixed-seed corpus has 12,000 Claude, 5,500 Codex and 500 Pi
transcripts, eight Codex homes and five homes with synthetic SQLite sidecars.
All files live in private temporary directories and are removed on fixture drop.
The exact 90/9/1% mix is 4KiB/64KiB/1MiB. Native acquisition, policy, exact ACK,
accepted fingerprint, state save and reload helpers seed the corpus. No live
provider input, auth material or generated transcript is checked in.

One shared virtual UTC/monotonic clock drives real cadence, account-switch
owners and native collection/census windows. Watcher hints transfer once into
the native traversal, which retains deferred work for cursor follow-up. The measured half-open window is `[0,7200)` seconds, with separate cold
seed and active-drain receipts. Cases cover quiet AC/Battery/Low Power/Unknown,
one active session per source with 2KiB appended each five minutes (including
real Codex SQLite WAL mutations through the existing external-provider WAL-image
helper, avoiding process-local writable SHM at the read path), one minute-30
context invalidation reselect, and an account switch forcing an immediate pass.
The reselect must finish every generated Claude file exactly once and leave no
context debt. Metadata companions cover successful stderr login and the native
60-minute TTL. Tests use no sleeps or elapsed-time assertions.

## Linux work counters and baseline

`crates/ottto-service/src/snapshots/resource-baseline.json` is the single baseline
B. Its header pins the current-main production revision, generator seed and exact corpus manifest, and
explicitly lists Linux counters, source-specific counters, exclusions and the
separate macOS RC metric set. Each observed scenario/source/phase/hour count must
be at most `1.20 * B`, using exact integer comparison. Baseline increases require
a reviewed PR. A missing defined-platform counter, phase or source fails; an
observed zero remains zero. Source-specific sidecar fields apply to Codex only.
Quiet sidecar reuse additionally requires >=95% with a positive denominator for
each native loader kind.

Linux judges native/Full/Tail and guard read bytes from the actual page row,
parser consumption, physical decoded rows, existing save-work encoded bytes and
dirty rows, native child starts by kind, actual diagnostic formatter/writer
bytes including prefix/newline, and per-kind sidecar reload/reuse counts. The
save observer includes every existing `save_work` call in the measured pass.
Counter scopes include native prepare, collection, ACK, save, and reload.

These are **logical work counters**. Native page read bytes exclude discovery,
failed plans, joins and sidecars; parser bytes have their narrower existing
meaning. This production revision has no sidecar byte tally or maintenance
`cache_write` page counter. The header excludes those absent metrics explicitly:
sidecar reload counts and encoded save bytes are the nearest existing counters.
Encoded bytes are not SQLite pages, WAL/checkpoint bytes or physical disk I/O.
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
on the final head. Resource tests are ignored in ordinary discovery and selected
explicitly, serially, without retries. The advisory build uses basic optimization
only for the service test crate (`--config profile.test.package.ottto-service.opt-level=1`),
retaining test debug assertions/overflow checks and the workspace's existing
optimized dependencies ([Cargo profile overrides](https://doc.rust-lang.org/cargo/reference/profiles.html#overrides)). That profile is pinned in B. It changes neither native
Mac nor money builds. Command wall time is CI overhead evidence. Calibration exceeded the initial
40-minute total estimate, so the single advisory job allows 75 minutes. This
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
binding recompute validation before marking candidate evidence passed.

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

The validator consumes reviewed aggregates; it neither runs the real Mac soak
nor independently verifies live process identity. Verify candidate PID/start/
digest and previous-stable provenance before producing evidence. Keep raw
sampler/provider data local; publish aggregates only.
