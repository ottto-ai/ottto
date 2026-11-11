# Resource calibration and RC scorecards

Resource calibration runs in the **Resource regression (advisory)** workflow on
`ubuntu-latest`: pull requests touching `crates/ottto-service/**`, a nightly run,
and manual branch dispatch. It is independent of required Linux checks and is
not selected by `merge_group`. Its job name is not a required status check.

A daemon pull request includes a nonblank `Resource:` body line. Describe the
measured scope and limitations, or use `Resource: none; reason=<scope>` when the
change does not affect resources. The line discloses evidence; it does not waive
a resource failure. Workflow code reads the PR body as data.

The workflow creates a deterministic synthetic corpus inside private temporary
directories, reuses native acquisition and durable acknowledgement helpers,
and removes the corpus when fixtures drop. The full profile has 12,000 Claude,
5,500 Codex and 500 Pi transcripts, eight Codex homes and five homes with
sidecars. Transcript byte sizes use a fixed 90%/9%/1% mix of 4 KiB, 64 KiB and
1 MiB. The content digest excludes temporary directory names.

Resource tests are ignored by ordinary test discovery, so calibration does not
become required indirectly. The advisory workflow explicitly selects the corpus
module and metadata tests, serially and without retry. It reports command wall
time as CI overhead evidence; test decisions use virtual time and work counts.
The shared clock defaults to native UTC and monotonic clocks in production.

The calibration reports actual parser-consumed bytes, decoded state rows,
sidecar reuse/reload counts, native CLI child starts and scan calls. Parser
consumption does **not** measure raw I/O: guards, prefetch, headers, sidecars,
SQLite, WAL and checkpoints have additional work. Unobserved read/write/page
metrics remain `null`. Current calibration is not a complete resource-budget
check, and a successful calibration run is not a complete resource receipt.

A resource baseline may contain only observed counts for the exact corpus,
scenario, source, phase and hour, pinned to the production-main revision used
for calibration. Missing observations cannot be filled with zero. A baseline
increase requires a reviewed pull request; a previous PR's run is not a baseline.
No complete checked-in baseline exists yet.

## Stable candidate resource scorecard

`scripts/resource_scorecard.py <stable-candidate-rc-qa.json>` validates the
`resource_scorecard` embedded in existing RC evidence. The evidence template
starts with `resource_soak: not_run`. The RC gate validates the scorecard, and
the stable release binding validates it before marking RC evidence passed.

The validator requires sampler version 6, at least two battery hours after
15 minutes of startup exclusion, at least 99% sample coverage, gaps no longer
than two seconds, one verified process instance and no restart. CPU includes
child-process CPU. Footprint peak uses interval maxima; time above 500 MiB
uses instantaneous readings. Candidate manifest and executable hashes must
match the parent evidence. A canonical JSON SHA-256 binds the embedded previous
stable scorecard; comparable host, OS, architecture, power, workload, duration
and source input counts are required.

Absolute ceilings are 180 CPU seconds/hour, 100 mW battery energy,
0.25 GiB written/hour, 150 MiB median footprint, 600 MiB peak footprint and
60 seconds/hour above 500 MiB. An adverse increase over 20% also fails against
the previous stable, including reads, wakeups, logs and children. Reuse uses the
inverse direction. A zero baseline uses the metric's explicit absolute bound;
without such a bound, a nonzero result fails. Reads above 3 GiB/hour raise an
alarm without becoming another absolute failure. Missing, nonfinite, negative
or mismatched observations fail; supplied pass flags are not trusted.

The validator consumes reviewed aggregates; it does not run a sampler or verify
live process identity itself. Collect and verify candidate PID/start/digest and
previous-stable provenance before producing evidence. Keep raw local samples
and provider data out of public artifacts.
