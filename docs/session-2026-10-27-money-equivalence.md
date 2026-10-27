# Emitted money equality gate

Manual CI compares retained in-memory Tail/Unchanged reads with cold Full reads
of identical synthetic files. Each arm uses the native parser, evidence attach,
side-call resolution, identity reconciliation, policy and finish stages. The
comparison covers complete emitted session bodies in upload envelopes, including
body witnesses, plus SHA-256 digests. It never compares accumulators. Base and
candidate compile independently with the same test harness and input clocks;
exact saved input bytes must match across both builds. Within each build,
retained versus Full raw bytes and digests remain exactly equal. Receipts keep
those raw bodies and digests and add a cross-build body/digest. Only that second
body replaces each wire snapshot's `source_file_fingerprint` with
`physical-identity:excluded`, then recomputes its semantic envelope through the
production revision v1/v2 functions. A guard requires every other field to match
raw emission, including all other envelope fields and money. No hashes are
removed or blanked; inode and ctime are not pinned.

Accepted scope: cross-arm changes in scan-identity or sidecar version strings
inside the file fingerprint are invisible to the cross-build step; these are
re-read triggers, not money. Explicit version fields outside that fingerprint
remain compared. All counts, tokens, costs, selectors, timestamps, IDs and
ordering still participate. Raw bodies/digests remain available as evidence.

Dispatch on a reader branch:

```sh
gh workflow run ci.yml --ref <branch> -f money_equivalence=true
```

`money_equivalence_base=<ref-or-sha>` overrides the comparison ref. Empty resolves
the branch's open PR base (or main without a PR); ambiguous bases fail. The job
records exact source SHAs and uploads `money-equivalence-receipts` for 14 days.
One standard macOS runner executes two builds, with a 55-minute ceiling and no
matrix, automatic retries or cache writes. Other CI jobs are skipped for this
dispatch. Ordinary PR/push validation keeps its existing checks and gains no
additional macOS job. Cancel/disable this dispatch job to roll back its cost.
The workflow is public; organizational budgets and runner pins are unchanged.

Active fixtures, one test each:

- Progressive response updates across pages.
- Duplicate request IDs in a file.
- Resolver conflict.
- Quiet session with telemetry and a side call arriving after the native read.
- Side call with a transcript owner.
- Side call without a transcript owner.
- Side call whose actual owner's directory is outside the listed scan root.
- Failed or incomplete telemetry on a live session publishes a request-owned
  token-only estimate on both arms: one request, input/output 10/10, cache read
  3, cache creation 5m/1h 5/2, absent costs, false telemetry completeness and no
  request-owned quarantine. Each arm continues from its own finished failed-step
  index; a healthy read replaces the estimate with reported cost `0.0001`,
  `telemetry_matched` origin and true completeness, conserving requests/tokens.
  Both phases independently reach real upload and compare complete envelopes,
  body witnesses and digests; both emissions enter the receipt. Cross-phase
  cost/origin/completeness must differ. The warm-up finalizes healthy reported
  telemetry so the failed estimate changes the effective body and survives
  ordinary semantic no-op suppression. The failed phase removes the trace
  sidecar to preserve its unpaired malformed API-sidecar input. History-upgrade
  holds are separate.
- Codex V2 counting remains selected after index reload and retained Tail.
- Codex Legacy-ACK remains selected after index reload and retained Tail.

Every active fixture asserts its observed retained acquisition mode and emits
nonempty final bodies. Linux explicitly prints UNEXECUTED when the native
retained-layout contract is unavailable; that cannot pass the macOS job.
The existing scanner/pipeline tests remain unchanged apart from test inclusion
and a test-only scanner helper for Codex.

Named ignored tests fail if explicitly run. Their reasons are feature gaps:
restart between pages, upgrade without a semantic revision, and downgrade then
re-upgrade need durable E1 restore/codec/generation binding. Branch copies,
resume copies, moves, one growing twin, stale/queued holders and mixed accounts
need the family commit vector; main currently forces family Full reads. Pi
remains the explicitly documented Full-on-change exception. None is simulated
as restored. A future durable scanner can be added as a third comparison arm.

Local validation is limited to explicit-file rustfmt and `git diff --check`.
Hosted Linux owns portable compilation/tests; this manual macOS job owns native
retained-path evidence. A successful Linux run alone is not an equality verdict.
