# Claude terminal containment: local opt-in, default OFF

`claude_terminal_off_enabled` defaults to **false**. With OFF, the ordinary main
completion, discovery, retry, upload and absence paths run. This is a staged
release of containment code, not a fleet rollout of containment policy.

The existing machine-local sentinel pattern (`mcp_inventory/disabled`,
`context_footprint/disabled`) supplies the setting. A regular, non-symlink file
named `claude_terminal_off_enabled` in Ottto's support directory opts in. The
owner changes it manually; there is no remote control or new settings/index
serialization format. The daemon pins the setting for its lifetime, across
workers and cooperative yields. Restart after a change. Unit tests ignore the
host file and explicitly opt in with a scoped test guard.

Only Ron can authorize ON on his M4 with a typed go, and only Ron flips that
machine's setting. No agent changed the installed setting in this work.
The owner procedure, **after** that authorization and the ON blockers below:

```sh
support="${OTTTO_LOCAL_PLATFORM_SUPPORT_DIR:-$HOME/Library/Application Support/Ottto}"
# ON, owner only; then restart the installed Ottto service normally.
touch "$support/claude_terminal_off_enabled"
# OFF, owner only; then restart the installed Ottto service normally.
rm "$support/claude_terminal_off_enabled"
```

The supported upgrade input is shipped main. The constant-ON development
versions of this still-draft PR were not rollout versions; their untagged
checkpoints are not migration input. Those development hashes cannot be
distinguished from main's without invalidating main's resume too. OFF therefore
keeps main's fingerprint: a shipped checkpoint resumes without a new re-arm.
Every rollout-reachable ON checkpoint gets the tag described below before the
first authorized ON use.

The existing traversal-context digest includes an ON-only domain tag. A saved
ON traversal therefore cannot resume in OFF, including after restart: main
starts a fresh traversal before reconciliation. No new persisted field is
needed. OFF-to-ON similarly starts a new policy-scoped traversal. A transition
can pay main's ordinary reconstruction/re-read cost; it never adopts a receipt,
ACK, source context, family proof or absence in a shortcut.

ON withholds all Claude terminal effects before raw removals/reconciliation,
retirement and tombstone drain, while ordinary page upload, exact ACK and
selected save continue. New cohorts remain unproven; strict posture/cache/curve
outputs pause. Small-cohort completion/corrections wait for paged reconstruction,
delayed rather than erased. Stale unchanged pending custody remains unproven;
admission advances in its retained window. Root discovery coalesces through a
backlog, with a suppressing 1800-second probe. Targeted service retains ordinary
privacy, byte/page, audit deadline, failed-open park and six-hour hold gates.
Each real held serve renews its own RAM six-hour floor. Presence is recorded
before enqueue suppression, including stat-confirmed hints. Read the
[discovery design](2026-10-30-terminal-off-discovery.md) and
[OFF-path hunk audit](2026-10-30-claude-terminal-off-static-audit.md).

## Inherited trace-read safety

The merged trace-reader change supplies the per-file opened-length-plus-one
bound, generation validation and its regression fixtures. Containment adds only
ON pass pacing to that reader. OFF uses the merged reader without a pass budget.

## Readiness and known ON residuals

OFF merge still requires R6/R12, the empty-context B1 control, OFF identity,
Linux and the merge-queue Mac. Two ON blockers are fixed here, both gated on
`claude_terminal_off()` and with no persisted field:

- **B-P2 (missing ACK):** a stale family member whose committed head carries a
  body the server never accepted (and no refusal quarantine owns) is never
  covered by the redundant stale-clear suppression. It stays Parse, and the
  re-arm also forgets its upload body witness (as main does for a
  placeholder), so that re-parse is not a semantic no-op and its head is
  offered again, also across a partial checkpoint taken before it is parsed;
  ACKed members keep the suppressed clear (Skip).
- **B-P5 (re-arm loop):** under containment neither the contract latch nor
  source-wide context adoption discharges, so the semantic stale clear used to
  re-arm every stale family at every red-retry or floor start. A bounded RAM
  memo (16,384 hashed keys, FIFO, eviction diagnostic) now serves it once per
  family and generation (traversal context, upload context pair, contract,
  latch). A start counts the clear as served only when the traversal it
  replaces is the one whose start cleared it, so a working index discarded
  after a cancelled page or a failed checkpoint save is cleared again. A
  cleared member stays cleared until it is read; eviction or a restart costs
  at most one more re-read, never proof, ACK or settlement.

**X3 (#920 retirement under ON).** ON never starts a new generation, so the
traversal's census window is frozen and #920's terminal retirement never runs.
With ON, the stay-retired guard and the admission release cutoff age against
the service clock (floored to a day), and the drained-walk withheld-terminal
block runs the terminal's aged retirement (keep overlap, 90% occupancy release)
at that clock, without the vanished prune, join or shadow counts. Its
kept-overlap row omits `census_missing_over_budget` (measured only by the
terminal's join, so not measured, never 0). OFF is main.
If an ON walk never drains, admission still frees space, in mtime order
(counted by `census_retire_kept_overflow_admission_total`).

**X3-R (ship with disclosure for M4 ON, Lead B 2026-10-31).** Under ON, vanished
keys are never pruned (the prune stays terminal-only), so the census record
count only grows. A new key past 65,536 records is refused: unknown,
fail-closed, never "no holder". Each refusal is counted by
`census_record_limit_refused_total`, which the ON offers line
`ALARM claude_terminal_off offers=… census_record_limit_refused_total=N`
carries once per withheld terminal; N > 0 is the M4 alarm. Before the M4 ON
enable, take a counts-only reading of M4's current census record count, so
the headroom to 65,536 is known. The fleet fix goes with E7-8 paging or a
terminal-only prune.

OFF retains main's retry-admission completion veto: a retained, storage-deferred
admission cannot grant a complete census. The unchanged oversized accepted
singleton control guards that refusal; disabling containment does not bypass it.

## OFF proof and the separate ON gate

OFF is proven by main's own tests: every original retains its exact text,
attributes and platform gates and runs at the default OFF. The retained feature
fixtures cover the switch, OFF checkpoints, custody and containment regressions.

The ON readiness gate lives in the ON PR. Enabling containment anywhere,
including the M4, requires its complete readiness gate to pass, the four parked
native cases to pass, and Lead B's sign-off. The OFF release does not authorize ON.
The train Mac must pass the unchanged main tests by name, including the native
heap-layout, authority-correction and never-quarantine money suites.

ON is **not ready anywhere**, including the M4. Lead B's pending labels remain:

- **BLOCKS-RELEASE before ON:** R2 (correction settlement against wrong revision),
  R10 (unproven money-harness coverage), R7/R8/R9 (held-page custody, manifest
  membership and accepted-body differences), R5/R11 (repeating re-reads), and R1
  if still red after B1. None is relabelled fixture-only without evidence.
- **SHIP-WITH-DISCLOSURE for M4 ON, fix before fleet default-ON:** R3's bounded,
  counted page-0 correction drain; R4's counted one-time history-upgrade burst
  above one file/page, which still needs an M4 measurement.
- **R13:** repair the fixture phase (START before RESUME) and obtain a green
  production-path result. This is still pending, not an asserted pass.

Additional accepted containment disclosures, S3–S8:

- S3: at most 10,000 RAM observations per scope, 40,000 aggregate and 64 scopes.
  Counted evictions permit conservative extra metadata/read work; measure M4's
  cohort. Restart or eviction loses a key's RAM floor and permits a cold offer.
- S4: without known identity/birth, unchanged held reuse/floor is unavailable.
- S5: a cold overlapping-root key can pay one ScopeChanged Full after restart.
- S6: the 30-minute ceiling bounds **discovery**, not FIFO body-read latency.
  Walk interval and oldest-unscanned age are diagnostics; ordinary read budgets
  and backoff still apply. Discovery itself consumes zero transcript body bytes.
- S7: prior review estimated about 14 MB worst-case observation RAM, plus at
  most 640 KB for the new optional served-at values. This is a planning estimate,
  not measured RSS; runtime heap accounting includes every scheduling field.
- S8: the directory walk's scratch pending map clones paths each page. It now
  keeps the **first** duplicate, matching main's previous `.find()` semantics;
  it is not persisted or carried across pages.

Existing per-class retention gauges/alarms remain ON-only. Ron accepted
2026-10-29: ships with per-class gauges/alarms; per-family completion,
usage-proof retirement and the CAS peak are next-release top priorities.
Ordinary held-history total remains a post-release gauge gap. F4 and #876 remain
paired next-release work; no new absence shortcut is introduced here.

## ON follow-up fixes (ON PR, all gated on `claude_terminal_off()`)

These change only the ON path; with the switch OFF each gated site runs main's
code. None adds a persisted field, and none adds a field to an OFF-reachable
struct: ON-only counts live in the `local_resource_diagnostics` per-source
static array (Claude slots 6-9), so OFF struct sizes and the heap-bound walk
equal main (Lead B Q2, 2026-10-31).

- **R7 (witness-bound family re-read):** like main's `stale_pending_roots`,
  neither the ON start's semantic clear nor its per-page retry admission takes
  a family whose authority quarantine is bound to its retained witness; its
  RetryPending deadline keeps the due arm. B-P2's unACKed heads and the B-P5
  memo stay over the full stale set. On a platform without a supported native
  layout (`heap_layout_bound::layout_supported()` is false, so anything but
  pinned macOS), ON's resumed admission runs no carry batch and promotes no
  stale family to the oversized retry root, the same as main's start there.
  Pinned macOS is unchanged. Lead B kept R7 (2026-10-31, 18 witness-bound
  families SEEN on M4); #899's four-batch resume test now expects each batch
  to end one root later and asserts the skipped family's debt stays owed.
- **R11 (exact-ACK re-read under contract debt):** the ON start's semantic
  (contract) clear keeps a member's body when main independently accepted it
  (every snapshot fingerprint ACKed, committed head current) and its request
  census is current for its fingerprint, the same check main's C1b carry uses
  (`terminal_off_stale_member_can_skip_clear`). No upload-context receipt is
  required (Lead B Ask 1, 2026-10-31): exact ACK settles the money, and the
  context debt stays owed on its own paced UploadContext path, so the two do
  not stack into about 12.3k Full reads at ON start (M4: 12,783 exact-ACK
  files, 461 with a receipt). Any member change re-arms. B-P2's unACKed heads,
  held, listed and no-list-held members and the BASE control keep the clear.
  `claude_terminal_off semantic_context_reselection` reports
  `carried_exact_ack_without_receipt`.
- **R5 (held history re-read every walk round):** a bounded RAM memo
  (10,000 path digests, FIFO, `upload_context_held_memo_evicted` diagnostic)
  records that a file's last complete parse was history-held in exactly this
  context (path, context, fingerprint, replay generation and epoch, body
  revision, list state and digest, no-list policy, cutoff and move policy).
  The list digest is folded on demand from the installed list (at most 2,048
  digests), never stored.
  Only the UploadContext selection gate and the targeted `upload_context`
  wake consult it; `file_upload_context_requires_adoption` itself is
  unchanged. A non-held parse, a context or fingerprint change, eviction or a
  restart forgets it. Disclosure: one extra held re-read (no upload) after a
  restart or eviction, and about 1.3 MB extra RAM at capacity.
- **NBF (non-blocking held keys):** a key that non-blocking settlement holds
  keeps one immediate retry; its held re-read floors it for six hours (same
  object, context and revision), and when the floor expires it is re-offered
  (`held_retry_due`) and read once even if nothing else selects it, so a held
  key is never left idle. Disclosure: at most two reads in a new hold's first
  six hours, then at most one per six hours, counted by
  `terminal_off_nbf_initial_retry_read` (`nbf_initial_retry_reads`) and
  `terminal_off_held_retry_due_read` (`nbf_floor_expiry_forced_reads`, Lead B
  Ask 2c: about 7.1k account-held families on M4, so up to about 7.1k forced
  reads per six hours); up to six hours of added held
  release latency, a gate before fleet default-ON. Blocking holds (B1) are
  unchanged.
- **R4 disclosure counter:** each ON page emits `history_upgrade_page`
  (`admitted_files`, `budget`, `extra_files`): history files actually admitted
  to a parser, including local work beyond the upgrade budget, drained from
  the static diagnostics array at page end.
- **R10 fix P (context pacing):** under ON, Claude never adopts the
  source-wide context, so UploadContext stays a file's first selecting gate.
  `context_only_read` now also requires that the decision without the
  UploadContext gate is not Parse, so a real sidecar or retry read uses
  ordinary read budgets while pure context catch-up keeps its one-file
  pacing. ON preflight opens UploadContext candidates before sorting, so both
  sides of that comparison use the full opened identity. OFF and Codex keep
  main's classification.
- **R10 money harness:** `terminal_off_on_money_receipts` includes the
  unchanged money-equivalence harness under the scoped ON guard.
  `scripts/money_equivalence.py` runs base-OFF, head-OFF and head-ON (the same
  head binary, a separate process and output directory), each requiring all
  ten native money receipts and three disk receipts, and compares both head
  arms with base-OFF through the existing decoded-body comparison
  (`MONEY_EQUIVALENCE_DIFF`, `MONEY_EQUIVALENCE_ON_DIFF`). No ON-specific
  exclusion is allowed; the manifest records `terminal_off_on`. Linux reports
  the native harness UNEXECUTED. The three arms share one test thread's
  containment RAM memos, so a green result does not claim cold-process memo
  fidelity.
