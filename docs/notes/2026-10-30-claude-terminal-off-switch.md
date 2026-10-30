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

## Shared safety exception in OFF

Trace sidecar reads retain a per-file take() bound and opened/path generation
validation in both modes. This fixes an inherited main race: the real capture
writer can append its cap-crossing final row after the reader's initial stat.
The old reader could certify that oversized/growing file as complete. The shared
fix withholds evidence instead; it adds no proof, ACK or receipt. Stable trace
rows, dedupe and health counters are compared with the exact main reader body in
a test-only reference. A real cap-crossing producer fixture asserts consumed
bytes equal the initial opened length plus one, with no complete evidence.
Per-pass strict-cohort pacing remains ON-only. This is the explicit shared
correctness exception in the hunk audit, not an OFF terminal-policy change.
The shared trace bound moves to its own main PR (`t1/trace-reader-bound`);
#899 will merge main after it lands and keeps its copy of the change until then.

## Readiness and known ON residuals

OFF merge still requires R6/R12, the empty-context B1 control, OFF identity,
Linux and the merge-queue Mac. Two ON blockers are fixed here, both gated on
`claude_terminal_off()` and with no persisted field:

- **B-P2 (missing ACK):** a stale family member whose committed head carries a
  body the server never accepted (and no refusal quarantine owns) is never
  covered by the redundant stale-clear suppression. It stays Parse and its
  head is offered again; ACKed members keep the suppressed clear (Skip).
- **B-P5 (re-arm loop):** under containment neither the contract latch nor
  source-wide context adoption discharges, so the semantic stale clear used to
  re-arm every stale family at every red-retry or floor start. A bounded RAM
  memo (16,384 hashed keys, FIFO, eviction diagnostic) now serves it once per
  family and generation (traversal context, upload context pair, contract,
  latch). A cleared member stays cleared until it is read; eviction or a
  restart costs at most one more re-read, never proof, ACK or settlement.

## OFF proof and the ON-readiness manifest

OFF is proven by main's own tests. Every test that exists on main runs with
main's exact text at the default OFF; shared fixture helpers keep main's body
and reach the containment version only while a test opts in to ON. The
containment version of each changed main test runs separately as
`terminal_off_on_<name>` under the explicit ON guard, with every money, ACK,
body-equality and zero-read assertion of its original.

ON twins (and new ON tests) that are known red are ignored with the reason
`terminal-off ON-readiness: <cluster>`. The unit test
`terminal_off_on_readiness_ignores_equal_the_checked_in_manifest` compares every
such ignore in the crate's sources with the checked-in list in
`snapshots/terminal_off/readiness_manifest.rs`, so the count is visible in CI
and cannot drift.

- Turning ON anywhere, Ron's M4 included, and flipping the default to ON both
  require that manifest to be **empty** plus Lead B's sign-off.
- An entry is un-ignored only together with its cluster's fix, never by editing
  an assertion.

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
