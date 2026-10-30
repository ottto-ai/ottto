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
  membership and accepted-body differences). R5/R11 have the L3 fixes below;
  closure still requires their runtime controls. R1 needs the six B1 twins green
  on the branch Mac. None is relabelled fixture-only without evidence.
- **SHIP-WITH-DISCLOSURE for M4 ON, fix before fleet default-ON:** R3's bounded,
  counted page-0 correction drain. R4 pacing is closed by B1; its remaining
  latch-clear premise is P5 (the completion migration). Actual history reads
  beyond the upgrade budget remain counted for the M4 measurement.
- **R13:** repair the fixture phase (START before RESUME) and obtain a green
  production-path result. This is still pending, not an asserted pass.

L3's held-context memo is RAM scheduling state only. A complete history-held
parse suppresses only that file's UploadContext selection in its exact path,
context, fingerprint, replay epoch, revision and history policy/list scope.
Every complete non-held parse forgets it. Context/fingerprint mismatches forget
the previous hit. It grants no receipt, ACK, absence, census or usage proof.
**Restart or eviction permits one extra held re-read per file, with no upload.**
The cap is 10,000; `upload_context_held_memo_evicted` counts evictions.

R11's ON semantic stale clear skips a member only when main's independent
acceptance predicate and the current per-file context receipt both hold.
ACK-less, held, listed and no-list-held members retain the clear. Destination
changes invalidate the receipt. The full money/BASE matrix is Mac-only; Linux
cannot close it. The C6 held-correction adapter now activates real file context
and uses validated uploader ACK receipts; its strict `[2,0]` assertion stays.
If that twin remains red it returns to R5.

The `history_upgrade_page` diagnostic object under `counts` exposes `admitted_files`,
`budget` and `extra_files` (actual history files read beyond that page's upgrade
budget). The shared ON history fixture uses the collected-at audit clock and
retains the serialized upload ledger across cycles. The held → index rebuild →
release control counts resend bytes and requires zero second acceptance.
These controls need runtime evidence before ON readiness can be claimed.

NBF (non-blocking hold floors) is BLOCKS-RELEASE until its runtime control
passes. Account-deferred keys and bound members of committed families now
register explicit held-key custody in the existing bounded RAM observations.
A fresh hold keeps its one immediate retry (the r26 held-retry contract);
from its first held re-read on, an unchanged object in the same context is
read at most once per six hours, and only an actual acquisition renews the
timestamp. So a new non-blocking hold costs at most two reads in its first
six hours (the first read plus one immediate retry or restart read; Lead B
approved), then one per six hours. The extra early reads are counted as
`nbf_initial_retry_reads` (process total, `terminal_off_nbf_initial_retry_read`
diagnostic, no persisted field) so the M4 trial shows their rate. When a held
key's floor expires it is re-offered once through the targeted queue
(`held_retry_due`): a walk that suppresses unchanged stats and the
deduplicated targeted token would otherwise leave it unread, which is a
custody break. If the ordinary candidate decision would still skip it
(unchanged, context settled), that one floor-expiry read is forced as an
activity/quarantine retry (`terminal_off_held_retry_due_read` diagnostic); the
key's settlement then holds it again (floored for six more hours) or settles
it. The floor crosses traversal
starts without changing sweep-held family roots, proof state or disk formats.
Object/context changes and observation eviction fail toward another read.

**M4-ON disclosure / fleet gate:** NBF adds up to six hours of held
release/re-read latency before ordinary page scheduling. Resolving that added
latency is a separate gate before fleet default-ON. The three census twins and
three p12 wrappers retain their exact read/money assertions at the six-hour
fixture rounds; they remain ignored as NBF pending runtime verification.

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
  most 640 KB for the new optional served-at values, plus approximately 1.3 MB
  for the 10,000-entry held-context memo. These are planning estimates, not
  measured RSS; runtime heap accounting includes the added page count and list
  digest. The process-global memo is capped independently of the scan index.
- S8: the directory walk's scratch pending map clones paths each page. It now
  keeps the **first** duplicate, matching main's previous `.find()` semantics;
  it is not persisted or carried across pages.

Existing per-class retention gauges/alarms remain ON-only. Ron accepted
2026-10-29: ships with per-class gauges/alarms; per-family completion,
usage-proof retirement and the CAS peak are next-release top priorities.
Ordinary held-history total remains a post-release gauge gap. F4 and #876 remain
paired next-release work; no new absence shortcut is introduced here.
