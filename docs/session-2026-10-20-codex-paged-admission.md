# Codex paged admission (FC1)

A Codex rollout larger than 2 GiB (`MAX_CODEX_JSONL_FILE_BYTES`) used to be
refused at discovery and counted in `oversized_file_count` on every scan,
forever. The sampled scan already reads large files through the paged P1
cursor, whose per-page budgets do not depend on the file's length, so the
refusal excluded files that the cursor could read.

## Behaviour

- **Discovery.** Codex has no discovery cap. Claude Code and Pi keep theirs
  (256 MiB).
- **Admission.** Each opened handle gets a `ReadAdmission`, stored on the
  active file and never widened later.
  - `Bounded`: Codex, a sampled scan and a validated layout. There is no size
    limit at open; bodies are read by the cursor, as a budgeted tail, or
    (the protected-tier fallback, O7) as main's whole-file in-page replay
    when the reopened descriptor is at or below the unpaged limit.
  - `Unpaged`: everything else. It keeps today's per-source cap at open, on
    the opened descriptor's length.
  - Admission is routing, not a budget proof. Every body read keeps the
    existing page, layout, cursor and accounting gates.
- **Identity opens.** Opens that only compare identity take at most two 4 KiB
  samples and no cap: parent matches, group identify, memo and parked
  matches, and revalidation.
- **Parent `Oversize`.** A parent is an `Oversize` witness only where the
  scan cannot page it. This is decided from the opened descriptor's length.
  Parent witnesses come only from the sampled parent pass, as before: on an
  unsampled scan an over-limit parent is refused at its unpaged open, and
  its child stays held with no recorded cause. The refusal keeps the
  parent's persisted ledger, and ledger validation (identity only) still
  validates it. A fresh unsampled traversal validates ledgers before its
  discovery fills the census, so in that run the ledger does not resolve the
  child (existing census ordering, unchanged). The ledger helps where the
  census exists at validation: a resumed traversal, or a sampled scan.
- **Parent ledger cap.** A paged scan admits and cursor-reads an over-limit
  parent, but a parent with 4097 ownership signatures, one past the cap,
  still has no usable ledger: its child is held under `LedgerCapped`, never
  `Oversize`. At the cap (4096) the ledger resolves the child.
- **One runtime refusal** (`refuse_unpaged_overrun`), at every point where a
  non-cursor read starts:
  - R-a: the main-loop read;
  - R-b: a non-paged group, from each member's identify-time length;
  - R-c: the protected-tier replay.

  A Codex handle whose remaining bytes exceed the unpaged limit is never read
  in a page. A `Bounded` handle is requeued (the next plan pages it). An
  `Unpaged` handle is counted oversized and is not read, as at open.
- **Group members.** A member's identify-time length is not final. Each
  member body open still checks its own descriptor under the job's
  admission, and a member that grew past the limit ends the job as `Strict`
  debt. That member is disclosed as strict debt, not counted in
  `oversized_file_count`.
- **O7 (protected-tier replay), FC1-narrow.** Direct O7 routing is unchanged
  for descriptors at or below 2 GiB at the admission check: the replay reads
  the whole file in the page, as on main. R-c checks the reopened descriptor
  before any parser exists; over the limit a `Bounded` file is requeued to
  the cursor (new coverage, these files were refused before) and an
  `Unpaged` one is counted oversized. A failed O7 reopen counts as oversized
  only when it is the unpaged size refusal (`Unpaged`, `InvalidData`, the
  descriptor over the limit: the same predicate as at open). Any other
  failure is `OpenRead`, as before. The length check is not a hard byte cap
  against concurrent growth (a file that grows during an in-page read is read
  on) and not a total memory bound; both are pre-existing on main.
  An earlier revision also requeued replays of files over the 64 MiB
  singleton budget; that widened guard is removed by the parent's
  engineering scope decision (FC1-narrow).

Preserved: opened-descriptor identity and TOCTOU checks, #645 `NotFound`
causes, prior bodies, held, ACK and protected state, and truthful observed
keys. No discovery-body, census, scheduler or constant changes are included.
`MAX_CODEX_JSONL_FILE_BYTES` and every page budget keep their values.

## `snapshot-audit` v5 (prospective)

`local_snapshot_audit:v5` adds `oversized_file_count` and `census_complete`
to the report. The schema string is the HMAC domain of all six key
derivations (session, semantic, machine, semantic component, revision and
legacy-policy candidate keys), so every blinded key changes, as at every
earlier bump. The audit state schema stays `local_snapshot_audit_state:v3`.

A consumer must treat an unknown or missing completeness field,
`oversized_file_count > 0`, or `census_complete == false` as an incomplete
audit leg. This is a producer change only. The private validator's v5
support is separate work, and no audit was run or collected for this change.

`v4-golden-keys.json` is kept, unreferenced by tests now: it is the
provenance of the v5 keys (their inputs were checked against it) and the
reference for the validator's v4 mapping. A later cleanup may retire it.

The v5 golden keys come from supported CI, not a local build. A first CI
pass with placeholder keys failed on purpose and printed the actual keys and
their unblinded fixture inputs: the payload and rescanned fingerprints, the
six component hashes and the revision hash. Under the v4 domain those inputs
reproduce every v4 golden key. Under the v5 domain they give exactly the
keys CI printed. Only then were the keys written to
`fixtures/snapshot-audit/v5-golden-keys.json`.

## Latency and shared-resource cost

This change needs no flag: a build that contains it behaves this way. It
does **not** promise unchanged publication latency system-wide: newly
admitted files over 2 GiB can delay smaller jobs and census completion.

**What stays as on main, per file.** Direct O7 routing for descriptors at or
below 2 GiB at the admission check, and every other route for files at or
below 2 GiB (the open caps, R-a, R-b and R-c compare against the unpaged
limit and never fire at or below it). Protection is main's: the first
completed priority read captures a tier receipt and a protected owner, so the
file is never sampled again (`allow_sample` requires `!protected`) and every
later change is a Full read, a cursor read above 64 MiB, as on main.

**Files over 2 GiB (new coverage).** Every per-page budget is unchanged and
independent of L. Elapsed time is linear in L, with no ceiling:

| File length L | Pages | 5-minute cadence | Idle cadence (10 min) |
|---|---|---|---|
| 4 GiB: first read, O7 requeue, or every change of a non-retained file (protected, or over 256 usage turns, expected for sessions over 2 GiB) | 64 per read | 5.3 h | 10.7 h |
| over 2 GiB in general, same reads | `ceil(L / 64 MiB)` per read | no upper bound: linear in L | no upper bound |

A cursor reduction is retained only with at most 256 distinct usage turns
(`MAX_PRIORITY_WITNESSES`), so a file over that is not retained and its next
change is a full cursor read
(`over_limit_file_with_257_usage_turns_is_not_retained`).

**Interference with smaller files (slot and census).** There is one cursor
slot, rotated by whole attempts and non-preemptive, and a cursor job or a
deferred waiter holds the strict census. One 4 GiB file therefore holds the
slot for 64 pages per attempt (5.3 h at the 5-minute cadence, 10.7 h idle):
every other read over 64 MiB that arrives meanwhile (a first read, a
protected change's Full read, a replaced file) waits up to that long, and the
census generation grows by 64 pages each time the file is due, which delays
the census-gated steps (manifest re-publication, backfill completion,
context-curve settlement, reconciliation). While its job is resident,
retained copies of small files can be evicted to make room, so their next
read is a Full read. On main the same mechanisms apply with files of at most
2 GiB (at most 32 pages per attempt); FC1 removes that ceiling. With no
Codex file over 2 GiB on the machine, nothing here changes.

**The generation fence (K7).** A file whose cursor attempt already completed
in the current census generation is `Fenced`: its next large read waits for
the next generation. The fence is not specific to FC1: `cursor_plan` fences
every large read after an attempt in the generation. A generation is one
bounded traversal (`census_token`: context fingerprint and census window). It
retires only when no directory or candidate is pending (deferred and
in-progress large files stay pending), the raw census is complete, no legacy
join baseline remains, and no protected entry awaits finalization; a restart
(hints or parent resolution) ends it early. So the fence lasts the rest of
the current traversal, dominated by the remaining pages of every large read
still pending in it (the sum of `ceil(Fj / 64 MiB)`), then the file's own
`ceil(L / 64 MiB)` pages in the next generation.

**Convergence after AD-1 (#659), conditional.** The audit interval is one
hour, so a cursor read of more than about 12 pages at the 5-minute cadence,
or about 6 pages at the 10-minute idle cadence, outlives it: a file over
about 768 MiB or about 384 MiB respectively, or a smaller one when the read
waits for the slot or the fence. A stable outlived read verifies at commit,
so **only a quiescent, loss-free, complete file under a trusted census**
needs at most one more whole read after its last change (F-T19(a); the Skip
in later generations is #659's AD-T6/T7). A read during which the file grows
still stages its debt (F-T19(b)), so an active non-retained session over
2 GiB can be read back to back while it keeps changing.

**Does not converge, for files over 2 GiB.** The non-converging classes of
the FC1 design of record (§0.3). FC1 does not create their mechanisms; it
newly exposes files over 2 GiB to them.

- **Lossy** (for example, one record over 16 MiB, `MAX_JSONL_LINE_BYTES`):
  the read refuses as `Lossy` before AD-1's arm, publishes uncertified and
  keeps its marker (#659's
  `lossy_grown_job_publishes_uncertified_through_same_object_identity`). It
  costs `ceil(L / 64 MiB)` pages every census generation with no change,
  holding the single slot and the census, and its marker permanently takes
  one audit slot toward the pending limit that disables sampling for every
  file when exceeded.
- **N2, a withheld final record on a stable file:** its fragment debt is due
  at the read's start plus one hour, so a read that outlives the interval
  (every read over 2 GiB) is due at commit. The same `ceil(L / 64 MiB)`
  pages every generation, while the record stays withheld.
- **Singletons under an untrusted census:** the cursor certificate is not
  retained, so every change is a whole `ceil(L / 64 MiB)` read while the
  census stays untrusted.

## Residuals

- P1-AUDIT-DUTY, as left by AD-1 (#659): a read that outlives the audit
  interval verifies at commit when the file was stable (F-T19(a)). A grown
  read stages its debt (F-T19(b)); a partial read does too (#659's AD-T4).
  A lossy read refuses before the arm and keeps its marker (#659's
  `lossy_grown_job_publishes_uncertified_through_same_object_identity`).
- P1-RETAIN: retention limits and eviction. Mechanism unchanged; FC1 extends
  its reach to files over 2 GiB (the per-change row above; design §0.3).
- Lossy reads and N2. Mechanism unchanged; FC1 extends its reach to files
  over 2 GiB (the "does not converge" list above; design §0.3).
- Restart, memory pressure and unsupported layouts. A scan with an
  unsupported layout still refuses Codex files over 2 GiB, counted and
  disclosed.
- Cursor slot starvation. Files over 2 GiB add to its standing load (see the
  interference paragraph above).
- A non-paged group member that grows past the unpaged limit after identify
  ends the job as strict debt; it is not counted in `oversized_file_count`.
- F-T21 (retained eviction under state pressure) is not a row here: FC1 does
  not change eviction, the paused charge or the state budget. It stays a
  P1-RETAIN test.

`ta::sample_at` above 2^32 (F-T6c) is covered by AD-1 (#659)'s sparse-file
unit test in `transcript_acquisition`.

Scaled tests prove the routing. They do not prove real throughput above
2 GiB.

## Installed acceptance (not run here)

On an installed build with the cursor enabled:

- `cursor_disabled_unsupported_layout == 0`;
- Codex `oversized_file_count == 0`.

Merging the source is not activating the installed runtime.
