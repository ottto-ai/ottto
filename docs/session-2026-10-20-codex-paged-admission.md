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
    limit at open; bodies are read by the cursor or as a budgeted tail.
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
- **O7 (protected-tier replay).** It now requeues to the cursor when the file
  is larger than the 64 MiB singleton budget. Before, it re-read the whole
  file in one page up to 2 GiB. A failed O7 reopen counts as oversized only
  when it is the unpaged size refusal (`Unpaged`, `InvalidData`, the
  descriptor over the limit: the same predicate as at open). Any other
  failure is `OpenRead`, as before.

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

## Latency trade-off (O7)

O7 needs no flag: a build that contains this change behaves this way.

**Once per file, at its first priority tail.** O7 fires on every tail that
parses priority-tier usage. But the first priority publication leaves a tier
receipt on the file's index entry, so its history is protected
(`codex_history_is_protected`), and protected files are never sampled again
(`allow_sample` requires `!protected`, unchanged from main). Every later
change is therefore a Full read, and a Full read of a file over 64 MiB was
already a cursor read on main. So for an existing file of 65 MiB to 2 GiB,
FC1 moves one read, the first priority tail's in-page replay, to the cursor:
`ceil(L / 64 MiB)` pages once. Later changes cost what they cost on main.
A test pins this: the second change is a Full cursor read, not an O7 tail.

| File length L | Pages | 5-minute cadence | Idle cadence (10 min) |
|---|---|---|---|
| 65 MiB – 2 GiB (existing), first priority tail | 2 – 32, once | 10 min – 2.7 h | 20 min – 5.3 h |
| 4 GiB (newly admitted), every protected change | 64 per change | 5.3 h | 10.7 h |
| over 2 GiB in general | `ceil(L / 64 MiB)` per change | no upper bound: linear in L | no upper bound |

Files over 2 GiB are new coverage (they were excluded before). Once
protected, each of their changes is a Full cursor read of the whole file.

**Plus the slot wait.** There is one cursor slot, rotated by whole attempts.
On main, every change of a protected file over 64 MiB already takes a whole
attempt. FC1 adds the first priority tail of 65 MiB – 2 GiB files and every
change of protected files over 2 GiB to that load. Every other paged read
(first reads over 64 MiB, other O7 requeues) waits behind those attempts,
and they wait behind it. This is the standing load behind the
cursor-slot-starvation residual below.

**Plus the generation fence (K7).** A file whose cursor attempt already
completed in the current census generation is `Fenced`: its next large read
waits for the next generation. A generation is one bounded traversal
(`census_token`: context fingerprint and census window). It completes only
when no directory or candidate is pending, and deferred or in-progress large
files stay pending. So the fence lasts the rest of the current traversal:
at least one page, at most the remaining pages of every large read still
pending in it (the sum of `ceil(Fj / 64 MiB)` over those files). Then come
the file's own `ceil(L / 64 MiB)` pages in the next generation. With no
other large read pending, the traversal ends with the file's own attempt and
there is no fence.

The bytes read are the same as before; they are spread over pages instead of
one page of up to 2 GiB. This is a material publication-latency cost for a
priority-tier session's first priority change over 64 MiB, and for every
change of protected sessions over 2 GiB. It is not a counter shift. It is the
price of never reading more than the singleton budget in one page.

## Residuals (unchanged by this change)

- P1-AUDIT-DUTY: a full read that outlives the audit interval stages its
  debt again (pinned by F-T19(a) until AD-1).
- P1-RETAIN: retention limits and eviction.
- Lossy reads and N2.
- Restart, memory pressure and unsupported layouts. A scan with an
  unsupported layout still refuses Codex files over 2 GiB, counted and
  disclosed.
- Cursor slot starvation. FC1 adds to its standing load (see the latency section).
- A non-paged group member that grows past the unpaged limit after identify
  ends the job as strict debt; it is not counted in `oversized_file_count`.
- `ta::sample_at` above 2^32 (the audit sample a `Full(AuditDue)` read takes
  on a file over 4 GiB) has no test here: the function is private to
  `transcript_acquisition` (F-T6c).

Scaled tests prove the routing. They do not prove real throughput above
2 GiB.

## Installed acceptance (not run here)

On an installed build with the cursor enabled:

- `cursor_disabled_unsupported_layout == 0`;
- Codex `oversized_file_count == 0`.

Merging the source is not activating the installed runtime.
