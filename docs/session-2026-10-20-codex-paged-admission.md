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
- **Parent ledger cap.** A paged scan admits and cursor-reads an over-limit
  parent, but a parent past the 4096-signature cap still has no usable
  ledger: its child is held under `LedgerCapped`, never `Oversize`.
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
parses priority-tier usage. But the first completed priority read captures a
tier receipt and a protected owner on the file's index entry (before upload
settlement), so its history is protected (`codex_history_is_protected`), and
protected files are never sampled again (`allow_sample` requires
`!protected`, unchanged from main). A replaced or rotated object starts a new
lifecycle with a Full read, which never goes through O7. Every later
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
waits for the next generation. The fence is not specific to FC1:
`cursor_plan` fences every large read after an attempt in the generation,
including main's Full reads of protected files. A generation is one bounded
traversal (`census_token`: context fingerprint and census window). It
retires only when no directory or candidate is pending (deferred and
in-progress large files stay pending), the raw census is complete, no legacy
join baseline remains, and no protected entry awaits finalization; a restart
(hints or parent resolution) ends it early. So the fence lasts the rest of
the current traversal. Its dominant term is the remaining pages of every
large read still pending in it (the sum of `ceil(Fj / 64 MiB)` over those
files), plus the remaining discovery, small-file and finalization pages.
Then come the file's own `ceil(L / 64 MiB)` pages in the next generation.
With no other work pending, the traversal ends with the file's own attempt
and there is no fence.

**After AD-1 (#659).** AD-1 does not change any figure above. It changes what
follows a file's last change. The audit interval is one hour, so a cursor
read of more than about 12 pages at the 5-minute cadence (a file over about
768 MiB) outlives it. Before AD-1, such a read of an unchanged file staged
audit debt and was read in full again every generation, so a large quiescent
file kept paying whole reads with no change at all. After AD-1 a stable
outlived read verifies at commit: a quiescent file needs at most one more
whole read after its last change, then it is skipped (F-T19(a)). A read
during which the file grows still stages its debt (F-T19(b)), so an active
protected session over 2 GiB can be read back to back while it keeps
changing; that is the per-change cost above, not an extra one.

The bytes read are the same as before; they are spread over pages instead of
one page of up to 2 GiB. This is a material publication-latency cost for a
priority-tier session's first priority change over 64 MiB, and for every
change of protected sessions over 2 GiB. It is not a counter shift. It is the
price of never reading more than the singleton budget in one page.

## Residuals (unchanged by this change)

- P1-AUDIT-DUTY, as left by AD-1 (#659): a read that outlives the audit
  interval verifies at commit when the file was stable (F-T19(a)); a grown,
  partial or lossy read still stages its debt (F-T19(b)).
- P1-RETAIN: retention limits and eviction.
- Lossy reads and N2.
- Restart, memory pressure and unsupported layouts. A scan with an
  unsupported layout still refuses Codex files over 2 GiB, counted and
  disclosed.
- Cursor slot starvation. FC1 adds to its standing load (see the latency section).
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
