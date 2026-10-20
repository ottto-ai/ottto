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
  its child stays held with no recorded cause unless a valid persisted
  ledger resolves it.
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
  admission, and a member that grew past the limit ends the job as `Strict`.
- **O7 (protected-tier replay).** It now requeues to the cursor when the file
  is larger than the 64 MiB singleton budget. Before, it re-read the whole
  file in one page up to 2 GiB.

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

The v5 golden keys come from supported CI, not a local build. A first CI
pass with placeholder keys failed on purpose and printed the actual keys and
their unblinded fixture inputs: the payload and rescanned fingerprints, the
six component hashes and the revision hash. Under the v4 domain those inputs
reproduce every v4 golden key. Under the v5 domain they give exactly the
keys CI printed. Only then were the keys written to
`fixtures/snapshot-audit/v5-golden-keys.json`.

## Latency trade-off (O7)

O7 needs no flag: a build that contains this change behaves this way. An
existing protected-tier tail over 64 MiB used to publish within one page. It
now waits for a cursor read of the whole file: `ceil(L / 64 MiB)` pages
(2 to 32 pages for 65 MiB to 2 GiB: about 10 minutes to 2.7 hours at the
5-minute cadence, 20 minutes to 5.3 hours at the idle cadence), plus any
wait for the single cursor slot, plus the census-generation fence when the
file was already attempted in the generation. The bytes read are the same;
they are spread over pages. This is a material publication-latency cost,
not a counter shift. It is the price of never reading more than the
singleton budget in one page.

## Residuals (unchanged by this change)

- P1-AUDIT-DUTY: a full read that outlives the audit interval stages its
  debt again (pinned by F-T19(a) until AD-1).
- P1-RETAIN: retention limits and eviction.
- Lossy reads and N2.
- Restart, memory pressure and unsupported layouts. A scan with an
  unsupported layout still refuses Codex files over 2 GiB, counted and
  disclosed.
- Cursor slot starvation.

Scaled tests prove the routing. They do not prove real throughput above
2 GiB.

## Installed acceptance (not run here)

On an installed build with the cursor enabled:

- `cursor_disabled_unsupported_layout == 0`;
- Codex `oversized_file_count == 0`.

Merging the source is not activating the installed runtime.
