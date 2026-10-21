# Cache-policy regression harness (red on main)

Test-only harness for the resume-checkpoint cache policy (Slice M, M0). Each
`cache_policy_*` test in `crates/ottto-service/src/snapshots/cache_policy_tests.rs`
drives the real production scan step loop against one shared
`SharedCache::default()`. It asserts the DESIRED policy, so it fails on main
for the reason its doc comment names. Preconditions are asserted first, so a
setup failure cannot pass as the defect. No production code, hook, Cargo or
lockfile changes. The module registers in `snapshots.rs`. Its helpers are
copied from `transcript_acquisition_tests` and the StateMissing retention
baseline.

The default cache is `TranscriptCache::with_byte_limit(STATE_BYTES)`, and the
copy budget is measured against that same constant. So the tests size real
transcripts against the 32,505,856-byte state budget instead of injecting a
smaller limit.

1. **G1, degrade gracefully.** Twelve growing Claude sessions of 1,000
   responses each, so about four cycle through the budget
   (`capacity = STATE / entry - 2`). Round 0 reads every file for the first
   time in creation order, so the first-seen sessions fill the cache. Then
   three rounds: append to every file, then scan each newest first. A
   census-incomplete Codex page runs before each round. Its unsampled active
   meets a zero copy budget, and since #654 it must not wipe. Desired:
   - no wipe-all clear;
   - the `capacity - 1` or more most recently appended files resident after
     every round;
   - at least `capacity - 1` tails in rounds 2 and 3;
   - the optional cache within the budget at every page end;
   - output byte-equal to a cacheless control.

   Red on main: fill-and-freeze. Admission never evicts, so the first-seen
   files stay resident. The most recently appended files are refused and
   reread `Full(StateMissing)` every round.
2. **G2, cold flood.** Four warm 600-response sessions are retained. Then 50
   cold 200-response sessions (mtime two days back) are read once. Desired:
   - no warm entry is lost during the flood;
   - cold files never evict;
   - every clone is admitted;
   - each warm session's next append is a tail and keeps its entry.

   Red on main: the cold entries keep the free room. A warm session's tail
   then refuses its own re-admission (`retention_bound_refused`), so the
   session loses its entry. The flood-time assertions are expected to pass
   on main.
3. **G3, priority.** An entry ranked below every filler is read as a tail
   beside four newer fillers that fill the cache. Its long appended record
   meets a zero copy budget. Desired: no newer entry is evicted and nothing
   is wiped. Red on main: `ClearOtherActive` releases all four fillers.
4. **M1 (i), no wipe-all.** The same full but not overflowing cache, with a
   recent tailed file. Desired: `clear_other_active` 0,
   `clear_entries_released` 0, and at most one filler yields to the newer
   file's own re-admission. Red on main: one `ClearOtherActive` releasing four
   entries.
5. **M2, fill-and-freeze.** Old-mtime fillers fill the cache. A recent
   600-response session completes its first full read. Desired: it displaces
   old fillers, is retained, and its next append is a tail. Red on main:
   `retention_bound_refused` 1, `insert_entries_evicted` 0, and the next
   append reads `Full(StateMissing)`.

Each test prints one count-only `CACHE_POLICY` stderr line. On an unsupported
layout each test prints `UNEXECUTED` and returns. These tests are **UNRUN until
CI**. No local tests or builds were run for this patch.
