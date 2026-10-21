# Copy refusal evicts only what is needed (Slice M1)

A zero copy budget at a scan step start used to wipe the whole resume cache
for a Tail, Unchanged, group or cursor active, for no active, and whenever the
step's resident walk could not measure the cache (for example a contended
`try_lock`). The budget is `(STATE - resident - active) / 2`, so it is zero
whenever the cache is merely full, not only when it overflows. Each wipe sends
every resident session back to a full read (`Full(StateMissing)`).

## Tests (red on main first)

`crates/ottto-service/src/snapshots/cache_policy_tests.rs` (M1 subset of the
M0 harness, plus two new tests):

- `cache_policy_m1_full_cache_tail_at_zero_budget_releases_nothing` (M1 i):
  a merely full cache beside a Tail whose long line meets a zero budget
  releases nothing.
- `cache_policy_g3_older_candidate_never_evicts_newer_entries` (G3): the
  same with an older-ranked Tail; all four newer fillers stay.
- `cache_policy_m1_tail_growth_releases_at_most_overflow_plus_one_entry`
  (M1 ii): a Tail whose borrowed state grows past the room releases exactly
  one filler, not all.
- `cache_policy_m1_refusal_decision_matrix_evicts_the_minimum` (M1 iii):
  injected step measurements. A merely full cache, no active, and an unknown
  resident (lock contention) release nothing; a real overflow evicts the
  minimum number of entries; an unknown or oversized active charge keeps
  the conservative clear.

The #654 guard matrix (`sampled_unsampled_native_refusal_guard_matrix`) is
M1 (iv) and must stay green unchanged.

The tests-first head adds a test-only seam (`StepMeasure`,
`release_cache_to_fit`) that forwards to main's release and ignores the
active's charge, so the decision matrix compiles and fails on main for its
stated reason. The fix adds
`cache_policy_m1_counts_copy_refusal_releases_by_cause` for the new counters.

## Fix

In `snapshots/sampled_scan.rs` the step-start budget walk now also reports a
`StepMeasure`: the resident bound and the active file's optional charge. That
charge is the active's walk less its reader line buffer, because a full read
of the same line holds that buffer too (native baseline, #641/#654). The walk
of a non-cursor active runs to the whole state budget past that buffer
instead of stopping at the remainder; the copy budget itself is unchanged.

The copy refusal (`release_for_copy_refusal`) then decides:

| shape | before | now |
|---|---|---|
| Tail, Unchanged or other non-baseline active, charge known | clear (`ClearOtherActive`) | nothing if this step's walk shows the residents fit; else evict in victim order until they fit |
| that active, charge unknown or larger than the budget beside an empty cache | clear | clear, counted `ClearOtherActive` |
| no active | clear (`ClearNoActive`) | release to fit (a no-op unless the residents overflow) |
| full or unsampled native baseline, resident unknown or over | clear (`ClearFullResidentBoundUnknown`) | re-measure under blocking locks, evict only a real overflow |
| full or unsampled baseline, resident bounded | nothing (#641/#654) | unchanged |
| unsupported audit metadata | clear | unchanged (M1b is out of scope) |

The fit is measured under blocking locks in the one order (retained, then
cursor): `SharedCache::release_to_fit` evicts with
`TranscriptCache::release_until_for(limit, Release::CopyRefusal)` until the
retained copies fit beside the cursor state, the context overhead and the
active's charge. If even an empty cache would not fit, it evicts nothing and
the caller clears. Callers without a step measurement (the test-only
`release_cache_for_copy_refusal` wrapper) keep the conservative release.

## Memory bound

After any M1 release, residents plus cursor state plus the context overhead
plus the active's optional charge are at most `STATE_BYTES` (31 MiB),
measured under blocking locks. Where that charge is unknown, the cache is
cleared as before. Pre-existing gaps, out of scope here: `memo_record` grows
the cursor memo without admission (review F4a), and the #660 side ledger is
not yet in cursor admission (F4b).

## Counters

Four new process-global counts in the cache lifecycle row:
`copy_refusal_entries_evicted`, `copy_refusal_bytes_released`,
`copy_refusal_remeasured` and `copy_refusal_kept`. Cursor reservations keep
`cursor_reservation_entries_evicted` (review F7). The row's maximum width
stays under 2048 bytes (about 1.9 KB at all-`u64::MAX`).

## Test flake

The tests-first commit also fixes a pre-existing flake in `transcript_cache`
tests: the
`retained_at` fixture named temp files by process id and clock nanoseconds
only, so two back-to-back calls could collide under `create_new`. A counter
now keeps the names unique.

## Round 2 (review changes)

The exact-head review of round 1 asked for four changes and five
disclosures. All production edits stay in `snapshots/sampled_scan.rs`,
`transcript_cache.rs` and the lifecycle counters.

- **Visit-limited active (F1).** Round 1 cleared the cache whenever the
  active's per-step walk hit the 4,096-visit cap, as a long Codex tail's
  usage hours can. Such an active now gets the visit-robust byte walk
  (`completed_bound`) for the refusal's charge only; the copy budget stays
  zero, and the refusal evicts to fit as for any known charge. Each such
  step counts `copy_refusal_walk_visit_limit`. Only a charge over the whole
  state budget still clears. The byte walk runs on every step of such an
  active while it lives (in practice one pass: the next read is `Full`).
- **Cursor and group overflow (F2).** A byte-charged job was walked only to
  the remaining room, so a real overflow recorded `usize::MAX` as its E3
  charge and cleared the cache on that step and the steps after. It is now
  walked to the whole state budget; the budget still charges it against the
  remainder, the refusal evicts to fit on the real charge, and the E3 record
  is that real walk. `usize::MAX` remains only where the job alone exceeds
  the state budget.
- **Path A, the hot tail (F3, owner-accepted).** With evict-to-fit alone, a
  tail at a zero budget beside a merely full cache kept every resident and
  lost its own copy, so an actively tailed file was read `Full` on every
  later pass, where main's wipe re-retained it. Now, at a zero-budget step of
  a sampled tail only, after the fit, `admit_tail_copy` evicts entries ranked
  strictly older than the tailed file (its mtime, clipped to now), in victim
  order, until the tail's own copy fits its next step's budget: the walk
  plus twice its optional charge. It evicts nothing unless evicting every
  older entry would make that room (`TranscriptCache::release_older_until`),
  never a newer entry (G3), and never for a charge over one entry's limit.
  Each eviction counts `copy_refusal_admission_evicted`. The room is sized
  at that step's charge: a tail that keeps growing afterwards can still
  outgrow it, and a zero-budget completion step has already fixed its own
  budget. Neither completion-time admission nor `retain_reduction` changes.
- **Exempt shape on the production path (F4).** A new test drives the
  step-start release of an unsampled native read with an unknown resident:
  it re-measures and releases nothing. The test-only
  `release_cache_for_copy_refusal` wrapper now documents that its `None`
  and non-exempt rows pin a branch production never reaches.

Tests: M1 (i) and (ii) are restated for Path A. (i) now expects no
evict-to-fit eviction, at most two older fillers yielding to the tail's
copy, and the tail re-retained. (ii) expects exactly two fillers. New:
`cache_policy_m1_hot_tail_beside_idle_entries_never_reads_full` (the hot
file is never read `Full` over three passes),
`cache_policy_m1_visit_limited_active_evicts_at_most_what_it_needs`,
`cache_policy_m1_exempt_unsampled_read_remeasures_an_unknown_resident` and,
in `group_job_tests`, `group_overflow_evicts_at_most_overflow_plus_one_entry`.
The decision matrix and counter tests now use a tail ranked below every
filler, so they pin evict-to-fit alone. G3 is unchanged.

Disclosures:

- **Line-buffer slack (F5, owner-accepted).** The active's optional charge
  excludes its reader line buffer as native baseline. A tail's buffer can
  exceed a full read's by Vec doubling slack, under twice its longest line
  and at most `MAX_JSONL_LINE_BYTES`; that slack is uncharged optional
  memory. The copy budget still charges the whole buffer.
- **Per-step counters (F6).** `copy_refusal_kept`, `copy_refusal_remeasured`
  and `copy_refusal_walk_visit_limit` count zero-budget step starts, not
  files or refusals: a long tail beside a full cache counts once per line.
- **Blocking lock under contention (F8).** While a resident walk keeps
  failing its `try_lock`, every zero-budget step takes the blocking retained
  lock to re-measure, and every zero-budget tail step takes it for Path A.
  This is bounded and correct, but it serializes those scans while the
  contention lasts.
