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
