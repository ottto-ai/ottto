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
stated reason.

It also fixes a pre-existing flake in `transcript_cache` tests: the
`retained_at` fixture named temp files by process id and clock nanoseconds
only, so two back-to-back calls could collide under `create_new`. A counter
now keeps the names unique.
