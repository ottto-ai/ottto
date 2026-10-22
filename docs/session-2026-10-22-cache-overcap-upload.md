# Over-cap cache observations upload a bounded set, not none

A session with more cache observations than one patch carries (64) used to
upload none of them: `cache_wire_for_requests` cleared every operation and sent
partial coverage with the total as `omitted_observation_count`. Long, busy
sessions, which are the likeliest to have expensive cache rebuilds, therefore
showed no breaks at all. The upload step (`prepare_cache_observations`) had the
same all-or-nothing clear when retractions pushed a patch over its budget.

## Fix

- `snapshots.rs` `cache_wire_for_requests`: over the cap, upload the rows the
  bounded detector already keeps (the first 64 in session order), sorted in
  session order, with partial coverage and an exact count of the rest. If the
  bytes budget is still exceeded, drop rows from the end and count each one.
  The first rows never change as a session grows, so a tail pass adds no
  retractions and the accepted state never exceeds the cap.
- `prepare_cache_observations`: a partial patch with an exact omitted count is
  treated like a complete one for stale-row retraction (every request was
  read). Over budget, it keeps every retraction and drops the last upserts,
  counting each, instead of clearing everything. A lossy parse (partial with
  no count) is unchanged: no operations, no retractions.
- `omitted_observation_count` now means observations not uploaded, not the
  session total. Uploaded rows plus the count equal the session's breaks.

Why not the newest 64: a sliding window must retract every row that falls
out. When a session grows by many breaks between passes, upserts plus
retractions exceed the 64-operation patch, so the newest window cannot always
be reached in one pass and full-read parity would depend on pass history.

## Contract and weight

- Server: the patch schema already accepts operations with partial coverage
  and an omitted count; state keeps the cumulative rows. No server change.
- No scan identity, parser version, or body witness version change. Cache
  evidence is not part of semantic identity; the body witness already hashes
  the cumulative state. Sessions already uploaded with no rows heal on their
  next append; finished sessions keep their old empty partial state until a
  re-read for another reason.
- Weight: at most 64 rows per session per patch, computed in the same pass
  from the requests the reducer already retains. No extra reads.

## Tests

- `snapshots/cache_overcap_tests.rs`: 64, 65 and 10,000 breaks; duplicate and
  conflicting replays; reversed clocks; successive tail uploads equal one full
  upload (also from the old empty partial state); stale prior rows retracted
  with upserts trimmed, then converging.
- `transcript_acquisition_tests.rs`
  `sampled_native_codex_over_cap_cache_breaks_tail_with_full_parse_parity`:
  a 65-break Codex session tails to 70 breaks with full-read parity.
- `cache_wire_overflow_discloses_and_preserves_prior_on_correction` now expects
  64 operations and one omitted.
