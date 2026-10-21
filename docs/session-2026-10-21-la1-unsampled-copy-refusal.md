# Unsampled native copy refusal keeps unrelated residents

At each scan step the sampled scanner computes an optional copy budget beside
the active file. A budget of zero calls the copy-refusal release. Before this
change, an unsampled active took the `ClearOtherActive` branch and cleared every
retained reduction in the shared process cache. Unsampled actives include a
Claude file read while the sidecar census is incomplete, and a Codex file under
the 64 MiB singleton limit read while the census is incomplete. Unrelated files
that had a valid, bounded resident then read `Full` instead of `Tail` on their
next append.

## The exemption

The release now skips the clear only when all of these hold:

- the scan's audit metadata is supported;
- the active satisfies `owns_no_optimization_state`. That means `sampling`,
  `cursor`, `group` and `parser.reader.acquisition` are all absent; `aliases`
  and `applied_receipts` are empty; and there is no tier-replay group proof
  (`codex_tier_replay.join` is absent);
- this same step's budget walk measured the resident bound as `Some(r)`, with
  `r <= STATE_BYTES`.

The measurement comes from the walk the step already runs (`copy_budget_parts`
returns it next to the budget). It is used once, at the step-start refusal
decision, before parser progress, admission, any await or local mutation. It is
never carried to another step. No walk is added.

## Unchanged behavior

- The `#641` sampled `Full` branch.
- Unsupported metadata (`ClearMetadataUnsupported`) and no active
  (`ClearNoActive`).
- Every structural miss (`ClearOtherActive`): `Tail`/`Unchanged` borrowed
  state, cursor jobs, groups, aliases, receipts or a present acquisition.
- The no-argument wrapper (now test-only) and `completion_copy_budget` pass no
  measurement, so they stay conservative.
- The copy budget stays zero, so the exempt active retains nothing. No cap,
  admission or budget exclusion changed.

## Diagnostic reclassification

If the resident bound is unknown, the exempt shape still clears. It is now
recorded as `ClearFullResidentBoundUnknown` instead of `ClearOtherActive`.
Unknown covers an unsupported layout, the visit limit, overflow above the state
budget, and a contended or poisoned lock. Saved counter comparisons across this
change need to account for the move.

## Limits

This is not a combined native-plus-cache RSS bound. The unsampled native parse
is baseline memory that can coexist with bounded residents, as it already does
for sampled `Full` reads.

These known residuals remain open:

- fill-and-freeze;
- the 256-entry capacity;
- selection and rearm loops;
- `Tail` refusal clears;
- memo overflow;
- unknown-resident clears.

The fixtures prove the mechanism on the real production step. They do not show
that observed bursts or CPU costs are fixed. Tests ran only in CI; no local
build or test was run.
