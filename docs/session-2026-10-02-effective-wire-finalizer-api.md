# Effective upload-body finalization

`finalize_scan_after_policy_with_body_witness` lets upload callers supply the
existing additive body witness for their effective wire projection. Semantic
fingerprints are recomputed first. The supplied function feeds both the existing
per-file body-witness fold and quarantine retry comparison, so a projection
correction can upload once and a repeated stable projection can settle as a no-op.

`finalize_scan_after_policy` retains the default body-witness function. Raw local
snapshot items, semantic identity, state-only finalization, source selection, and
digest domains retain their existing behavior. Callers must provide a stable
witness matching the body they upload; this API does not trigger historical
rescans or change a protocol contract.

Focused tests cover default snapshot/index byte and no-op equivalence, effective
projection stability with unchanged local items and semantic state, and quarantine
decisions using the same projection after fingerprint recomputation.

Eight focused service library tests passed with offline dependencies and an
isolated build directory: three new finalizer tests and existing curve correction,
semantic no-op, due quarantine retry, lossy-file finalization, and state-only
fallback tests. Touched-file formatting and diff whitespace checks passed.
