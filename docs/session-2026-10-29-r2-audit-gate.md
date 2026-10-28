# R2 audit gates on checkpoint reuse

Ordinary checkpoint-backed acquisition now chooses Tail or Unchanged from
content identity, scope and the existing head/boundary checks. An old full-check
time, a due audit deadline or a regressed audit clock does not force Full.
Completing a Tail or Unchanged read keeps the prior verification time and debt;
it grants no Full-audit or additional census credit. Content identity continues
to use `same_content`, which excludes ctime.

Pending audit count no longer gates ordinary sampling/restore, clears the cache
or disables its copy-budget calculation. Existing resource measurements and
caps remain in force. Legacy audit-capacity diagnostics still report actual
pending/slot state; they can be false while ordinary sampling is allowed.
The `clear_metadata_unsupported` counter remains in the diagnostics shape but
this acquisition path no longer emits it.

This is the gate-only cut. Parent-proof seal horizons, Codex cursor-prefix
completion, legacy prefix admission, no-checkpoint audit/recovery behavior,
verification migration and persisted formats remain separate work. It makes
no whole-source restart-coverage or zero-byte restoration claim. Existing
restore head/named-line re-derivation is still accounted separately from native
Tail bytes.

Regression coverage uses the existing production scanner and durable writer /
restore paths with a fresh cache owner: a two-hour-old record with an append,
a due quiet record, a regressed clock, 256/300 independent pending audit keys
and a same-size edit. Assertions distinguish actual disk restoration, Full /
Tail / Unchanged, native read extent, debt and emitted-body equality. Additional
Unix acquisition tests restore a serialized certificate and inspect actual FD
suffix bytes without requiring the native heap layout. Existing proof-fence
assertions retain their clock and audit refusals.

Validation for this static branch: explicit-file rustfmt and `git diff --check`.
No Cargo, tests or CI were run. Native restore fixtures require the supported
heap layout and are unexecuted until the authorized native lane runs. Linux,
native contracts, money equality and independent owner review are integration
gates after the predecessor lands.
