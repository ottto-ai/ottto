# Standalone audit gates on checkpoint reuse

Approved 2026-10-29: this gate-only slice lands standalone on main, ahead
of its former R2 slot. It can enter R1 if green and merged before the R1 cut.
It supplies the LA-1 audit-gate dependency for the Pi restore work. Only the
two audit-gate commits are transplanted; bootstrap and format work stay separate.

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
completion, legacy prefix admission, verification migration and persisted
formats remain separate work. Missing checkpoints are classified StateMissing,
never AuditDue/ClockChanged. S2 owns the disposition and allowed-cause admission;
a new label grants no additional read permission. It makes
no whole-source restart-coverage or zero-byte restoration claim. Existing
restore head/named-line re-derivation is still accounted separately from native
Tail bytes.

Regression coverage uses the existing production scanner and durable writer /
restore paths with a fresh cache owner: a two-hour-old record with an append,
a due quiet record, a regressed clock, 256/300 independent pending audit keys
a same-size edit, 50-hour-old records, restore admission refusal plus index
debt and cleared selection plus debt. Assertions distinguish actual disk restoration, Full /
Tail / Unchanged, native read extent, debt and emitted-body equality. Additional
Unix acquisition tests restore a serialized certificate and inspect actual FD
suffix bytes without requiring the native heap layout. A test-only observer at the shared File::read call captures the stream offset,
requested length, returned bytes and errors for certificate head/boundary reads.
It covers quiet, append and short-read/EOF cases independently of completed
context metrics; it does not measure rederive, other readers or page-cache disk
activity. Quiet restore reads both samples, so total zero-byte restore remains
unmet. Existing proof-fence assertions retain their clock and audit refusals.

The restore fixture uses main's always-capturing scanner binding outside a sync
cycle, replacing the retired capture-default helper in its two store openings.
All assertions and real writer/restore paths are retained.

Validation: explicit-file rustfmt and `git diff --check`; no local Cargo build,
test or Clippy. Linux CI runs on the review-ready standalone PR. Native restore
fixtures still require the supported heap layout; native contracts, money
equality and E3/Lead B owner review remain owed. The Mac slot order is #857,
then #854, then this PR; the owning integration agent dispatches those checks.
