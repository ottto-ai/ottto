# macOS durable bootstrap fixture repair

PR #865's macOS Rust-contract run 40851256864 failed three tests. These are
fixture defects, not production file-identity, timestamp, APFS or ordering bugs.
The positive retained-cache paths require `heap_layout_bound::layout_supported()`:
64-bit macOS on a validated Rust compiler. Linux skips these assertions, so its
green result did not qualify the failing paths.

- `v1_counting_provenance_comes_from_each_decoded_reduction` restored an unchanged
  pinned v1 record and demanded one post-save write. The current writer still
  emits format 1; generation is normalized out of dirty detection. With no changed
  body, binding or certificate, that record is clean. The fixture now stages real
  current-index audit debt before saving, creating an ordinary dirty replacement.
  The exact one-write assertion remains, with new assertions for the saved debt
  and changed record bytes. The second restore still checks each decoded counting
  decision, and the incompatible-cutover negative control remains.
- `pinned_v1_bootstrap_ordinary_save_then_second_restart_tails_without_a_full`
  configured durable passes with identity capture disabled for Codex while
  `OwnedSourceScan::new` enables it for both sources under `cfg(test)`. The binding
  correctly refused that mismatch as `ineligible.scope`, producing a Full.
- `completed_full_audit_before_durable_replacement_recovers_after_restart` had
  the same capture mismatch on Codex's final restart. Both scanner fixtures now
  bind durable passes to their scanner's capture mode. Their exact Tail, Full,
  audit-carrier, body-equivalence and replacement assertions remain unchanged.

Production's sync cycle already supplies the same `request_identity_capture` to
`begin_durable_pass` and `OwnedSourceScan::new_with_identity_capture`. No production
source, persisted format, allowlist, audit deadline rule, grouped custody or
replay authority changes here. The audit-safe v1 core and grouped-custody
completion remain intact.

Validation: changed-file formatting and diff checks; package-scoped macOS clippy
with all targets, locked dependencies and warnings denied. No local tests or
macOS/money workflow dispatches are part of this repair. Native runtime
qualification remains with the PR owner.

The follow-up sibling audit searched the complete Rust tree for durable-pass
setup, restore, post-save writes and pinned-v1 serializers. Two more recovery
fixtures had the same Codex capture mismatch:
`missing_index_debt_carrier_recovers_by_full_in_one_pass_for_both_sources` and
`missing_index_terminal_loss_carries_recovered_debt_until_verified_full_for_both_sources`.
Their original assertions ended at quiet restart or envelope inspection, which
never proved that the replacement could restore. Both now bind capture to the
scanner and append after restart, requiring exactly one disk restore, Tail
without Full, and body equality with a cold Full for each source. Existing
Full/debt/GC/idle checks remain unchanged.

Checked sibling restart, inventory-overflow, parent-ledger, MCP-version,
sidecar-reduction and E2-pipeline fixtures already align capture. No-record,
foreign-context, opaque-hold and grouped-debt fixtures deliberately avoid
compatible retained-record restoration. Pinned-v1 failed-rewrite tests use a
fresh store without a read-populated content memo; store dirty-batch and
read-memo tests already distinguish unchanged records from real debt changes.
No additional clean-record write assumption was found. Production's shared
capture flag and all persisted/runtime contracts remain unchanged.
