# Delete Claude terminal-off

Terminal-off will not be enabled. Remove its marker, scheduling/retention
containment, ON strict-cohort pass budget, and opt-in test variants. Production
keeps the previous absent-marker behavior: ordinary terminal completion, census,
upload/ACK ordering, checkpoint identity, and clock reads stay unchanged. The
ordinary reader keeps its protected per-pair allowance; that helper moves
unchanged from `claude_local_otel/strict_budget.rs` into `claude_local_otel.rs`.

The switch macro, thread-scoped test guard and `marker_at` helper move to
`snapshots/local_switch.rs`, which the other local switches (money freshness,
admission re-offer, resumed prefix) still use. The terminal-off invocation is
deleted, and no `claude_terminal_off()` remains, including in tests. The OFF
checkpoint test moves to `snapshots/checkpoint_main_tests.rs`.

`traversal_healthy` folds to `state.complete && evidence_owed::enabled()` for
an existing Claude retry admission. Terminal effects are allowed, and the
identity latch retains every original OFF condition. No serialized field or
version changes.

Remove ON-only diagnostics and test counters. Retain the always-zero
`rearm_full_suppressed` field for debug diagnostics; serialized output omits it.
No diagnostic slots are renumbered. The money oracle and money-equivalence
sources and expectations remain unchanged. Local validation is formatting and
package clippy only; runtime and money checks belong to Linux CI. The PR records
the exact-head results and OFF proof, including indirect helper expansion.
