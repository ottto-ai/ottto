# Delete Claude terminal-off

Terminal-off will not be enabled. Remove its marker, scheduling/retention
containment, strict-reader allowance, and opt-in test variants. Production keeps
the previous absent-marker behavior: ordinary terminal completion, census,
upload/ACK ordering, checkpoint identity, and clock reads stay unchanged.

The switch macro and thread-scoped test guard move to `snapshots/local_switch.rs`
because the existing money-freshness switch still uses them. The terminal-off
invocation is deleted. Only the unchanged OFF checkpoint test retains a test-only
`claude_terminal_off()` returning false; its source moves to
`snapshots/checkpoint_main_tests.rs`.

`traversal_healthy` retains the gate's false conjunct: an existing Claude retry
admission still prevents healthy completion. It must not become
`state.complete`. Terminal effects are allowed, and the identity latch retains
every original OFF condition. No serialized field or version changes.

Remove ON-only diagnostics and test counters. Keep the existing emitted
`rearm_full_suppressed` field at zero so the OFF diagnostic output stays exact.
No diagnostic slots are renumbered. The money oracle and money-equivalence
sources and expectations remain unchanged. Local validation is formatting and
package clippy only; runtime and money checks belong to Linux CI. The PR records
the exact-head results and OFF proof, including indirect helper expansion.

This draft follows the E2 gate retirement PR; integration owns ordering and
conflict resolution. The remaining switch-ledger update belongs to its board
owner.
