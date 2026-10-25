# Observe-only unchanged transcript reread guard

`REREAD_GUARD_ENFORCE` is compiled as `false`. Claude and Codex selection,
including joined members and priority receipts, always receives Admit. The
observer never skips, delays or yields a read, changes a census result, holds a
plan, or waits for a reservation save. Existing read-selection policy continues
to apply. Enabling enforcement requires a separate reviewed change.

After Parse selection, unchanged size, nanosecond mtime and opened device/inode
metadata identify repeated work. Legacy missing object evidence is treated
conservatively. Device/inode witnesses live in a separate bounded diagnostic
map, preserving the existing delivery-entry layout and replay-reset removal.
Identity-only parent side reads retain their main-Skip contract and do not
mutate main-index observation state; their accounting belongs in the follow-up.

The existing local census line reports `unchanged_reread_over_budget{cause}`:
selected attempts that would exceed the proposed two-read rolling seven-day
budget or a traversal tripwire. It also reports observed selections, plan and
indexed counts, whether the tripwire would fire, and diagnostic-capacity losses.
`REREAD_BUDGET_EXHAUSTED mode=observe` and `REREAD_TRIPWIRE mode=observe` are
rate-limited local alarms. There is no withheld disclosure or upload field.
A selection later satisfied by a cache hit is conservatively counted.

The plan threshold is `max(floor(indexed_files / 20), 300)`. Plans above it alarm
without suppressing re-arms. Runtime selections continue above the threshold;
each further selection is counted as one would-refuse event. Plan counting is
currently conservative for stale families; composition with scoped retry must
count the actual funded re-arm set before any future enforcement.

Each of the three sparse diagnostic maps is capped at 256 keys and pruned on
load: 16-byte key digest plus two 32-bit hour stamps, physical metadata witnesses,
and growth-read diagnostics. Combined inline key/value payload is at most 32,768
bytes on the validated layout. The existing requested-layout walker charges all
three full BTree maps 633,248 bytes per index (two index owners: 1,266,496 bytes),
plus their enclosing state. Inline-only stamp/witness accounting preserves that
node charge without visiting each scalar. Aggregate observations and tripwire
counts continue past capacity; per-key observation then becomes incomplete.
Separate `reread_tracking_dropped{attempts|physical|growth}` local counts disclose
omitted live insertions and load-time truncations. Capacity never affects selection.
Empty default state remains omitted; unused guard state is not initialized by
load/save. These are live-state/layout bounds, not peak decode-memory bounds:
the decoder buffers and materializes diagnostic input before pruning. Bounded
decoding and dormant grant/string limits remain a follow-up.

Observation keeps the most recent two hour stamps. It conservatively retains
stamps through 181 hours to cover hour rounding and the enforcement calculator's
maximum twelve-hour ticket age. Persisted wall high-water and suspend-inclusive
clock checks still diagnose invalid clocks; observe mode admits even then.
The dormant enforcement calculator has separate arithmetic/clock unit tests;
its durable debt, grant and protected-read contracts are not shipped as policy.

New synthetic tests check exact would-refuse counts, restart/pruning, map caps,
clock rules and unconditional Admit. A seven-day multi-event fixture compares
page outputs and delivery decisions with observation disabled/enabled and checks
a whole-history alarm without a plan hold. Legacy correction tests need no
budget allowances. Test builds retain the current-selection Admit-ticket
invariant, with direct reader drivers explicitly obtaining their tickets.
