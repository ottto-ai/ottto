# Local disappearance reason totals

The existing `bounded_traversal_transition` local resource record gains
`counts.disappearance_process_totals_v1`. Its closed shape is `version: 1`,
`scope: "process_lifetime_not_window"`, four `u64` counts and a sticky
`overflowed` boolean. Counts have this fixed order:

1. `not_found`: an existing branch received `ErrorKind::NotFound`.
2. `root_resolution_unresolved`: an existing known-root or legacy-root fallback.
3. `preflight_fingerprint_changed`: a quarantined family's second open changed
   the physical/sidecar witness from its preflight.
4. `comparison_target_revision_changed`: an opened comparison target differs
   from its frozen revision.

These count increment events, including repeated encounters, across the process
lifetime for each of the three existing sources. They do not count unique files,
families or proven deletions. Existing operational increments run first with
their original arithmetic. Copies, aggregation and checkpoint restoration do
not record again. Counters never affect scanner decisions, gates, admission,
ACKs, wire data or saved index contents.

Starting capture receives the caller's existing source explicitly to snapshot
before reset/rearm; root resolution separately receives that existing source.
No source field is added to retained operational state. Retirement snapshots use
the same source. Record cadence and CPU/RSS sampling remain unchanged.

Each source has four static relaxed atomics and one sticky overflow flag. Loads
are best effort and **non-atomic across counters and overflow**. A wrapping
`fetch_add` can be observed before its sticky flag store becomes visible.
`overflowed: false` therefore cannot establish exact concurrent conservation;
`true` invalidates exact intervals. Other traversals of the same source may
contribute. These totals cannot decompose a particular traversal's aggregate.

First observations establish only a baseline. Reset, collection gap, missing
older-binary field and restored historical-window attribution are **UNKNOWN**,
never inferred zero. No attribution metadata or historical backfill is added.
The existing local sink remains best effort.

Producer work adds one fixed atomic increment and, on wrap, a flag store; no
producer allocation, lock, retry loop, filesystem work or retained graph is
introduced. Static storage around 120 bytes and temporary snapshot value size at most
64 bytes are target-layout bounds asserted by tests, currently unverified until
CI. Payload growth and serialization String capacity are different quantities;
no allocator, RSS or timing improvement is claimed. Rust serialization tests
bound the complete maximum-integer transition line, including its log prefix
and newline, to 4096 bytes. These tests are written but **UNRUN until CI**.

Fixture assertions cover real root fallback, missing metadata/open, watcher
removal, changed preflight and frozen-target comparison branches. The launcher
preflight fixture is a no-false-positive control, not a mismatch-positive claim.
Unsupported-layout frozen-target positives remain explicitly **UNEXECUTED**.
Isolated counter tests cover fixed source/class order and the wrap visibility
hazard; they are not scanner pipeline evidence. No local tests or builds were
run for this patch.
