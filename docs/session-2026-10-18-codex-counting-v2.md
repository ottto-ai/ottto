# Codex usage counting V2 (inactive until a reviewed cutover)

Codex writes two usage streams: UI `token_count` events and, in newer CLIs, native `token_usage_record`s with a per-response `usage` and the thread counter after it. Today the parser counts only the UI stream. That double-counts equal-total re-emissions and misses work the UI never reports, such as compaction responses.

New sessions can now use an occurrence reducer (`snapshots/codex_usage_occurrence.rs`):

- Natives are counted by their coverage of the thread counter, one dimension at a time. A native that starts at the previous high-water mark counts its `usage`. A restatement of covered counters counts 0. On overlap only the part not yet covered counts: `max(0, after - max(before, hwm))`. A gap counts its `usage`. A conflicting restatement under the same response id is reported.
- Turn UI is held as pending rows until its turn closes. A turn with a native drops its UI; a UI-only turn publishes it at closure. A native that arrives after closure counts 0. Pending is capped at 64 rows, each with at most 4096 bytes of content. The first overflow publishes the turn's UI, and natives for that turn then count 0. UI outside any bound turn keeps today's rule.
- Inside a bound turn, an equal `last`/total re-emission with no native in between is dropped. A last-less first or reset cumulative base is not counted.

The counting version (`snapshots/codex_counting_version.rs`) is decided once per session from the root `session_meta` creation timestamp, a compiled cutover, and this destination index's existing acknowledgement evidence. A session already acknowledged by a writer that did not mark V2 stays Legacy. The local index bool `codex_counting_v2` moves atomically with its entry's acknowledgement fields. The compiled cutover is `None`, so every session stays on Legacy counting, byte for byte. Turning V2 on is a separate reviewed change. It must freeze one instant after the grouped-parser and retained-reduction paths are configured.

Each finished V2 parse adds its receipts (late, flushed and restated natives, dropped UI repeats, uncounted bases, closure mismatches, reopened turns) to a fixed-size `codex_counting_v2` block of the local-only Codex scan diagnostics. Its still-open UI-only turn debt goes there too: `open_turn_ui_pending` sessions, events and usage. That block is written to the terminal journal and is never sent. The grouped parser does not fold receipts yet.

Pending-state heap is charged through the existing requested-layout accounting. Byte pressure never changes what is counted: the row and content caps depend only on content. Disclosed residuals: if the destination index is lost, a post-cutover session acknowledged by an old binary re-derives V2. A binary downgrade after V2 publication is not fenced.

Unchanged: wire contract, cadence, Claude parsing, Legacy output. Tests (eight counting regressions plus version and acknowledgement controls) run in Public CI only.
