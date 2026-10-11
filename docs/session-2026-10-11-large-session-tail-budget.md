# Large-session transcript tail accounting

An append to an otherwise reusable long Claude Code or Codex transcript could
select a full read because optional heap accounting exceeded its 4,096-visit
limit. Raising that limit would make the per-line scanner repeatedly walk a
growing session history.

Private owned collections now maintain conservative requested-layout charges
for response records, response maps, request history, physical signatures and
context/compaction history. Updates measure only affected elements; vector
capacity and conservative tree-node storage remain charged. Clones recalculate
their own capacities. Mutable value guards invalidate the summary before lending
access, including when a caller forgets a guard. Opaque or externally mutable
values cannot produce a valid summary. These collection helpers are shared by
both providers.

Finalized native output uses one completion-only composed accounting pass.
Each container charges its storage first; independently bounded child counters
consume the same decreasing aggregate byte allowance. Normal 4,096-visit
counters are unchanged. Unknown zero-sized vector elements and mutable shared
graphs are refused; a shared payload still uses an ordinary bounded traversal.
This API is never used for a per-line scan budget.

The 64 MiB process overlap allowance, 31 MiB native cache/active/copy allowance,
8 MiB entry limit, 256-entry limit, scratch/parked allowances, 4 KiB head and
4 KiB boundary guards, hourly audit debt, cold/restart fallback, durable index,
account/sidecar invalidation and upload acknowledgements retain their existing
behavior. Wire bytes, native reductions and provider ownership are unchanged.

Synthetic native regression: 1,200 records plus one append. Originally Claude
reread 298,670 bytes for a 252-byte append; Codex reread 355,379 bytes for a
299-byte append. The repaired scanner reads those suffixes plus 8,192 guard
bytes. Both bodies equal their independent native full-reader oracle.

Validation additionally covers allocation charges, clone capacities, reset,
forgotten guards, nested collections, opaque/mutable refusal and aggregate
byte-budget exhaustion. Source proof does not establish installed CPU or RSS
savings. Containing-release acceptance must use ordinary activity and matched
read/guard denominators with a full-reader parity witness.
