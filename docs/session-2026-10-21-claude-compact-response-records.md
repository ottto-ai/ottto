# Compact Claude response records

Claude Code writes one transcript row per assistant content block. Rows of
one provider response can arrive out of provider order, so the parser keeps
every usage-bearing row ("record") until the file is complete, then orders
and merges each response. A retained reader copy is taken before that
finish, so it holds every record of every response. Before this change each
record was charged about 5 to 10 KB, mostly for three B-tree maps (selector
context, selector sources, tool uses) and four request-slot strings that
repeat the record's own fields. Each response also paid a 1.5 KB map node. A
realistic 600-response session passed the 8 MiB entry limit, so the next
append read the whole file again (`Full(StateMissing)`).

## The retained form

`snapshots/claude_response_records.rs` stores each record as
`CompactClaudeResponseRecord`:

- the request slot keeps only its token counts when its strings equal the
  record's request id, timestamp, model and effort, which is how
  `claude_cache_request_slot` builds them; any other slot is kept whole;
- model, effort and request id equal to the response's first record are a
  back-reference;
- the selector is an index into a per-file table of distinct selectors (64
  entries); past the cap a record keeps its own selector;
- tool uses are the `BTreeMap` entries as a sorted list;
- the cost block is boxed, and absent when it is the default.

Responses live in an owned vector in first-seen order. An owned map from the
response key to the slot index replaces the map of whole responses.

## Why output cannot change

Every encoding is total: each value either has an exact cheaper form or is
stored as is. `resolve_with` decodes every record back to
`ClaudeResponseRecord` in physical order, then runs the unchanged
ordering and merge code. Finalize walks responses in the same `sequence`
order. Selectors are shared by equal value (context and sources), never as
"same as the previous record", so the last-writer `sources` merge sees the
same values in the same order. `claude_compact_records_decode_exactly`
checks decode(encode(r)) == r over the redundancy cases.

## Visit walls

Only `seen_claude_capability_tool_uses` uses an `OwnedMap` summary. Its
walk costs two visits regardless of tool history. The shared Claude/Codex
`activity_capability_buckets` field and `note_capability_call` retain their
original BTreeMap form. Their conversion is deferred for separate ownership
clearance and Codex resume parity. The visit test asserts only the Claude
seen-tool-use improvement. A 2,000-tool-use session spanning 2,000 distinct
hours still exceeds the whole-accumulator visit wall through the shared map;
this residual remains explicit in CI.

## Decoded peak (review correction)

Compact retained charge is not a bound on finish's memory. Before a retained
copy is allocated, completion now computes an allocation-free bound on the
largest decoded response. It includes the real `ClaudeResponseRecord` inline
layout and all decoded field heaps, selector expansion, derived/explicit slot
strings, tool-map construction scratch, stable-sort scratch, both vectors
while canonicalizing (including realloc overlap), and the extra timestamp
copy. Responses already resolve one at a time; the resolver/merge is unchanged.

The existing copy budget already subtracts residents, the entire active
compact book and selector table, and other active fields. Its two shares fund
the retained copy and native finish/output. The new decode bound is deducted
from both shares before cloning, conservatively funding their coexistence
with the temporary decode and accumulated output. Refusal declines optional
retention and preserves native output, loss and resolve behavior; this is
not a total process RSS cap. No separate credit or cache mechanism is added.

CI covers the 4,096-record, three-selector progressive response that resolves
to one output, tests the budget refusal before allocation, and measures the
actual parser-through-finish peak. A separate born-pointer finish audit
includes decode/sort/output while a retained copy remains alive; frees of
pre-existing compact records cannot hide new allocations. Layout comparisons
restore accounting for decoded records and cover explicit slots, inline
selector overflow and tools. CI prints decoded-record BASE charges (all
records decoded for the whole read), compact charge, extra decode bound,
output charge and observed finish peaks. Retained-charge savings are not
claimed as whole-finish or RSS savings: a near-cap single response can have a
larger finish bound than its decoded-record BASE due to coexistence/scratch.

## Unchanged

- No charge rule, cap or budget changed (`heap_layout_bound` is untouched).
- No change to `transcript_acquisition.rs`, `SharedCache::insert`,
  `retain_reduction`, Codex containers or native resolve/output semantics.
- The finished output's own per-response charge (usage occurrences) is
  unchanged.

## Limits

Claude files over 256 MiB are still never read, so this alone does not give
actively written 2-4 GiB sessions a tail. The finished-output charge at a
tail completion and the cache fill policy also still refuse some long
sessions.
