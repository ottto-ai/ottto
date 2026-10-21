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

`seen_claude_capability_tool_uses` and `activity_capability_buckets` are now
`OwnedMap` summaries. Their byte charge is the same as the plain containers;
a retained walk now costs two visits each instead of one visit per tool use
or bucket, so a long browser- or computer-use-heavy session no longer exceeds
the 4,096-visit walk.

## Unchanged

- No charge rule, cap or budget changed (`heap_layout_bound` is untouched).
- No change to `transcript_acquisition.rs`, `SharedCache::insert`,
  `retain_reduction`, Codex containers or the native finish.
- The finished output's own per-response charge (usage occurrences) is
  unchanged.

## Limits

Claude files over 256 MiB are still never read, so this alone does not give
actively written 2-4 GiB sessions a tail. The finished-output charge at a
tail completion and the cache fill policy also still refuse some long
sessions.
