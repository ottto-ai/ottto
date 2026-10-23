# Composition reader checkpoint shards

The disabled incremental reader now persists checkpoints in 256 stable hash
shards. Only shards with changed transcript bytes are loaded and rewritten;
compaction is limited to those shards. Each shard and totals file has an
immutable generation name. Atomic shard writes precede a small manifest with
generation and SHA-256 references, committed last. An interrupted commit leaves
the old manifest usable. Newer committed manifests recover stale pins from local
state without reading transcript history. Pins are compressed and written once
at the end of a run. Obsolete generations are removed after manifest commit.

Scope totals still merge successful per-file deltas and subtract replaced file
contributions. Per-session day totals use sorted vectors. Loaded file and tool
names are interned. A compact membership multiset replaces the upload-time scan
of every checkpoint and retains window and 30-day distinct file session counts,
including parent/subagent folding. No checkpoints are retired into pins, and no
30-day cutoff is applied to checkpoint file rows.

The directory walk retains only changed files. Head scans stop when identity or
a usable folder is found. After run allocations drop, the system allocator is
asked to return free pages. Actual RSS remains a measured acceptance condition;
calling the relief API alone does not establish that condition.

Request 1 ends at Claude's first assistant response or Codex's shared prelude
boundary. The daemon does not expose its saved per-file start verdict through an
accessor usable here without additional I/O, so both sources currently use the
explicit unmeasured-start fallback. Input before that boundary is classified as
`automatic_additions/start_not_measured`. Existing measured-start classifier
behavior remains covered. Rendered-attachment and never-counted-record rules
continue to apply. Unknown IDs in saved open rows restart only that checkpoint
at its current end, increment health counters, and preserve previous totals.

Regression coverage includes incremental/full totals parity, interrupted shard
and pins commits, untouched shards, checkpoint-local unknown IDs, request-1
splits, and raw paths retained in local open calls never entering uploads. The
shared maximum payload fixture includes per-file session counts; its synthetic
workspace and repository labels use a public example name.

The scale harness compares the production v1 parsing/cache functions and v2 on
one synthetic fixture, with a supplied clock and in-memory upload boundary.
V1 retains its actual recent-file and maximum-file-size filters. Consequently,
coverage differs from the accumulated 60-day v2 build and the large daily rollout;
results must report those differences and every failed acceptance condition.
The production switch remains off and the PR remains draft.
