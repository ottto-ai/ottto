# Streaming transcript file admission

Claude, Codex and Pi transcripts have no whole-file size refusal. The first
read streams physical lines; later growth remains eligible for Tail. The
16 MiB physical-line limit is unchanged. Compressed Codex inputs retain their
existing decoder, work budgets and resumable archive custody.

History upgrades, context-only reads and scoped copy-prefix recovery admit
an otherwise eligible first file or native twin group even above a page's byte
budget. Subsequent units wait for the next page. Size no longer bypasses recovery
pacing when restart restore is enabled. Saved refusal debt remains decodable
and clears through ordinary mutation and save without a state version change; the
legacy status field `last_oversized_file_count` emits zero.

Local counts-only observations report `largest_file_bytes` by source and
scalar file bytes and `first_read_ms` by source. First reads reuse footprint sampling.
The same metric lines flag a file over 1 GiB or a first read exceeding 300 s;
observations never decide admission and contain no paths or transcript content.

Regression fixtures replace assertions of the removed refusal behavior. They
check sparse metadata above each former limit, publish small synthetic usage,
exercise Tail across a test-only size seam,
and cover first-unit history/context/group admission and old-state decoding.
Unread-byte maxima reuse existing disk/checkpoint sizes. Unread age and its
six-hour alarm require an extent clock and are deferred; no persisted state is added.
An interrupted Claude Full restarts from 0 until the one-DB Tail state lands.
Claude first-unit reads above 1 GiB extrapolate beyond observed files; peaks remain unmeasured.
The separate 640 KiB wire-item limit and offsets above 4 GiB remain outside this
change. This change must land after #1224.
