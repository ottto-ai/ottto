# Streaming transcript file admission

Claude, Codex and Pi transcripts have no whole-file size refusal. The first
read streams physical lines; later growth remains eligible for Tail. The
16 MiB physical-line limit is unchanged. Compressed Codex inputs retain their
existing decoder, work budgets and resumable archive custody.

History upgrades, context-only reads and scoped copy-prefix recovery admit
an otherwise eligible first file or native twin group even above a page's byte
budget. Subsequent units wait for the next page. Size no longer bypasses recovery
pacing. Saved refusal debt is ignored without changing the state version; the
legacy status field `last_oversized_file_count` emits zero.

Local counts-only observations report `largest_file_bytes` by source and
`first_read_ms` by source and size bucket. First reads reuse footprint sampling.
An alarm records a Claude file crossing 1 GiB or a first read exceeding 300 s;
observations never decide admission and contain no paths or transcript content.

Regression fixtures replace assertions of the removed refusal behavior. They
publish usage above each former file limit, exercise Tail across those limits,
and cover first-unit history/context/group admission and old-state decoding.
The separate 640 KiB wire-item limit and offsets above 4 GiB remain outside this
change. This change must land after #1224.
