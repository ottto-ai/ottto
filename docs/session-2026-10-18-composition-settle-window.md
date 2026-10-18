# Context composition skips transcripts that are still being written

Composition fences each workspace: every transcript's metadata must match
between discovery and the end of the parse, or the whole workspace is skipped
for the cycle and keeps its last good upload. A live session appends to its
transcript every few seconds. In a busy workspace one transcript was almost
always written during discovery or the parse, so that workspace often failed
cycles with `context composition metadata incomplete` (about one in five on the
author's Mac) and refreshed late.

A transcript modified within the last 10 minutes (`SETTLE_WINDOW`) that the
workspace's last upload did not include is now left out of this cycle's
signature and parse. A later cycle picks it up once it is quiet. A recent
transcript that the last upload did include stays in the scan, so a
replacement never drops history that was already reported. A workspace whose
transcripts are all new and recent is skipped and keeps its last good upload.
Grouping, the representative workspace and its hash are unchanged, because
the filter runs after discovery. The cache file was already read for every
workspace; it is now read just before the signature instead of just after.

The fence itself stays: a transcript that is kept and changes mid-scan still
skips its workspace for the cycle. In one check on the author's Mac, 23
transcripts had been written in the last 10 minutes; only 7 of them (3 Claude,
4 Codex) were in the busiest workspace's last upload, so far fewer files can
now trip the fence. The filter only removes work, so it adds no reads or CPU.
Caps and budgets are unchanged.

Test: `live_transcript_does_not_fence_the_settled_files_of_its_workspace`
appends to a live transcript after discovery; the old per-workspace signature
fails, a live transcript the last upload included is kept, and with a new live
transcript left out the settled one still builds an uploadable report.
