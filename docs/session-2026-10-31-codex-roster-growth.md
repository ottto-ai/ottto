# Known Codex rollout growth during a retained traversal

An append to a known rollout does not necessarily change its parent directory's
metadata. A retained traversal now checks known roster members independently of
moved-directory listings, using the existing refresh's remaining entry budget.
The visit count rotates large rosters across pages. The ordinary candidate and
acquisition paths still validate the file and decide Full versus Tail.

Only stat-proven growth beyond the indexed extent queues a new candidate, with
`census_member: false`. Existing pending candidates keep their census role, and inventory-held keys
wait for the existing evidence-gated release. Unchanged lengths, certified unchanged EOF fragments, symlinks and oversized
files do not gain a new enqueue. No new body reader or retry cause is added.

The existing traversal counts expose `codex_roster_refresh_visited` and
`codex_roster_growth_enqueued`; zero values are omitted. Older saved traversals
load these counters as zero. Growth hints also feed the existing next-generation
page count.

The regression tests use synthetic Codex turns: one checks a directory-quiet
append, a single Tail and complete emitted-money equivalence to a cold Full;
the other checks no enqueue or acquisition for unchanged bytes, including an
mtime-only change, and inventory-held growth with unchanged refusal evidence. Local tests remain CI-only.
