# Codex session-start footprint from line delivery

The footprint uploader consumes the primary snapshot reader's parsed lines through
a RAM-only feed keyed by opened file objects. It no longer lists rollouts, opens
them, or stores a rollout-path/cwd index. The migration removes only
`codex_session_start/index.json`; remove this cleanup after two stable releases.
Destination upload deduplication and start watermarks remain durable and unchanged.

Each observer declares 256 KiB of pass storage, including at most 16 KiB for its
immutable scan-root snapshot and 4 KiB for the resolved home. AGENTS.md is capped
at 128 KiB and skills at 96 KiB, before copying text. Capped results retain small
metadata for ranking but cannot upload. The shared parser's durable layout and
existing entry points remain unchanged.

The feed accounts vector/string capacities, pending parsers, terminal and
unseen entries, home associations, a pruned scope cache and the high-water
allocation of its FileObject index within 4 MiB. Cached per-entry byte totals
avoid whole-feed heap walks in callbacks. Under pressure, the oldest half is
evicted in a linear-time batch; that work is amortized over removed entries,
and every eviction is counted. Bounded alternatives are retained; registered homes
are filtered before winner selection. This avoids losing an eligible older
session to a newer process-only home. Expiry, eviction and Full replacement can
still remove observations without a recovery read. The uploader separately holds
a snapshot capped by feed ownership, plus scope/ranking work sets bounded by the
feed's entry and string counts; these temporary copies have a separate bound
from the shared feed. Snapshot is clone-only under a short feed lock, bounded
by the 4 MiB feed: Done text, homes and scopes are deep-copied under that lock.
Worst work is O(entries + copied payload), without a measured wall-time bound.
Age/scope filtering and uploader I/O follow after release; maintenance has its
own metadata walk. Active worker parsers are charged independently.

`feed_files`, `feed_bytes` and `pending` are gauges. `evicted`, `text_capped`,
`codex_prelude_unseen_prefix`, `codex_prelude_gap_dropped` and `root_missing`
accumulate since startup. Unseen prefixes and gaps are proxies for unavailable
observations, not an exact count of starts lost at restart.

Unsent starts can be lost at restart, including growing sessions, until a newer
start in that cwd. The existing footprint thread can leave roughly six hours of
starts unsent. No new scheduler or shutdown network operation is added. Main
reader source/age/size gates apply; an org window below fourteen days narrows
coverage, files above 2 GiB are excluded, and group/resumed delivery awaits LD2.
Already retained entries can upload while the uploader's own gates permit it.

Only newline-complete physical rows are observed. The former 2 MiB prelude-read
limit is removed; the 200-row limit remains total across contiguous Tail reads.
An incomplete end discards nonterminal state. Tail must start at the previous
physical end, including skipped bytes. Deleted files can remain until their
last observed mtime ages out. Equal starts use ascending FileObject order rather
than transcript-path order. LD2 must fan out both Codex consumers when it takes
the current single observer slot. Archive delivery is the main reader's concern;
the footprint has no archive reader or compressed-file refusal counter.

## Complete peak of this projection

Let F = 4 MiB, N = retained Done entries, C = peak uploader scope pairs
(C <= 512 + N), W = concurrent observers, v(x) = 2x + 4 Vec slots, and
B = 256 + 12*sizeof(usize) + 11*sizeof(String), the existing conservative
BTree node charge. A capacity-based envelope is:

```
F + W*(256 KiB + sizeof(Observer))                   shared feed + workers
  + v(N)*sizeof(Start) + min(F, N*231 KiB)           uploader snapshot
  + v(C)*sizeof((String,String)) + C*1088            scope clone/new misses
  + 2*(N+1)*B + N*1088                              seen cwd/scope sets
  + v(12)*sizeof((Prelude,PathBuf,PathBuf))
      + 12*232 KiB                                  candidates (conservative)
  + R + transient overlap                           one request's scratch
```

The 231 KiB covers 224 KiB text, three 1 KiB strings and 4 KiB home;
Pending also keeps a 1 KiB session id within its worker declaration. R is one
existing request's metadata chain, config parse, file measurement, skill/item
vectors, JSON content/serialization and HTTP buffers, charged by their actual
capacities; it is separate from candidate storage. No new request concurrency
or acquisition-reader buffers are introduced. This is a projection envelope,
not a numeric process RSS limit or evidence of native stack margin.

Put now budgets the incoming entry and conservative geometric container growth,
evicts first, then uses fallible reservations before insert/push. Root slots are
reserved once; each pair's budget is checked before configured-path clone/push.
Transient overlap remains: old/new Vec buffers at growth/shrink, table rebuild,
root Vec-to-Arc conversion, canonicalize's returned path and OS scratch before
its length is known, and request encoding/output. Add the old Vec allocations
(feed Vec realloc overlap <= F/2, v(N)*sizeof(Start), and v(C)*sizeof(pair))
when realloc cannot extend in place; root construction can overlap its <=16 KiB
slot Vec and <=16 KiB Arc plus the just-resolved path. The doubled table
high-water charge already allows two table allocations. Allocator rounding,
headers, realpath scratch, R and native stack/RSS still require owner acceptance
and authorized CI evidence; a <=4 MiB settled metric does not prove that peak.

At ten roots/five homes, take N=11,810 (conservatively including archive
inventory), C=12,322 and W=2. The two scan workers are the background and
one-shot builders in snapshot_sync.rs (spawn_local_snapshot_sync and
spawn_one_shot_local_snapshot_sync); the one-shot in-flight guard prevents a
third normal worker. Using tested 512-byte inline ceilings for Observer,
Start and candidate tuples, 24-byte Strings, 48-byte scope pairs and B=616,
the formula's bounded projection terms plus old Vec/root conversion overlap
sum to 81,305,712 bytes (<78 MiB). This excludes R, allocator/realpath scratch
and the existing two 8 MiB worker stacks; including stacks gives <94 MiB + R
and that scratch. It is an inventory scenario, not a total-process RSS cap:
secure config reading still uses unbounded read_to_end and HTTP/TOML scratch
is inherited. Those terms have no finite universal number in this slice.
Native RSS/stack receipts remain separate evidence.

No restart re-reads: the feed rebuilds only from normal acquisition (durable
restore/Tail); missing prefixes do not authorize a recovery head read. Codex
archive preludes await E2-11 11b/11c and are neither harvested nor counted here.
The obsolete index cleanup attempts exactly one remove_file per feed lifetime;
index_cleanup_removed/absent/failed are cumulative 0/1 counts on the existing
harvest metrics line. Absent is tolerated, failure is best effort, and a
folder at that exact filename is never traversed. Before the first attempt all
three counts are zero; gated harvests still attempt cleanup but may emit no
metrics line. Remove this migration after two stable releases.
