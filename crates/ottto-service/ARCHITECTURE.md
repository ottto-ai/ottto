# ottto-service architecture

`ottto-service` is the local daemon. It reads Claude Code, Codex and Pi session files on the
user's machine, reduces them to usage, and uploads that usage. This page states the shipped
design and the stable rules every change keeps. Paths are under `src/`. When a change alters
behaviour described here, update this page in the same PR.

## Read path

```
file-system hint / periodic listing → select file → read new bytes from saved offset → per-source reducer
  → running result kept in RAM (Claude: the state database's Tail) → upload → exact acknowledgement → index save
```

- **Discovery.** The recursive watcher (`snapshot_watcher.rs`) turns file-system events into
  hints. File-system events are advisory and can be missed, so a periodic listing that compares
  size, modification time and file identity remains the safety net (`snapshot_roots.rs`). A file
  whose length grew past its saved size is never dropped from discovery because of its age. A file
  never read, last modified more than 60 days before the walk, is not read for the first time;
  a file already read, owed or queued keeps the walk's window.
  Each listing gives hint priority to indexed files whose listing stamp changed since their
  last read, promoting queued files in place. Unchanged census files, including owed files,
  keep their ordinary queue order. Existing selection budgets and read gates still apply.
  A queued Claude directory or census member missing below its own readable scan root
  is a removal when the secure absence proof succeeds, even with missing intermediate
  directories. A missing configured root, including a nested root, keeps the census
  incomplete. Recreation before that proof keeps the loss; recreation after a valid
  witness belongs to the next ordinary census, under its existing admission gates.
  Candidate discovery retains its earlier immediate-live-parent shortcut, which does
  not provide the secure proof's ancestor or recreation guarantees.
- **Settled sources skip repeated walks** (`snapshots/discovery/walk_idle.rs`). A walk that
  completed its census cleanly, with nothing owed to the index, the upload or telemetry, arms one
  in-memory record per source, bound to the inputs the walk read and the store generation its
  finish left. Until `WALK_GAP` (the listing interval, three hours) after that walk's first
  pass, a pass with no watcher hint or listing request, unchanged inputs, a live watcher covering
  every existing root, and a pass gap of at most one hour returns an empty, census-incomplete page:
  it reads, uploads and saves nothing and sends no status receipt: the walk's receipt and manifest
  stand, and check-in beats (sent with no scan start while a record is armed) keep them fresh.
  Anything else walks as before: any failure, an account switch, a restart or another writer's
  save. A due sampled audit waits for the next walk, at the latest the backstop. A pass that took
  a hint clears the record before any fallible step, so a failed pass is followed by a walk. An
  idle pass never emits a body. A watcher overflow, a dropped-event rescan (FSEvents
  MustScanSubDirs with its user or kernel drop flags) or a watcher re-create requests a listing,
  so that pass walks. Limit: a change the watcher misses silently, with no event and no drop
  flag, waits for the backstop; if its file is deleted before then, its unread usage is lost.
  Back-to-back walks narrow that window to about one walk but do not close it.
  Desktop store-only edits to idle sessions (rename, archive, removal) do not wake the gate:
  their titles, lineage and placement can show up to `WALK_GAP` late. Amounts are unaffected.
- **Selection.** Each pass picks files and a read mode (`transcript_acquisition.rs`). Tail, a read
  from the saved offset, is the normal mode, so bytes read track bytes appended. A Full read has a
  named cause (new or replaced file, missing or invalid saved result, a real edit) and is counted
  by cause. Re-reading unchanged content that was already uploaded is treated as a bug.
  Forced Claude twins with a current, verified, loss-free census may use the same validated Tail
  loader. They still provide no copy proof or body-binding authority. Without audit capacity or
  when the loader holds, they read natively on their holder's page. Exact/Empty growth can lose
  census verification and require a native read on the next force.
  Every plain Full/Tail acquisition with a read plan stops at its opening frozen length.
  Appends beyond that extent belong to the next ordinary pass. A grown in-page read
  validates its held-file prefix and path before publishing; it keeps no new Tail
  checkpoint and earns no Full-audit or source-verification credit. An unfinished
  boundary record remains withheld. If the prefix would weaken a committed body or
  cannot reserve its audit marker, that file gets one same-walk retry; a second growth
  refusal releases a committed body to the next pass, or leaves a new file unreadable.
  A changed scope or object at strict revalidation discards the attempt and shares this
  persisted same-walk retry, which holds the walk as a census member until the file reads
  or refuses again; a file whose growth Full is paced gets no retry. If the allowance is
  spent, strict revalidation records the file as unreadable.
  Unsampled native reads without a plan (including some protected/forced paths) remain unbounded and out of scope.
- **Reduction.** One reducer per source turns lines into usage and keeps a running result. Old
  evidence is read only for the session group a change affects.
- **Codex counting.** Every new parse uses V2. An accepted old-formula file keeps its
  accepted body until its physical content stamp changes, including during audit,
  retry and cursor resume. A changed file is recounted to cold V2 exactly, even when
  the total falls; a joined group recounts together when any member changes.
  Missing or corrupt old heads remain skipped with repair owed. Index rebuilds and
  a new destination start with V2. V2 heads and paused jobs ignore retired counting
  views and retain their existing Tail path. The process-local `codex_legacy_recount`
  alarm records shrink, unknown baseline or previously unaccepted usage; retries or
  crashes may repeat it. Historical counting slots still decode without selecting a rule.
  Retired counting histories drop their values; two empty store roots remain for older readers.
- **Codex rollout encodings.** Plain `.jsonl` and compressed `.jsonl.zst` use the same
  ordinary first-read selection, reducer, modification-time age rules and decoded-byte page
  budget. Exact plaintext siblings win before either header opens. Decoder memory is funded
  inside the shared state-memory allowance; a refusal requeues the ordinary candidate with its
  census and watcher flags. There is no separate archive queue, reservation, pacing or inventory
  population/read-volume limit. A fresh-data page first fills up to half its slots with fresh
  plain rollouts in queue order, so a hinted archive backlog cannot hold recent sessions back;
  the remaining fresh work stays FIFO, archives included. Freshness and ordinary pages
  then fill spare slots with non-fresh census members in queue order, using the same read
  budget and deferred-path requeue. Fill does not count as a census turn. A periodic relist
  can select files and certify their membership from the retained census while only
  non-census directories remain pending; pending census-member directories still block.
  Compressed rollouts keep their original modification time, so they age as the plain file did.
  A provider-written new plaintext object takes the existing
  counted Full path; only a returning original object can continue from its saved suffix.
  A restart during its first read re-decodes the prefix, counted as decoder work, before reaching
  EOF. It does not restore a compressed decoder or introduce a stepped compressed reader.
- **Codex ownership.** One secure header opener supplies ordinary membership proof for either
  encoding. A failure holds its file and decisions depending on it; an unknown header remains
  a wildcard over every potentially colliding owner. Boundary validation covers surviving
  singleton sessions and joined groups across every registered home. A new file
  naming a page owner fails; unrelated new files defer to the next roster refresh.
  New directories are recursively listed with the same helper and their rollouts
  use the same owner check, including same-owner subagents. Empty directories defer.
  Validation leaves the census unchanged so the next refresh queues new directories
  for the existing bounded traversal.
  Every header ownership change and vanished census directory fails closed.
  Refresh and checkpoint share the stable `DirectoryCensus::relist` helper.
  Each boundary re-lists changed directories and re-reads new or changed headers.
  The page roster moves from the traversal snapshot into validation; clones share
  it in memory, and no additional traversal state is persisted.
  New archives use every filename ownership candidate, like held archives;
  archives beside known, still-present plaintext defer. If unrelated plaintext
  vanishes and activates its roster archive, that archive uses the same filename
  fence: a page-owner candidate or missing filename proof fails the page.
  Unknown or unreadable headers remain conservative failures, including unrelated
  compressed rereads.
  A symlink entry that refresh cannot certify can block pages across homes.
  A new rollout seen before its first complete header fails that page once.
  A proven compression or same-object move commits the old and new graph closures
  and Tail keys together during preparation; RAM adopts the destination after COMMIT.
  A refused carry holds only its predecessor's proven owner and counts as inventory debt.
  A rollout moved while a reader owns it waits for a later pass.
- **Codex revert groups.** Same-home revert files with one native session id can
  publish one whole-session body when their independently admitted usage keys are
  disjoint. Each member keeps its own parser, cumulative counters and cache detector;
  original billed turns after a revert's history boundary remain in the sum.
  The first offer waits until every member is a compressed sealed archive; live
  groups hold before any header/decoder read. Compressed members use the ordinary
  decoder. Different member accounts, incomplete
  members, overlap or missing proof hold the complete group without singleton output.
  A first acquisition without saved reductions keeps every contribution and its key
  proof in memory until the full offer is built. It uses the existing counted Full
  counters; an interrupted process discards the attempt and the next one reads the group
  again. Deterministic failed attempts reuse the existing per-group refusal memo
  and attempt fence, so an unchanged next pass does not replay the transcripts.
  On the first source-aware load, indexed unsettled sealed groups with saved owner
  proof reuse the existing cleared-source re-arm debt and observed-file queue.
  Captured or settled groups never re-arm. Exact acknowledgement settles only the captured member revisions through
  the existing entity incidence and member-set witness. Accepted unchanged members
  reuse their existing inventory stamps and read no transcript bytes after restart.
  Changed or missing accepted members remain owed when the saved state cannot prove
  a complete replacement without rereading sealed history. Member activity/tool and
  provider-skill facts merge before their existing projection; changed files stay distinct and artifacts
  use the existing union. Continuous plain groups
  retain their existing replay path; no admitted-key ledger is persisted.
- **Claude copied history.** An earlier main file proves a later copy's
  pre-birth requests from local facts: an accepted body, or a counted,
  identity-complete body committed here or on the same page, with a current
  census and no hold, quarantine or content-twin hold on that page. Unproven
  copies count at once, with no acceptance wait. Removals relying on a holder
  not yet accepted are provisional: an index save drops them and marks the copy
  for one re-decision when that holder failed to commit or was deleted. Saves
  re-mark only copies whose saved decision disagrees with current ownership,
  groups or census; census walks run to completion. Stored groups keep
  historical removals, including accepted holders deleted later. The byte
  format stays compatible with 0.1.239–0.1.251, but rolling back below this
  release is unsafe once a copy is decided locally; fix forward. Source and
  copy uploads stay independent, so ACK order can leave a temporary gap.
  An all-covered copy-only page drops its items when the session has another
  file; own turns still publish. The first on-page file of a session carries its
  summed body and keeps its own start; the body's last-activity clock is the
  latest of every on-page file of that session, and only a later request clock
  sets its end. A selected content twin pulls every live
  overlapping census main, and a selected main file (not history-held)
  pulls every live census content twin sharing a request hash. Ordinary discovery
  acquires pulled files through the existing history and resident admission gates.
  A missing overlapping twin with additional hashes or a non-Exact census holds
  the replacement before all-copy suppression; the items stay owed without receipts.
  A page containing only census twins also waits for every live filename
  member of that session. The `absent_content_twin` diagnostic counts held
  sessions; even a bound contributor hold keeps the session progress-blocking.
  Deletion or retirement of the contributor's census hashes releases the content
  dependency. Disjoint and missing-census twins remain outside this fence;
  unrelated sessions sharing hashes may conservatively wait together. A twin
  whose session main shares no request with it can wait until that main is
  independently selected. Twin pulls can read extra overlapping copy sources.
  Money rule three selects content twins, path twins and disclosed main
  files once, using every census hash and one in-memory census walk without
  a deadline. Only a candidate sharing ids with an earlier locally owned holder
  and that holder are re-owed, with the rule version stamped in the same save.
  Disclosed main files include cross-session resumes whose own path and
  content identity would otherwise leave their counted prefix unchanged.
  Money rule five compares settled, unheld disclosed main files against current
  holder proof once per store, using the save-time decision comparison and
  accepted request rows. Only counted hashes newly covered by an earlier holder
  select a copy for one ordinary correction obligation; holders are not marked
  and body revisions do not change. Existing content-twin scheduling co-reads
  overlapping mains: an isolated copy and same-session main cost at most two
  ordinary reads per mark, without forcing Full. Larger overlap closures retain
  their existing scheduling; the rule adds no population-wide read bound.
  The normal save records the marks and version together, so marks number at
  most the settled disclosed mains and never rearm
  on restart. A resumed same-session copy still needs its holder on the same
  page to remove the prefix; an off-page holder leaves it counted and disclosed.
  Older daemons ignore a newer money-rule version; layout 8 already requires
  a forward update for readers predating the accepted-request store.
  Subagent path-twin homes sharing census ids are both selected once, for
  all-copy and prefix copies. The selector and mid-page holder lookup record
  elapsed milliseconds; holder pulls also record a scalar count.
  A subagent twin keeps skips held by an earlier same-session fold before
  its first own response, regardless of the subagent cutoff or file birth.
  Unmatched responses are own turns, including those before birth. Shared
  responses after the first own turn keep the existing cutoff decision.
  Same-session main files with no copied requests at parse time on one page
  drop timed, nonzero duplicate requests by usage dominance and equal native
  accounts, with equal usage tied by birth and location. Zero, ambiguous and
  untimed occurrences never drop.
  Marker disagreements or incomparable usage keep every occurrence and disclose
  once per request id as `twin_overcount_kept`. This is drop-only, without a
  cutoff or persisted decision; restoring copies never makes a file eligible.
  Accepted residuals: an absent complete twin can be deemed redundant by id
  inclusion in a partial twin, and equal native accounts can later carry
  different telemetry accounts; the keeper's placement
  follows the existing reconciliation policy.

- **Upload.** A session is uploaded as a whole-session replacement, idempotent at the receiver. It
  settles only on an exact acknowledgement of the exact bytes sent to that destination. A local
  receipt never counts as an acknowledgement; refused, not-stored and partial answers are not
  accepted, and parts the server did accept stay recorded. An enabled response without the
  entity acknowledgement contract fails the page and leaves its bodies eligible for the next
  cycle. A revision-only move can carry a
  file's receipt when its final entities and bodies are unchanged and every entity has an
  exact stamp under the active upload context. Claude records those stamps under its resumed
  mode while unaffected file receipts use the base context. A copy-capability change therefore
  conservatively re-sends unchanged files once.

Snapshot envelopes send only the `snapshot_revision:v2` witness. The receiver already
accepts bodies without the v1 revision fields. ACK matching, unchanged skips and receipt
carry use their existing content and body proofs. Local snapshot audits use schema v5,
with revision keys blinded from the v2 hash and explicit census and oversize evidence.
The identity size budget retains 134 bytes of headroom so the smaller envelope does
not change admission or account tagging at the byte cap.

Telemetry-only Claude uploads require the advertised head-CAS capability and the
exact telemetry contract and pairing window. They declare head CAS in isolated
requests, without cache patches or cache-state ACK negotiation. Growth carries
the saved ACK head etag; an owed conflict challenge replaces that base in the
semantic envelope after the ordinary evidence chunk rebuilds the telemetry body.
Normal source requests retain their existing batch classes and ACK contracts.

Stale-older refusals from current servers mean the server already holds the
newer usage. Earlier refusals stay counted as owed, with their dispositions
unchanged. Owed entities never grant an automatic rebuild or re-offer. Retries
use retained bodies; transcripts are read again only for changed input. Unknown
non-permanent reasons hold their entity without invalidating sibling ACKs.
Eligible superseded quarantines that become current again resume their remaining ordinary retry budget, saved before source acquisition.

**Refusal custody.** A fresh permanent `accepted_log_stale_older_upload` refusal
follows the existing dominated, terminal residue path and never becomes an
accepted-body ACK. Its exact covered body can earn its file's upload-context
receipt, retiring that file revision's freshness debt while the refusal stays recorded.
For a held cache-head probe, the file and candidate witnesses track the cache-free
probe actually offered; the same exact-coverage receipt gates still apply.
On the first preparation per source in a process, files with complete covered stale
terminal membership and a mismatched body digest are selected once for parsing.
Their source witness stays intact; aligned files need no further parse. A runtime
hold or incomplete parse can leave the digest unaligned until the next process.
An optional per-record `exposure` observation, written only
when a fresh permanent refusal is recorded, separates those records from legacy
ones; a missing or malformed observation keeps a stale record owed, and legacy
dispositions never change. The refusal owner keeps exact body witnesses for owed
revisions and suppresses identical owed bytes; changed input gets its own offer
and exact acknowledgement. Unknown non-permanent reasons, including
`accepted_log_stale_older_mixed`, use ordinary RetryPending custody for that
entity only. A body witness is not a stored body: missing body custody never
triggers transcript reconstruction, and legacy owed entities never ride
quarantine, re-offer, audit or revision-triggered reconstruction. Diagnostics add
scalar owed/held counts to the existing refusal records; only a rising owed count
raises the refusal alarm. Claude, Codex and Pi share this machinery. A pass whose
only holds are validated ordinary retryable refusals, validated ACK conflicts or
named HTTP-503 identity deferrals with a server retry deadline finishes successfully
while each exact body remains owed in RetryPending custody. Validation, body-witness
and usage-decrease review holds and named HTTP-429 identity deferrals still defer
the pass, including beside an isolated hold. Uploads, acknowledgements, custody,
retry clocks, totals and placement are
unchanged. Held cache-head probes and quarantine origins use structured diagnostics
with fingerprint and body-witness hash8 values only, plus source and saved-head
presence for probes.

Claude Desktop title sweeps keep compact parsed session facts in the shared RAM
cache while each regular file's device, inode, length and nanosecond mtime match.
Every eligible sweep still lists the store, evicts unlisted facts and reconstructs
account and original identity from the current path. Failed loads are never kept;
loading holds no cache lock. Census, refusal, pruning and retry rules are unchanged,
and callers without a shared cache load cold. The status lane keeps its separate
Desktop metadata cache.

## Codex sidecar facts

The process-owned transcript cache retains complete Codex home facts in RAM,
using the shared file stamp for the resolved SQLite main file and its WAL.
Only the active cycle scope's facts are kept; returning facts discard idle
entries from previous scopes. Cycle serialization excludes overlapping loads.
Every pass lists the homes and rebuilds metadata merges, ownership conflicts,
completeness and path fingerprints. A home whose stamps match is reused; only
changed or added homes reload, and an unstamped or incomplete home is not kept.
A pass that reuses a home and ends with an identity conflict, or with changed
merged title inputs for a reused home's ids, reloads every home cold once.
Changed thread databases use one
streaming census with independent staging for title, usage and created rows.
Raw title equality uses an optional digest; a SHA midstate preserves the exact
existing fingerprint bytes after the merged title prefix is known.

Codex logs are not read. Priority comes only from rollout thread settings; a
row an earlier build priced from logs keeps that tier through its protected
tier receipt. Sidecar facts are never persisted; a restart fully loads them.
Terminal scan diagnostics include reuse/reload counts for state, history and
session index facts, plus absent roots.

## CLI status metadata

Codex login state and bundled model metadata are cached in RAM per home while the
canonical CLI binary, `auth.json` and `config.toml` file stamps match, for at most
60 minutes. Stamp capture uses metadata only. Missing auth, nonregular inputs,
failed commands and inputs changed during loading are never kept. Setup reads
bypass reuse and refresh successful facts. Only the full status listing evicts
removed homes; account-screen reads never evict other homes.

Login is reused only when this pass's fresh auth read supplies email, plan,
subscription product and billing channel. Otherwise CLI account fields are read
fresh and merged exactly as before. The cache retains only the login enum.
Cached login facts contain no account, email, plan or identity. Auth-file and
provider identity reads and config-model application keep their ordinary freshness.
Claude version detection uses the same helper with only its binary stamp. Pi
model listings remain uncached because their output depends on Pi config/auth.
The allowlisted zsh login-shell provider environment is shared in process memory
for 30 minutes per effective HOME, including failed imports. Concurrent callers
share one bounded import; current process values are merged afresh and win.
Pi verification and explicit status refresh re-import and repopulate it.
Environment values are never logged or persisted.

The status read of each source's active-session reconciliation uses the same
helper, keyed by its cache file. Every local request builds status, so the
parsed reconciliation is reused while the file stamp is unchanged; a reconcile
always replaces the file, and the next read parses it again. Its optional
`last_activity_at` carries the maximum parsed session activity time per source,
including sessions without usage rows. Each new observation is filtered to at
most five minutes after reconciliation before taking the maximum. Empty scans,
rescans and policy-stop clears preserve it. Older caches seed it from existing
ceiling-filtered watermarks as best-effort history: a legacy future timestamp
can surface after the clock passes it. A rollback can drop the field and cause
re-seeding on upgrade. This local status fact is independent of uploads.

Each source's optional `collection` status is a RAM-only pulse in its existing cadence state.
Absence means unknown: no collection offered this run, missing installation/grant, paused,
admin-disabled or policy-stopped. Pause, grant loss and either policy stop clear the pulse;
a new eligible collection attempt starts its awake clock again. The shared active-session
reconciliation path stamps completion, including empty scans and failed cache writes, before
upload work. Status reports `collecting`, `server_backoff`, `offline` or `stalled`, with the
last completed scan's `last_scan_at` when known. A transport prepare error is offline until a
completion or non-transport outcome. Stalled takes precedence after more than the larger of
60 awake minutes or the current planned interval (including the failure ladder) plus 30 minutes.
Honoured sheds latch the effective deadline at its setter, after releasing the deadline lock.
Scan completion preserves any unexpired deadline from an independent upload lane.
That deadline also extends the pulse baseline; `until` is emitted only during server backoff,
projected from wall time plus the remaining awake duration. All elapsed decisions use
`scan_clock::now()`, so sleep does not age the pulse. This observation never changes cadence,
canonical health, upload decisions or persisted state.

Existing resource records carry fixed command classes, child starts and per-PID
child CPU totals; arguments, paths and command output are never included.

## Stores

**First-read recency tiers.** A destination's first census anchor starts its tier
at 1 day in `BackfillState.first_read_tiers`; the tiers are 1, 3, 7, 14, 30, then
the 60-day first-read window, and a tier's bound is the source's anchor minus its
days (1 day is 24 hours). An absent entry is the final tier, so a daemon upgraded
mid-import keeps its untiered order and pacing. Claude, Codex and Pi are tiered.
The participants are the sources rotation runs (`enabled_snapshot_sources_in`:
granted and without a local disable marker) whose import for the destination is
not complete and that are not in the tier's `stopped` set, anchored or not: a
source that has not anchored yet holds the tier until its first prepare, which
anchors it or, when it may not anchor (an existing index, a completed or
unverified history), puts it in `stopped`. A policy stop (disabled by an admin, a
zero receipt window) or a failed prepare also puts the source in `stopped`, so it
never holds its siblings' tier; its work stays owed and its next anchored prepare
rejoins. Prepare sets the runtime `first_read_tier_cutoff`. `TierGate` looks at the
queue once per selection: a queued file never read (no index entry, confirmed
empty, account hold or a Tail head with a reduction; the census's metadata-only
head for an owed file is no read) older than the bound sits out page selection; it
stays queued, so the census, freshness debt, disappearance diagnostics and
completion keep owing it, and it never asks for a paced pass. A Codex join group is
read whole once any member is selected, so it takes its newest member's tier;
within a tier the newest-first order is unchanged.

Claude admits a path family (root, subagents, path twins) whole once any member is
read or in the tier. A copied or forked file's holder is known only from the request
census after a read, so no tier holds a child for its holder: whenever the holder
is older than the bound, the child is read first, counts its unproven prefix and is
marked `DISCLOSED`. Every main in that copy's folder is then pulled into the current
tier with its family, and the page that reads a pulled main also re-reads the
folder's `DISCLOSED` copies, so the copy decision proves the holder in that page and
both corrected bodies are uploaded together; the server never holds the holder
beside an uncorrected copy. The copy's first body still differs from an untiered
read that reads the holder and the copy in one page: it counts and discloses the
prefix until the holder's page. The existing save-time re-decide
(`CopyOwnership::reconcile`, changed copy decisions, settled counted copies) still
settles a holder in another folder, so the final state matches an untiered read.
Chains follow one read at a time. A folder whose copy never finds its holder
re-reads that copy on each tier page that reads one of its pulled mains. Under an
account-switch claim cutoff, a holder whose session ended before the cutoff is
the previous owner's history: finish never uploads it, yet it still owns the
requests its copies hold, so a copied prefix from before the cutoff counts
nowhere at the new destination, whatever the page placement or read order. It
proves them, in its page or once finish has emptied it (`confirmed_empty_files`),
only with positive local facts: its file was last written before the cutoff
(the census record's mtime; a file emptied for another reason, such as a parse
with no positive usage, may be newer), the birth store records this location
as its session's only one (a path twin may carry its requests in a body that is
refused; no observation proves nothing), and its current
census holds the request. The named-parent fallback never uses it. Otherwise,
and for a deleted holder, its copies count the prefix and disclose it. The older paths a page selected through a family pull
and through a folder pull are counted on `source_finish` for diagnostics only.

Finish records a participant's tier done when its walk ended (or its census
completed, which an empty history does on its first pass), no selectable census
member is left, no terminal retry is held and its upload settled. A tier waits only
for work in flight inside the import: a queued file under a Claude account hold, or
an unchanged file (same listing stamp) whose every current entity has a permanent
refusal (the upload ledger's or an `UnprovenTerminal` quarantine) whose refused body
witnesses rebuild the file's stored body digest, stays
owed, retried and disclosed as before but does not hold the tier, and a
transport-settled pass whose only holds are account deferrals settles it. A pending
retry, shed, transport failure, lost ACK or conflict in retry still holds it. Under
the backfill-state lock the tier advances once every participant is done; the saved
advance returns the participants, and finish asks each for a paced pass. The census
cannot complete while deferred files are queued, so bootstrap completion follows the
final tier. While the destination is in the final tier, paced requests carry
`first_import = false`: those passes run at background QoS at the unchanged
`PACED_AC`/`PACED_BATTERY` pace, while tiers 1 to 30 keep first-import QoS on AC.
`first_read_cutoff` keeps meaning 60 days; `tier_ready_cutoff` reports the highest
completed tier that the source also finished on its own pass (`finished`, which a
stop forgets), so a late, resumed or recovered source claims nothing until it
finishes a tier itself. The field is omitted otherwise, and the receiver keeps its
last stored value. The terminal report reads both from one backfill-state load.

Terminal scan status optionally reports `first_read_cutoff`, the destination/source's
first census end minus the fixed 60-day first-read window, as UTC milliseconds.
The first census end is saved once in `BackfillState.first_census_ends` before
collection, only for a missing index without prior completion. Generation-zero
restart uses that saved end for admission. Completion, replay and wider upload
windows preserve it. Existing stores without an anchor omit the field; check-ins
always omit it. Older builds ignore this optional map and drop it on their next
backfill-state save, so re-upgrade omits the cutoff for existing destinations.

- **Scan index** (`snapshots/scan_index_*`): per source, the bookkeeping of what was read and
  accepted: per-file progress and fingerprints, full-scan state, account and usage evidence. It is
  saved atomically under the state directory's single-writer lock.
- **Account history.** Ordinary Claude state-v2 saves compact stored account-window
  runs after custody merge and retirement, using the same checked summary as resident
  retention. Families go in key order and work stops between whole families once
  the archive-read allowance is spent; a refused family waits for the next load.
  Queued rollovers and opaque decode holds defer compaction. Row deletion and exact cold
  metadata publish together; loading stays read-only and idle maintenance owns reclaim.
- **Claude, Codex and Pi continuation** (`snapshots/tail_source/`, `durable_tail_codec.rs`): a completed read stages
  its running reduction into the state database; the pass's save commits it with the index. A later
  read loads the committed head, checks identity and the file certificate, and streams the pages,
  session facts (title, first prompt, workspace, opening settings; Codex also stores its agent
  label and prelude) among them: no transcript byte is
  read back for content. A refusal is a counted Full; only a newer build's
  head holds. An equal-size mtime move at or before the indexed read's nonzero ctime can
  restore from that read's certificate when size and stored mtime bind it to the entry,
  births are known and equal, and both bounded sample digests match. This removes a
  whole-file read for retention touches; ordinary later writes still read Full. A first
  touch after a long gap can still read Full; steady reuse depends on the lease cadence
  remaining within its backdate interval. A same-size mtime move outside that bound,
  forward or back, continues from stored state only when the file's write
  generation count proves it a touch: macOS APFS counts every data write, the same
  bytes rewritten included, and never a metadata change such as setting the mtime.
  The count is read with `fgetattrlist` on the held descriptor, before the samples,
  and is kept only when it is nonzero, the file system returned it and the volume
  is APFS (`fstatfs`, kept per device). A read keeps it only when the held
  descriptor reports the same count at commit and the read sealed the whole
  opening length; it is stored beside the certificate in the Tail head (envelope 2,
  writer capability 7) and compared only under the same inode and the same known
  birth. A due audit still reads Full, so a touch never stands in for an audit or
  reaches a quiet retirement. Otherwise a proven touch reads both samples (the
  retained checkpoint's, or the restore's) and then continues as an unchanged
  file does: it carries the certificate's verification and debt, earns
  no Full credit, and never enters `same_content`/`unchanged`, so an exact-stamp
  seal and Full-verification credit ignore the count. Without a count (another
  platform or file system, a zero count, a head written before counts, a file set
  aside) the rule above is unchanged. Freshness debt lists a proven touch at its
  indexed mtime, so the walk owes what it owed before the touch. Rolling back
  below the release that writes envelope 2 holds collection until roll-forward.
  Source fingerprints include metadata and
  bounded content samples, rather than a whole-file digest. Freshness debt clears only
  through the existing receipt proof on a later listing.
  Codex checks its ownership-affecting sidecar binding before reusing a head; changed
  ownership evidence reconstructs through the counted Full path. Pi stores its usage ledger,
  totals and fork state on the same Tail seam. Each pass removes the
  retired restart-record directory beside a scan index (`sampled_scan/retired_records.rs`): counted,
  retried, never via full erasure.
- **Workspace observations.** Native completion records a resolved repository binding in the
  session's Workspace fact before staging Tail state. The binding survives restart and directory
  removal; unsuccessful lookups remain unbound and can resolve on later ordinary selected work. Git
  worktrees keep the shared common-directory identity. Explicit non-Git and unknown folders can
  carry a sanitized directory basename under the workspace-label upload policy; labels never
  determine identity. Path-only Workspace v1 facts remain readable; only bound Workspace facts
  write v2, and other fact kinds stay v1. Older readers hold v2 facts as future state rather than
  reconstructing them. No historical sessions are selected just to enrich metadata.
- Claude Desktop store discovery reads ordinary directories at any depth, retaining
  symlink rejection and the per-scan entry budget. Its identity census token enters a
  session fingerprint only when that session carries original Desktop identity evidence.
  Titles, account evidence and spawn lineage keep their independent fingerprint inputs.
  A census restart records the discarded checkpoint before starting a replacement walk.
- A clean census completion arms the next routine walk in process memory only.
  Routine walk pages use ordinary cadence when only their file allowance is full;
  resident-charge deferrals still request paced pages. A process restart, sidecar
  restart, changed traversal context, unhealthy retry or clean follow-up keeps pacing.
- Claude's identity-incomplete request census keeps source verification through a complete,
  loss-free Tail bound to the verified predecessor entry and head. This does not supply missing
  request identities, complete-negative evidence, Full audit credit or upload acceptance.
- The Tail is one more kind in the same state database, committed in the same save as the index.
- Proven Codex compression and same-object relocation carry the existing logical state,
  fingerprints, exact ACK/context facts and debt without reading or uploading. Compression
  proof is an absent plaintext predecessor and its exact same-directory `.zst` sibling with
  the same session identity; a relocation requires physical object/content equality. The old
  and new graph closures, Tail keys, fragments and head binding move in one rollback unit of
  the ordinary save. A failed save exposes the complete old or complete new state.
  A provider-written new plaintext object follows the existing replaced-file path: one counted
  Full and one whole-session replacement. Returning the original object retains ordinary Tail
  continuation. The old archive catalogue entries remain readable by key and keep their field and
  cause ordinals. The generic retirement path deletes their rows on the next committed graph save.
- A parser or scan-identity version bump invalidates every saved record. A change that bumps one
  also migrates saved state forward, or it explicitly accepts the full re-read.

## Returning to an account

Claims record exact owner/API/machine/installation/OS-scope namespaces in trusted
owner-only history. Returning claims require live hardware and surviving custody;
same-owner rotation keeps the existing prior-credential policy. No orphan discovery.
Logout seeds proven outgoing history best effort; history I/O failures count a
skipped seed and allow logout/reset. Claim-time Unknown history still holds.
Forget invalidates old installation rows.
History-bearing journals use v3, rejected by released v2 readers. The selected
cutoff precedes activation; history is synced/read back before pending clear.
Existing aliases, loaders and exact destination ACKs retain all source custody.
Completion belongs to settled delivery, per destination/replay revision. Older
writers may drop that map, causing one bounded re-walk after upgrade. Quiet return
reads no bodies or parser bytes and sends no historical bodies; identity samples
follow uninterrupted census behavior. Server cutoffs still exclude pre-cutoff debt.
Deleted custody selects fresh, under existing first-read/cutoff gates, with no ACKs.

## Hot and cold state

Resident state stays small: what is needed to decide what to do with a file (identity, offset,
totals, revisions, acknowledgement references) and per-session-group summaries (current account,
flags, counts, cursors). Per-request evidence is read for the session group a decision affects and
released afterwards; whole-state copies are avoided because the allocator keeps freed memory.

- Reads are typed **Present / Absent / Unknown**. Unknown is never treated as absent, zero or
  proof; the dependent decision is held, counted and retried.
- Any lookup, index or filter that answers "not present" must be complete for its source and
  scope, updated together with the data it summarizes, and rebuilt when it can't be trusted.
  Otherwise its answer is Unknown.
- Memory is measured as `phys_footprint` for the whole process (see the resource fields in
  [docs/diagnostics.md](../../docs/diagnostics.md)).

Native pages also use a soft 230 MiB resident charge target. A completion charges the larger
of loaded Tail bytes and full encoded reduction pages, plus a per-file estimate. Files, path
twins, forced families and Codex join groups finish as indivisible units; an oversize first
unit always progresses. Remaining selected work returns to the saved traversal with its original
flags. This paces work without dropping data or claiming a hard process-memory bound. A saved
resident deferral, or a selection that filled its file allowance while source work remains queued,
requests another ordinary pass after 30 seconds on AC or 180 seconds on battery with Low Power
Mode off. Unknown power and Low Power Mode retain ordinary cadence.
A same-process re-walk after completion or a clean-follow-up retirement keeps routine
cadence. A terminal-unhealthy retry also runs at routine cadence when its problems are
file-level only: no namespace loss, directory cap, rejected symlink or watcher overflow.
Retry arming needs no same-process evidence: after a restart or upgrade, a kept
terminal-unhealthy traversal's first eligible retry walk is routine under those conditions.
The active routine marker is process-local and binds the scan context and census window;
resuming an unfinished walk after restart does not restore it. Resident deferral can still
request pacing.
Prepare, finish, server minima, upload backoff and background QoS still apply.
During a first backfill (not a replay revision bump), a Codex page that spent a byte budget with
work still queued also requests a paced pass.
While destination bootstrap is pending, AC passes also keep runnable bounded-walk work or an
owed clean follow-up on the same 30-second pacing. Every request made during the first import
carries the first-import flag, so on AC its pages keep the thread's ordinary QoS instead of
background; battery and steady-state passes stay at background. When a source first sees an
upload destination while its first import there is owed, it requests one such paced pass at once
instead of waiting out the tier it carried from before. The request uses the
index after upload settlement, including a first offer's final-page conflict. Metadata-only
retention, decode holds and unchanged held or conflicted debt grant no follow-up urgency;
queued unblocked siblings can still advance. Terminal-unhealthy walks use the scanner's own
retry eligibility. Battery cannot renew this reason; an AC request already issued may wake
once after unplugging. Clean retirement or bootstrap completion ends this request.

All scan-index saves use SQLite. Legacy JSON is retained only as one-time
import input. Collection waits for verified publication and adoption. Ordinary
source passes retry transient import/publication failures; deterministic input
refusals retain the existing support blocker. Successful authenticated adoption
clears it. Quarantine and user Repair use the same verified publisher at G=0;
Repair keeps its identity and accepted-debt carry, witness and cooldown ordering.

Snapshot audits start from an empty in-memory graph, finish the traversal in
memory and aggregate every page. Each invocation reports the complete selected
source again; the report schema is unchanged. Audit state directories retain
only their privacy marker; old audit checkpoints are neither loaded nor updated.

## SQLite

SQLite runs in-process, so a query is a function call rather than a round trip.

- Small indexed reads are fine; batch only where it makes the code simpler. Use primary-key or
  index lookups, cached prepared statements and one range scan per group or kind.
- All writes of one publication go in one transaction; `BEGIN IMMEDIATE` is taken only at commit.
  No per-row commits.
- Read transactions stay short and never span parsing, uploads or network waits, so WAL
  checkpoints can run.
- Each state-store connection releases its own cache after its own pass, after maintenance
  and before cache gauges are sampled. Release is best effort; `cache_size=-8192` stays
  unchanged and the next pass refills the cache.
- Durability stays at `FULL`. Erasing data leaves nothing readable in the database, WAL or SHM
  files.
- Complete valid saves commit above aggregate charged-work targets. The 32 MiB target sizes the
  next collection page; crossing 256 MiB emits a counts-only alarm without refusing the save.

## One generic path per source

Claude Code, Codex and Pi share one implementation of discovery, selection, tail reads, read
counters, the Tail store, saving, erasure, upload, acknowledgement, status, counters and
switches. Per-source code is limited to the root layout, the file reader and reducer, and money
rules that really differ: copied-prefix deduplication for Claude, cumulative deltas for Codex and
forks for Pi. Source capabilities are table fields, not `== Source::Claude` checks in shared code.

Claude subagent path twins retain a native copied-request skip only when an earlier
same-member page fold holds that id and the occurrence's usable provider timestamp is at
or after 2026-11-05T00:00:00Z. Other requests and idless copies count through the existing
restoration path; the parent-repeat rule and listed-family behavior remain unchanged.

A forked child's copied first response counts at its root when the same root
path's page or valid persisted request census holds that id. Census freshness
does not revoke positive membership. With no witness the child counts it until
its next fold can prove the copy. A root rewrite replaces the census; the child's
next fold then follows that replacement. Membership proves local source presence,
not server acceptance. No extra reads or persisted fields implement this rule.

## Module map: snapshots/ (target; migration in progress)

`snapshots.rs` and `snapshots/` are being split into the tree below by move-only changes. This is
the target, not an enforced layout; today most code still sits in `snapshots.rs`.

- `snapshots.rs`: the facade (at most 400 lines): module declarations, re-exports and the entry
  points other modules call.
- `sources/{claude,codex,pi}/`: per-source code only, as described above.
- Shared stages: `wire/`, `discovery/`, `scan/`, `scan_index/`, `session_facts/`, `usage/` and
  `upload/`.
- Existing subtrees that stay as they are: `state_v2/` and `tail_source/`.
- `tests/`: tests that span stages; test data under `tests/fixtures/`.

Move-only changes are checked with `scripts/check_move_ledger.py` (every item moves byte for byte,
except that a fn with an unchanged body may have a signature rustfmt re-wrapped and a struct may
have named fields rustfmt re-wrapped; only visibility, `use`/`mod` lines, path literals and wrappers
change; a `use` binding kept by name keeps its target, visibility, literal-preserving attributes and
multiplicity; modules with moved items reject every added glob and every added explicit binding
beside an item-level macro call; edits to listed validator files that anchor on moved code are
reported) and
`scripts/check_test_id_map.py` (every test keeps its ID or has a row in
`scripts/test_id_renames.tsv`, and its never-retry decision stays the same).
Whole-file moves are checked with `scripts/check_file_moves.py move` (a module file and every
file below it move byte for byte; only the old parent's `mod` line, one facade alias at the old
name and the new parent's `mod` line change; no `super` path in a moved file reaches outside its
subtree), after an optional change checked with `scripts/check_file_moves.py absolutize` that only
replaces such `super` paths with the `crate::` path they denote. Both modes are built for
accidental changes by trusted authors and fail on what they cannot reason about (include edges
into moved files, unlisted derives, attributes and item-level macros, allowlisted names rebound
anywhere in the crate, macros reached through `use .. as` aliases or `$m!` forwarding, location
macros, glob importers that see the new name, globs whose private items change with the move,
unknown Cargo targets, old-path strings after decoding escapes and normalizing separators and
case) and print their limits: implicit log targets, panic locations, approved derives assumed
context-free, runtime paths and `include!(env!(..))`.
`scripts/check_source_layout.py` reports how far the tree is from the target.
Public CI also runs `--enforce-new --base <ref>`: production `.rs` files added
against the base anywhere in the repository must have at most 3,000 lines and
warn above 1,500. Exact (R100) file moves count as existing files; `*_tests.rs`,
`tests.rs` and files under `tests/` are excluded. Existing files remain report-only
unless a rule is explicitly enabled with `--enforce`; a limits-table row cannot
exempt a new production file from the ceiling.

## Never drop data

- A size, count or time limit may pace, defer or spill work, with a counted warning or alarm. It
  never drops, strips or skips usage or account data. Display-only data is shed first.
- Holds are transient, resource or correctness holds. A held file that grows stays discoverable or
  is read through a counted path; a correctness hold never publishes and catches up by Tail when it
  resolves. Pacing maps that fill up evict the oldest entry and let the read happen.
- Large valid data finishes through bounded, restart-safe progress rather than waiting forever.
- Correct money is the right totals on the right account. A cold Full read, the RAM path, a
  restored record plus tail, a restart between pages and an upgrade produce the same totals and
  the same account placement. The money oracle in `snapshots/sampled_scan/transition_fixture.rs`
  and the `money_equivalence` CI job check this.

## One version

- A runtime switch is a support-directory marker, never an environment variable alone, and it is
  temporary. Its OFF state preserves existing behaviour except for explicitly documented changes.
  When retired, the feature is either on by default with the OFF path deleted, or deleted.
- No parallel old/new versions are kept "just in case": old formats are read once and migrated;
  retired persisted fields are decoded and dropped at the next save, and retired wire fields stay
  accepted by the receiver.
- Superseded paths are deleted with their settings, docs, callers and tests in the same change.

## Privacy

Transcripts never leave the machine. Logs, diagnostics and status carry counts, never transcript
text, paths or raw identifiers; types holding local-only text don't derive `Debug`. Identity is
never inferred across sessions, folders, machines, parent and child sessions, profiles or copies.
What a privacy setting removes from an upload is decided in `upload_policy.rs`, or by the builders
that read its settings; it never refuses a body, and hashes are computed afterwards from what is
sent.
The Companion session list uses local titles and workspace labels before upload filtering.
Erasure (retirement, uninstall) reaches every store and is counted when it fails.
Source removal, grant loss, logout, account switch and forget installation only stop
collection and keep local state; re-enabling a source resumes from it and drops
nothing, so nothing already sent is re-sent. User-facing detail: [docs/privacy.md](../../docs/privacy.md).

Local collection never depends on an upload setting. No read-side identity (file scope, Codex
group scope, traversal, memos, tier receipts) includes a setting, the attribution key, a
server capability or the replay directive; the upload filter applies them at send. Delivery proofs
keep the full upload context. A setting or capability flip therefore reads and sends nothing for a
file whose delivery is fully proven: it owes delivery, paid on the file's next ordinary read, and
applies to bodies from then on, never retroactively.

## Codex cloud task collection

`cloud_sessions` runs independently of local transcript collection and upload,
under the same consent as local Codex sessions. There is no per-Mac grant.
Each due slice reads the Codex activity hint once through the source-scoped
relay, under an I/O lease. Listing runs only when the hint turns it on and
names the `cloud_session_changes.v3` contract; anything else (listing off, an
older server, another contract) is off and the hint is read again in 30
minutes, or six hours when the route is missing.
The same hint's `SnapshotUploadPolicy` decides whether titles and environment
names are sent, and every body is stamped with it. Any 409 (listing off, a
policy mismatch) rechecks like listing off, so a policy mismatch waits up to
30 minutes; a 410 (contract retired) rechecks like a missing route, every six
hours. Refusals settle nothing.

The head interval lives in the collector, outside the schedule: five minutes,
doubling after each successful head listing from which the server accepted
nothing new, up to 24 hours. Only an `accepted` outcome resets it; a `noop`
(another Mac already sent it, or an expired ACK) does not. A daily crawl streams
pages and retains only its next cursor in memory, continuing five minutes later
when its slice budget ends. It continues across midnight without a total
page/task ceiling. Only positive task facts are uploaded; missing tasks never
imply deletion. The supervisor wakes at least every six hours.

Each task is sent as `source_session_id` = its raw Codex task `id` (the
`task_id` alias is not read); the server keys it by (user, source, id), so
every Mac of that user sends one head per task. A row whose id breaks the
shared rule (1..=255 code points, no control character, no boundary
whitespace) is skipped, never repaired, and counted; one counts-only line per
changed count is logged, never an id. A page whose rows are all skipped this
way still follows its cursor. An ACK settles only ids echoed byte for byte.
The existing graph-independent upload-history SQLite connection stores only
each task's semantic digest (over its facts and the applied policy) and head
etag, keyed by a local digest of the task id (so every valid id fits the key
column and no raw id is written) and scoped to destination, organization, user
and contract.
Accepted and noop ACKs store the head; a rejected task or a conflict without a
head stores none, earns no credit and is not resent until it changes. Fixed
expiry permits safe re-offering; the server returns no-op for an exact repeat
even after ACK loss or restart. Requests are packed under 200 tasks and the
server's 512 KiB body ceiling. The cache contains no task payloads, titles or
raw IDs and never enters local graph load/save or receipt settlement. The file
stays at `user_version` 1: its cloud tables are created if missing at open, and
older builds open the file and ignore them. Cloud failures and retry deadlines
do not change local delivery. Every hint, provider, send and cache admission
validates current local identity; identity changes close admission and drain
admitted I/O before replacing account or device state. Startup removes the
retired per-Mac grant files under `cloud_sessions/` and nothing else.

### Collector approval continuity

Daily provider reporting approvals survive daemon updates and sign-ins to the
same Ottto account on the same physical Mac. An enabled bound approval can rebind
to the current relay device through its `grants/{id}/rebind` endpoint,
authenticated with that target device's relay token. The request sends the
stored grant version, new scope fingerprint, live hardware hash and original
disclosure; the server resolves the previous device. Successful rebind preserves
the grant epoch, consent-time build, account fingerprint and exclusions. The
local grant is replaced atomically. It never replays transcripts.

Live hardware must match the saved identity before collection and rebind. Missing
hardware proof stops collection. A copied saved hardware identity requires an explicit
forget-installation and new pairing before approval on the new Mac; fresh consent
alone cannot override the hardware check. A revoked or disabled approval is never rebound.
Terminal refusals stop retries for that binding until the binding changes or the
service restarts. HTTP 404 retains the stopped-binding behavior for servers that
have not deployed rebind yet. Transport, 429 and server errors use normal polling.

## Codex daily provider reference

With a live approval, `provider_daily_reference` reads the provider's own daily usage for
every Codex login on the Mac and uploads normalized scalar rows. Each tick reads the default
home and every accepted slot home once (never a home seen only through a running process),
keeps one login per opaque account (identified first, then the default home, then the lowest
slot id) and uses a slot only while its live token proves the pair it was registered with.
Logins are read most overdue first, each at its own 6 h cadence and breaker; a 429 or a
grant-wide refusal ends the tick. The attempt time is saved before every request, and a
request is never made when that save fails. `state.json` (schema 2) keeps one entry per
account and the latest discovery summary; status reads that summary and never a credential.
An answer with a `users` count above one anywhere is refused as workspace-wide. A batch counts
as stored only when its acknowledgement names the expected grant and its row counts add up;
when every batch of a read is stored as current, the account keeps a proof of that series,
and another login of the same tick returning the identical series is not uploaded again.
A login is one secure read and one parse of
its home's `auth.json`; the request token, `ChatGPT-Account-Id` header, attribution
fingerprint and account identity all come from that parse. Expiry and identity come from the
live access token; an id token only cross-checks the pair. A token lapsing within five minutes
is never used, and credentials are never refreshed or written.

Under the current disclosure every batch of one read carries the same optional
`account_identity` (the account and workspace hashes Codex session evidence uses) and the
same `collected_at`, empty batches included. The read's last covered day is always the last
complete UTC day at that `collected_at`. `provider_daily_reference::tests::accounts` emits the
producer fixtures in `fixtures/provider-daily-reference/`; the snapshots parity test emits the
cross-language identity vectors.

## Install variants

Ottto installs one of two variants per Mac: the app (`Ottto.app` runs
`serve-xpc` from its bundle) or the headless Homebrew formula (`serve`). Both
use the per-user launchd label `net.ottto.service`, and the app wins. Before
it takes the state lock, a launchd-started `serve` whose executable is under
a Homebrew prefix checks for an installed app (`/Applications` or
`~/Applications`) with an executable bundled service, a version at least its
own and a signature that satisfies the Companion code requirement. If that
app's own process runs for this user, the Homebrew copy hands over: it writes
its pid to `homebrew-handover` in the support folder and waits, holding no
state, up to 180 s for the app to take the job back with `--migrate-owner`
(launchd's bootout ends it). If the app quits or does not take over, it
removes the marker and serves. With the app installed but not running, or
while the app's `homebrew-keeps-serving` marker exists (the app restored this
job after its own takeover failed), it serves at once (`homebrew_step_aside`).
Doctor reports a second variant under `install_variants`. The release gate
runs the same decision through the hidden `service step-aside-check`.

## Local control dispatch

Control dispatch validates the protocol version, then checks the command's
caller policy. Local commands check caller authority before daemon-state poison
and release the state lock before dispatch. Session launch consume and report
also require a CLI token. Cached agent status checks caller authority alone.
Public updates and backend-token commands use their own handler paths. Identity
commands keep their handler-side authorization and invalidate pending launch
handoffs before mutation.

## Local health diagnostics

Verification authorizes before source reads or result writes; setup authorizes
before acquiring the process-wide scan lock. Telemetry controls require the
validated user and organization to match the connected local account, under the
identity lifecycle lock, and refuse work while an identity change is reserved.
Telemetry status and disable also require the validated device to match the
local health device binding and the request key id to equal the validated key id
(including both absent), before any local reads or effects for the action.
Codex daily-reference controls build their complete returned status from local
stores before releasing that lock. Browser control requires an HTTPS Origin
of ottto.net, www.ottto.net or app.ottto.net and a loopback Host with the
listener's port. Probes return their existing identity and detailed health
replies with that same Origin/Host boundary, without a token.
Other probe callers receive only liveness/version. Duplicate Host, Origin and Authorization
headers are refused.

Local health events retain only the latest observation per Upload, SetupRead and
SnapshotSync family, per Verify source, and per ScanIndex source/reason/polarity.
The command ledger retains the latest terminal result per action. Both lists keep
insertion order; they are current diagnostics rather than a lifetime history in
status/CLI JSON or uploaded health evidence. Usage, upload bodies, receipts and
placement do not depend on this diagnostic history.

Status keeps its owned snapshot; control serialization happens after the daemon
state lock is released. Runtime observations belong only to that response;
reprojection replaces its observation.
ScanIndex catch-up materializes only the latest set and clear for each pair and
advances the observed transition high-water marks even across a long polling gap.

Accepted Claude request holders are recorded per source/session slot and contributor location.
Only an exact body ACK replaces a slot's counted, nonzero request hashes, including an empty set.
Copy removals consult those hashes before local ownership and census evidence.
Rows survive refusal, temporary census loss, historical replay and bounded rebuilds.
A destination change clears them; positive deletion prunes only hashes no stored copy names.
The rows confer no upload receipt authority. State layout 8 stores each slot separately;
older readers refuse this layout and require a forward update.
