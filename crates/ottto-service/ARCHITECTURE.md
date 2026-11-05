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
- **Selection.** Each pass picks files and a read mode (`transcript_acquisition.rs`). Tail, a read
  from the saved offset, is the normal mode, so bytes read track bytes appended. A Full read has a
  named cause (new or replaced file, missing or invalid saved result, a real edit) and is counted
  by cause. Re-reading unchanged content that was already uploaded is treated as a bug.
- **Reduction.** One reducer per source turns lines into usage and keeps a running result. Old
  evidence is read only for the session group a change affects.
- **Codex rollout encodings.** Plain `.jsonl` and compressed `.jsonl.zst` use the same
  ordinary first-read selection, reducer, modification-time age rules and decoded-byte page
  budget. Exact plaintext siblings win before either header opens. Decoder memory is funded
  inside the shared state-memory allowance; a refusal requeues the ordinary candidate with its
  census and watcher flags. There is no separate archive queue, reservation, pacing or inventory
  population/read-volume limit. Compressed rollouts keep their original modification time,
  so they age as the plain file did. Legacy held archive member keys count as already seen
  for the ordinary first-read age gate; their values remain inert, and header/ownership
  admission still applies. A provider-written new plaintext object takes the existing
  counted Full path; only a returning original object can continue from its saved suffix.
  A restart during its first read re-decodes the prefix, counted as decoder work, before reaching
  EOF. It does not restore a compressed decoder or introduce a stepped compressed reader.
- **Codex ownership.** One secure header opener supplies ordinary membership proof for either
  encoding. A failure holds its file and decisions depending on it; an unknown header remains
  a wildcard over every potentially colliding owner. Any missing header/listing proof still
  prevents absence-based counting-evidence collection. Boundary validation covers surviving
  singleton sessions and joined groups across every registered home. A new file
  naming a page owner fails; unrelated new files defer to the next roster refresh.
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
  A new empty day directory still fails one page (about once per home per day).
  A symlink entry that refresh cannot certify can block pages across homes.
  A new rollout seen before its first complete header fails that page once.
  A proven compression or same-object move commits the old and new graph closures
  and Tail keys together during preparation; RAM adopts the destination after COMMIT.
  A refused carry holds only its predecessor's proven owner and counts as inventory debt.
  A rollout moved while a reader owns it waits for a later pass. Multi-file compressed
  sessions remain unsupported for grouped replay.
- **Upload.** A session is uploaded as a whole-session replacement, idempotent at the receiver. It
  settles only on an exact acknowledgement of the exact bytes sent to that destination. A local
  receipt never counts as an acknowledgement; refused, not-stored and partial answers are not
  accepted, and parts the server did accept stay recorded.

Stale-older refusals from current servers mean the server already holds the
newer usage. Earlier refusals stay counted as owed, with their dispositions
unchanged. Owed entities never grant an automatic rebuild or re-offer. Retries
use retained bodies; transcripts are read again only for changed input. Unknown
non-permanent reasons hold their entity without invalidating sibling ACKs.

**Refusal custody.** A fresh permanent `accepted_log_stale_older_upload` refusal
follows the existing dominated, terminal residue path and never becomes an
accepted-body ACK. An optional per-record `exposure` observation, written only
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
raises the refusal alarm. Claude, Codex and Pi share this machinery.

## Stores

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
  head holds. Codex checks its ownership-affecting sidecar binding before reusing a head; changed
  ownership evidence reconstructs through the counted Full path. Pi stores its usage ledger,
  totals and fork state on the same Tail seam. Each pass removes the
  retired restart-record directory beside a scan index (`sampled_scan/retired_records.rs`): counted,
  retried, never via full erasure.
- The Tail is one more kind in the same state database, committed in the same save as the index.
- Proven Codex compression and same-object relocation carry the existing logical state,
  fingerprints, exact ACK/context facts and debt without reading or uploading. Compression
  proof is an absent plaintext predecessor and its exact same-directory `.zst` sibling with
  the same session identity; a relocation requires physical object/content equality. The old
  and new graph closures, Tail keys, fragments and head binding move in one rollback unit of
  the ordinary save. A failed save exposes the complete old or complete new state.
  A provider-written new plaintext object follows the existing replaced-file path: one counted
  Full and one whole-session replacement. Returning the original object retains ordinary Tail
  continuation. The old archive catalogue entries remain accepted and inert; their physical rows
  are neither hydrated nor rewritten, and old field/cause ordinals and formats stay unchanged.
  Compatibility with older binaries is decode-only; older scheduling may replay retained work.
- A parser or scan-identity version bump invalidates every saved record. A change that bumps one
  also migrates saved state forward, or it explicitly accepts the full re-read.

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

## SQLite

SQLite runs in-process, so a query is a function call rather than a round trip.

- Small indexed reads are fine; batch only where it makes the code simpler. Use primary-key or
  index lookups, cached prepared statements and one range scan per group or kind.
- All writes of one publication go in one transaction; `BEGIN IMMEDIATE` is taken only at commit.
  No per-row commits.
- Read transactions stay short and never span parsing, uploads or network waits, so WAL
  checkpoints can run.
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
have named fields rustfmt re-wrapped; only visibility, `use`/`mod` lines, path literals and
wrappers change; edits to listed validator files that anchor on moved code are reported) and
`scripts/check_test_id_map.py` (every test keeps its ID or has a row in
`scripts/test_id_renames.tsv`, and its never-retry decision stays the same).
`scripts/check_source_layout.py` reports how far the tree is from the target.

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
