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
  whose length grew past its saved size is never dropped from discovery because of its age.
- **Selection.** Each pass picks files and a read mode (`transcript_acquisition.rs`). Tail, a read
  from the saved offset, is the normal mode, so bytes read track bytes appended. A Full read has a
  named cause (new or replaced file, missing or invalid saved result, a real edit) and is counted
  by cause. Re-reading unchanged content that was already uploaded is treated as a bug.
- **Reduction.** One reducer per source turns lines into usage and keeps a running result. Old
  evidence is read only for the session group a change affects.
- **Upload.** A session is uploaded as a whole-session replacement, idempotent at the receiver. It
  settles only on an exact acknowledgement of the exact bytes sent to that destination. A local
  receipt never counts as an acknowledgement; refused, not-stored and partial answers are not
  accepted, and parts the server did accept stay recorded.

Stale-older refusals from current servers mean the server already holds the
newer usage. Earlier refusals stay counted as owed, with their dispositions
unchanged. Owed entities never grant an automatic rebuild or re-offer. Retries
use retained bodies; transcripts are read again only for changed input. Unknown
non-permanent reasons hold their entity without invalidating sibling ACKs. See
[refusal custody](../../docs/development/refused-snapshot-reassessment.md).

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
- **Claude continuation** (`snapshots/tail_source/`, `durable_tail_codec.rs`): a completed read stages
  its running reduction into the state database; the pass's save commits it with the index. A later
  read loads the committed head, checks identity and the file certificate, and streams the pages,
  session facts (title, first prompt, workspace, opening settings) among them: no transcript byte is
  read back for content. A refusal is a counted Full; only a newer build's
  head holds. Codex and Pi keep RAM reductions and read Full after a restart. Each pass removes the
  retired restart-record directory beside a scan index (`sampled_scan/retired_records.rs`): counted,
  retried, never via full erasure.
- The Tail is one more kind in the same state database, committed in the same save as the index.
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

- A runtime switch is a support-directory marker (normally `local_switch!`), never an environment
  variable alone, and it is temporary. Its OFF state preserves existing behaviour except for
  explicitly documented changes. When retired, the feature is either on by default with the OFF
  path deleted, or deleted.
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
collection and keep local state; re-enabling a source resumes from it and drops only
that source's upload witnesses. User-facing detail: [docs/privacy.md](../../docs/privacy.md).

Local collection never depends on an upload setting. No read-side identity (file scope, Codex
group scope, traversal, memos, tier receipts, archives) includes a setting, the attribution key, a
server capability or the replay directive; the upload filter applies them at send. Delivery proofs
keep the full upload context. A setting or capability flip therefore reads and sends nothing for a
file whose delivery is fully proven: it owes delivery, paid on the file's next ordinary read, and
applies to bodies from then on, never retroactively.
