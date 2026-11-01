# ottto-service architecture

`ottto-service` is the local daemon. It reads Claude Code, Codex and Pi session files on the
user's machine, reduces them to usage, and uploads that usage. This page states the shipped
design and the stable rules every change keeps. Paths are under `src/`. When a change alters
behaviour described here, update this page in the same PR.

## Read path

```
file-system hint / periodic listing → select file → read new bytes from saved offset → per-source reducer
  → running result kept in RAM (and the record store when enabled) → upload → exact acknowledgement → index save
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

## Stores

- **Scan index** (`snapshots/scan_index_*`): per source, the bookkeeping of what was read and
  accepted: per-file progress and fingerprints, full-scan state, account and usage evidence. It is
  saved atomically under the state directory's single-writer lock.
- **Record store** (`durable_tail_store.rs`, `durable_tail_codec.rs`): format v3 write-ahead
  records stage the running reduction at native settlement, before publication effects and index
  save. Exact local receipts settle record custody, never upload acknowledgement. Restore validates
  source, key, context, scope, format, file certificate and committed index evidence before bounded
  content replay and Tail. Refusals use counted recovery or hold without changing accepted usage.
  Byte budgets pace writes and replay; deferred work stays discoverable. Consent-gated local-only
  fields stay in the record and never enter diagnostics or uploads from the store. Erasure unlinks
  records and syncs the directory under the existing writer lock; failures are counted and retried.
- The two stores join by key digest and hold no references into each other.
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

## One generic path per source

Claude Code, Codex and Pi share one implementation of discovery, selection, tail reads, read
counters, the record store, saving, erasure, upload, acknowledgement, status, counters and
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
- **Restart restore** (`snapshots/restart_restore.rs`) defaults OFF. Its process-fixed policy
  requires the `restart_restore_enabled` marker and `DISCOVERY_DEPENDENCY_READY`. That constant is
  false in this build, so the marker cannot turn it ON until the discovery dependency is implemented
  and the constant flips. OFF disables ordinary record reads, writes, repair and GC; consent/source
  erasure and counted deletion of outgrown v1 records remain active. The former v1 warm-restore
  route is removed: files use no-record acquisition, with a paced Full on growth when needed.
- No parallel old/new versions are kept "just in case": old formats are read once and migrated;
  retired persisted fields are decoded and dropped at the next save, and retired wire fields stay
  accepted by the receiver.
- Superseded paths are deleted with their settings, docs, callers and tests in the same change.

## Privacy

Transcripts never leave the machine. Logs, diagnostics and status carry counts, never transcript
text, paths or raw identifiers; types holding local-only text don't derive `Debug`. Identity is
never inferred across sessions, folders, machines, parent and child sessions, profiles or copies.
Erasure (consent off, retirement, source removal, forget installation, uninstall) reaches every
store and is counted when it fails. User-facing detail: [docs/privacy.md](../../docs/privacy.md).
