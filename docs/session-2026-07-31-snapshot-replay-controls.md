# 2026-07-31 — Snapshot replay and continuity controls

## Outcome

The public daemon replay path now fails closed on incomplete evidence instead
of allowing an apparently healthy checkpoint or manifest. The change is
daemon-first and additive; it does not enable replay, release a build, restart a
daemon, or tighten the backend registration route.

## Scan and parse boundary

- Candidate discovery is a deterministic, bounded directory traversal with a
  durable queue, frozen census boundary, and separately bounded deletion
  reconciliation. One tick observes at most 10,000 directory entries plus its
  one-entry boundary witness and parses at most 10,000 candidates. A single
  directory wider than the discovery budget fails red without materializing
  the tail. It rejects root and descendant symlinks, keeps per-path
  unreadable/oversize/disappearance counts, and continues with healthy paths.
- Watcher paths are coalesced, bounded, exact-path hints, never source-wide
  completeness authority. An ordinary hint joins the durable census, is
  revalidated through the same no-follow opened-object checks, and cannot
  starve ordinary directory candidates even under a one-file test page. Queue
  order is FIFO, and remove/rename hints delete the prior durable observation
  without treating the now-missing path as census loss, so a continuously
  active sibling cannot strand stale index entries or keep settlement red.
  overflow or a watcher backend error is different: lost paths dirty the
  current generation, and no terminal manifest can publish until a following
  clean durable traversal. A terminal unhealthy generation retains its red
  witness and retries on a bounded 1-minute-to-1-hour backoff instead of
  rescanning history every tick, while healthy hinted siblings continue
  through quarantine-not-fence.
- The parser reads the exact `O_NOFOLLOW`-opened regular file. Its v2 identity
  binds device/inode/change-time-nanoseconds plus bounded first/last content
  samples; change time catches middle-only in-place rewrites whose size and
  mtime were restored. Nanosecond mtime remains in the scan fingerprint and
  `semantic_sync:v1` remains unchanged.
- Malformed JSON, invalid UTF-8, over-cap lines, or a recognized usage shape
  that failed conversion make the file incomplete. An incomplete file is not
  recorded as empty or settled. Confirmed-empty is a separate durable state.
- Pi accepts both current nested `type=message` assistant usage and legacy
  `message_end` usage. Provider response time has the same precedence in both
  shapes; a later envelope write time cannot move usage across an hour. Every
  exact duplicate response-id occurrence is reconciled by a canonical instant
  plus usage digest, including multiple pairs under one reused id; unmatched
  divergent cross-shape reuse makes the whole file retryable. Numeric
  timestamps are accepted at either the message or top level, and current
  nested user content arrays feed the safe title fallback.
- Claude desktop titles are optional enrichment. CLI sessions without a title
  and desktop-only titles without a CLI session id are complete no-ops, not
  corrupt files. True parse/read/type failures retain prior durable titles,
  keep the manifest red, and retry with the same bounded backoff. Recovery
  starts a fresh transcript generation before completeness can publish.
- Fingerprints, nullable activity clocks, and file entity sets are finalized
  after enrichment, privacy policy, account cutoff, and historical replay
  combination. The manifest is emitted only from committed final fingerprints;
  census completeness/loss evidence remains in top-level status counts.
  `snapshot_manifest:v2` is an exact seven-field
  `semantic_activity_window`: membership uses the accepted entity's latest
  usage/session activity clock in `[window_start, window_end)`, never local file
  mtime, path, or `collected_at`. An explicit null witness keeps metadata-only
  entities uploadable but outside the semantic manifest. Missing or malformed
  persisted activity forces reparse/rebuild instead of silent omission. Its
  length-prefixed, sorted-distinct fold is
  pinned by `fixtures/snapshot-audit/snapshot-manifest-v2-golden.json` against
  the backend Python implementation; the shared metadata-only golden pins the
  upload-versus-manifest boundary.

## Durable state and quarantine

Scan index and upload progress use v2-only paths so an old overlapping daemon
cannot overwrite them. Both are process-locked, generation-CAS-written through
an fsynced temporary file, atomically renamed, and followed by directory fsync.
Upload-progress load/save/clear all take the same lock. Clear compares the
loaded generation and destination, renames to a tombstone, fsyncs the parent,
then removes it; a stale daemon cannot delete a winner. Invalid progress is
moved to a unique corrupt sibling under the lock and rebuilt without overwriting
the evidence. Syntactically valid corrupt activity clocks and quarantine retry
deadlines beyond the bounded horizon are treated the same way.

Per-entity permanent rejection is quarantine, not a source fence. The exact
fingerprint is checkpointed locally with a content-free witness over collector,
parser, scan identity, snapshot schema, and ACK contract, and excluded from the
server-agreement manifest. A changed source produces a new fingerprint;
changing repair code or a contract component automatically retries even the
same semantic fingerprint. Unchanged backend-only failures retry on a
deterministically staggered 6–12 hour clock, at most one 20-entity retry page per
cycle; far-future or backward-clock-corrupted deadlines cannot fence forever.
Before upload, quarantine revisions absent from the authoritative current index
are pruned and checkpointed, so one long-lived poison item cannot make the
hash-only progress ledger grow with every unrelated historical revision.
Partial commits advance only files whose complete entity set is accepted or
quarantined; an unsettled repair retry preserves the older mismatched witness so
the following cycle retries again.

## Batch/ACK contract

Every request declares `snapshot_entity_ack:v1`. A capable response must be an
exact, disjoint partition of the request into accepted, unchanged, permanently
rejected, or conflict occurrences. ACK rows carry `occurrence_count`, and direct
duplicate ACK validation remains multiset-exact. The uploader coalesces byte-
equal same-fingerprint bodies to one representative; divergent bodies under one
fingerprint are corruption and are quarantined while healthy siblings continue.
Partial, short, foreign, zero-count, over-counted, or cross-classified ACKs
settle nothing. Legacy 422 handling is full-batch/no-write followed by bounded
singleton isolation; timeouts retain bounded splits. Items are capped at 128
KiB, exact uncompressed requests at 4 MiB, and conservative serialized-item
packing keeps pages below that request boundary before exact preflight.

Conflicts remain unsettled. Challenge/head-token field names and adoption rules
must be frozen with the backend contract before the daemon adds them. A future
challenge may be adopted only from a fresh complete scan, never from a partial
census or cached body.

## Reproducible revision witness

The exact legacy `snapshot_revision:v1` fields remain for old-backend
tolerance. Additive `snapshot_revision:v2` is SHA-256 over RFC 8785 canonical
JSON with this explicit material:

- contract/canonicalization, source and source session id;
- parser and scan-identity versions;
- opened/source-file fingerprint;
- stable lifecycle fields (`status` and source activity timestamps);
- stable provenance (`collector`, input-token scope, state token/archive
  evidence), excluding mutable `source_file_count`;
- upload policy and all post-policy semantic component hashes.

It excludes `collected_at`, snapshot/content/revision hashes, semantic envelope,
challenge/base fields, and source-wide inventory. Identical content observed on
a later scan therefore keeps the same revision; parser, component, lifecycle,
or opened-file witness changes move it. The v3 semantic-envelope golden carries
all 60 canonical bodies and digests for cross-language reproduction.

## Registration continuity rollout

Registration always declares capability `prior_device_credential_v1`. A first
registration sends no prior proof; a re-registration sends the currently
persisted device id and secret together or fails locally. New response fields
are optional for old-backend tolerance and rotation claims are consistency-
checked before persistence. Device binding and returned secret are installed
under the existing identity reservation, with rollback of the previous secret
if the binding write fails.

Rollout order is strict: release and upgrade the public daemon first; only then
may the backend reject missing/partial proof and enforce active-installation
continuity. This checkpoint does not perform either rollout step.
