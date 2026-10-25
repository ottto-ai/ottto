# 2026-10-22 - Codex context window paired with each context watermark (D1)

## What changed

- The Codex parser copies `model_context_window` from the SAME owned
  `token_count` record that sets each context watermark, and the snapshot item
  carries three new optional fields next to the watermarks:
  - `first_turn_context_window_tokens` (record that set `first_turn_context_tokens`);
  - `peak_context_fill_window_tokens` (record that set `peak_context_fill_tokens`);
  - `last_turn_context_window_tokens` (record that set `last_turn_context_tokens`).
- Capture is in `apply_codex_owned_line`, inside the existing positive-context
  branch, so the zero-usage record Codex writes at a compaction sets nothing,
  and fork-copied parent records (never owned) never set a window.
- Rules:
  - first: the window of the first counted record;
  - peak: the window of the first record that reached the peak; a later equal
    record only fills a window that is still missing and never replaces a known
    one (approved meaning rule for ties);
  - last: the window of the last counted record as-is, including none, so a
    later record without a window never keeps an older record's window;
  - a window is emitted only for Codex and only when its own watermark is
    emitted; never 0 (`codex_model_context_window` already drops 0).
- Parser version `codex_jsonl:v39` to `codex_jsonl:v40`. Scan identity stays
  `codex_jsonl:v34`: no revisit token, no replay, no new poll, no extra read.

## Identity and upload effects

- The windows are outside the `context_posture` semantic component, the
  fingerprint, the content hash, revision v1 and v2 and the body witness
  (`codex_context_windows_are_hash_witness_and_revision_neutral`). The pinned
  `context_posture` digest test is unchanged.
- Consequence (accepted by the ingest owner and disclosed here): a body whose ONLY change is a window settles as unchanged and
  is not re-uploaded. A window can change without a hashed change, for example
  a duplicate `token_count` with a different window, or a later equal-sized
  turn (the last-turn watermark is not hashed either). Such a session keeps the
  window last delivered until something hashed changes. No hash or revisit was
  added to repair this.
- What the parser bump moves (parser metadata, not the windows):
  - goldens that carry the parser version or a revision hash: semantic
    envelope golden (Codex cases: `parser_version`, `revision_hash`,
    `revision_v2_hash`), context curve golden and manifest, body witness ACK
    fixture, cache observation fixture and manifest, census residue status
    fixture. `content_hash` is unchanged in every regenerated fixture;
  - local caches scoped by the parser version: retained Tail reductions
    (`file_scope`), Codex group scope and tier replay receipts. The next
    change to each Codex rollout after the update is read Full once, then
    Tails again. Quarantine witnesses carry the parser version, so a
    quarantined Codex entity is retried once under the new parser;
  - an unchanged rollout is not selected (scan fingerprint excludes the parser
    version; unchanged-file control in
    `paged_singleton_carries_context_windows_like_unpaged_read`).
- Backend: the backend PR that accepts the three fields must be merged AND
  deployed to production before the Mac app release that carries this change
  is cut; an older backend drops the fields and those uploads lose the windows
  for good. The backend PR must also show whether the envelope's
  `revision_v2_parser_version` is in `content_hash`; if it is, every touched
  Codex session appends once after the release.

## Memory (DP7)

- Three `Option<u64>` on the accumulator and on `SnapshotItem`: inline
  scalars, no heap. The existing bounds charge them through the containing
  value's own size (`size_of_val` at the root, `size_of::<SnapshotItem>()` per
  retry slot), so retained copies, paged jobs and retry envelopes account for
  the growth with no cap change. The layout receipt (`D1_WINDOW_LAYOUT ...`)
  is printed by `codex_window_fields_inline_growth_and_worst_wire_bytes` on CI.
- Worst serialized growth per item: 166 bytes (three keys with `u64::MAX`),
  asserted exactly. The item wire budget already measures the real encoding
  and trims the curve first if an item would exceed it.

## Tests

- `snapshots/codex_context_window_tests.rs`: pairing, mid-session window
  change, missing window (last reset, no inheritance), zero window, peak ties
  (known first kept, missing first filled once, all missing), compaction
  zero-usage record and a positive record after a compaction, duplicate
  records, fork child owned-only, Claude and Pi emit no keys, hash / witness /
  revision neutrality, parser and scan identity constants, layout and worst
  wire bytes.
- `transcript_acquisition_tests.rs`:
  `sampled_native_codex_context_windows_match_full_read_across_tail_passes`
  (one record per real Tail pass, compared with a full re-read each pass).
- `codex_cursor_tests.rs`:
  `paged_singleton_carries_context_windows_like_unpaged_read` (paused and
  resumed cursor read equals the unpaged read; unchanged-file control).

## Archive

Windows are not archived (same as `last_turn_context_tokens`): an
archive replay restores the watermarks without their windows.
