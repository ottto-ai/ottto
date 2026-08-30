# Replay Scan And Manifest Window Separation

## Problem

Historical local-snapshot replay asks the scanner for `u64::MAX`; the scanner
correctly clamps that request to its local 730-day safety ceiling. The terminal
collector receipt then reused the scanner's effective width for
`snapshot_manifest:v2`. The backend accepts semantic manifest windows of at
most 183 days, so a completed replay could upload its entities successfully and
then fail its terminal `snapshot_status` request with HTTP 422.

The same status path serves Codex, Claude Code, and Pi. Redacted RC logs showed
non-retryable `snapshot_status` 4xx failures for all three sources, including
Pi. Pi also had separate snapshot-batch 422 evidence (semantic-envelope and
`client_report` compatibility failures); those are different contracts and are
not changed here.

## Contract

Scanning coverage and receipt evidence now have distinct meanings:

- `scan_request_window_days` may be `u64::MAX` during replay. The scanner keeps
  its existing 730-day local cap, traversal cursor, discovered/scanned counts,
  cap-hit state, and completion accounting.
- Every receipt width comes only from a successfully decoded server activity
  hint and must be in `0..=183`. Terminal paths reacquire that hint at the
  report boundary, after scanning/uploading, instead of retaining the pre-scan
  value. Missing, malformed, or wider hints fail closed without manufacturing
  a fallback width.
- `snapshot_manifest:v2` is recomputed from the durable scan index using the
  report-time hint's exact half-open semantic activity window ending at the
  frozen census time. Entities scanned for replay but active outside that
  window are not counted or folded into the manifest.
- Cycle-start and periodic heartbeat receipts fetch the current hint too. They
  carry a cached manifest only when its width exactly matches that hint;
  otherwise they withdraw the stale local witness and remain manifest-free.
- Zero is an explicit manifest-free terminal tombstone, not an error. It
  withdraws the cached census, reports `last_backfill_window_days=0` with
  `last_census_complete=false`, and keeps later heartbeats manifest-free. A
  cap-hit/incomplete census follows the same manifest-withdrawal discipline.

No prompts, outputs, paths, titles, commands, URLs, or other local content are
added to the wire. Snapshot body, parser, semantic-envelope, scan-identity,
replay-generation, and ACK contracts are unchanged.

## Verification

Focused tests cover:

- a mid-replay `183 -> 30` policy change that rebuilds the terminal manifest at
  30 days without narrowing the wide scan;
- preserved 730-day scanner coverage with report-time terminal evidence;
- first-contact cycle-start, heartbeat, and terminal receipts under a 30-day
  policy;
- a zero-width terminal tombstone followed by manifest-free heartbeats;
- every terminal inventory path swept across 1, 30, 90, and 183-day hints;
- semantic exclusion of replay-only old entities;
- complete and cap-hit/incomplete scans;
- absent, malformed, oversized, and `u64::MAX` hint rejection;
- Codex, Claude Code, and Pi parity;
- a server-contract fixture that returns HTTP 422 for the former 730-day
  manifest and accepts the corrected 183-day manifest.

This change prepares a daemon candidate only. It does not publish a release,
start replay, or mutate production state.
