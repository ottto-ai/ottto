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
- `receipt_window_days` comes only from the successfully decoded server
  activity hint and must be in `1..=183`. Missing, malformed, zero, or wider
  hints fail closed before scanning or reporting.
- `snapshot_manifest:v2` is recomputed from the durable scan index using the
  exact half-open semantic activity window ending at the frozen census time.
  Entities scanned for replay but active outside that window are not counted or
  folded into the manifest.
- Terminal and manifest-bearing heartbeat receipts report the same evidence
  width as the manifest. A cap-hit/incomplete census still withdraws the
  manifest and reports `last_census_complete=false`.

No prompts, outputs, paths, titles, commands, URLs, or other local content are
added to the wire. Snapshot body, parser, semantic-envelope, scan-identity,
replay-generation, and ACK contracts are unchanged.

## Verification

Focused tests cover:

- a 183-day negotiated hint with a `u64::MAX` replay request;
- preserved 730-day scanner coverage and 183-day terminal evidence accounting;
- semantic exclusion of replay-only old entities;
- complete and cap-hit/incomplete scans;
- absent, malformed, zero, oversized, and `u64::MAX` hint rejection;
- Codex, Claude Code, and Pi parity;
- a server-contract fixture that returns HTTP 422 for the former 730-day
  manifest and accepts the corrected 183-day manifest.

This change prepares a daemon candidate only. It does not publish a release,
start replay, or mutate production state.
