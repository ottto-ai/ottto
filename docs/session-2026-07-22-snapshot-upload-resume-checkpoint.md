# 2026-07-22 — resumable local snapshot uploads

## Outcome

Local snapshot scans now checkpoint every accepted upload page and resume from
the remaining semantic snapshot fingerprints after a timeout, validation
failure, daemon restart, or machine restart. One invalid snapshot no longer
causes every previously accepted page in the same scan to be replayed.

## Root cause

The incremental scanner built the complete next scan index in memory, uploaded
changed snapshots in 20-item pages, and saved the index only after every page
succeeded. Delaying the index commit was necessary for correctness, but it also
meant a late failure discarded all delivery progress. On the next five-minute
cycle the daemon parsed and uploaded the complete change set again, even though
the backend had already accepted most pages idempotently.

The failure became visible when a new policy-scoped attribution-label index
required a historical scan. Many pages succeeded before one item-level payload
validation failure; transient request timeouts produced the same replay shape.

## Design

- Each policy-scoped scan index has a neighboring upload-progress file.
- The file contains only schema version, a one-way relay-device namespace hash,
  and accepted 64-character semantic snapshot fingerprints. It contains no raw
  account/device identifier, prompt, response, title, path, session id, usage
  payload, attribution label, or credential material. Legacy or
  destination-mismatched progress is discarded so an account switch cannot
  inherit another destination's accepted set.
- The daemon atomically replaces that file after each accepted page.
- A later cycle or restarted daemon filters already accepted fingerprints
  before constructing requests.
- Scan indexes and historical-bootstrap completion are destination-scoped. A
  relay-device/account switch therefore starts a fresh delivery cursor, and the
  daemon revalidates the relay binding before committing the final cursor.
- Accepted hashes absent from the current policy/cutoff-filtered scan are
  pruned before upload, bounding checkpoint size even when one invalid session
  blocks completion across many revisions.
- Item-specific `400`/`422` failures are bisected so valid siblings can be
  accepted and checkpointed. Timeout-heavy multi-item pages use the same
  bounded split. Adaptive work is capped at 6 splits and 12 child requests per
  cycle—enough to isolate one poison item from a 20-item page while keeping a
  broad outage or contract mismatch low and bounded.
- The final scan index and historical-bootstrap marker are saved before the
  progress file is removed. A crash at any earlier point leaves enough
  hash-only state to resume without data loss.
- Local checkpoint failures and accepted-count response mismatches are typed as
  local-state and backend-response failures, never transport outages; their
  diagnostics contain no payload or local path.

The backend wire schema and idempotent snapshot fingerprint contract are
unchanged.

## Validation

- `cargo test -p ottto-service snapshot_sync::tests`
- Focused regression coverage proves 20-item page bounds, partial success plus
  persistent timeout and restart, item-specific `422` isolation plus restart,
  account-switch invalidation, bounded broad-drift retries, and policy-scoped
  checkpoint naming. It also covers destination-scoped backfill/cursor safety,
  concurrent relay switching, typed local/backend-response failures, and
  permanent-poison checkpoint pruning.
- `cargo fmt --check`
