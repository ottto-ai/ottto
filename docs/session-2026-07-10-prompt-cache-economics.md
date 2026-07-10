# Local prompt-cache economics capture

Date: 2026-07-10

## Purpose

Preserve the local evidence needed to distinguish a gross cache-read discount
from net cache value. Backend acceptance must deploy before this runtime because
the snapshot wire models use `extra="forbid"`.

## Collector behavior

- Claude Code remains the reference path for exact cache-read and 5-minute /
  1-hour cache-write token capture. Duplicate content-block records continue to
  deduplicate by response identity.
- Pi now treats `usage.cacheWrite1h` as the one-hour subset of flat
  `usage.cacheWrite`, sends the residual to the generic/5-minute bucket, and
  preserves `usage.cost` total, input, output, cache-read, and cache-write
  dimensions on every model/hour row plus the snapshot aggregate.
- Codex continues to capture cached reads. The parser now accepts forward
  `cache_write_tokens` / `cacheWriteTokens` aliases, but current local Codex
  JSONL does not expose writes. Downstream GPT-5.6+ net-value coverage therefore
  remains partial rather than assuming writes are zero.

Dollar values are accumulated as integer pico-dollars and serialized as decimal
strings, so top-level, model, and hourly bucket totals remain byte-stable and
reconcile under the backend `Decimal` validator. Missing, null, negative, or
invalid provider fields stay missing instead of becoming explicit zeroes. If
one Pi message omits all cost evidence, the session aggregate does not claim a
complete provider-reported total.

## Validation

- Pi multi-message component-cost aggregation and zero dimensions.
- Pi partial/invalid component coverage and missing-cost aggregation.
- Pi flat total plus `cacheWrite1h` split.
- Codex forward cache-write alias.
- Existing Claude duplicate, cumulative, and TTL-split suite.
- Daemon/backend `extra="forbid"` field allowlist.

Final gates: 589 library tests plus 3 binary tests pass in a clean PATH, with
zero failures. `cargo fmt --check` and all-target `cargo clippy -D warnings`
also pass.

Parser versions move to `codex_jsonl:v18` and `pi_jsonl:v8` so already indexed
sessions are re-evaluated with the corrected semantics.
