# Codex session-exclusive usage collection

Codex legacy full/recent forks physically copy parent rollout records into the
child JSONL. The snapshot parser previously treated that copied prefix as child
work, duplicating parent tokens, requests, activity, compactions, latency, and
derived cost across every fork.

## Collector contract

- `subagent_history_start_ordinal` is authoritative when present. Ordinals
  before the boundary are inherited context; the boundary and later records
  belong to the child. Missing, gapped, or incomplete ordinal sequences fail
  closed.
- Legacy subagent forks exclude records until the first provider-native
  `inter_agent_communication_metadata` record with `trigger_turn=true`.
- No-history subagents and ordinary paginated files whose inherited prefix
  lives behind `history_base` treat their physical local records as owned.
  `thread_source=agent_created_thread` is stricter as of v36: neither
  `history_base` nor `subagent_history_start_ordinal` authorizes ownership;
  that shape requires the complete created-thread native witness.
- Legacy ordinary user forks and new-id resumes use a persisted, content-free
  parent prepass. A non-empty ordered turn/usage-signature prefix must match a
  complete parent ledger; the first divergent signature begins child-owned
  work. Missing, truncated, zero-match, zero-owned, or ambiguous parent
  evidence fails closed. The index retains at most 256 requested parent ids
  and 4,096 signatures per parent, reparses only requested unchanged parents,
  and binds each ledger to the exact opened parent rollout. Authorization waits
  for a healthy complete frozen filesystem census proving one unique physical
  parent across all Codex rollouts, including files outside the usage lookback,
  then revalidates that object immediately after the child parse. Changed,
  duplicated, or concurrently replaced parent evidence stays retryable and
  cannot enter the shared or persisted ledger. Expected parent-prepass work
  requests a clean next generation without becoming a permanent lossy-parser
  error or unhealthy backoff. Fork-of-fork graph identity remains independent
  of usage ownership. Same-id resumes have no fork boundary and remain one
  additive session.
- Unresolved forks do not fall through to the inclusive
  `state_5.sqlite.threads.tokens_used` fallback. That block is durable across
  incremental scan calls, and state-only fallback waits for a complete rollout
  census so a later candidate page cannot race it.
- Usage before the first authoritative `session_meta`, a legacy child bootstrap
  suffix beyond the bounded 64-record proof window, and a native ordinal file
  that ends exactly before its first child-owned record all remain retryable and
  fail closed.
- The first physical `session_meta` remains the identity/lineage envelope.
  Copied parent headers cannot overwrite child identity.
- Owned response usage prefers `last_token_usage`. Repeated cumulative
  checkpoints are idempotent; a non-monotonic cumulative begins a new additive
  epoch instead of deleting already accepted work. Older records without last
  usage use the reset-safe cumulative fallback.
- Proven snapshots emit
  `usage_accounting_contract="session_exclusive_reported_usage:v1"`. This
  means every provider-reported usage occurrence in the rollout is owned by
  this session; it does not claim that hidden, failed, or provider-account
  requests absent from the rollout are an exhaustive billing ledger. The field
  is omitted when ownership proof is unavailable. Its optional presence
  participates in the usage-accounting semantic hash; absence retains the
  legacy hash shape.

Parser and scan identity advance to `codex_jsonl:v29`. Historical replay
revision `codex_session_exclusive_usage:v2` deliberately revisits settled Codex
history once.

## Economics coverage boundary

A privacy-safe comparison against the recent local Codex debug trace found no
Claude-like successful auxiliary model-request class: every non-warmup
`/responses` request carried a thread and turn, while model-catalog requests
used `/models`. However, failed/retried transport attempts do not always produce
rollout usage, and the debug database is rotating and best-effort. Rollouts also
carry no stable provider request id with which to prove an exact occurrence
union. Therefore the v1 marker is intentionally limited to rollout-reported
usage, not exhaustive account billing; debug traces remain selector diagnostics
only.

## Sanitized North Star QA targets

Local content-free token checkpoints for the four suspicious legacy children
produce these exclusive totals. Cache-write is zero because these recorded
rollouts expose no cache-write field. Cost is the deterministic standard,
short-context GPT-5.6 Sol estimate at $5/M fresh input, $0.50/M cache reads,
$6.25/M cache writes, and $30/M output; reasoning output is a subset of output.

| Child suffix | Requests | Input | Cache read | Cache write | Output | Reasoning subset | Expected cost |
|---|---:|---:|---:|---:|---:|---:|---:|
| `b36be5` | 156 | 20,681,755 | 20,253,696 | 0 | 36,892 | 13,359 | $13.373903 |
| `b1402b` | 160 | 20,218,739 | 19,746,816 | 0 | 41,624 | 15,267 | $13.481743 |
| `9417c9` | 41 | 4,949,500 | 4,690,688 | 0 | 12,852 | 4,580 | $4.024964 |
| `904208` | 159 | 19,828,892 | 19,484,928 | 0 | 36,574 | 13,138 | $12.559504 |

If a response was independently proven priority/fast by the existing Codex
turn trace, its row prices at that tier instead; the token targets remain
unchanged.

The generated regression fixture contains 15,359 inherited positive response
checkpoints followed by 156 owned checkpoints and asserts only the owned totals
above. It contains no prompts, tool arguments, paths, or transcript prose.

## Validation

- `cargo check -p ottto-service`
- `cargo test -p ottto-service codex_ -- --nocapture`
- `cargo test -p ottto-service` (1,357 tests passed; 2 ignored)
- `scripts/public_repo_manifest_check.sh`
- `scripts/public_repo_contract_check.sh`
