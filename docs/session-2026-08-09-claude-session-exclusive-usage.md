# Claude session-exclusive usage collection

## Problem

Claude Code writes one assistant transcript record per response content block.
Task and Workflow subagents progressively increase `output_tokens` across rows
that share the same `(message.id, requestId)`. The prior first-row dedup counted
one request but retained an incomplete output total. Separately, top-level
session forks copy billed history into the new transcript, so treating every
usage row as child-owned double-counted the copied prefix.

## Collection contract

Claude usage is now deferred until the complete transcript has been read. Rows
with one response identity are resolved in transcript order:

- input, cache, model, effort, selector, request identity, and cost fields must
  remain compatible;
- cumulative output must be monotonic, and the terminal value is counted;
- selectors that appear on later content blocks are merged without allowing
  conflicting non-empty values;
- one resolved response contributes one request, one context observation, and
  one latency sample.

A conflict makes the file retryable through the existing recognized-usage loss
gate. Usage rows with neither response identifier retain the conservative
one-line/one-request fallback but cannot claim exclusive accounting proof.

Current Claude branch writers stamp copied records with
`forkedFrom.sessionId` and `forkedFrom.messageUuid`. Valid copied records return
before lifecycle, usage, activity, title, model, compaction, context, latency,
or artifact extraction. A malformed marker quarantines the file. This changes
usage ownership only; Task/Workflow parent, root, agent, depth, and workflow
facts are unchanged.

Historical Claude snapshots deliberately omit `usage_accounting_contract`.
Future evidence captured at `claude_api_request:v2` can claim
`session_exclusive_reported_usage:v1` only when a healthy enhanced-trace join
assigns every reported API occurrence to an existing filesystem family member
by exact request id. Transcript-owned responses preserve their exact cache TTL
split; auxiliary aggregate cache creation remains `unattributed_total_tokens`.
The trace owner never rewrites provider graph facts.

## Replay

Claude parser provenance advances to `claude_code_jsonl:v32`, scan identity to
`claude_code_jsonl:v26`, and the deliberate full replay revision to
`claude_reported_usage_union:v3`. The bounded replay revisits settled files so
historical snapshots clear any earlier accounting claim. Current capture
rebuilds usage only after a complete family census; earlier bounded pages are
reselected for the corrective pass.

## Validation

Rust fixtures cover:

- Task and Workflow child ownership without graph changes;
- progressive output and late selector resolution;
- conflicting/non-monotonic response quarantine;
- missing identifiers and conservative proof omission;
- explicit fork, zero-owned-work fork, and fork-of-fork exclusion;
- same-session resume and compaction continuity;
- exact transcript/API-log/trace request joins, including a root-owned
  API-only auxiliary occurrence and a trace-owned Task child occurrence;
- aggregate auxiliary cache creation routed to unattributed tokens while exact
  transcript cache-TTL buckets remain intact;
- unknown trace owners, malformed evidence, request-set gaps, and conflicting
  earlier bounded-page occurrences refusing accounting proof;
- privacy-safe persisted family witnesses, child-only corrective reparses, and
  unchanged parent/root/agent/depth/workflow graph facts;
- conditional wire/hash compatibility for the shared accounting field, plus
  proof omission across Task, Workflow, progressive, and explicit-fork cases.

The measured legacy-fork cross-file prefix ledger is intentionally deferred.
Until that bounded ownership index exists, historical top-level transcripts
without `forkedFrom` remain unproven rather than being assigned by heuristic.
