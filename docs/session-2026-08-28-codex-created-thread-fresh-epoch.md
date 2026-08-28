# 2026-08-28 — Codex created-thread fresh-epoch ownership

## Outcome

Codex historical replay can now derive provider-created child rollouts that
start a fresh cumulative-usage epoch. These files previously stayed
uncommittable even though every usage checkpoint was numeric, timestamped, and
provider-reported.

The observed stable census failure contained 1,201 recognized usage drops in
five files. The same five files produced the five zero-snapshot usage-evidence
diagnostics; those are file-level witnesses for the same loss family, not five
additional usage records.

## Root cause

Codex has emitted two physical layouts for `agent_created_thread` rollouts:

- a copied parent prefix followed by child-owned records; and
- an all-local child file whose first cumulative usage equals that response's
  `last_token_usage`.

The v33 ownership parser handled only the copied-prefix layout. When the first
child turn differed from the parent's first signature, it classified the whole
file as an ambiguous fork. The generic loss accounting then counted every
valid positive usage checkpoint in the file as a recognized drop and prevented
the source census from becoming healthy.

This was an ownership-parser gap, not malformed usage, missing timestamps,
transport ordering, replay-ledger settlement, or safe unusable data.

## Ownership proof

The parser still requires the exact provider-owned child-to-parent edge from
the local state sidecar and a complete parent ownership ledger bound to the
opened parent rollout. Before the first ownership signature, it retains at most
64 records in memory.

If the child starts by matching the parent, the existing copied-prefix proof is
unchanged. If it diverges before any parent signature matches, the parser waits
for the first positive usage checkpoint and admits the buffered child records
only when:

`total_token_usage == last_token_usage`

That equality is a bounded provider-native receipt that the child's cumulative
counter began with this response, so no physical predecessor usage exists in
the file. A missing last-response record, a zero checkpoint, a divergent
cumulative total, an absent or conflicting sidecar edge, an incomplete parent
ledger, or a buffer overflow still fails closed.

## Replay decision

This repair changes historical derivation: affected files move from no entity
to a session-exclusive usage entity. `CODEX_SNAPSHOT_PARSER_VERSION` therefore
moves to `codex_jsonl:v34`, and the explicit one-shot replay revision moves to
`codex_session_exclusive_usage:v4`. Parser-version drift alone still does not
replay machines that already completed an older revision.

The change unblocks the Ingestion North Star Codex census and ships in the next
stable release.
