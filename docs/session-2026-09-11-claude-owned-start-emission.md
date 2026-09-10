# Claude owned-start snapshot emission

## Gap

A read-only Context Intelligence audit on 2026-09-10 found Claude Code context
curves staying `ownership_unresolved` even when local ownership evidence was
available. Two daemon paths lost that evidence before a corrective snapshot
could be uploaded:

- the loopback relay decoded `claude_code.api_request` logs only from OTLP JSON,
  while `claude_code.llm_request` traces already accepted JSON and protobuf;
- a transcript `forkedFrom.sessionId` plus `forkedFrom.messageUuid` marker was
  reduced to an in-memory owned-start flag. If that file appeared before the
  terminal page of a bounded census, the unresolved page was uploaded and the
  unchanged file was never selected again after duplicate-request validation.

The request join also treated optional enrichment attributes such as client
request id, event sequence, app version, and reported cost as ownership
requirements. The ownership contract needs the provider request id shared by
the API log and LLM trace plus the trace agent lineage; optional enrichment
must not suppress that proof.

## Fix

The relay now reduces both JSON and protobuf API-request logs through the same
privacy-safe allowlist. The request ledger joins API and trace rows by exact
provider request id, still rejects conflicting client request ids when both are
present, and keeps reported cost absent when the event does not supply it.

The scan index now retains a local-only marker fingerprint and its complete
duplicate-request census witness. A marker seen on an earlier page is re-armed
once after the census proves it safe. The unchanged transcript can then emit a
`complete` or `sampled` curve on a later bounded page without waiting to land on
the terminal page by chance. Changed transcripts must pass a new complete
census, and missing or conflicting evidence remains unresolved.

The Claude curve ownership derivation advances to
`claude_owned_request_start_proof:v2`. This rearms one bounded historical replay
for already-indexed transcripts. The replay uses the existing cursor and entity
acknowledgement machinery; an interrupted corrective upload remains retryable.

## Compatibility and privacy

The snapshot wire is unchanged. Provider marker proof continues to use the
existing `session_context_curve:v1` coverage; only the local derivation revision
used to schedule replay advances. Paired request proof continues to use
`usage_accounting_contract=session_exclusive_reported_usage:v1`. No enum value,
schema version, prompt, response, tool payload, path, or raw account identifier
was added.

Synthetic tests cover protobuf API-log reduction, a fork marker on an earlier
bounded page, a non-forked session with the minimal paired request proof, and a
missing pair that stays truthfully unresolved.
