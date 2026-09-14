# Claude progressive response provider-time ordering

## Problem

Claude/Fable can append an earlier partial observation for one provider
response after a later terminal observation. The local collector previously
folded repeated `(message.id, requestId)` records in physical file order and
required prompt counters to be invariant. A valid response therefore looked
like a usage regression, became non-progressing residue, and held that session
out of local snapshot emission.

The production witness was content-free: the same response identity had a
later provider timestamp with populated input/cache/output counters followed in
the file by an earlier provider timestamp whose progressive counters were still
mostly zero. No prompt, response, command, path, URL, or reasoning content was
needed to diagnose the failure.

## Resolution

`ClaudeResponseObservation` now retains response-local records until the whole
transcript has been read. Resolution then:

1. orders valid RFC 3339 provider timestamps chronologically when every record
   in the response supplies valid provider time, otherwise preserving physical
   order for the full response;
2. orders same-instant states by their cumulative usage tuple and collapses a
   comparable monotonic chain to that instant's terminal state;
3. uses physical occurrence sequence only after provider time and usage are
   equal, while refusing incomparable states at the same provider instant;
4. accepts monotonic population of every cumulative usage counter;
5. still refuses any true chronological counter regression or conflicting
   model, request, selector, effort, or tool identity; and
6. derives the short/long context bucket from the resolved terminal effective
   input, avoiding a false selector conflict between an early zero-valued
   record and the populated terminal record.

The Claude parser provenance advances from `claude_code_jsonl:v34` to `v35`.
The scan-identity version stays unchanged: files that hit this failure were
never checkpointed as complete and are retried naturally, while already valid
unchanged sessions do not need a general semantic rescan. The context-curve
derivation key includes parser provenance, so its existing bounded replay
generation advances without a new wire contract or scheduler.

## Safety boundaries

- Copied or inherited prefixes remain excluded. A session without complete
  owned-start proof still emits `coverage=ownership_unresolved`, with no owned
  curve points or compaction boundaries.
- A quarantined Claude family keeps its two-open identity fence. The family
  scoping added previously continues to let unrelated healthy roots advance.
- Exact equal-time repeats and comparable progressive states remain harmless,
  but incomparable same-time usage and true chronological regressions remain
  fail-closed retryable residue.
- Response-local buffering is capped at 4,096 observations per response and
  65,536 observations per file. Overflow retains no additional records and
  marks the file as retryable usage loss instead of growing heap without bound.
- No wire payload fields or caps, accepted-log capability, backend schema,
  release metadata, or upload privacy allowlist changed.
- This commit does not publish or release the daemon.

## Validation

- focused provider-order, regression, equal-time conflict, copied-prefix, and
  quarantine-family tests;
- full `ottto-service` library tests;
- Rust formatting and clippy with warnings denied;
- canonical context-curve and semantic-envelope fixtures regenerated and
  revalidated;
- public manifest, secret-scan, and surface gates;
- isolated local snapshot audit against the affected transcript family, using
  only content-free counters and deleting the audit copy afterward. Parser v35
  emitted all 92 family files captured by the final 2026-09-14 audit with zero
  dropped usage records; known root
  `ffa3b701-5f3c-4a9d-91ad-f8cce11ae2c3` emitted 3,976 requests, 19
  compactions, 93,819 first-turn tokens, 966,930 peak tokens, and 695,792
  last-turn tokens. Its exact owned curve
  correctly remains `ownership_unresolved` pending independent copied-prefix
  ownership proof.

## Review disposition

The independent standard review used both allowed discovery passes and found
two P2 availability defects. The first pass found that mixed valid/missing
timestamps could move a stamped terminal record ahead of an unstamped partial;
the resolver now falls back to physical order for that entire response and a
focused mixed-time test covers it. The second pass found that retaining every
duplicate observation could amplify a 256 MiB transcript into unbounded heap;
the response/file caps and fail-closed overflow test cover that boundary.

A third model-review attempt was refused by the review tool's 2/2 family
budget. Risk closeout therefore relies on the two findings being concretely
reproduced and fixed, their focused regression tests, the complete service
library suite, clippy with warnings denied, the public-surface gates, and the
isolated real-family scanner canary. Residual risk is limited to unseen Claude
writer orderings; missing chronology stays on the legacy physical-order path,
while contradictions and buffer overflow remain retryable rather than being
silently accepted.
