# Cache observation `next_unavailable` carries no next slot

The cache detector set `status: next_unavailable` when an affected request had
a following request that was not comparable (model, effort, configuration,
compaction, ordering, or prompt-size boundary), but it still attached that
request as `immediate_next`. The `session_cache_observations:v1` contract
reserves `immediate_next` for `complete` rows: `awaiting_next` and
`next_unavailable` must omit it. Ingest rejected the whole snapshot item with
HTTP 422 ("cache observation without next cannot contain immediate_next"), and
the rejection repeated deterministically on every retry of that session.

The detector now attaches `immediate_next` only when the next request is a
comparable recovery witness, so the wire satisfies
`status == "complete" ⇔ immediate_next present`. Status selection, event
identity, and previous/baseline/episode slots are unchanged. Already accepted
heads never contained the rejected shape, so the next complete patch replaces
the session's cache state normally.

The defect dates from the detector's introduction. It surfaced more often in
0.1.144 release-candidate QA because the active Codex session contained such a
boundary; the per-file effective projection adoption API is not activated in
production and does not change this path.

A focused detector test failed before the fix and passes after it; the full
`ottto-service` library suite passed.
