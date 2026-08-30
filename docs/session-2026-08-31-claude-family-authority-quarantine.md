# Claude family authority quarantine

Claude reported-usage enrichment is fail closed: a snapshot may declare
`session_exclusive_reported_usage:v1` only when the daemon reconstructs the
complete root/subagent family against exact transcript, API-request, and trace
ownership fingerprints.

Before this repair, enrichment cleared that declaration on every parsed Claude
snapshot before attempting reconstruction. If a family that had already been
proven could not reconstruct a later transcript revision, the daemon uploaded
the weaker body. The backend correctly refused it as
`usage_accounting_authority_downgrade`, but retrying the unchanged body could
never settle it.

The daemon now distinguishes that state from backend poison quarantine:

- The last exact proven family witness remains durable. The current pending
  request/occurrence proof is retained rather than cleared.
- A content-free family quarantine binds the proven-witness digest to every
  known member's exact scan fingerprint. The weaker revision is removed at the
  network boundary and is never counted as accepted or backend-quarantined.
- Retry uses a deterministic six-to-twelve-hour family deadline. The durable
  budget is four failed complete-family reconstructions: the initial failure
  plus three retries. This gives transient sidecar lag three recovery windows
  and bounds an unchanged family's non-terminal lifetime to 18-36 hours.
- A changed member revision, changed membership set, or mismatched witness
  bypasses the deadline and reparses every current family member, including
  unchanged quarantined siblings outside the ordinary bounded page. The retry
  record is updated only after that full-family parse.
- Healthy unrelated entities continue to upload. The held family remains
  pending and makes the source census non-terminal only while retry budget
  remains. Exhaustion transitions durably to the explicit
  `unproven_terminal` disposition: weaker bodies remain held, the retained
  authority witness remains intact, and every affected entity is reported in
  status as `last_ownership_incomplete_file_count`.
- `last_ownership_incomplete_file_count` is the existing schema-v5,
  backend-admitted ownership-loss counter introduced by the ottto#379 lineage
  (`65d79c9e`). Terminal loss is added after the filesystem census, matching
  v6 loss-accounting semantics: `last_census_complete` can be true alongside a
  nonzero named loss instead of deadlocking or silently dropping the family.
- On successful reconstruction, the authoritative revision uploads normally,
  the local family quarantine clears, and the terminal census may complete.

The backend authority fence is unchanged and remains the final protection
against an authority downgrade.
