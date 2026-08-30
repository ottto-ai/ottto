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
- Retry is bounded to a deterministic six-to-twelve-hour family deadline. A
  changed member revision or mismatched witness bypasses the deadline; a due
  pass reparses every member so reconstruction sees one complete family.
- Healthy unrelated entities continue to upload. The held family remains
  pending, makes the source census non-terminal, and preserves the existing
  clean-follow-up rule until a complete pass restores authority.
- On successful reconstruction, the authoritative revision uploads normally,
  the local family quarantine clears, and the terminal census may complete.

The backend authority fence is unchanged and remains the final protection
against an authority downgrade.
