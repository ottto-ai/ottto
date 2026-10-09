# Claude own-request producer integration readiness

Public draft #512 is reconciled with main at
`506176b81b2e6184e90a2eac8cabad3ae398d63a`, including the zero event-clock
normalization and API sidecar decode reuse. The merge conflict in snapshot tests
retains both own-request-account and giant-row test discovery. The generated
export inventory is regenerated from tracked files.

The qualification module and its dedicated tests remain byte-identical to the
previous reviewed producer at `2b727f485016b9cb95620f3640f717a6b1475787`.
The shared enrichment path retains original creator evidence before enrichment,
then runs effort, strict usage/trace reconciliation, and own-request
qualification in that order. API decode reuse keeps strict health and
opened-object generation checks; it does not add a persisted proof.

This reconciliation makes no new producer behavior decision. Verification
covers the shared enrichment and retry cases, decode reuse, and the event-clock
normalization, with synthetic native fixtures only. Existing strict discovery
and focused verification apply to the prior producer; this mechanical merge
resolution does not claim a new model-review verdict. Validation results are
reported with the draft.

Release and emission remain held until the compatible receiver is deployed to
both web and worker. The deployment callback must precede emission evidence;
source checks establish neither live paired settlement nor installed acceptance.
