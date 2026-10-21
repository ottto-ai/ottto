# One-time Claude Code history re-read through body-witness adoption

The daemon already has a per-file "re-read once" counter: the effective upload
body-witness revision (added 2026-10-02). Each indexed file whose stored
revision differs from the active one is selected once (`BodyWitnessAdoption`),
re-sends its body, and stores the new revision only when its upload settles. A
restart therefore resumes where it stopped and never re-reads a settled file.

This change uses that counter to re-read every Claude Code file once, so the
context numbers from the newer Claude parser fill in for existing history. It
does not change the parser version, the scan identity or the historical replay
generation, so no body identity, progress generation or census state is reset.

## Change

- `snapshot_sync.rs`: the constant `EFFECTIVE_UPLOAD_BODY_WITNESS_REVISION = 1`
  becomes `effective_upload_body_witness_revision(source)`: Claude Code `2`,
  Codex and Pi `1`. A plain constant bump would also re-read all Codex and Pi
  history. `prepare_sync_source` activates the per-source value.
- `snapshots.rs`: a page budget for adoption-only files. A file is
  adoption-only when its first selecting gate is `BodyWitnessAdoption` and the
  same decision without that gate is `Skip`. The first 2,000 such files per page
  (one page per sync cycle) are read. Later ones take the ordinary `Skip` path:
  the entry, its accepted body and its old revision stay unchanged, so a later
  page adopts them. Files selected for any other reason (new, changed, audit,
  authority quarantine retry, forced family, comparison target) are never
  deferred. A deferred file is skipped, not requeued, so the census still
  completes on time.
- The Claude parse-reason log line gains `body_witness_adoption_deferred=<n>`
  (count only). The `body_witness_adoption` count per page shows progress and
  falls to 0 when the re-read is done.

Authority-quarantined Claude families are unaffected: the quarantine gate runs
before the adoption gate, so a held family keeps its own bounded retry and is
neither adopted nor deferred while held. It adopts on its next retry.

## Release rule

Ship in the same release as the Claude context parser change it serves, and
after the C1a proof re-arm fix. Bump each source's revision once only; a second
bump re-reads all history again.

## Expected load (one Mac with a large history)

About 10,500 Claude files (14 GB). With the 2,000-file budget that is roughly
2.5 to 3 GB of reads per cycle, about 6,500 changed bodies plus up to about
4,000 unchanged re-sends that the server settles as unchanged, and 30 to 60
minutes in total if pages settle. If uploads do not settle, unstamped files are
selected again next cycle, which is the existing back-pressure.

## Proven families (server constraint)

The server permanently refuses a body without the
`session_exclusive_reported_usage:v1` contract when the session's accepted head
was proven. An adoption re-read goes through the same ownership fold as any
other read, so a family with a local usage witness that would now lose the
contract is held by the existing demotion quarantine: nothing is uploaded and
its files keep the old revision (held source files never adopt). The re-read
adds no new path to such a body. The remaining case is a session whose accepted
head was proven but whose local witness is gone: the daemon does not store the
accepted body-witness version, so it cannot tell. Any re-read reaches that case
today (re-arms, appends); this re-read only reaches more history. It is
refused once and the refused fingerprint is quarantined; money and identity on
the server are unchanged.

## Residuals

- A family's root and subagent files may adopt on different pages. Each file's
  body is independent, the same as when only one member changes.
- If 2,000 or more adoption-only files never settle, they keep using the budget
  and the rest wait. Nothing is lost; the log line shows the deferred count.

## Tests (CI)

- `claude_context_backfill_selects_every_root_and_subagent_once`
- `claude_context_backfill_resumes_after_restart_without_rereading_settled_files`
- `claude_context_backfill_leaves_codex_and_pi_unselected`
- `claude_context_backfill_spreads_adoption_only_files_over_pages`
- `claude_context_backfill_quarantined_family_keeps_its_own_retry_gate`
