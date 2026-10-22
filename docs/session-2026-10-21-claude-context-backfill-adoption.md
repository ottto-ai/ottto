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
  (one page per sync cycle) are read, and at most 4 GiB of them by file size
  (`BODY_WITNESS_ADOPTION_ONLY_BYTES_PER_PAGE`; the first such file of a page is
  always admitted, so one oversized file still progresses alone). Both caps are
  per destination-scoped Claude index per cycle: a Mac with two Claude
  destinations reads up to twice as much. Later ones take the ordinary `Skip` path:
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

## Local re-emission exclusions (the one protected list)

Some sessions must not be re-sent by this re-read until their own recovery
settles them. This is the single protected-session list on the Mac:
`<support dir>/snapshots/claude_code-reemission-exclusions.txt` (mode 0600,
never in the repo, config or logs). SESSION (01a0f6e0) owns its content; the
Mac's runtime owner installs it; the daemon only reads it. MONEY P2 reuses this
reader (`snapshots/claude_reemission_exclusions.rs`) and this file; there is no
`claude-protected-entities.json`. Each line is the lowercase 64-hex SHA-256 of
one exact, full Claude `source_session_id`; blank and `#` lines are ignored; at
most 1,024 lines and 64 KiB. Families are listed by their ROOT digest, verified
against the index's path-derived ids (root = file stem, subagent =
`<root>_<stem>`). A member-only line still excludes its whole family: on each
load the list is closed over the index's roots (a listed subagent adds its root
digest), so no sibling's adoption can cancel a carry or re-arm the listed
member (StateMissing N1). Listing roots stays the install rule, as defence in
depth.

- Read once per Claude cycle, before the scan. Other sources never read it.
- The list fails closed (SOURCE Amendment 3):
  - Never installed (no file and no seen-marker): adoption-only files whose
    entity was first indexed before 2026-10-21T00:00:00Z are held: Skip, old
    stamp kept, no budget used, counted as `body_witness_adoption_held_no_list`.
    Newer ones proceed. The index keeps no first-indexed time, so the file's
    birth time from the opened descriptor stands in for it; a file born before
    the cutoff cannot have been indexed later than it was born, and an unknown
    birth time counts as old. On a Mac where no list is ever installed, history
    older than the cutoff is therefore not re-read.
  - Installed: the first well-formed read writes a 0600 seen-marker
    `claude_code-reemission-exclusions.seen` beside the list. An empty but
    well-formed file counts as installed. The marker is outside the rebuildable
    scan index, so a restart or an index rebuild keeps it. If the marker cannot
    be written, adoption pauses (`marker_unwritable`) until it is, so a later
    missing file is never mistaken for a list that was never installed.
  - Marker present and file missing: adoption pauses (budget 0, every
    adoption-only file deferred), the log line reports
    `body_witness_adoption_list=missing_after_install`, and each Claude cycle
    raises the local alarm record `ottto-service: local_resources
    {"stage":"claude_reemission_list_missing_after_install",...}` in the
    service log (`local_resource_diagnostics`, local only, no wire field).
    Restoring the file (empty is fine) resumes.
  - Unreadable, oversized or malformed: adoption pauses that cycle, as before.
  - Changed and new files are never held or paused by the list, and the hold
    applies to Claude Code only (Codex and Pi never load the list).
- A listed file is one whose family root id or own member id digest is in the
  list. When only the re-read selects it, it takes the ordinary Skip: no read,
  no upload, old stamp kept, no budget used. When its recovery settles, its line
  is removed (the file stays, possibly empty) and it adopts with no new
  revision. Deleting the file instead pauses the re-read.
- The parse-reason log line adds `body_witness_adoption_excluded=<n>`,
  `body_witness_adoption_held_no_list=<n>`,
  `body_witness_adoption_exclusions_invalid=<0|1>` and
  `body_witness_adoption_list=<not_installed|installed|missing_after_install|unreadable|marker_unwritable>`.
  No id, digest or path is logged.

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
- Reach: the re-read covers the files the index holds, which are the Claude
  files inside the ordinary receipt window (at most 183 days). Older files are
  not walked by ordinary cycles and their entries were already retired from the
  index, so they are not re-read. Reaching them needs a durable completion
  marker plus pacing and the exclusion list for files discovered as new; that
  is a separate decision. A listed file that ages out of the window before its
  line is removed is also not re-read.

## Tests (CI)

- `claude_context_backfill_selects_every_root_and_subagent_once`
- `claude_context_backfill_resumes_after_restart_without_rereading_settled_files`
- `claude_context_backfill_leaves_codex_and_pi_unselected` (Codex adoption is
  never held by the Claude list, whatever the file's age)
- `claude_context_backfill_spreads_adoption_only_files_over_pages`
- `claude_context_backfill_caps_adoption_only_bytes_per_page` (a byte budget
  below every file admits one per page; one that fits two but not three spreads
  six files over three pages)
- `stale_family_carry_tests::c1b_member_only_reemission_line_excludes_the_carried_family_root`
- `claude_context_backfill_quarantined_family_keeps_its_own_retry_gate`
- `claude_context_backfill_skips_sessions_on_the_local_reemission_list` (a
  member-only line keeps its whole family on the old stamp)
- `claude_context_backfill_holds_old_entities_until_the_list_is_installed`
- `claude_context_backfill_empty_list_installs_the_marker_and_adopts_old_entities`
- `claude_context_backfill_pauses_with_an_alarm_when_an_installed_list_goes_missing`
  (also restart and index rebuild keep the marker)
- `snapshots::claude_reemission_exclusions::tests` (never installed holds old
  and unknown only, empty list writes a 0600 marker and a later missing file
  pauses, an unwritable marker pauses until written, a listed member closes
  over its root, listed root or member, malformed and oversized lists never
  write the marker)
