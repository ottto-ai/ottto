# Context composition counts copied history once

A forked Codex rollout and a resumed or forked Claude transcript start with
records copied from an earlier session. Composition counted those records as
new context in the copy too, and counted the earlier session's turns as the
copy's requests, so entered tokens, events and residency were inflated.

Codex: the first `session_meta` header decides, using the session sink's fork
markers. `subagent_history_start_ordinal` marks records with a lower ordinal
as copied. Created threads and `history_base` (paginated) forks keep inherited
history outside the file, so every record is local. A legacy subagent fork's
own records start at its trigger turn. A legacy user fork, or a legacy
subagent fork without a trigger turn, has no boundary in the file and is
skipped whole.

Claude: copied records keep their uuids and timestamps, so the file created
first owns them. Within one workspace, files are parsed in creation-time order
(modification time where creation time is unavailable), so an original that
keeps working after a fork still owns its records. Record uuids are remembered
as 64-bit hashes (about 8 bytes per record, freed after the workspace). A
record whose uuid was already counted is copied. A transcript made only of
copied records is skipped.

A copied record adds no event, entered tokens, top-file count or session
total. It still adds residency for the copying session's own requests, because
those requests resend it. Copied turns are not counted as requests. For a
plain resume the result is the same whichever file is parsed first.

The harvest metrics line adds `excluded_not_fresh` (sessions skipped whole)
and `copied_history` (sessions with a trimmed copied part). Wire fields are
unchanged; a daily bucket that holds only copied residency is now sent with
zero events. `COMPOSITION_PARSER_VERSION` moves to v3, so every cached
workspace rebuilds once on its next cycle (at most 12 per source, within the
existing caps).

Local read-only survey (one heavy Mac, 14 days): 8 Codex rollouts are
ordinal subagent forks with copied prefixes; 6 are paginated forks and 28
created threads with local history only; none needed exclusion. 52 of 6,366
Claude transcripts repeat records of another transcript, about 5% of record
bytes.

A workspace whose sessions are all excluded yields an empty report, which is
not uploaded, so an earlier upload for it stays until replaced. That is the
existing behavior for any empty report; no local session needed exclusion.

Validation: focused tests run in CI (no local cargo run for this change).
