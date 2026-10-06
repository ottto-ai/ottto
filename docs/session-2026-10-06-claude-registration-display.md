# Claude registration display supplement

The local service can supplement an already activity-qualified Claude Code root
session's Mac display from `~/.claude/sessions/<pid>.json`. Acquisition runs on
the existing reconciliation path, behind the Claude status adapter. It does not
add a scheduler, background poll, session ledger or provider call.

The reader enumerates at most 256 directory entries, accepts at most 16 JSON
registrations, reads at most 8 KiB per file (128 KiB total), and uses one bounded
`ps` call (4 KiB output, existing one-second timeout). The process query uses C
locale and UTC, matching the provider's `procStart` witness. Missing, dead,
reused-PID or unverifiable processes supply no supplement. An incomplete census
fails closed; malformed, oversized, nonregular and symlink files are ignored
without discarding independently healthy records. Directory-relative no-follow
opens pin acquisition to the selected directory. Conflicting live projections
for one session ID suppress that ID only. Noninteractive or foreign PID-domain
registrations cannot supplement root sessions.

Only an exact root session ID joins. The latest registration is re-read; an
adoption replaces the old logical ID rather than inheriting a process's old
conversation. Subagents keep their own labels. Existing intentional or
provenance-unknown names remain authoritative. A registration with explicit
user/auto/derived name provenance can replace a generated first-prompt, AI title
or summary only when the existing title proves the title policy allowed it.
Unknown/peer/hook/collision provenance does not override an existing title.
Names use the existing display-title validator. Missing surface information can
be filled from supported Desktop, CLI or SDK entrypoints; an existing surface
wins. Private peer transport, paths, raw whole objects, credentials, accounts,
launcher identity and cumulative cost state are not retained.

Allowlisted name/entrypoint provenance and the process-witness basis stay in the
existing local active-session cache. They are not new upload fields. Uploaded
snapshots, canonical fingerprints, usage hours, cost, attribution and account
identity are unchanged. Active qualification still requires newly advanced,
recent transcript activity; process presence does not create an active row or
refresh activity. Web titles/search/history remain unchanged because the current
upload title-source enum cannot truthfully represent registration provenance.

Session dates remain distinct: transcript minimum/maximum events are an activity
span; native original Desktop creation is a separate existing witness; process
registration `startedAt` can precede adoption and is never conversation creation.
`updatedAt`, status transitions, missing files, crashes and process exits cannot
prove logical conversation completion. Claude end remains unavailable. The local
active row omits invalid, pre-epoch or inverted start values instead of exposing
an invalid activity date. Valid RFC3339 offsets are compared as instants.

Synthetic native tests cover adoption, stale/crashed records, PID reuse, live
conflicts, file safety and budgets, privacy-policy and intentional-name
precedence, independent subagents, timezone/resume activity dates, and unchanged
uploaded snapshots/accounting. The native process test queries only its own test
process; it neither opens operator provider state nor invokes the provider.
