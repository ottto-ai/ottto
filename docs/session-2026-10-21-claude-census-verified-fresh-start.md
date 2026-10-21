# Claude census-verified fresh start

Status: inactive. `CLAUDE_CENSUS_VERIFIED_FRESH_START_ENABLED` is `false`;
nothing below runs, reads, stats or persists anything until it is enabled.

## Problem

A new customer's backfilled Claude Code history has no Claude Code telemetry,
so no session can prove it owns its first request. The strict posture rule
then clears first/peak/last context and compaction scalars for every such
session. Most of them are ordinary fresh sessions; a minority are copies
(resume, fork, migration) whose leading responses belong to another session.

## Copy signature

At parse time a root transcript (never a subagent) is a candidate only when
its source bytes are verified, it yields exactly one session whose id is the
file stem, request identity is complete and every record passes the copy
signature against the file's birth time:

- a copy if any record is more than 60 s older than the file's birth;
- a copy if the first record with a `uuid` is more than 60 s older than the
  first timestamped record;
- a copy if the first record's session id is not the file stem, or any later
  record names another session.

Inputs the signature cannot judge fail closed as unknown: no readable birth
time, a birth or record in the future, an unparseable or missing timestamp,
or an untimed first `uuid` record. Many copies carry no fork marker, so the
absence of `forkedFrom` proves nothing.

## State machine

Each candidate root keeps one scalar witness in the scan index, keyed by root
session id: the exact source file fingerprint, the parser and derivation
revision, and a state.

- `candidate`: the signature passed. Appended bytes or a parser or derivation
  upgrade restart here, without numbers.
- `verified`: a complete, accepted census saw the root's own family complete
  and no duplicate. Verification re-arms the root's file once so the next body
  carries its numbers.
- `emitted`: posture built a body with numbers for this revision.
- `reparse_owed`: an emitted revision was re-parsed and refused for a
  transient reason, so its body went out without numbers. The next accepted
  census re-arms it once and moves it back to `verified`.
- `refused`: a telemetry verdict (a proven or quarantined family) or a
  telemetry row that contradicts this root. Never re-armed.
- `revoked`: a duplicate request (persisted owner, visibly shared pending, or
  the same root id under two indexed paths). An emitted revision is re-armed
  once so its next body uploads without numbers. A parse that replaces or
  removes an emitted witness from another path of the same root re-arms the
  emitted path the same way.

Every re-arm is spent by its transition. A `verified` revision is never
re-armed again, so repeated closed and open windows cannot replay a file.

A census window is accepted only when the census is complete, the duplicate
census is valid, the persisted fence is not overflowed, every indexed family
member was observed this window, reports are healthy and the fold does not
carry a native completion or a selected fallback. The predicate uses today's census composition: an
indexed member without usable request identity (for example an API-error-only
session) leaves the window unaccepted, so nothing verifies on that Mac.

## Admission

Posture admits a withheld root item for scalars only when the witness is
current (same fingerprint and revision) and in `verified`, `reparse_owed` or
`emitted`; the item has no contract, no owned start and no excluded prefix;
its request identity is complete; no request is a persisted or visible
duplicate; no telemetry row assigns one of its requests to another root,
another session or a subagent, and no report holds two rows for one of its
requests; reports are healthy; its own family pending is
current, valid and holds exactly its requests; and its telemetry is settled.
Telemetry is settled when both sidecars are confirmed absent by the existing
absence check or both were read completely. An unknown, unreadable, present
but unpaired sidecar is not absent. Rows that agree (this root, this session,
no agent) refuse nothing and add no authority.

Admission is sticky while the duplicate census fence is closed: an admitted
revision keeps its scalars, but any known duplicate still wins. Admitted items
rebuild first/peak/last from all owned occurrences, and compactions count only
after the first owned response. Cache observations, the context curve,
`session_start`, account attribution, naming inputs and request identity
refusals are unchanged, and `transcript_ownership_complete` and the duplicate
census are not affected by this path.

Switching the feature off re-arms every emitted revision once, so its next
body uploads without numbers, and drops every witness.

## Resource bounds

- The witness map holds at most 65,536 roots; each field is at most 512 bytes,
  and the tolerant decoder reads a non-object, over-bound map or malformed
  entry as not admitted.
- The native comparison budget charges each new witness insert and every
  selected restore before allocation; partial commits and per-key reverts
  restore the previous witness.
- The parse-time observation is a fixed-size scalar struct. The birth time
  costs one `symlink_metadata` call per root transcript that passed every
  other candidate check while enabled, and is used only if size and
  modification time still match.
- Fold evidence is built once per fold, only for page roots with an
  admissible witness, and is refused before allocation above the existing
  pending-occurrence cap. The census step walks the index once, borrowing its
  keys, and copies only its witnesses' own request hashes. Partial commits
  copy the witness map like the sibling census maps.
- Replacing an emitted witness walks the index once to re-arm another path
  of the same root. That happens only on that transition.
- The settled-telemetry root set holds only roots with an admissible witness,
  so it is bounded by the witness map.
- No audit schema change, no scan or parser version bump, no wire field.

## Limits and open items

- Copy detection relies on the file birth time. A copy whose birth predates
  its records by at most 60 s and whose ids were rewritten is not detected.
- A duplicate always revokes, including for the original session when a later
  copy shares its requests.
- Admission and refusal counts are not yet in the local audit.
- The settled-telemetry check reuses the existing absence check, which runs
  only when the pass may emit request identity. Without that permit no root
  settles, so an emitted root re-parsed in such a pass loses its numbers
  until the next accepted window.
- A root whose earlier upload carried a telemetry contract is refused only
  while its family witness or quarantine record remains.
- Foreign rows veto only when loaded: rows of a root whose sidecars are not
  paired and complete are not seen.
- A family with a confirmed-empty member never verifies.
- A historical replay clears every witness, so verification starts again.
- Enabling the feature, and any historical re-parse it implies, needs a
  separate decision.
