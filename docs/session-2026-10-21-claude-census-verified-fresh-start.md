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
- `settlement_rearmed`: a stranded candidate (unsettled telemetry, unchanged
  file) spent its one settlement re-arm. It verifies like a candidate, and
  this revision is never re-armed for settlement again.
- `verified`: a complete, accepted census saw the root's own family complete
  and no duplicate. Verification re-arms the root's file once so the next body
  carries its numbers.
- `emitted`: the server holds a body with numbers for this revision: an
  `accepted` entity in the upload ACK, or a plain `unchanged` one (the
  identical body is already stored). An `unchanged` entity carrying the
  `unchanged_basis` key (`usage_identical`, `dominated_by_head` or any other
  value) was not stored. That, a refusal, a held or ledger-suppressed body,
  or no ACK leaves the witness `verified`, and nothing is offered again until
  the file changes. This keeps a contract-less body dominated by a proven
  server head from looping.
- `reparse_owed`: an emitted revision was re-parsed and refused for a
  transient reason, so its body went out without numbers. The next accepted
  census re-arms it once and moves it back to `verified`.
- `refused`: a telemetry verdict (a proven or quarantined family) or a
  telemetry row that contradicts this root. Never re-armed.
- `revoked`: a duplicate request (persisted owner, visibly shared pending, a
  census `SharesHash`, or the same root id under two indexed paths). Any
  `verified`, `reparse_owed` or `emitted` revision is re-armed once so its
  next body uploads without numbers: the server may hold numbers whose ACK
  this process never saw (a lost response, a ledger-suppressed retry, a lost
  index save). A parse that replaces or removes such a witness from another
  path of the same root re-arms that path the same way.

Every re-arm is spent by its transition. A `verified` revision is never
re-armed again, so repeated closed and open windows cannot replay a file. A
revocation also re-arms a root whose body was admitted in the same fold.

## Verification

A census window is accepted only by the census disjointness predicate
(`claude_census_disjointness_complete`, owned by the census work). Until that
predicate exists, the window check is a stub that accepts nothing, so nothing
verifies. A candidate verifies only when, in a complete census:

- the predicate is true, the owner map is within its budget, and the fold
  carries no native completion or selected fallback and its reports are
  healthy;
- the root's own census status is `Disjoint` (only possible while the
  predicate is true);
- its own census record is `Exact` or `Empty` from a source-verified parse;
  unverified or tail records never back a positive verdict;
- its telemetry is settled in this pass;
- its own family is complete with a non-empty request set and no duplicate.

A `SharesHash` status revokes whenever it is seen, even while the predicate
is false. `Unobserved` changes nothing for an emitted root and does not
verify a candidate. A candidate whose telemetry is not settled spends no
verification re-arm. An unchanged file carries no current-window evidence,
so a candidate gets one settlement attempt, spent by its first pass that
holds the contract-5 permit, is funded, and whose census accepts its window
with a `Disjoint`, source-verified own record. A stranded candidate (not
parsed in that window) is re-armed once; a candidate parsed in that window
that still did not verify spends the attempt without a re-arm, since a
re-parse cannot change the outcome. Never under the stub, never by time, and
once per exact revision (file fingerprint, which includes path, size and
modification time, plus the parser and 2c revision; so a rename is a new
binding). The spent attempt is the `settlement_rearmed` state. The full
selected save commits it with the cleared file fingerprint, a failed save
reloads the unspent candidate, and a restart neither repeats nor clears it.
A partial (shed) checkpoint does not pair them yet: it keeps the cleared
fingerprint as re-parse debt but the witness only moves with a settled key,
so a crash after it can earn one more attempt. A stranded candidate's
telemetry is checked only by its re-parse, so a re-parse whose telemetry
does not settle spends the attempt with no gain.

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

The witness binds to the source fingerprint and to
`CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` plus a 2c revision, not to the census
derivation alone, so a parser upgrade withholds until re-verified.

Admission is sticky while the duplicate census fence is closed: an admitted
revision keeps its scalars, but any known duplicate still wins. Admitted items
rebuild first/peak/last from all owned occurrences, and compactions count only
after the first owned response. Cache observations, the context curve,
`session_start`, account attribution, naming inputs and request identity
refusals are unchanged, and `transcript_ownership_complete` and the duplicate
census are not affected by this path.

Switching the feature off re-arms every `verified`, `reparse_owed` or
`emitted` revision once, so its next body uploads without numbers, and drops
every witness.

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
- Every 2c set is funded by one aggregate charge to the fold's native
  reservation before any of it is allocated: the settled-telemetry root set
  and the admitted root set (one full tree node per root plus its key bytes),
  and the upload views of offered and stored fingerprints (one node per
  admissible-root item each, borrowing the item's fingerprint, so no clone).
  The fold part is returned after the fold; the upload part stays with the
  same completion, which owns the reservation through the upload settlement,
  and is returned after it. A fold without a native reservation, or without
  funds, settles no telemetry, so nothing new is verified, admitted or
  re-armed for settlement and the strict body stays; withdrawal, revocation
  and ACK handling still run. If the admitted items exceed the funded count,
  no view is built and the witnesses stay `verified`.
- Everything is empty and never walked while off.
- No audit schema change, no scan or parser version bump, no wire field.

## Limits and open items

- Copy detection relies on the file birth time. A copy whose birth predates
  its records by at most 60 s and whose ids were rewritten is not detected.
- A duplicate always revokes, including for the original session when a later
  copy shares its requests.
- Admission and refusal counts are not yet in the local audit. In-memory
  values exist for verifications made while an `IdentityIncomplete` or
  `Lossy` record exists, for census windows over the owner budget, for
  settlement re-arms, and for admitted bodies the server did not apply.
- Over the owner budget the census map is incomplete: the predicate stays
  false (no new verification) and the case is counted, but a new duplicate
  of an emitted root can go unseen until a later in-budget complete census,
  which then withholds it.
- A body the server holds but whose ACK was lost (a crash before the index
  save, a lost response, a ledger-suppressed retry) stays `verified`; only a
  later revocation or switch-off withdraws it, at the cost of one extra parse
  for a revision that may never have emitted.
- A revocation found in the same fold that admitted a body withdraws it on
  the next pass: that body still uploads its numbers once.
- A candidate needs current-window evidence to verify, so a candidate whose
  file does not change after its census pass (for example a backfill parsed
  without the contract-5 permit, or any candidate parsed while the predicate
  is the stub) waits for its next parse.
- The copy check by shared hashes catches a copy whose source is still
  present only when the source shows the copied request ids.
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
- Activation gates: the real H3 predicate; a real-route positive control for
  the subagent parent charge (the #588 guard refuses the actual Claude
  subagent parse shape, which a regression test pins); and an owner charge
  disposition for ordinary folds, because a fold that carries a native
  reservation also carries a native completion, which is not verification
  eligible.
- Kill path after activation: release a build with the switch set back to
  false, never a rollback to an older binary. The false switch re-arms every
  admissible revision once so its next body withdraws the numbers, then drops
  the map. An older binary ignores and drops the field on save without
  withdrawing anything, and an earlier 2c build drops `settlement_rearmed`
  witnesses, so a re-upgrade could earn a second settlement attempt.
