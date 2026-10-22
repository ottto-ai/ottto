# Claude context numbers from the transcript file (design E)

## Problem

Claude Code's first, peak and last context and compaction count were uploaded
only when the strict rule owned a session: a provider-proven start and no
unresolved duplicate request. The global duplicate fence is closed on most
passes of a large corpus, so nearly every session uploaded empty scalars. The
member waiver (`session-2026-10-20-claude-posture-member-waiver.md`) admitted
only sessions whose own telemetry proved every request.

A transcript's copied records (Desktop Rewind, a resume or fork copy, a
restored file) keep their original timestamps. The file itself therefore shows
what was copied: a record written before the file existed was not written by
this session.

## Rule

- A record in a ROOT transcript whose timestamp is more than 60 s before the
  file's birth (`created()` of the opened file) is tagged `copied_by_birth`.
  The tag is context-only: usage, cost, request identity, account evidence and
  contract 5 rows are unchanged.
- Subagent transcripts are exempt only when the path (`subagents/agent-*`,
  the family census rule; the scanner refuses symlinks) names a child and the
  records themselves carry `isSidechain: true`. The path alone keys the item
  as a child, so a root transcript copied under `subagents/` is not exempt.
  The exemption covers the birth rule only: the telemetry tripwire below
  applies to subagent files too (SOURCE condition 2). The `forkedFrom` early
  return is unchanged.
- Admission never mints or changes a usage contract.
- First, peak and last come from untagged responses, including id-less ones.
  Compactions count only untagged boundaries after the first own response
  (`response_count_before > first_own_sequence`, 0-based). Tagged boundaries
  are dropped by timestamp, so a second copied block after own turns is
  dropped too. NULL is never 0.
- The parser keeps today's values and a separate inline own-only tally. The
  fold ships the tally on every branch that cannot rebuild from complete
  request occurrences, so there is one source for first/peak/last (R2/R3).
  The strict branch with complete identity still rebuilds from owned
  occurrences; an item the parser did not read is cleared there instead of
  shipping raw values.

### Admission

The waiver and the closed-fence clear are replaced. An item the strict rule
does not own is admitted with basis `file_birth_rule` unless one of these
withholds the whole tuple (and reduces session start to the client version):

| Reason | When |
|---|---|
| `unknown_birth` | the file system gave no birth, a birth at or before 2020-01-01T00:00:00Z (0, the epoch, a reset clock), or the item was not read by the transcript parser |
| `untimed_record` | a root response or boundary has no usable timestamp |
| `all_copied` | every response was copied: nothing was measured here |
| `multi_file` | the session id has a second transcript file (below) |
| `tripwire` | loaded telemetry contradicts the tags, now or earlier for this file version (below) |
| `evidence_bound` | this root's own requests exceed the pending-occurrence cap (250,000), whatever else is on the page; or the page's telemetry lookup could not be sized under that cap (fail closed) |

Curves and cache observations still read the strict rule; curves stay off (R10).

### Session start

Session start stays under its existing gate: an item the strict rule does not
own keeps the client version only, admitted or not.

### Same session id in two folders

When a session id has a second transcript path in this page or the scan
index, the files are not merged in the fold. Every file of that id withholds
the WHOLE tuple (first, peak, last, compaction count and timestamps) and
session start keeps the client version only (SESSION Context, review F1). The
server keeps one row per session and the newest upload wins, so shipping each
file's own peak, last or count would show an arbitrary file's partial numbers
as the session's. The `multi_file` counter stays. SOURCE condition 4 describes
a merge (de-duplicate, first from the earliest born file, max peak, latest
last, compactions once, compatible accounts only); a real merge is a later
slice. About 4 of 11,432 files in the parity sweep are affected, all slot
moves.

### Telemetry tripwire

API and trace rows loaded for this page only veto; they never fill a number.
Besides the paired, healthy rows used for usage proof, the API rows of roots
whose trace sidecar is missing or whose pair is incomplete are moved aside
(not cloned) before the strict read narrows to paired roots, and are passed to
the fold for the veto only. They are already in memory at that point; holding
them through the fold is the only added cost.
A session is withheld when a kept request is reported under another root, a
tagged request is reported under this root, or one request has several
reporting roots. An API row whose trace row is missing still names its owner
(SI ruling). Missing telemetry is not a contradiction. The check runs on every
fold against the rows loaded for that page, so a row that arrives late
withholds on the next fold that loads it; the cleared scalars change the
semantic fingerprint and upload as a normal revision.

Which rows a fold loads depends on which sessions are on the page (review F2).
So that admit and withhold cannot alternate with page makeup, a veto is
remembered in memory for the vetoed file version (in-process path hash plus
source file fingerprint, which includes size, mtime and parser version): the
same bytes stay withheld on later folds that did not load the row, and the
file is checked afresh only when its fingerprint changes. The memory is not
persisted and holds at most 4,096 files; past that every later admission
withholds until restart (fail closed). After a daemon restart the memory is
empty: a vetoed file whose row is not loaded on its first fold is admitted
again until a fold loads the row, and that fold withholds and remembers it.

The evidence bound is per root, never per page: a root is withheld only when
its own requests exceed the existing pending cap (250,000). Other roots on the
page are still checked, however many there are, so a big page (the one-time
history backfill, a closed-fence full re-arm) judges every session exactly as
a small page does. No sidecar is read for this.

## Local counts

`ClaudeLocalEvidenceStats` carries `context_file_birth`, printed on its own
line (`local snapshot sync: claude context basis counts=...`) after the Claude
local-evidence counts line. It is skipped in that struct's serialized form, so
the existing counts line and snapshot-audit are unchanged. Nothing is
uploaded. Fields: tagged records, sessions by basis (`proof`,
`file_birth_rule`, telemetry-confirmed),
sessions withheld by reason (tripwire withholds remembered from an earlier
fold also counted on their own), `partially_pre_birth` files,
`remembered_veto_overflowed` (the 4,096-file veto memory is full, so every
later file-birth admission withholds until restart), and the same per Claude Code version (sixteen
versions in first-seen order, then `other`; malformed versions count as
`unknown`), plus sessions held by the family demotion quarantine (R7: the hold
is unchanged and its scalars wait with the body), plus contract-less bodies
carrying scalars split by whether a local proven family witness exists (R9,
below).

Resource withholds (SOURCE Amendment 7): `evidence_bound` sessions and a full
veto memory withhold for a resource limit, not for content. Every pass counts
them. The first fold of the daemon process that has either raises one local
alarm on the service log (`ottto-service: local_resources` record, stage
`claude_context_resource_withhold`, with the evidence-bound count and the
overflow flag only; no path, id, wire field or UI). A per-pass accessor,
`ClaudeContextFileBirthCounts::resource_withheld()`, reports the same signal;
the one-time history backfill (#677) stops on it. That stop rule lands with
#677, not here. A test-only seam lowers the per-root bound so the count, the
alarm and the accessor are tested without a 250,000-request fixture.

## Known undercounts and residuals (disclosed)

- An owned compaction before the first own response is not counted (a fork
  followed by an immediate `/compact`). This is the SESSION rule: compactions
  count only after the first own request. Timed boundaries are classified by
  timestamp, so this can only undercount.
- A restored, synced or slot-moved file that keeps growing is admitted with
  post-birth numbers only (SOURCE Amendment 5, accepted residual): its records
  older than the new birth are tagged as copied, and only the file's new turns
  are measured. First, peak and last then cover only the activity since the
  file's birth. "First" is the first prompt after the copy or restore; for a
  restore that is not the session's original first prompt. Peak can be
  under-counted; nothing is ever over-counted from copied records.
  Exception: a compaction whose boundary is in copied history but whose
  summary was written after the session's own first request can count once
  (an over-count of at most one per such compaction; test
  `compaction_pairs_across_the_copy_line_count_once` case 2). Token and
  prompt-size numbers are unaffected. The file
  withholds only when every response predates the birth (`all_copied`). Where
  the original file is also present (the same session id in two files), the
  whole-tuple `multi_file` withhold wins. These files are counted locally as
  `partially_pre_birth` (the earliest kept record follows excluded pre-birth
  records; a Rewind copy that then grew counts too), in the same bounded
  per-version table.

- Resource withholds clear a session that was admitted before (SOURCE
  Amendment 7, option C accepted). Keeping the last emitted numbers would mean
  holding whole bodies, usage included, so the scalars are cleared instead in
  three cases: one session family with more than 250,000 requests of its own
  (the largest on the M4 is about 60,000), a telemetry lookup that cannot be
  sliced under the cap (no real page reaches it), and a full 4,096-file veto
  memory (review-678c R1; until restart). All three are counted, alarmed once
  per process and stop the backfill (above).

## Upload stability

`last_turn_context_tokens` is not part of the semantic fingerprint, so a change
in last alone does not upload (R8, pinned by a test).

R9, SOURCE Amendment 2 option (i), with no new persisted field:

- Local proven family witness present: a Claude body without the v1 contract
  is held by the existing family demotion quarantine, so no contract-less
  scalar change goes out against a proven head (condition 6). Counted as
  `contractless_scalars_witness_present_session_count`.
- Witness gone: the daemon cannot know the server head and may offer the body
  once per change (`contractless_scalars_witness_missing_session_count`).
  Before backend #11882 the server refuses it and the existing permanent
  refusal path holds that exact body. After #11882 it answers `unchanged` with
  `unchanged_basis` (`usage_identical` or `dominated_by_head`): the server did
  not store the body. The uploader then records nothing as stored (no accepted
  fingerprint, body witness or cache state) and holds the exact body in the
  existing quarantine ledger as unproven-terminal without a refusal record, so
  it is never re-offered until the body changes and never marked emitted. A
  content-free log line counts these ACKs (`local snapshot unchanged not
  stored`). The field is read from the ACK only. Either way the server head
  and money are unchanged; money's B1 + P2 later remove the constraint.
  A held body never blocks a later, different body of the same session: any
  local change is a new fingerprint and is offered (pinned by a test, in the
  same cycle and after the hold is carried through the index). The hold
  counters stay local diagnostics, not customer-facing (SESSION Context).
- Rollout note: once backend R11 or money's B1 + P2 let the server store these
  posture-only bodies, held bodies are not offered again until they change.
  That rollout needs a one-time re-arm of the held bodies.

## Resource bounds

The per-file birth and tally are inline scalars (no heap) on the accumulator
and the item; the retained tail copy carries them unchanged. They are charged
by `size_of` in the existing parser and retry-retention budgets. Nothing is
added per record, so #667's compact response records are unchanged.

Fold scratch has a hard bound and fails closed. The owners lookup (request id
hash to owning root) is built from the telemetry rows already loaded, in
request-hash partitions. Before it allocates, the rows are counted (a page with
at most 250,000 loaded rows is one partition; a bigger page gets twice the
needed partition count, doubled up to four times if hashes are skewed) so no
partition holds more than the 250,000 pending cap. One partition map is reused,
so the lookup never exceeds 250,000 entries (about 38 B each with B-tree slack,
at most about 9.5 MB) however large the page is. All rows of one request fall
in one partition, so the verdicts equal one page-wide lookup. Partitions that
cannot be sized refuse the page: every file-birth item on it withholds as
`evidence_bound`. Per item the fold keeps one path hash and one verdict (16 B);
per root on the page one `usize`. Nothing is kept per candidate request. A
typical page needs a few KB (estimated from the types; not measured, no local
build). The multi-file check holds one borrowed key and one hash per
Claude page item and reuses one string for the index walk. The veto memory is
process-lifetime, at most 4,096 entries of two `u64` (under 100 KB).

## Verification

Synthetic regressions through the real parser and fold: a Rewind-style copy
with a second copied block (own-only first/peak/last and compactions, session
start reduced to the version, money unchanged), a growing fresh file with
numbers on its first fold under an incomplete census, a late-born subagent
file, a root transcript copied under a subagent path, the same session id in
two folders and across two accounts, unknown birth and an unparsed item, an
all-copied file, a birth at or before 2020, a missing or invalid response or
boundary timestamp, the per-root evidence bound, a restored file that grows
(post-birth numbers, `partially_pre_birth`, and the `multi_file` withhold
when the original is present), both tripwire
contradictions, a contradiction in a later telemetry slice than the
root's confirmed requests, a late contradiction that stays withheld until the
file changes, the bounded veto memory failing closed (a resource withhold:
alarm once, accessor set), a root past the seam-lowered evidence bound
(counted on every pass, alarm once, accessor set), an API row
without its trace row (in the fold, and through the pipeline with only an API
sidecar), parity with the strict rule for a telemetry-proven session, id-less
responses on both branches, the R8 fingerprint pin, the per-version bound
(twenty versions: sixteen rows plus `other`), the tripwire on a subagent file,
the R9 counters (witness missing on a fresh file, witness present in the
seven-entity demotion cohort), an `unchanged` ACK with `usage_identical` or
`dominated_by_head` that is held, not marked emitted, and not re-sent (with a
plain `unchanged` control), and a held body followed by local growth whose
new body is offered and accepted.
One capture-ON test runs the real scan and local evidence pipeline with the
request identity permit, with the duplicate fence open and closed, and checks
that every body differs from the withheld control only in context scalars,
session start and the derived fingerprint.
