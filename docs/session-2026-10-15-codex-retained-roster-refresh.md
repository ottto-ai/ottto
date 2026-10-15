# Codex sessions stopped updating while a census was retained

On an observed Mac, a running Codex session stopped updating locally and in the
web app for about an hour at a time. Its rollout and the Codex state database
kept growing. Codex uploads arrived only at roughly hourly intervals. In
between, a Codex page ran every few minutes and parsed nothing
(`scanned_files: 0`). After 15 minutes without a scanned activity, the active
list dropped the session.

## Cause

A Codex generation whose discovery finished but whose census did not complete
is kept. A red one (any retryable problem) waits for its bounded retry, which
backs off to once an hour. A green one with an incomplete state or sidecar
census waits until it completes, possibly indefinitely. The generation's
rollout roster and directory witness were frozen at the walk. Every later page
uses them as ownership evidence:

- Each page with a candidate inventories the first record of every roster file.
- A selected file outside the roster made that inventory incomplete.
- An incomplete inventory holds every candidate on the page.

So one rollout created after the walk (a new chat, a subagent, a slot home)
held every existing session's update on every page until the next walk. On the
observed Mac new rollouts appeared every few minutes, so almost every page was
held. Seen live: after a new rollout appeared, the next page parsed nothing,
the alias-parser unreadable count rose by one and ownership-incomplete grew by
the page's candidate count.

The observed generation was red because each walk recorded one `OpenRead`
failure. The likely source is the sampled reader: it refuses bytes beyond the
length captured when the read starts, so a live rollout appended while it is
read fails with "acquisition exceeds stable source". Without a full re-walk,
that one failure kept the census red for an hour.

## Fix

- **Retained roster refresh.** Before each page of a retained Codex generation,
  directories whose witness moved since the walk are re-listed, one level
  deep:
  - Rollouts that appeared join the roster and the census candidates, exactly
    as the walk adds them.
  - Rollouts that left drop out of the roster.
  - New subdirectories go through the ordinary bounded walk.
  - The directory's witness is replaced only when the same metadata brackets
    the listing.
  - A listing the walk would mark red (a symlink, an unreadable entry, a change
    during the listing) refreshes nothing. That directory keeps its old witness
    and the existing holds apply.

  Unchanged directories cost one `lstat` each. Files already in the roster are
  not selected again. The retry deadline and its backoff are unchanged.
- **Held candidates come back when their blocker moves.** A page whose header
  inventory is incomplete holds every candidate, including sessions whose own
  ownership is fine. Those candidates used to leave the queue and wait for
  their next write or the next walk, so a valid session that went quiet while
  held stayed stale. The page now records, in the generation's durable
  residue:
  - the held candidates;
  - each refused first record with its metadata witness;
  - each held candidate outside the roster with its witness;
  - whether the walk still had directories open.

  Before each page, one `lstat` per recorded path checks that evidence. When
  it has moved (a refused record changed, was replaced, is gone or left the
  roster, an unlisted
  candidate joined the roster, or the walk finished), the held candidates
  still in the roster are queued once more. They meet the same inventory and
  ownership gates. If the evidence still proves nothing, the page is held and
  recorded again. Unmoved evidence queues nothing, so an unresolved hold
  re-reads no transcript. An inventory that hit its population or read bound,
  or had no stable census, records nothing and waits for the walk, as before.
  The record is part of the persisted traversal, so it survives a restart, and
  a new walk replaces it.
- **Header read retry.** A first-record read that races an append is repeated
  up to three times. Each attempt still has to observe an unchanged object, and
  each abandoned attempt is charged to the inventory read budget.
- **Read failure log.** A transcript read failure now logs its static reader
  text. It never logs a path or content.

## Ownership is unchanged

Joining still requires the inventory, the stable directory census and the
capture, send and checkpoint validation. With an up-to-date roster, a new
physical segment of a settled session forms a group with it. The settled
segment is never sent alone as a replacement.

An unreadable first record still holds the whole page: its owner is unknown, so
it may belong to any selected session. The hold lasts only while the record
stays unreadable.

## Tests

The new tests use a red generation kept behind its retry deadline:

- A changed known rollout and a new unrelated rollout are both admitted on the
  same page. Only those two files are parsed, and the retry deadline does not
  move.
- A new rollout with no watcher hint is still admitted. An idle page parses
  nothing. An admitted file is not read again.
- A new segment of a settled session is joined or held, never sent alone,
  while an unrelated new rollout on the page is admitted.
- A new unreadable first record holds the page together with a valid unrelated
  rollout. An idle tick parses nothing, and the hold survives a serialize
  round trip. After the unreadable file is removed, the next tick admits the
  originally held session without any write or hint to it, before the retry
  deadline, and a later idle tick does not re-read it.
- The unreadable record is rewritten but still unreadable: the page is held
  again and nothing is emitted. An idle tick parses nothing. It is then
  repaired in place: the next tick admits both the held session and the
  repaired one, with no write to the held file and no walk.

## Not changed / residual

- A hold whose evidence never moves stays held until the held file changes or
  the next walk: an unreadable first record may belong to any session.
- A refused first record that keeps changing (a file still being written)
  releases the hold on each tick. That costs one header inventory per tick, as
  any hinted page already does, but no transcript read while it stays
  unreadable.
- An inventory past its population or read bound is still released only by
  the walk.
- An append during a transcript read still counts as a retryable problem. The
  census stays red until a walk sees no such race, but freshness no longer
  depends on that walk.
- Rollouts held for ownership (unresolved fork or parent lineage) are re-parsed
  whenever they change, as on a healthy census. Their hold is unchanged.

## Verify after release

On a Mac with a red Codex census, between walks:

- Codex `native_collection_page` records show `scanned_files` above zero when
  rollouts changed.
- Receipts arrive within one page of a session's activity, not hourly.
- The fenced census `losses.discovered` grows as rollouts appear.
- The `transcript read failed` log text names the recurring `OpenRead` cause.
  Its source is still an inference from the code (an append during the
  sampled read), not observed. Every reader error behind that line is a fixed
  string or an operating-system I/O error; none carries a path or content.
