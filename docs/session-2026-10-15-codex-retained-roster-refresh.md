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
- A new unreadable first record holds the page. After it is removed, the next
  page proceeds before the retry deadline.

## Not changed / residual

- Candidates held by an incomplete inventory go to the generation residue.
  They are selected again on their next change, or at the next walk. A held
  session that goes quiet can wait for the walk. Re-queuing them needs a bound
  so a persistent hold cannot prevent the re-walk, and is left to that code's
  owner.
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
