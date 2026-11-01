# Re-listing pass: queue only files that need a read (all sources)

A kept generation whose first walk has finished re-lists its roots, metadata
only, at most every 30 minutes. A listed file is queued when its stamp (size or
certified Codex EOF fragment, mtime nanoseconds, file birth when known; never
ctime) differs from its index entry, or when work is owed on it (empty
fingerprint, unverified sampled generation). Other reasons to read an unchanged
file were weighed by the generation's walk and keep their own schedulers and
the next walk, as on main; re-offering them every pass would re-read the same
files every 30 minutes. The check is stat-only; no file is opened. Acquisition
still chooses Tail or Full. An owed file whose stamp is unchanged is queued at
most once per file per 6 hours, measured from the start of the pass that
queued it (a bounded per-generation map, decoded leniently; past the bound the
oldest stamp is dropped and counted in `listing_owed_pace_evicted`, so a
re-queue can only come sooner). On the listing path and in the hint filter an
entry stored without mtime nanos compares at whole seconds.

A queued file joins the census by the watcher-hint rule: always for Claude and
Pi, and for Codex only if this generation has not observed it yet. A hint that
lands on a queued Claude/Pi non-member makes it a member. The pass never
starts a generation, never re-arms, and records no walk problem or census
count (the first walk owns them, including a too-wide directory), so it can
only delay a generation's discovery, never complete it. Codex selects nothing
while any directory is pending, re-listing included.

A file the generation already saw that has no index entry (a hold, an
oversized file) has no stamp, so the pass leaves it to its owner's floor. A
Codex file held by an incomplete header inventory is left to that hold's own
evidence-gated release. An
oversized file found by a re-pass records no debt and stays unobserved: debt
and loss count are recorded together by the first walk, and a later pass lists
the file again once it is readable.

Under the opt-in Claude terminal-off switch the pass does not start: its own
identity-aware rediscovery is the listing there, and it upgrades a pending
re-listing root to its full walk. This is a temporary exception deleted with
the switch (#1026).

New files no longer wait for the oversized/unhealthy 6-hour floor: the pass
finds them within about 30 minutes, without a hint or a restart.

A watcher hint is dropped only when its file is unchanged, not owed, not
account-held, and the ordinary candidate gate skips it at that stamp, so a
metadata-only event never queues a settled file and every other hint is queued
as on main. Owner re-enqueues (the sampled-audit retry) bypass it.

The pass supersedes the retained Codex roster's stat rotation, which is
deleted with its two counters (`codex_roster_refresh_visited`,
`codex_roster_growth_enqueued`; their persisted slots stay as decode-only
placeholders). Known Codex growth is now queued by the pass for all sources
alike; an mtime change is a stamp change, a ctime change never is. The
moved-directory roster refresh is unchanged.

Counters: `listing_generations`, `listing_changes_without_hint` (changed
files) and `listing_owed_requeued` (owed files with an unchanged stamp) in
the traversal counts. Codex growth the pass queues outside the census is not
added to the page's next-generation hint count, which counts watcher hints
only. Hint-less growth of a known Codex rollout is now found within 30 minutes
rather than on the next tick; watcher hints are unchanged. The 6-hour full sweep timer is removed: every successful
scan reset it and the 30-minute cold tier always came due first.

Out of scope: the first walk still enqueues every in-window file as a census
member; overflow handling and deletion proof are unchanged.
