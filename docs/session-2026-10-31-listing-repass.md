# Re-listing pass: queue only stamp changes (all sources)

A kept generation whose first walk has finished re-lists its roots, metadata
only, at most every 30 minutes. Each in-window file's stamp (size or certified
Codex EOF fragment, mtime nanoseconds, file birth when known; never ctime) is
compared with its index entry. Unchanged files are marked seen and never
queued; changed or new files are queued as fresh data, and acquisition still
chooses Tail or Full. A new file joins the census like a hint does; growth of
an already observed file does not. The pass never starts a generation, never
re-arms, and records no walk problem or census count, so it can only delay a
generation's discovery, never complete it. Codex keeps its "no selection while
directories are pending" rule only for the first walk. A file the generation
already saw that has no index entry (a hold, an oversized file) has no stamp,
so the pass leaves it to its owner's floor. Under the opt-in Claude
terminal-off marker the pass does not start: terminal-off's own
identity-aware rediscovery is the listing there, and it upgrades a pending
re-listing root to its full walk.

New files no longer wait for the oversized/unhealthy 6-hour floor: the pass
finds them within about 30 minutes, without a hint or a restart.

Watcher hints for existing files go through the same stamp compare, so a
metadata-only event never queues an unchanged file. Owner re-enqueues (the
sampled-audit retry) bypass it.

Counters: `listing_generations` and `listing_changes_without_hint` in the
traversal counts. The 6-hour full sweep timer is removed: every successful
scan reset it and the 30-minute cold tier always came due first.

Out of scope: the first walk still enqueues every in-window file as a census
member; overflow handling and deletion proof are unchanged.
