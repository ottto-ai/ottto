# Composition recovery without history replay

Only the current committed generation is retained. Manifest-last commits,
file and parent directory syncs, the install record, bounded full reads, and
whole-checkpoint identifier validation remain in place. A valid index can
reconcile a newer manifest after an interrupted final index write.

Bad or missing scope manifests, totals, or referenced shards cause a counted
quarantine. A durable marker precedes moving the scope's state aside. On the
next daily run every file in that scope restarts at its current end. Its new
upload includes optional `history_reset_at` (`YYYY-MM-DD`); the server must keep
existing daily rows. No historical transcript bytes are replayed. Healthy
scopes remain independent. A durable per-file restart flag survives partial
resets, absent files, failed opens, and interrupted index writes; only a
successful EOF checkpoint followed by its index write clears it. Those checkpoints cannot later trigger a
full reread after a rewrite. Unknown identifiers in a single checkpoint restart
only that checkpoint, preserving its aggregated history.

A missing or invalid index resets the agent's entire v2 state the same way.
The durable install witness distinguishes an installation from index loss.
Only the original installation can authorize initial history reads from zero
within the repair allowance. The witness is only checked for presence. If the
first run stops before saving its pins, the next run treats the agent as reset
(counted): files live at install are pinned at their current ends, and that
history is never measured. This is by design.

In a valid index, a file with no pin is classified by its birth time. Born at
or after the last saved scan started, it did not exist when those pins were
saved, so it is a new session. It is read from its start as new bytes, with no
restart counted. Born earlier, or with no recorded birth time, it starts at its
current end and counts as a checkpoint restart. A checkpoint committed by a
later run that stopped before saving its pins still wins. Reconciliation
re-creates the pin from that checkpoint, so reading goes on from its offset.
Pending scope resets and agent resets still force the current end.

A file rewritten in place (not cold) is still read again in full within the
daily repair budget, and that read replaces the file's own share. This is the
existing repair feature, counted in `bytes_repair`, not a recovery replay.

Daily reads check only the shards they load. An untouched shard keeps its
reference and is checked when a later read first loads it, before anything is
read. A due upload of an unchanged scope is built from its totals, whose hash
`load_scope` checks. A reset scope whose files have all disappeared commits
empty, so its reset never stays pending.

The worker acquires a nonblocking OS-backed exclusive lock before worktree
mapping or checking the saved run date. The lock lives until process exit and
survives scheduler death. Atomic writes use unique temporary filenames. The
parent bounds the entire stdin/write/wait/reply exchange to 35 minutes and keeps
the saved-day rule for later wakes. It waits on one channel with a timeout; a
dedicated thread reaps the worker. On timeout or failure the parent kills the
worker's process group and returns without joining, so the scheduler never
blocks on a stuck process. The exit status is judged before a failed input
write: a busy lock counts as `worker_lock_busy`. The worker has its own
watchdog: it exits after the same 35 minutes, so a hung orphan frees the lock.

Source metrics include `scopes_quarantined`, `files_quarantined`, `agent_resets`,
and `checkpoint_restarts`. Parent metrics include `worker_timeouts`,
`worker_failures`, and `worker_lock_busy`. Daily run-health transport needs these
counters; the server pipeline also needs the optional `history_reset_at` upload
field. Neither transport integration nor the disabled release switch changes
here.

Regressions cover corrupt manifests/totals/shards/indexes, unchanged bad state
on due upload, isolated healthy scopes, forward-only resets, unknown checkpoint
identifiers, reserved read ends, directory syncs, blocked stdin/work, protocol
failures, concurrent workers, and orphaned workers retaining their lock. They
also cover:

- sessions created after install, read in full and counted once after a stop
  before the pins write;
- a reset scope uploading again and then reading new files;
- damage in an untouched shard, found on its first load;
- a reset scope whose files are gone;
- a lock-busy worker whose input write fails;
- a hung orphan stopped by its watchdog.
