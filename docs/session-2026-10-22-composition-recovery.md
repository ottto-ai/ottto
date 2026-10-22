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
Only the original installation can authorize initial reads from zero within
the repair allowance. A missing pin always starts at the current end.

The worker acquires a nonblocking OS-backed exclusive lock before worktree
mapping or checking the saved run date. The lock lives until process exit and
survives scheduler death. Atomic writes use unique temporary filenames. The
parent bounds the entire stdin/write/wait/reply exchange to 35 minutes, kills
and reaps on timeout or failure, and retains the saved-day rule for later wakes.

Source metrics include `scopes_quarantined`, `files_quarantined`, `agent_resets`,
and `checkpoint_restarts`. Parent metrics include `worker_timeouts`,
`worker_failures`, and `worker_lock_busy`. Daily run-health transport needs these
counters; the server pipeline also needs the optional `history_reset_at` upload
field. Neither transport integration nor the disabled release switch changes
here.

Regressions cover corrupt manifests/totals/shards/indexes, unchanged bad state
on due upload, isolated healthy scopes, forward-only resets, unknown checkpoint
identifiers, reserved read ends, directory syncs, blocked stdin/work, protocol
failures, concurrent workers, and orphaned workers retaining their lock.
