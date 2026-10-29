# Restart Fulls after a failed durable-store write

A post-save durable-store batch that returns an error (a failed write or
rename) returns before the deferred-key requeue. The store keeps each offered
key's predecessor, so after a restart the next change of that file refuses the
record as behind the committed entry and reads Full. This change only measures
that cost; the requeue fix belongs to a later durable-store milestone.

- `store_write_after_save_failed[files]` counts the records offered to the
  failed batch, at the error.
- `store_write_failed_restart_full[files,bytes]` (upper bound) counts Fulls
  whose restore refused the record as `entry_changed`, with the completed
  native bytes each Full read. A RAM-only mark set at the refusal is consumed
  by the key's next completed acquisition; only a Full counts.
- It is an upper bound, not an exact count: it reuses the `entry_changed`
  refusal and no persisted marker records a failed write, so it also covers a
  record never offered (deferred or evicted before the write). No persisted
  field is added.
- A `durable_tail_restart_full_alarm` record fires on the first counted file
  in each process, with no wait, then at most once per 24 h in that process
  (the accepted-rebuild alarm's 24 h throttle, kept in RAM). A restart re-arms
  it; the counter is the persistent signal.

Linux fixtures cover the refused-predecessor Full and its bytes, a fault-free
restart at zero, and the alarm: first file, no repeat in the process, again
after a restart. A macOS-gated scan fixture covers the
real rename failure, restart and counted Full. Local clippy compiles fixtures;
tests remain CI-only.
