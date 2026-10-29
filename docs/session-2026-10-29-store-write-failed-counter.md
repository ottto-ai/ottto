# Restart Fulls after a failed durable-store write

A post-save durable-store batch that returns an error (a failed write or
rename) returns before the deferred-key requeue. The store keeps each offered
key's predecessor, so after a restart the next change of that file refuses the
record as behind the committed entry and reads Full. This change only measures
that cost; the requeue fix belongs to a later durable-store milestone.

- `store_write_after_save_failed[files]` counts the records offered to the
  failed batch, at the error.
- `store_write_failed_restart_full[files,bytes]` counts Fulls whose restore
  refused the record as `entry_changed`, with the completed native bytes each
  Full read. A RAM-only mark set at the refusal is consumed by the key's next
  completed acquisition; only a Full counts.
- `entry_changed` is the closest existing refusal. It also covers a record
  never offered (deferred or evicted before the write), so the count is an
  upper bound on write-failure Fulls. No persisted field is added.
- A `durable_tail_restart_full_alarm` record fires once the files count has
  stayed above zero for more than 24 h, then at most once per 24 h, using the
  pending-since and 24 h throttle of the accepted-rebuild alarm, kept in RAM.

Linux fixtures cover the refused-predecessor Full and its bytes, a fault-free
restart at zero, and the alarm window. A macOS-gated scan fixture covers the
real rename failure, restart and counted Full. Local clippy compiles fixtures;
tests remain CI-only.
