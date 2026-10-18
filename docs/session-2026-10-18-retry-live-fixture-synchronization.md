# Retry live fixture synchronization

The supported Rust 1.95 CI suite exposed a test setup race after #612: the
live retry test reported zero turns, then its server was cancelled before
connection one. The cancellation was cleanup after the zero-turn assertion,
not a token, HTTP, or ACK failure.

The fixture scheduled its retry 30 ms in the future inside a 150 ms ordinary
wait. The ordinary wait correctly stops at its deadline; a delayed wake can
therefore leave no retry boundary to execute. This test must not require a
sleep to resume inside that narrow interval.

Synchronize fixture eligibility on the owner's due Instant before starting
the unchanged 150 ms ordinary wait. The native test proves an already due
retry executes through the real idle boundary without another scan, preserving
one token, one policy GET, one batch, exact durable ACK/restart behavior, the
ordinary deadline anchor, and the allocation bound. It does not prove a future
timer wakes within a real-time scheduling window.

`bounded_retry_owner_due_boundary_preserves_ordinary_deadline` separately uses
explicit Instants with the real RetryOwner: its future due time shortens the
ordinary wake, no turn executes one nanosecond before due, exactly one executes
at due, and settlement restores the original ordinary deadline. Existing
RetryBudget clock tests and native owner fairness/recovery tests remain.

Only test code changes. Production retry, timeouts, ACKs, resource limits,
layout enforcement and suite concurrency remain unchanged. Validation uses
existing CI; no local Cargo build or test is needed.
