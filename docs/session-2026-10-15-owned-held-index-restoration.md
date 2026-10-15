# Reuse the owned scan index when restoring local holds

A completed upload with restorable, non-progressing local holds already owns its
scanned index. Restoring those keys previously cloned the entire index before
replacing a small subset of entries. The caller now consumes that graph and
restores held entries in place. The original borrowed implementation remains
unchanged under `cfg(test)` as a reference.

The eligibility predicate, partial settlement route, held-key membership,
terminal placeholders, accepted-body ledger, activity pruning, retry debt,
checkpoint locking, compare-and-swap, schema and upload contracts are unchanged.
No-hold uploads and partial/deferred settlement are outside this optimization.

Validation compares every serialized field against the original implementation,
checks held and healthy entry/ACK/debt invariants, compares exact saved bytes,
and reloads the saved state. Existing real pipeline fixtures additionally
compare the complete result at the changed settlement boundary while retaining
their body, receipt, debt and restart assertions.

The allocation comparison uses the existing thread-local probe and synthetic
32/64-family fixtures with 16 requests per family. Both incoming graphs are born
inside the measurement; the additional phase peak is measured above that graph.
Receipts distinguish requested allocation bytes from usable allocator bytes.
They do not measure RSS, installed memory savings, transcript rereads, or UI
performance. Hosted CI must validate execution before any acceptance claim.
