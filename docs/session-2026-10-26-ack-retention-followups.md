# ACK retention follow-ups (#778)

Three follow-ups named in the #778 reviews.

Partial-save liveness (SOURCE R2-2). A partial save commits only a subset of
the scan. A new file whose sibling has not settled is left out of that subset,
but the file still exists. If an entity with an ACK moved into such a file,
the subset alone looked like proof that the entity was gone. Two paths acted
on that: promotion of a pending retirement obligation, and retirement from
committed incidence. Both now also check the full pre-selection scan index.
An entity that the scan still references keeps its ACK, and its obligation
stays pending. The final all-accepted save is unchanged.

Waiting for a complete census (SOURCE R2-3). When unindexed debt exceeds the
unsettled limit, only a complete census can retire it. The capacity-stop log
line now carries `consecutive_incomplete_census_stops`: the number of
consecutive capacity stops in this process whose scan was not a complete
census. Any other finish outcome, or a complete census, resets it. It is a
local count only. It is not uploaded or persisted, and nothing is pruned
because of it.

Huge-file convergence. Admission is per entity and settlement is per file.
Emitted file entities come only from completely parsed files, and finalization
records their exact set in the scan index before admission. So every member of
a live file uses live slots, even when unrelated debt fills the 4,096
unsettled slots. A new regression covers one file with 5,000 entities next to
4,096 debt ACKs. A page fails mid-file, the partial save retains the accepted
pages, and the next cycle sends only the remaining entities. The file then
settles and transfers every ACK to the index.

The retained-retry equality reader already restores the stale-count scalar
(`bounded_snapshot_retry.rs`, #778 Round 5); no change was needed.
