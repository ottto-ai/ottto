# ACK retention follow-ups (#778)

Three follow-ups named in the #778 reviews.

Partial-save liveness (SOURCE R2-2, review #794 F1). Several selections save
only part of the scan: the partial checkpoint after a shed or upload error,
and the local-hold subsets after a Completed, Deferred or Rejected upload.
Each can leave out a new file whose sibling has not settled (or is locally
held), but the file still exists. If an entity with an ACK moved into such a
file, the subset alone looked like proof that the entity was gone, and its
retirement obligation was promoted or its ACK retired. Finish now captures,
before any selection, which retirement obligations the full scan still
references. Every save keeps those obligations pending and never retires
their ACKs. The set is bounded by the obligations (held ACKs); the scan is
only borrowed. When no selection omits a live file, every referenced entity
is already in the saved incidence and nothing changes.

Waiting for a complete census (SOURCE R2-3). When unindexed debt exceeds the
unsettled limit, only a complete census can retire it. The capacity-stop log
line now carries `consecutive_incomplete_census_stops`: the number of
consecutive capacity stops in this process whose scan was not a complete
census. A guard created at the start of finish resets it on every other exit
(success, shed, disabled, bootstrap or transport failure, early return), and
a complete census also resets it. It is a local count only. It is not
uploaded or persisted, and nothing is pruned because of it.

Huge-file convergence. Admission is per entity and settlement is per file.
Emitted file entities come only from completely parsed files, and finish
finalizes their exact set into the scan index before admission. So every
member of a live file uses live slots, even when unrelated debt fills the
4,096 unsettled slots. Today's Claude and Codex parsers emit one file-backed
entity per parsed file, so no real transcript yields thousands of entities.
The finish-level regression therefore multiplies the scanned item into a
5,000-entity group of that file, as the first-install case does; the real
finish finalization records the group's incidence and body-set witness. The
test reads the file's fingerprints back from what the pipeline offered and
ACKed, not from the values it seeded. It runs with 4,096 debt ACKs, and each finished scan is marked
census-incomplete so census cleanup cannot retire that debt. A real HTTP
failure that the uploader neither resends nor splits stops the first finish
after accepted pages; the second finish sends only the rest,
settles the file and transfers every ACK, leaving exactly the debt. A
lower-level test covers the same sequence directly against the ledger.

The retained-retry equality reader already restores the stale-count scalar
(`bounded_snapshot_retry.rs`, #778 Round 5); no change was needed.
