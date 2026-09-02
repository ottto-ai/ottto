# A clean index is not proof of acceptance

## Problem

The legacy-settlement migration added in ottto#392 exists because an earlier
daemon could silently drop a snapshot retry obligation. Its repair is a bounded
sweep: at most 50 pre-ledger revisions per source cycle are re-armed as
`RetryPending` quarantine records, re-offered through the already-deployed
snapshot entity-ACK upload contract, and recorded in
`accepted_snapshot_fingerprints` only when the server answers with an exact
entity ACK. The sweep pages a lexicographic cursor that is persisted before the
scan, so a restart resumes instead of rebuilding one unbounded request.

That migration also had a fast path. Before arming anything it asked whether the
index looked clean — no bounded cursor, no traversal, no unsettled-sweep flag,
an empty quarantine — and if so it assigned every currently indexed revision
into `accepted_snapshot_fingerprints` and marked the ledger migrated:

```rust
let current = self.current_snapshot_fingerprints();
if self.legacy_settlement_reconcile_after_fingerprint.is_none()
    && self.traversal.is_none()
    && !self.bounded_sweep_had_unsettled_upload
    && self.quarantined_snapshot_fingerprints.is_empty()
{
    self.accepted_snapshot_fingerprints = current;
    self.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
    return (BTreeSet::new(), true);
}
```

The inference is "the index is clean, therefore the server accepted every
revision in it". The loss this migration repairs is precisely the
counterexample. That path ends in **completed-cycle index persistence**: a due
quarantine obligation is released into a scan that owns no upload item, the
cycle reports itself complete, the durable quarantine is replaced by the empty
in-flight map, and the disposable upload ledger is deleted. What remains on disk
is a clean index in which one revision is still a live current file fingerprint
and was never offered to the server at all.

So the fast path's precondition is not evidence of settlement — it is the
signature of the bug. A machine that finished a clean census before upgrading
took the fast path on its first cycle and wrote its stranded revisions into the
accepted ledger. Once there, they are removed from
`legacy_settlement_reconciliation_pending_fingerprints()` forever: no re-offer,
no quarantine record, no log line, no counter. The migration built to recover
those revisions was the thing that sealed them.

The escape on the one machine that was inspected was luck, not a guard: its
upgrade landed while a terminal-unhealthy traversal with empty pending sets was
still persisted — the artifact of the very bug — so `traversal.is_none()` was
false and it paged normally. A completed census clears that traversal on any
ordinary cycle.

## Change

### The fast path is gone

`prepare_legacy_settlement_reconciliation` no longer has a shortcut. Every
ledger runs the same bounded sweep from the start.

This is affordable because the sweep is idempotent and self-terminating, which
is a property of its own state rather than of the caller:

- a cycle arms at most one page and never re-arms an already-armed revision,
  because `unarmed` excludes anything already in the quarantine map;
- the cursor is lexicographic over a `BTreeSet` and advances to the last
  selected revision, so pages are disjoint and cover the set;
- the pending set is `current - accepted`, filtered to revisions that are either
  unquarantined or `RetryPending`, so an explicit terminal disposition retires a
  revision from the migration just as an ACK does;
- `finish_legacy_settlement_reconciliation` closes the migration the first cycle
  that pending is empty.

For a machine whose history really was fully settled, the cost is one bounded
pass in which the server answers each revision as an unchanged no-op. At 50 per
five-minute source cycle that is background work measured in hours for a corpus
of a few thousand revisions, paid once. The alternative — keeping the fast path
and gating it on some per-revision proof — would need a witness the ledger does
not have, which is the whole difficulty (see below).

There is now no code path that records a revision as accepted without either an
exact entity ACK or an explicit terminal quarantine disposition that discloses
it, so there is nothing left to disclose in a "sealed N without proof" log line.

### Ledgers already sealed are re-opened once

The accepted-revision ledger keeps no per-revision provenance and no witness of
which migration path wrote it. An entry proved by a real entity ACK and an entry
assigned by the fast path are byte-identical, and both migrations finish in the
same terminal shape — ledger version set, cursor `None`. **The ledger cannot
distinguish a fast-path seal from a completed sweep.** Stated plainly, because
it decides the repair: there is no safe way to re-open only the machines that
took the fast path.

So every ledger written by the previous migration is re-opened, exactly once.
`SNAPSHOT_ACCEPTED_LEDGER_VERSION` becomes `2`, and version `1` is now named
`SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION`. On the first cycle that reaches
the arming path with an unproven ledger,
`reopen_unproven_accepted_snapshot_ledger`:

- clears `accepted_snapshot_fingerprints` — required, not optional, since the
  pending set is `current - accepted` and a retained fast-path entry would keep
  the stranded revision out of the sweep, which is the defect itself;
- clears the bounded cursor, so the sweep starts from the beginning;
- drops the ledger version to the pre-ledger value `0`;
- prints one line naming how many revisions it re-opened.

Dropping the version instead of holding a separate "re-opened" bit is what makes
the re-open idempotent. The next cycle sees a plain unmigrated ledger and
resumes the sweep, rather than clearing the acceptances the sweep has since
re-earned. The server is the authority on what it holds, so re-offering a
revision it already has is a no-op that re-records it as accepted; re-offering
one it never received is the heal.

`finish_legacy_settlement_reconciliation` now refuses to advance a ledger still
at the unproven version. Its pending set is computed from an accepted set this
daemon has not re-proved, and would read as empty. Without that guard a cycle
that skipped arming — a pending historical replay, for instance — could observe
the stale empty set and re-seal the ledger before the re-open ever ran.

### Compatibility

An index at version `0` or `1` loads unchanged; the load-time guard accepts any
version at or below the current one. A version `2` index read by an older daemon
fails that guard and is quarantined and rebuilt, which is the pre-existing
behaviour for any ledger-version bump and costs a re-census, not data.

A machine that is mid-sweep when it upgrades restarts its sweep from the
beginning, because its partially re-earned acceptances are indistinguishable
from fast-path ones. That is one extra bounded pass, and it is the same
conservative reading applied everywhere else here.

## Tests

`crates/ottto-service/src/snapshots.rs`:

- `legacy_0_1_121_clean_index_is_rearmed_rather_than_sealed_as_accepted`
  constructs the exact fast-path precondition — pre-ledger index shape, no
  cursor, no traversal, no unsettled-sweep flag, empty quarantine — and asserts
  both revisions are armed as `RetryPending` with an immediate deadline, the
  accepted ledger stays empty, and the migration stays open. This is the
  replacement for the old test that asserted the seal.
- `ledger_migrated_without_settlement_proof_reopens_once_then_stays_terminal`
  persists and reloads a ledger at the unproven version whose accepted set names
  every revision, and asserts the whole set is re-offered rather than trusted,
  that a second cycle resumes instead of re-clearing, and that once the server
  settles both revisions the migration is terminal and never re-opens.
- `unproven_ledger_is_not_finished_without_the_bounded_reopen` proves the
  `finish` guard: an unproven ledger with an empty stale pending set is not
  sealed.
- `legacy_reconciliation_advances_one_page_per_cycle_and_terminates` drives 120
  revisions through settle-and-repeat cycles and asserts the pages are
  `[50, 50, 20]`, the cursor advances monotonically, and the migration closes on
  its own with every revision accepted.

The existing sweep tests are unchanged and still pass:
`legacy_0_1_121_unfinished_strand_rearms_in_persisted_bounded_pages` and
`legacy_reconciliation_bounds_real_scale_and_resumes_from_persisted_cursor`.

### Negative control

The removed early return was temporarily restored in the working tree, with no
other change. All three new tests failed — the clean-index test armed `{}`
instead of both revisions, the re-open test saw the re-opened set immediately
re-sealed, and the pagination test produced `[]` instead of `[50, 50, 20]`. The
restoration was then reverted and the suite re-run green, so the tests fail for
the defect and not for their own construction.
