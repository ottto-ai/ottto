# Durable Claude authority proof corrections

A complete healthy family census can replace its witness while an earlier-page
hold retains the prior witness binding. The loader correctly rejects this pair.
Preserving that validation and keeping exact held-body/ACK state are required.

The characterization tests model three existing-record transitions, using a different
synthetic witness digest and the real candidate/save/load methods:

| Transition | Count | Disposition | Deadline | Candidate result |
| --- | --- | --- | --- | --- |
| Rebind digest only | 4 | UnprovenTerminal | unchanged | Skip despite cleared correction debt |
| Rebind and make due | 1 | RetryPending | 0 | Parse remains due across unacknowledged reloads |
| Rebind and claim future retry | 1 | RetryPending | current time plus existing retry interval | Both unfinished members skip after reload |

The new digest can record which proof is consumed, but these record-only
transitions cannot simultaneously carry a one-attempt claim and unfinished
bounded correction pages. The existing candidate quarantine gate precedes the
entry's cleared source fingerprint. Merely honoring that fingerprint would also
reopen generic retry debt, which is not certified as a new proof correction.
Existing traversal state does not bind an authorized correction attempt to a
particular new witness. A record-only encoding that removes member revisions
also loses the ability to distinguish completed and still-owed members.

The repair adds an optional correction to the existing family quarantine:
the exact new proof digest and a bounded set of owed member IDs. Only a complete,
healthy, genuinely different proof may create it on a valid terminal record.
The record stays terminal with its existing maximum failure count and deadline;
it does not block the census as a pending retry. Each owed member can parse on
its own page. A same-pass reconstruction failure cancels the correction and
retains a terminal record bound to the current proof.

Successful parsing alone does not settle a member. Its grant drains in the same
durable settlement as an exact current-revision corrected-body ACK, or an exact
previously accepted body-set no-op. Offered, held, shed and unacknowledged bodies
remain owed across restart. Only the last settled member clears the record and
family pending state. A superseded revision's ACK cannot settle the current one.

Complete healthy census evidence may retire a disappeared member's grant and
member-map entry. Confirmed-empty members can settle without an upload only
when the stored empty fact, file revision and member-map revision agree and the
census is complete. A completed zero-entity parse can advance that revision pair
on an earlier partial page without draining debt. Partial/held restoration must
carry all paired facts together or restore their previous revisions. Neither
rule retracts old accepted entities or changes prior-entity, manifest or ACK debt.
An unsettled current-page read defers an older empty pair until finalization;
it cannot certify a newer revision. The existing whole-family disappearance
rule still applies when a complete filesystem census removes its witness,
including when provider reports are unavailable.

Each new proof conservatively rearms all retained members, including members
settled under the previous proof. Provider proof changes can alter a corrected
body without changing transcript bytes. Consequently cost scales with genuine
proof churn. Before durable settlement, crashes and sheds may repeat physical
parsing, with at most one attempt per member per pass; the protocol does not
promise exactly-once parsing.

Active corrections use record contract `claude_usage_authority_quarantine:v2`.
The new reader keeps ordinary v1 records unchanged. Invalid correction bindings,
empty or out-of-family owed sets fail closed. An older reader rejects v2 through
its existing contract validator and can quarantine/rebuild the whole index on
rollback. A live downgrade and installed rebuild cost are not established here.

Two additional terminal outcomes complete a correction without an ACK. An exact
permanent refusal of the current corrected body drains only alongside its existing
permanent-rejection and terminal-quarantine witnesses, on a clean terminal upload
outcome. Retryable, stale-revision, other-proof and partial outcomes do not qualify.
The refusal remains observable. A completed unheld parse whose corrected items are
all removed solely by the account-switch cutoff drains as a policy no-op. If any
item survives the cutoff, the ordinary ACK/no-op path applies. Both drains use the
final selected file revision; a restored prior entity invalidates the cutoff drain.
No extra persisted metadata is added. Completion flags are computed after these
and confirmed-empty drains, so settling the last empty member needs no extra sweep.

A daemon older than this release that reads an index written by it discards the
index and rescans from scratch. Usage is not lost; the rescan costs a full first
scan's time and upload volume. The decoder is pinned to previous stable 0.1.173,
release source `896b98f6b7347251b35c2d13cd462b132cd99d84`. Its record, authority
validator, index-load guard and quarantine/rebuild helper were source-compared
against the characterization base. The synthetic fixture reparses two files and
discards two local accepted-ledger entries. This is a cost estimate, not a measured
downgrade. An actual old binary was not run, and no valid saved first-scan/backfill
wall-time receipt was available; real rebuild wall time and bytes remain unmeasured.
The qualified compatibility gate accepts this disclosed source characterization.

The earlier implementation passed all 33 new correction regressions and the
containing hosted service suite (2,858 passed, zero failed, 22 ignored). Independent
strict review then found the terminal-outcome and completion-order defects above.
Seven additional regressions and their corrections await exact-head hosted CI and
focused verification. Requested allocation bytes remain distinct from installed
RSS, CPU and reread acceptance; this source change establishes none of those
installed outcomes.
