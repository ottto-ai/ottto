# Claude census: re-arm earlier pages only for a new or changed family proof

Date: 2026-10-15.

## Problem

A terminal Claude census proves each family whose members were all parsed in the census window. It then clears the source fingerprint of every member of a proven family that the terminal page did not parse, so the next traversal reparses those earlier-page members and rebuilds them from the new witness.

The clear did not compare the proof with the witness the index already held. It also kept itself going:

1. The census proves family F and clears the members that earlier pages parsed.
2. The next traversal reparses those members (`Rearmed`). Each rebuilds from the retained witness, and its body is unchanged.
3. That reparse puts every member of F back into the census window, so the terminal census proves F again with the same witness, and clears them again.

Every proven family that was not entirely on the terminal page was reparsed on every traversal, in full, without any change in its files or reported evidence. The existing re-arm comment already says the intent: "Reparse earlier-page members when terminal family proof changes".

## Change

At the terminal census, a proven family re-arms its earlier-page members only when its exact durable witness is new or differs from the witness the index held before this call. The comparison is the existing content-free witness digest (`claude_usage_family_witness_fingerprint`, already computed as `witness_fingerprints_before`). That digest covers the evidence fingerprint, per-member request-id and occurrence fingerprints, assigned request ids, and legacy exclusions. It does not use counts or timestamps. A witness retained from earlier passes without being re-proven compares the same way as a freshly proven one.

When the witness is unchanged, every earlier page already had it. Each member on those pages was either rebuilt from the reconstructed witness (same evidence digest, so the same rows) or demoted into the bounded authority quarantine, which owns that retry and is unchanged.

All other terms of the clear are unchanged: the duplicate-fence full re-arm, an invalidated witness, a changed duplicate owner, and a member that owns a changed duplicated request.

The terminal census now writes one aggregate log line when it re-arms anything, or keeps anything that the old rule would have re-armed. The line has file counts by first cause: full re-arm, new or changed family proof, invalidated witness, or changed request duplicate. It also has the number of unchanged proofs and the earlier-page files they kept, and the number of owned-start members re-armed in the pass. It has no identifiers or paths, reads nothing extra, and stores nothing.

## Unchanged behaviour

- A family proven for the first time re-arms its earlier-page members once.
- A changed proof re-arms them once. This covers changed reported evidence, a changed member request set or occurrence, and a changed legacy exclusion.
- A demoted body is still held and never uploaded; quarantine records, their retry cadence and their binding are unchanged.
- Settlement, the stale-pending traversal-start re-arm, owned-start re-arm, duplicate witnesses, fence coverage and backoff, upload authority and body witnesses are unchanged.
- Fingerprints already cleared by an older daemon stay cleared, so debt that exists when this change is installed is still reparsed once.

## Freshness after a member change

This change does not alter the path a changed family takes. Read from the source, the existing authority contract decides when a family that spans pages can be re-proven, under either re-arm rule:

- A new request in any member also appends the root's API and trace sidecars. The sidecar stat is part of every member's source fingerprint, so the next traversal selects the whole family.
- The root, parsed on an earlier page, no longer reconstructs from the retained witness, because the evidence digest changed. It is demoted into a `RetryPending` authority quarantine, and its new body is held while the accepted body stays current.
- Any `RetryPending` family makes the page's local holds progress-blocking (`LocalHoldSettlement::progress_blocking`). The traversal then owes a clean follow-up, so no census completes and no family can be re-proven while the quarantine is pending.
- Each failed reconstruction sets a wall-clock retry deadline 6 to 12 hours ahead, and the quarantine becomes terminal, and stops blocking, on the fourth failure. Only then can a complete census prove the changed witness.

The old loop did not take another path: its reparse also happened on earlier pages, before the blocked census. Only a family that sits entirely on the terminal page is re-proven in the same traversal. This note describes the contract; it does not accept the resulting delay as a freshness bound, and nothing here measures it. Changing it is a separate decision about the progress-blocking rule for a bound `RetryPending` hold, not a re-arm question.

A changed body without a family witness change is the other consequence. A release that changes the uploaded body of a reported-usage member, but not its witness, used to reach every proven multi-page family through this loop. After this change it does not. Such a change needs its own re-offer path, or it must ship and be verified before this change.

## Tests

`snapshots/claude_usage_proof_rearm_tests.rs` drives the production `apply_claude_reported_usage_with_index` fold with a synthetic two-member family and a save and load between traversals. It covers the first proof, an unchanged re-proof, changed evidence, and a child that changes alone. It passes the census flag directly, so it does not show what a full traversal can reach.

`snapshot_sync/stable_proof_rearm_pipeline_tests.rs` runs bounded traversals through the production page order: scan with the local OTEL support directory, local evidence, account binding, upload policy, finalization, hold classification, an in-process upload, settlement, and the durable save and reload. The family root and both subagents are on earlier pages; an unrelated session is alone on the terminal page. No test edits fingerprints, quarantines or clocks.

A shared setup runs the first proof and its cross-page correction and asserts only what the original and the new re-arm rule both produce: the first proof re-arms every member, and the correction delivers each member's reported body, whose ACK makes it the member's head. Each generation writes one count- and hash-only JSON receipt line to stderr, so test runs of different heads can be compared.

- `stable_claude_family_proof_stops_rereading_after_cross_page_correction` (new rule only): the unchanged re-proof keeps the corrected members settled, and the next two generations read no file and offer nothing.
- `changed_family_member_after_stable_proof_is_held_by_the_authority_retry` (either rule): an appended subagent request selects only that family. Its bodies are held under a bound `RetryPending` quarantine and never offered, the ACKed heads stay current, and later generations read nothing.
- `unhealthy_family_evidence_stays_held_without_renewed_family_reads` (either rule): malformed evidence holds the family the same way, without renewed reads.
- `rearm_debt_survives_a_shed_correction_and_reload_until_accepted`: under either rule, a shed correction keeps the re-arm debt across the save and reload, and a later generation delivers the corrected body after its exact ACK. Its final quiet generations are the new rule only.

## Open items

- The actual original-predicate baseline ran in CI38792771424 at ebf2fa99: both changed/unhealthy lifecycle tests passed, while the five stable-rule assertions failed as expected. Count/hash receipts include exact accepted correction and shed recovery; final optimized receipt comparison remains pending.
- A separate diagnostic baseline test reproduced saved-index quarantine/rebuild after repeated genuine member appends, at synthetic hour12. The family had three indexed files before reload and none afterward. This predates the change; its failing test and CI evidence are retained separately for recovery repair. It is not fixed by this optimization.

## Limits

This changes when the terminal census re-arms earlier-page members, and nothing else. It makes no claim about how much I/O is saved on any machine. It does not change the stale-pending or owned-start re-arms, the duplicate-fence full re-arm, the authority quarantine, or settlement.
