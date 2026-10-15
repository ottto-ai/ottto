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

## Consequences to know before release

- **Latency for a first change.** Take a family whose proof has been stable. If only one member changes, only that member is parsed, so the census cannot prove the family. The changed member is demoted and held under a `RetryPending` authority quarantine, and the family is reparsed when the quarantine requests it. That happens when the retry deadline (6 to 12 hours) passes, or earlier if a member changes again. The old loop reparsed the whole family on every traversal, so it re-proved the family one traversal later. The body is held, never downgraded.
- **Body changes without a witness change.** A release that changes the uploaded body of a reported-usage member, but not its family witness, used to reach every proven multi-page family through this loop on the next traversal. After this change it does not. Such a change needs its own re-offer path, or it must ship and be verified before this change.

## Tests

The tests are in `snapshots/claude_usage_proof_rearm_tests.rs`. They use the production `apply_claude_reported_usage_with_index` fold with a synthetic two-member family. The root is on an earlier page and the subagent is on the terminal page. The index goes through the production save and load between traversals.

- The first proof re-arms the root. The correction pass rebuilds it with reported usage. The next terminal census proves the same witness and keeps the root's fingerprint. A following census with nothing parsed keeps the witness and re-arms nothing.
- Changed reported evidence demotes and holds the root on its page. The terminal census then proves a changed witness and re-arms the root.
- A child that grows alone is held, the family is not re-proven, and the quarantine stays bound to the retained witness. The family reparse proves the changed witness and re-arms both members. The next page rebuilds both with the grown usage and resolves the quarantine.

## Limits

This changes when the terminal census re-arms earlier-page members, and nothing else. It makes no claim about how much I/O is saved on any machine. It does not change the stale-pending or owned-start re-arms, or the duplicate-fence full re-arm.
