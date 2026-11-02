# Claude census: never-committed members of a terminal family

Date: 2026-10-15.

## Problem

A Claude family can carry a terminal (`UnprovenTerminal`) authority quarantine whose record binds subagent transcripts that were never committed to the local scan index. The family root is committed; its subagents are not.

Each generation then went the same way:

1. The candidate gate checks `NewFile` before the authority quarantine, so every bound subagent was reparsed and held on an early page.
2. The hold is non-progressing (bound to the terminal record at exactly its revision), but the held key has no committed entry to restore. The replay-reset guard from the census convergence change (`locally_held_keys_restorable`) therefore kept the sweep unsettled.
3. The terminal page owed a clean follow-up, so the census never completed, the upload context was never adopted, and the next generation selected every Claude file again under `upload_context`.

The guard exists for a real reason. Dropping a never-committed member from the index leaves the family's complete-census membership incomplete. With only the root indexed, quarantine resolution, witness retention and the duplicate-owner universe all see a partial family. After a historical replay reset, when the root entry is gone too, the family reads as vanished.

## Change

For a held key with no committed entry, the `Completed` commit now keeps a delivery-free membership entry instead of dropping it, but only when all of these hold:

- the key is a subagent member of a family whose root entry is committed in the pre-scan index;
- the root's `UnprovenTerminal` quarantine is bound to the retained witness and records exactly this key's scanned source revision;
- none of the key's held entities is an account deferral, and settlement is otherwise non-progress-blocking (no `RetryPending` family anywhere, upload `Completed`).

The entry keeps only file identity (size, modification time, source fingerprint, scan identity). It has no snapshot fingerprint, upload body witness, effective witness revision, exact entity set, empty marker, terminal JSONL disposition, owned-start witness, activity, or accepted-ledger entry. It therefore adds nothing to `current_snapshot_fingerprints`, the manifest, or acceptance. No new index field, map, or bound is introduced; there is at most one entry per present file, as before.

Consequences:

- The unchanged member is skipped at the authority quarantine gate, exactly like a committed terminal member; nonzero terminal deadlines at or before 2026-10-28T06:00Z allow one E2 recovery, whose failed fold writes a fresh terminal deadline and whose success removes the authority record.
- `complete_claude_usage_family_members` sees the true present membership, so resolution still requires every member to be proven, and the witness and quarantine are retained.
- The traversal settles, the census completes, the upload context is adopted, and the next unchanged traversal parses nothing.

## Unchanged behaviour

- A replaced member (new revision) fails the quarantine gate, is reparsed once, held, and rebound; its body is never uploaded.
- A missing member is pruned by complete-census reconciliation like any vanished path.
- A family whose root entry is not committed (for example after a historical replay reset), the root member itself, account deferrals, and any `RetryPending` family keep the conservative block.
- If the quarantine is later resolved, the delivery-free entry has no snapshot, so it is reparsed under the then-current rules.
- Health stays red through the terminal quarantine's existing ownership-incomplete disclosure. The duplicate fence, its coverage rule and re-arm backoff are untouched; a closed fence still owes its scheduled full re-arm.

## Tests

- Unit (`snapshots/census_convergence_tests.rs`): the delivery-free entry, its manifest and acceptance parity, skip versus reparse decisions, family membership, and the negative shapes (account deferral, uncommitted root, other revision, `RetryPending`, root member).
- Pipeline (`snapshot_sync/census_convergence_pipeline_tests.rs`), through the shared settlement helpers with a save and reload between pages: the production shape completes its census in one window with the quarantine retained, held bodies never uploaded or accepted, siblings at parity, and a following unchanged traversal that parses nothing. Controls cover `RetryPending`, a historical replay reset, a missing member, and a replaced member.

## Limits

This removes one blocker of census completion. It does not address account-held files that are reparsed every generation by design, retention refusals in the transcript cache, or memory peaks, and it makes no resource-use claim on its own.
