# Reparse debt across partial snapshot checkpoints

A scan may deliberately clear a file's source fingerprint when census or duplicate evidence requires another parse. A later partial upload checkpoint can retain the old accepted file entry. Retaining that entry must not restore a cleared fingerprint and silently cancel the outstanding parse.

`ScanIndex::committable_subset` now carries an explicit empty source fingerprint into a retained entry. The previously accepted entity fingerprint, body witness, file metadata and receipt ledger still follow the existing settlement rules. The change cannot accept a held revision, publish a deletion or clear a duplicate fence.

Regression coverage checks a held revision through serialization and verifies that an unchanged rearmed file remains selected after a sibling is held. A control preserves the normal old checkpoint when no rearm was requested.

This repairs checkpoint correctness. It does not by itself resolve repeated Claude census work or establish lower CPU or memory use. Census convergence and rendering performance need separate validation.

## Claude census convergence

A completed Claude upload can still leave entities held locally: an account deferral (the request evidence cannot yet prove one owning account) or an authority demotion (the family usage proof could not be rebuilt). Before this change every such hold marked the bounded sweep unsettled, so a long traversal could never finish while one held file stayed unchanged, and each generation reparsed the whole family.

Holds are now split by whether a later page of the same traversal could change them.

- A demotion is non-progressing only while its family quarantine is terminal, well formed, bound to the retained family witness, and records exactly the held revision. The candidate gate skips that revision until the family changes.
- An account deferral is non-progressing once its index key is recorded in a bounded, persisted hold map (at most 4,096 keys). If that bound prevents recording, account deferrals stay blocking. Only Claude account deferrals take this path.
- Everything else blocks progress as before, including any `RetryPending` family anywhere in the index and every Rejected or Deferred upload outcome.

When no hold blocks progress, the commit keeps the committed revision for each held key: its file entry, exact entity set, empty marker, terminal disposition, owned-start witness, and the activity and accepted-ledger entries for those restored entities. A held body therefore never enters the committed entity set, the manifest, or the accepted ledger. A held key that was never committed stays absent. Every other key commits exactly as the no-hold save would, so the traversal can finish and adopt the current upload context. Account-held keys get an empty source fingerprint, so every later generation reparses them. Backfill and replay completion flags stay pending while any hold exists.

The hold map changes only when a completed parse re-decides a key, when the watcher or reconciliation removes the key, or when a complete raw census proves the key absent. Each persisted hold is added to the public ownership-incomplete count but never to the terminal share. The Claude receipt therefore stays an unsettled `parse_error` (one consecutive failure, no success clock) for as long as any hold persists. Overflow cannot turn health green.

### Family pending growth

The duplicate-request census keeps request evidence for each family member over one census window. A member seen again on a later page of the same window used to have to match exactly, so a transcript that grew between pages invalidated the whole family and closed the duplicate fence. A later observation now supersedes the stored one only when all of these hold:

- every stored request is still present at its stored response sequence and is unchanged;
- the single last stored response may progress in place, with usage that only grows and identity fields that only go from absent to present;
- every new request is sequenced after all stored ones.

Anything else still invalidates the family: removal, reordering, a changed earlier response, a changed identity field, or ambiguous last responses. A repeat of the same member within one page must still match exactly, and the occurrence cap still applies. The page counter `page_superseded_member_growth_count` reports admitted growth.

### Duplicate-fence coverage and backoff

A closed duplicate fence now reopens only after a terminal pass that observed every indexed Claude family member in the current census window. A member counts as observed when it has current-window, valid pending evidence. Two kinds of file are exempt: confirmed-empty files, and members of a root held by a bound quarantine. An incremental, reset, or partially undone traversal therefore cannot clear the fence. Coverage alone never closes an open fence. A complete census also ignores old-window pending for families that no longer have any indexed file.

While the fence stays closed, the full Claude re-arm runs at most once per backoff interval. The interval starts at one hour and doubles up to one day. It is tracked by two scheduling-only index fields, `claude_duplicate_fence_rearm_attempt` and `claude_duplicate_fence_next_full_rearm_unix_seconds`. Losing them, or finding an implausibly distant deadline, makes the next closed census re-arm at once. That costs work but never opens the fence. Closing the fence re-arms immediately, and opening it re-emits posture once and resets the backoff.

The census counters add `coverage_complete`, `coverage_missing_member_count`, `full_rearm`, `rearm_attempt` and `full_rearm_deferred_until`. Each page also logs how many Claude files were selected for parse under each selection reason (counts only, for example `upload_context` or `rearmed`).

### Limits

A terminal-held key keeps its committed revision while the upload context advances, so its entity is re-derived only after the quarantine resolves. An indexed member whose file stem differs from its session id, or an indexed but unparseable member, keeps the fence closed: this fails closed, at the cost of periodic replay. Out-of-order growth and in-place changes to earlier responses remain unsupported and invalidate the family. These changes do not by themselves establish lower CPU or memory use.
