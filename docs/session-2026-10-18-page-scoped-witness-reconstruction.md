# Page-scoped Claude witness reconstruction

## The cost

Every Claude source finish loads local API and trace evidence for every retained usage-family witness, plus this page's roots. The reported-usage rebuild then reconstructed every witnessed family that it did not prove on this pass. Each reconstruction re-runs the usage-ledger reduction and clones the family's assigned API rows into one map, and that map stays alive until the rebuild returns.

Only two places read that map:
- the rebuild loop, for items in this call;
- the context-posture loop, for items in this call.

Its use inside the witness `retain` was redundant, because every witness present before the rebuild is already kept through the earlier-root set. Families without an item on the page therefore paid a reduction and a full API-row copy that nothing read.

## The change

The rebuild now reconstructs only witnesses whose root belongs to an item in this call. This applies in both branches:
- complete census with healthy reports;
- incomplete census with healthy reports.

## What stays the same

These are unchanged:
- the evidence load set;
- request-identity evidence;
- the legacy request-owner map and its global uniqueness check;
- proven-family construction;
- witness retention;
- quarantine, rearm and duplicate-fence decisions;
- caps, persisted fields and wire output.

## Tests

Two synthetic tests use single-member families proven by one complete census.

1. **Parity.** A non-terminal page that parsed one family is rebuilt with all families' telemetry loaded. The test asserts that the rebuilt item serializes identically whether 0 or 8 unrelated witnessed families exist, and that witnesses and quarantine stay unchanged.
2. **Allocation.** The thread-local allocation probe measures the rebuild phase peak with 8 and with 32 witnessed families. The test asserts that each extra unrelated family adds less than one copy of that family's API rows.

The probe counts requested allocator bytes. It is not process RSS, and it does not depend on the validated heap layout.

## Limits

- At source publication these tests needed hosted CI validation. No local Cargo build or test ran.
- This removes one avoidable allocation owner from the finish phase.
- It does not reduce the evidence load set, which still scales with all witnessed families.
- It does not establish an installed memory or CPU saving.
