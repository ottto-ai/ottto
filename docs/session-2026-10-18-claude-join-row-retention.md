# Claude join row retention

Three local allocation eliminations preserve the existing proof and ownership
rules. Proven families keep API row clones only when the current page has an
item under that root; every proven key and witness remains for rebind, retention
and rearm. Legacy exclusions borrow the owner graph already built from the same
immutable reports instead of rebuilding it. That graph's canonical reducer
borrows API rows because it only reads request ids and fingerprints.

No row filtering is applied to the loaded cross-root reports. A global legacy
owner failure remains None, so unrelated invalid or ambiguous roots still veto
copied-prefix exclusions. The canonical validation/fold, proof, authority,
quarantine, identity, accepted bodies and ACK/debt settlement are unchanged.
No persisted state, wire field, cap or resource-guard exemption is added.

The terminal regression compares BASE row retention and candidate retention on
identical N-family input, requiring exact page body, complete index and authority
disposition parity, including all unrelated witnesses and debt. An isolated
thread-local test-only BASE control keeps the original row lifetime; production
has no switch. The same actual-path comparison measures requested allocator peak,
not RSS. Existing legacy exclusion and ledger regressions cover the shared graph
and borrowed canonical rows. Supported CI and independent review are required;
no installed CPU, memory or IO saving is implied.
