# Retain the authority proof until its restriction resolves

A healthy terminal native census can derive a new Claude family proof while an
older RetryPending record remains unresolved. Previously the fold installed the
new witness immediately, leaving the record bound to its previous witness. The
strict loader then quarantined the entire saved index and returned fresh state.

The fold now keeps the retained witness while that restriction remains. The new
proof stays in the already-owned proof map for rebuilding this pass's bodies.
Existing resolution installs the new witness together with removing the resolved
restriction in the same selected index mutation. A restriction created during the
same fold also retains its original proof. The terminal proof-correction grant
keeps its immediate paired update, so a failed corrected-body rebuild demotes
against that updated witness without receiving a later grant.

No persisted format, load predicate, retry deadline, attempt limit, ACK ledger,
held-body policy, account attribution, census condition or resource cap changes.
This prevents new mismatched saves; it does not recover previously quarantined
indexes or shorten reconstruction retries. Installation, historical attribution,
CPU savings and RSS effects require separate evidence.

Validation uses a real bounded native traversal with prior accepted bodies and
an unresolved RetryPending record, plus selected-subset, stale CAS and restart
conservation checks. Controlled fold cases cover same-pass demotion, existing
resolution, failed terminal correction without a late regrant, and per-member
contract-5 serialization under the production emission gate and exact ACK
validator. Supported CI and independent review are required before intake.

The first supported implementation CI repaired the real native writer/load
failure and passed selected-subset, stale-CAS and restart conservation. It also
exposed a separate freshness conflict: the historical member-change oracle
expects the next nonterminal page to resolve from a newly persisted proof, which
is unsafe while the old restriction remains bound to its prior proof. That
historical oracle and its wrapper remain byte-identical. A separately named
phase trace runs the same logical page order and reports the retained proof and
held next-page bodies. Its passing negative observation must not be reported as
restored original liveness; the historical oracle remains an expected failure
until a separately qualified mechanism resolves the conflict. No intake claim.
