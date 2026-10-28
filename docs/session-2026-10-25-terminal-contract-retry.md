# Paced retries after reconstruction contract changes

The exact semantic-fingerprint/upload-body-witness retry budget belongs to
`SnapshotQuarantineRecord`, retained in the scan index and the upload-progress
ledger. `ClaudeUsageAuthorityQuarantineRecord` instead binds a retained family
proof and its member revisions; it has no upload-body witness. This change
uses the former record so identical rejected bodies can be reassessed once
when reconstruction semantics change.

`reconstruction_contract: u16` defaults to 1 on legacy decode. The current
constant remains 1: introducing the mechanism grants existing v1 records no
retry. Bump it only alongside a reconstruction logic or contract change.
A newer contract changes only an older `unproven_terminal` record to
`retry_pending`, retains MAX-1 failures and stamps the new contract immediately.
The existing fingerprint-jittered 6–12 hour deadline paces that final attempt.
The loaded record adopts the active collector witness so a simultaneous
collector upgrade does not bypass the deadline. A failed reconstruction stamps
the current contract and returns terminal; a reload at that version cannot
rearm it again. Superseded records stay terminal. Server-permanent refusals
retain their separate reason-scoped reoffer rules.

The normal nested serde serializer and typed quarantine-map dispatch carry the
new field. The lenient scalar-repair representation explicitly preserves it.
The lenient decoder's `FIELDS`, serializer entries and dispatch registry name
ScanIndex top-level fields; this nested record member adds no top-level field
and no identity-carry field. Heap-layout inventories include the record field
and the upload ledger's transient pending-save flag.

No history replay, family-proof rearm, account rewrite or new upload field is
introduced. The existing terminal-census local line appends
`terminal_contract_retry`, a process total of local record transitions (both
index and disposable ledger copies can contribute).

Synthetic regression coverage exercises legacy decoding and scalar repair,
v1→v2 pacing, same-version and future-version suppression, one failed attempt
returning terminal, stale-ledger reconciliation, retained account/workspace
bindings, unchanged history-gate state, and a two-file Claude scan where the
retry selects only its owning file. Tests run in Public CI; local validation is
explicit-file rustfmt and bounded `cargo check -p ottto-service --tests`.

## Malformed bookkeeping and interrupted retries

A malformed-present reconstruction version decodes as unknown (`0`) in both
checkpoint representations, preserving every other field. The decoder consumes
invalid scalar or container values without retaining their contents. Absent
fields still mean v1; valid u16 values remain intact. Unknown pending or unproven
terminal records receive exactly one paced attempt at the current version, then
persist that stamp. Superseded and server-permanent gates remain in force.

Regression fixtures keep account/workspace bindings, prior ACK fingerprints and
body witnesses, cache states/heads, refusals, the identity-contract token, its
latch and history markers beside the damaged record. They cover null, strings,
negative/overflow integers and other JSON shapes, both ordinary decode and the
index's scalar-repair path, and checkpoint save/reload. Separate bumped-contract
success and selected-lease restart cases exercise exact ACK settlement, stale
index suppression and an interrupted attempt returning only after pacing.


## Durable acquisition bound

Contract-origin retries carry `contract_retry_claims: Some(n)` alongside their
version. Ordinary retries omit this member. Migration starts at zero; selection
increments and saves the claim in upload progress and merges its maximum into
the scan index before granting a runtime source lease. One claim selects one
indexed owning file. A restart restores no runtime lease. It retains the saved
claim and paced deadline, allowing at most one further claimed acquisition.
After two claims, an unsettled retry becomes terminal again; a conflict cannot
reset this budget. Ordinary conflicts retain their existing failure-count
behavior. Actual reconstruction failure can still return terminal sooner.

Same-version, exact-body merges and both checkpoint CAS paths retain the maximum
claim count. A newer claim also retains its cooldown; older index copies cannot
reopen it. A malformed-present counter is conservatively exhausted, preserving
the enclosing record and checkpoint. A new reconstruction version starts a new
bounded obligation. The local terminal-census line additionally discloses
`terminal_contract_retry_exhausted`; no upload field changes.

Synthetic scanner regressions count actual parser-read acquisitions for the
owning file and unrelated files over seven due cycles. They cover restarts
before outcomes, repeated server conflicts, actual post-read checkpoint-write
failures, stale index merges, same-generation CAS restoration and malformed
claim metadata, while preserving the retained identity and ACK fixture.


A legacy absent body witness is unknown, so learning its first exact body does
not erase a contract-origin counter. Budget merges conservatively bind that
unknown witness to the learned body, while two different known bodies retain
the existing independent-pair behavior. A separate real-scanner conflict case
covers the absent-body migration and its two-acquisition bound.

## ACK lifetime across a post-upload crash

Incremental upload input is a delta, not a census. A crash after an exact ACK
is saved in upload progress but before index settlement can leave that ACK
outside the next scan's empty or unrelated-only delta. Preserving its body in
test input masked this reachable production boundary. Upload-progress ACK
retention now owns that lifetime independently of the current delta and retires
evidence only after durable index adoption or a bound retirement handoff.

Contract-retry tests no longer insert an already ACKed sibling into uploader
input. The SOURCE regression claims and reads the held file, saves its validated
ACK through the actual uploader, drops both checkpoint objects before index
settlement, and resumes using the scanner's actual empty or unrelated-only
delta. It checks both crash windows, no reread of the accepted file, exact body
witness retention, durable index adoption, and preserved bindings, contract token
and latch. The existing conflict and failed-outcome-save tests retain every
ACK/read-cap assertion while excluding the ACKed sibling from upload input.
