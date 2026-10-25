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
