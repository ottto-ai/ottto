# Held-family and blocking-hold diagnostics

Added a start-row observation of the persisted canonical held-family digest
set, plus sparse local hold-reason counters next to the restore counters.
These explain repeated holds without emitting identifiers or paths. Unknown
or invalid scope has a null digest; it must not be interpreted as no holds.

No persisted format, selection, hold, money, census, upload or wire contract
changes. Hashing is linear in the bounded held-root set, with constant scratch
space. Reason counters observe existing branches without another index scan.

Regression coverage checks digest order independence, changed membership,
invalid scope, other-source isolation, authority/account classifications,
failed-restore classification, sparse serialization, merging and saturation.
Local validation is limited to explicit-file rustfmt 1.95.0 and diff whitespace
checks. Runtime validation belongs to Linux CI and the native macOS contracts
workflow. Strict independent review is required before handoff; CI and review
receipts are recorded in the pull request.
