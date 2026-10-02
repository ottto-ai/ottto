# Claude ownership recovery after partial uploads

A partial snapshot upload can accept a healthy Claude session while deferring an
unrelated entity. The collector retains an incomplete delivery sweep, then runs a
clean bounded census. Previously, unchanged files could be skipped while their
pending request evidence still belonged to the older census window. The clean
census rejected that stale proof and retired it without verifying owned-start;
later unchanged scans had no request evidence with which to recover.

At the beginning of a fresh bounded Claude census, indexed members of pending
families from an older window are re-armed for ordinary parsing. This
reconstructs evidence within the current frozen window; it does not establish
ownership by itself. Complete-census cleanup retires this reparse obligation,
so stable duplicate or unproven sessions return to no-op. A well-formed,
witness-bound authority quarantine deliberately retains old pending evidence
and keeps its existing deadline, revision-change and terminal retry gates;
that retained proof is excluded from generic re-arming. Unknown or malformed
stale proof still requires reconstruction. Resuming a page in
the same census does not re-arm files already consumed by that generation.

Eligible pending roots are evaluated once per family, so large quarantined
families do not repeatedly hash the same retained witness for every file.
When files are re-armed, a counts-only diagnostic records pending family and
file counts. Existing source-cycle duration, scanned-file, and census counters
measure the bounded recovery work; no paths or session identifiers are logged.

Ownership still requires the existing complete duplicate-request census,
request identities, explicit owned-start/predecessor rules, and matching source
fingerprints. Upload acceptance, head CAS, quarantine, incomplete sweep markers,
terminal manifests, and backfill completion retain their existing boundaries.
No reset, forced replay, cap increase, CLI change, or schema change is required.

The regression uses synthetic sessions, a partial-settlement subset, and durable
save/reload between pages. A fresh no-conflict census verifies ownership. One
unrelated conflict keeps the original sweep incomplete; a subsequent clean
census verifies the unchanged accepted sibling. Changed-source and restart
controls use the same ownership checks.

Additional controls keep a future unrelated quarantine deadline and unaccepted
state unchanged while local ownership recovers. A duplicate request on the last
page still refuses ownership and returns to no-op. Recovered cache evidence
contains the owned warm/cold/warm sequence (100,000 prompt tokens and cache reads
90,000 / 0 / 90,000); the copied 900,000-token prefix is excluded.
