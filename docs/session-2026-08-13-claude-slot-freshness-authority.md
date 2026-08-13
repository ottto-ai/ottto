# Claude slot freshness authority

Stable `0.1.113` production QA found a local-control race on a two-account Mac.
The normal source snapshot held a fresh exact Team quota bundle, while a later
concurrent default-slot scan fell back to Claude's lower-fidelity status line.
The slot-state merge retained the exact values but marked them stale, so the
Companion could disagree with both the daemon source snapshot and production.

The slot-state merge now keeps a same-account, same-organization exact snapshot
fresh when the incoming observation is fresh-but-partial and the snapshot is
still inside the existing account-jittered OAuth usage freshness horizon. It
keeps the original provider observation time, never extends the provider cache
horizon, and still marks the values stale after that horizon. Provider failures,
identity changes, organization changes, and cross-slot candidates retain the
existing fail-closed behavior.

Regression coverage proves both sides of the boundary: a fresh status-line
observation does not downgrade a still-fresh exact bundle, while the same
observation after the maximum cadence becomes stale. Freshness is evaluated at
merge time rather than the incoming observation time, so replaying an older
partial observation cannot extend the exact snapshot's lifetime. Existing same-identity,
cross-identity, retention-expiry, and malformed/future timestamp controls remain
green.

This change does not add a provider call, OAuth lifecycle operation, Keychain
write, login action, inference prompt, schedule, or new wire field.
