# Activation-off census safety shadow

Fix 3 phase B separates transcript retirement safety from money-visible request
hashes. Retirement moves the shared hash buffer; money getters remain empty.
A maintained oldest-retired queue lets an incoming active record reclaim only
the safety slots it needs. Active hashes are never reclaimed. Optional safety
metadata is best effort under serialized pressure; loss retains global safety
debt rather than making a negative certificate.

The census stores `!safety` with up to 4,096 SHA-256 local key ids, their first
incomplete timestamp, cumulative reclaimed hashes and a sticky overflow flag.
Missing or malformed persisted metadata closes strong shadow comparison.
Healthy complete-terminal prune or full authorized reconstruction removes a
key. Overflow cannot clear through timeout, prune or restart.

Record-local `x` holds acquisition, loss, bounded content pairs and capability
metadata. `sb` holds retired-only safety hashes using the existing base64 u64
codec. Existing fields, derivation, money getters and activation gates retain
their contracts. Ambiguous record keys never become last-wins evidence.

The terminal builds one diagnostic join. The usage fold compares same-window
legacy duplicate keys before authority/fence mutation; full request hashes
remain the legacy duplicate identity. A digest basis checks record and pending
equality after save. Provisional comparison and successful CAS alone cannot
qualify evidence restored from a different selected subset.

`request_census` distinguishes safety-incomplete debt, retired-peer sharing,
unread acquisition, old capability debt, optional metadata refusal, workspace
refusal and unqualified comparisons. Fixed diagnostic encoding remains bounded
at 8 KiB. Correction projections are unknown until their real tap is wired;
zero is not asserted as measured demand. No runtime corpus receipt is claimed.

Activation OFF; Fix 3 phase B. No selector, scheduler, history replay, new file
read, production activation or release is introduced. Validation runs only in
CI on the exact pushed head; no local Cargo or tests.
