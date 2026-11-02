# Accepted head revision progress

Upload-progress schema v4 stores the optional `accepted_revision_v2_hash` from
stored-body accepted/unchanged head-CAS ACKs, keyed by the accepted entity
fingerprint. This is the server-canonical head revision, independent of the
upload's content hash or local revision. A supplied hash replaces the prior
value; absence retains it. Legacy requests ignore the additive response field.
No recomposition reader or activation is added.

The privacy allowlist classifies this as H, bounded to one 64-lowercase-hex
value per accepted entity. Debug redacts it; diagnostics never export its bytes.
Existing ACK admission bounds the map and heap accounting includes it. Replay
reset, entity retirement, not-stored holds and source-off erase share the owning
record's lifetime. Failed retirement saves restore the in-memory proof.

Version 3 loads without the field and migrates on the existing generation-CAS
save. Future versions hold without quarantine or overwrite. Authenticated ACK
receipts continue sealing the exact progress bytes under their unchanged
wrapper version.

Validation: focused fixtures cover non-CAS handling, hash shape, canonical head
storage despite local differences, replacement, absent re-ACK across restart,
v3 migration, future hold and entity/source erasure. Local validation is
rustfmt and diff hygiene only; Rust compilation, clippy and tests run in Linux
CI. Memory footprint was not measured; the change adds one bounded digest map
and does not run the installed service. Independent money review is pending.
