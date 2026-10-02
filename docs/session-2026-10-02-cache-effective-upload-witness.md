# Cache evidence and effective upload witnesses

The local scanner previously compared the raw cache evidence body before the
uploader applied capability and accepted-head requirements. A successful ordinary
upload could therefore save a raw body witness for cache evidence that was never
sent. A later unchanged scan could suppress that evidence before upload.

The sync caller now uses one pure cache preparation function for both the
finalizer's effective body witness and the network body. Local consumers retain
the original evidence. The caller activates per-file projection revision 1 before
taking the committed baseline and scanning, so existing indexes adopt the
corrected projection through normal file-group settlement. Files containing held
items remain excluded from adoption until eligible.

Before effective no-op filtering, the caller captures admitted missing-head
identities without cloning request bodies. After finalization, durable upload
progress binds those identities to the exact current file and entity groups. A verified head
arrival reselects only affected files. Ordinary ACKs without head authority do
not settle that obligation. Matching cache body ACKs and saved sibling settlement
retire it; interrupted uploads and failed index saves preserve retry. A suppressed
ordinary no-op does not initiate another transport route. Its obligation stays
pending through restart until an existing legitimate upload or exact CAS probe
provides a validated head.

Focused tests exercise the scanner, finalizer, actual ACK validation, index
save/reload, capability transitions, quarantine, shared-session file bindings and
bounded progress storage. The change does not alter semantic identity, wire
contracts, prices, billing or cache-retention claims. Shipping source code alone
does not prove populated customer observations.
