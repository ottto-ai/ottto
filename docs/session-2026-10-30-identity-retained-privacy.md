# Retained request identity privacy

Retained identity remains gated by the exact server capability
`session_request_identity_retained:v1` and defaults off. Only a versioned,
witnessed stored-body ACK can save the proving row's account hash. The saved
hash supplies the grain of that same login-proved marker row; parts-proved
markers carry none, and saved state never creates identity evidence.

A superseded proof becomes a hash-free tombstone before the replacement upload.
Missing-proof feedback removes the proof and hash so fresh tags compete within
the existing wire caps. Namespace, replay generation, key rotation and session
LRU eviction erase retained rows. Forget-installation removes the snapshots
subtree; uninstall removes the support directory that contains it.

Retained row Debug redacts the account field. Diagnostics and status export
fixtures place an actual retained ledger on disk and assert that neither its
hash nor its compact representation appears in exported output. The maximum
ledger retains the accepted 4 MiB layout bound; the progress JSON and load-peak
bounds remain 7,900,000 and 13,500,000 bytes respectively.
