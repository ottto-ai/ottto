# Durable-tail format v2 bootstrap

Format v2 ships enabled for Claude Code and Codex. Pi remains outside this
store. Representation dispatch uses format, source and allowlist; a future
v2-only source needs no v1 pin and does not change existing source allowlists.

The fixed extension carries namespace and object identity, acquisition protocol,
recovery authority, held-new reuse state, body-witness revision and separate
counting contract/evidence. Coverage, fragment and provisional sections are
absent. There are no private-local values or additional private-local slots.
The audit-debt presence/deadline is omitted; v1 decoding consumes and drops it.
The certificate's verified timestamp remains until audit policy is retired.

Both pinned v1 writers share one envelope serializer and reduction allowlist.
Restore first validates their own format-1 scope against current inputs. Only
then does it decode and restore. The next ordinary post-save write rebinds v2;
there is no eager migration. A failed format-only rewrite and subsequent GC
retain the verified old representation. Counting cutover, interpretation and
acceptance evidence come from the decoded reduction. The owner digest binds
the stored key, object and head digest, with no transcript acquisition.

Reserved carriers hold acquisition and all mutation. Spent carriers survive
all deletion, and verified same-namespace/object writes copy their authority.
Another object or namespace holds until recovery-aware reconciliation. This
binary creates no recovery mark. The predecessor's counted T14 rebuild policy
remains; a damaged marked carrier is preserved instead of rebuilt.

`upgrade_state_missing` reports a missing record on an indexed cold-cache file's
first real content change, with a local-resources alarm. Idle files hold. The
existing replay ledger and save-before-read reservation carry the once-per-file,
per-release allowance; losing an unconsumed ticket conservatively holds. Ledger
capacity also holds. Existing unsupported-layout memory-only behavior remains.

Rollback holds every newer-format record's file until re-upgrade. After a
rollback longer than 24 hours, the operator decides hold versus counted reread;
the default remains hold. No record, object identity or digest value is logged.

Validation runs on CI only: Linux tests, native macOS contracts and emitted-money
equivalence. Synthetic fixtures exercise old-writer bootstrap, second restart,
R29 controls, counting provenance, marker mutation paths and pre-acquisition
holds. No live provider data is needed.
