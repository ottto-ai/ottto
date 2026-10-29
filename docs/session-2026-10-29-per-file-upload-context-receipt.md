# Per-file upload-context acceptance

Claude Code and Codex retain source-wide upload context only after a complete
census. An incomplete census can therefore reselect an already delivered file
on every subsequent walk. A local optional `ScanIndexEntry.upload_context_receipt`
now lets each file settle independently of that source-wide witness.

The receipt holds the existing context H digest, numeric capability replay epoch,
source H digest, and effective upload-body-set H digest. It never enters an upload.
Historical replay already resets delivery authority; it also discards receipts on
retained entries. A candidate captures the historical replay tag in memory, so an
ACK crossing either replay boundary cannot adopt. A context switch leaves old
receipts untouched until that file receives a new exact ACK.

Minting occurs on the final selected index, only after every entity of the file
has a fresh exact entity ACK for its admitted post-policy body in this cycle.
Restored ACK ledgers, count-only responses, parser completion, finalization,
quarantine, unstored unchanged responses and prior-context ACKs grant no receipt.
Partial file groups and restored held revisions cannot borrow sibling ACKs.
Shed/error partial checkpoints normalize runtime leases only for comparison;
they persist a receipt only for a complete selected file with fresh exact ACKs.
Reloaded ACK ledgers cannot mint one.
Byte-identical old bodies bypass no-op suppression only for this per-file debt;
permanent refusals and current quarantine retain their backoff. The existing
quarantine contract witness is bound to the upload-context H, so a policy change
can reconstruct a previously refused body. An identical re-projected refused
entity/body keeps its existing disposition, deadline and failure budget under
the new witness, without gaining acceptance. This adds 80 bytes to each retained
quarantine contract string; it adds no field or identifier. Empty or
policy-suppressed files have no body to acknowledge and gain no receipt.

The change grants no census completion, absence, retirement, tombstone drain,
account-window retirement, sole-login or terminal-fold authority. Destination
admission and privacy projection still run before receipt candidates are captured.
Pi retains its source-wide selection behavior.

The local `upload_context_rearm{files,bytes}` disclosure counts completed re-arms
once, emitted after the receipt's index save succeeds. Bytes mean indexed source
file size, not network bytes or measured savings. A restart with a matching
receipt reports no new re-arm. Failed/held files gain neither receipt nor count.

For three 64-character H digests and generation 0, compact persisted size grows
304 bytes per entry (up to 323 at `u64::MAX`). At approximately 14,500 indexed files,
this is 4,408,000 bytes, or 4.20 MiB (maximum 4,683,500 bytes). On supported 64-bit
layouts the receipt adds 80 inline bytes; three digest strings add 192 payload
bytes before allocator and tree-node overhead. Entry size grows 480 to 560 bytes;
heap-bound accounting includes the receipt. This estimate reuses the existing
file count; no live transcript inventory was read for this change.

The 0.1.201 and 0.1.202 complete entry codecs are frozen in the regression fixture
with their source pins. They ignore the optional field and drop it on save.
A downgrade-then-upgrade costs one re-upload pass. The same drop behavior applies
to 0.1.203. Current encode/decode retains the receipt.

Regression fixtures cover three quiet walks for both sources, a blocked Codex
census, context switches, restart, generation replay, held/refused backoff,
parse/finalize/quarantine/prior-context refusals, stale witnesses and old decoders.
Validation for this change is local all-target Clippy compilation and formatting;
no Rust tests or production daemon operations were executed. Runtime fixture
execution and post-release live before/after measurements remain unverified.
