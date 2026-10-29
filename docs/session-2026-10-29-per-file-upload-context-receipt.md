# Per-file upload-context acceptance

Claude Code and Codex retain source-wide upload context only after a complete
census. An incomplete census can therefore reselect an already delivered file
on every subsequent walk. A local optional `ScanIndexEntry.upload_context_receipt`
now lets each file settle independently while the source-wide witness differs
from the active context. A matching source-wide witness already suppresses this
debt, even without receipts. Selection and finalizer no-op bypass share this
conjunction, so a quiet upgraded index needs no catch-up read or upload.

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
quarantine contract string; it adds no field or identifier. A context-only
reassessment never leases an ordinary retry before its existing deadline. Empty
or policy-suppressed files gain no receipt and retain their existing source-wide
context gate, allowing a later policy to make them uploadable.

Interrupted uploads continue to honor the existing durable exact-body ACK
ledger: accepted pages are not sent again merely because a whole-file receipt
is absent. Those restored ACKs cannot mint a receipt; only current-cycle exact
ACKs do so. Ordinary and continuation prepares share the activation seam for
the index and progress quarantine witnesses and reset runtime receipt evidence
at that boundary. The common finish path captures each page's candidates after
admission. The synthetic head-CAS ACK helper returns an accepted head etag for
cache-bearing requests and leaves the production validator intact.

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
file count as an all-populated storage envelope, not an upgrade catch-up
estimate; no live transcript inventory was read for this change.

The 0.1.201 and 0.1.202 complete entry codecs are frozen in the regression fixture
with their source pins. They ignore the optional field and drop it on save.
A downgrade-then-upgrade costs one re-upload pass where source-wide context
still differs; already adopted sources stay quiet. The same drop behavior applies
to 0.1.203. Current encode/decode retains the receipt.

Mixed Codex files that cannot earn a whole-file receipt can still loop while
the source-wide context differs, as in base. Mixed-file backoff belongs to #899
(C1), not this repair. Confirmed-empty files keep the source-wide gate. A
counts-only read of current indexes at 2026-10-29 16:44 UTC found zero files
with both a quarantined entity and an accepted sibling in either source. There
were 57 confirmed-empty Codex files (8,438,034 indexed source bytes) and 2,598
Claude files (79,992,500 bytes). These retained cohorts do not measure active
policy eligibility, per-day reads or wire bytes; other withheld/mismatched groups
are not sized by this classification. UploadContext-only reads become zero for
unchanged files that settle, not for every residual file. A path move while
context debt exists can cause one wire re-upload, with no additional read.

Regression fixtures cover matched-context upgrades without receipts and mixed
accepted/quarantined file groups (three relists, zero parses and native bytes),
three quiet walks for both sources, a blocked Codex
census, context switches, restart, generation replay, held/refused backoff,
parse/finalize/quarantine/prior-context refusals, stale witnesses and old decoders.
Validation for this change is local all-target Clippy compilation and formatting;
no Rust tests or production daemon operations were executed. Runtime fixture
execution and post-release live before/after measurements remain unverified.


Context-stamped progress ACKs make that fresh receipt reachable for identical
bodies. `accepted_body_contexts` is an optional map parallel to the durable body
witness map. A stamp is written only from a live stored-body entity ACK, under
the active context; a count-only ACK leaves it unknown. Only current receipt
candidates can bypass body suppression for a differing stamp. Unknown stamps
bypass only while the source-wide context also differs; upgraded quiet sources
remain quiet. Same-context page ACKs survive restart and are never re-sent merely
because the whole-file receipt is still absent. Stamps alone never mint receipts.

New/grown native files and new upload revisions precede identical catch-up in
the existing page slots and bounded batch packing. Catch-up uses normal ACK
admission, byte limits, retries and pacing. Current destination policy always
projects re-sent bodies. `upload_context_resend{entities,bytes,identical,changed}`
counts each logical entity attempt once in the cycle; bytes are serialized item
bytes, excluding request envelope. Stamped accepted entities do not count again
after restart. Not-stored/duplicate-refused responses mint nothing. Not-stored
context candidates retain quarantine retry custody (6h then12h, capped at12h,
then existing terminal attempt cap); unchanged mixed files wait with accepted
siblings. Growth bypasses this unchanged-file hold and can earn a receipt on an
accepted new body. `upload_context_not_stored{files,bytes}` shares the diagnostics
line; bytes are indexed source sizes. Neither hold grants acceptance.

Each stamp carries a64-byte context H. A separate compact-JSON map costs134 bytes
per body plus27 bytes per nonempty map, because it also repeats the64-byte entity
key. Current aggregate M4 progress snapshots held zero accepted body entries in
both sources, so their immediate stamp growth is0. The read-only index cohort at
2026-10-29 17:36UTC was4326 Codex entities (14,069,232,523 native source bytes) and
12249 Claude entities in12255 nonempty files (20,873,860,321 source bytes).
These are full-catch-up cohort/native-size proxies, not measured wire sizes or
per-day savings; wire body lengths are not retained in these metadata files.
The earlier approximately14.5k Claude-file capacity/20.49GB source-scale estimate
remains useful for #899's historical scope. Already matched source-wide contexts
have no upgrade catch-up. Actual resend/not-stored counts and Codex daily reread
bytes before/after are reported after release, using demo account and M4 logs.

Frozen complete progress codecs at0.1.201,0.1.202 and0.1.203 ignore the stamp map;
missing maps load as unknown. All receipt-adoption quietness fixtures now drive
the production resumable uploader with retained progress and validated fake
transport. Direct `exact_acks` helpers remain mint-refusal unit seams only.
