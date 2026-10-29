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

Round 7 removes the receipt-specific native freshness promotion. It could split
terminal-family members across pages and disturb delivery-free membership;
the protected census pipeline assertions remain unchanged. Receipt transport
priority now leaves native census/family selection to its existing owner.

Identical-versus-changed classification compares the prior semantic entity set
as well as the additive body witness. Additive witnesses omit display titles,
so title redaction under the current destination policy is a changed ordinary
revision even when its additive digest is equal. The real-uploader privacy
fixture retains its changed-counter assertion and checks both the title-bearing
old POST and the title-free new POST.

At upload packing, every ordinary new/changed body precedes stamp-only catch-up,
including within mixed family units. Separate requests isolate ordinary bodies
from catch-up retry latency. All ordinary input reserves bytes first; ordinary
uploads remain admitted even when they exceed the allowance. The existing
2 MiB request-packing target now also caps stamp-only catch-up across a source
pass, and catch-up uses only its remaining bytes. This is a new catch-up ceiling
using an existing constant, not a pre-existing aggregate upload cap. Deferred
offers retain context debt and use the existing Deferred/partial-save path;
only a real ACK stamps a body. A restarted next pass sends the remainder without
re-sending newly stamped bodies. The tight-budget fixture covers both sources.

Cache-head bootstrap cannot send catch-up probes before ordinary full bodies.
Paced-out probes wait for a later pass without inventing a head token or
blocking ordinary siblings. No persisted field, timer or daemon operation is
added by these round-7 repairs. Validation runs no local Cargo tests.

Round 8 paces native context-only acquisition before parser construction.
At the previous head the file cap and Codex cursor budgets still applied,
but Claude context-only Full reads had no general native-byte cap and transport
could defer already-parsed bodies. Repeating that Full parse on later passes
invalidated the intended one-time read exposure.

Only pure context debt moves behind ordinary new/changed/recovery/authority
work; relative family order in that ordinary prefix is preserved. A deferred
context file returns to the same durable traversal with its census membership,
without constructing its body parser. Admission reserves both native bytes
and wire capacity: entity count times the maximum641KiB legal item, times
three for the possible two head-bootstrap POSTs plus final POST, with separator
reserves. Ordinary bodies reserve their built serialized sizes first. The
native allowance reuses Codex's64MiB singleton/cursor and Claude's1GiB history
allowance after ordinary body acquisition. A legal Claude file fits that
allowance; larger Codex singletons continue through their existing cursor.
A conservatively oversized wire group may be admitted alone; actual sends
still obey the transport backstop. No new durable size field is required.

Actual native body-reader deltas populate `local_bytes` on the existing context
resend/rearm diagnostic lines. `bytes` now consistently means serialized item
wire bytes, excluding request envelopes, rather than indexed native length;
resend also discloses files read. Zero-byte cache reuse is zero local bytes.
Counters and scheduling state are runtime-only. The portable real scan/uploader
fixture forces cold acquisition, spans more than three pages, puts a changed
file first under a tight native limit, checks every file parses exactly once,
requires a receipt for every parsed file in that same page and checks actual
local bytes against the source lengths. No macOS-gated fixture is modified.

Review follow-up: joined Codex aliases are admitted atomically using their
unique entity union, so aliases do not reserve the same wire body repeatedly.
A single conservatively oversized logical unit may use its own source-pass
allowance (the explicitly allowed alone exception). That allowance travels
only in runtime state to transport, allowing its complete current-pass ACK set;
each individual POST still uses the normal2MiB packing limit. This prevents
partial ACK/stamp progress from making a multi-entity file permanently owe a
fresh receipt. Resumed jobs reserve the same allowances and return intact to
the cursor slot when deferred. A batched requeue preserves original watcher
and census flags with one queue walk, avoiding quadratic deferred-tail work.
New portable fixtures cover joined Codex aliases and a synthetic post-policy
multi-entity file above the normal aggregate wire allowance, in addition to
the cold eight-file scan across more than three pages.

Ordinary joined Codex groups are prioritized before the preparation loop spends
its file allowance; prioritizing only the admitted queue was too late. Existing
own-page and census-member order remains inside each class. The joined-group
read-budget fixture now uses a three-file cap for two two-member groups, so it
also covers early file-limit deferral. A context cursor is charged prior ordinary
native reads before taking cursor room. Rearm wire bytes count a shared logical
entity once even when several physical aliases receive receipts.

The conservative wire reservation is1,969,161 B per entity, so an ordinary
one-entity context file generally takes one otherwise-empty pass. At a hypothetical
five-minute pass cadence, the measured4305/12261-entity cohorts imply roughly
14.95/42.57 days of normal pages before ordinary traffic, holds or cursor pacing.
These are sizing scenarios, not measured completion forecasts. Aliases share an
entity reservation and oversized logical units retain the explicit alone-pass
exception. This replaces the historical byte-throughput timing scenario; measured
wire totals remain estimates from recent POST traffic. Runtime fixtures are run
in Linux CI, never locally; local validation uses the serialized all-target clippy
wrapper. No macOS-gated tests were touched.

Round 10 reserves ordinary singleton file slots before any context-only joined
Codex group spends the remaining page allowance, including census-member and
oversized own-page groups. Ordinary own-page/census ordering remains inside its
class. Slot eviction prefers context-only/skip work over an ordinary singleton.
The existing native/wire read-budget implementation is unchanged. Two portable
real-scan/uploader fixtures cover an unhinted new file and a same-size mtime-only
rewrite at file limit two, with two- and three-member context groups deferred
unparsed and settled on a later pass.

Linux runtime evidence also exposed an oversized transport override being applied
when final projection contained ordinary work. The override now requires no
ordinary pending body and no earlier catch-up admission, and is consumed once.
The unchanged tight-wire fixture failed on the previous head with four POSTed
items where only two fit; it retains that assertion and now measures received
catch-up bytes each pass. The cold multi-pass scanner fixture checks both actual
wire remainder and native read allowance. The alias fixture's previous expected
sum counted both scanner aliases; transport deduplicates the fingerprint before
POSTing one representative. Its counter assertion now uses bytes received by
the fake transport. Resend entity classification remains once per cycle while
wire bytes charge each actual POST attempt. Settled receipt groups take the normal
candidate skip path so unchanged aliases stop reparsing on subsequent relists;
ordinary recovery gates and protected census assertions remain intact. No local
Cargo tests; all-target wrapper clippy and Linux CI provide validation.
