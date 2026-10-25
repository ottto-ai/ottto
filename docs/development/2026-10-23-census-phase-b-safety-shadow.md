# Activation-off census safety shadow

Fix 3 phase B separates transcript retirement safety from money-visible request
hashes. With the explicit shadow switch enabled, retirement creates shared bounded chunks; money getters remain empty.
A maintained oldest-retired queue lets an incoming active record reclaim only
the safety slots it needs. Active hashes are never reclaimed. Optional safety
metadata is best effort under serialized pressure; loss retains global safety
debt rather than making a negative certificate. Retired reparses first decline their
own reconstruction safety when it does not fit. Peer reclaim may fund their
main-equivalent MONEY core metadata, and never funds extra reconstruction
safety; the same oldest-retired queue and incomplete marker apply.

The existing root shadow metadata stores `s` with up to 4,096 SHA-256 local key ids, their first
incomplete timestamp, cumulative reclaimed hashes and a sticky overflow flag.
Missing `s` is empty on an upgrade with no `x`/`sb` records; it is closed when extension records exist. Malformed or duplicate metadata stays closed.
The bounded key marker is charged as shadow metadata; record serialization and
active-plus-safety hash storage retain their existing 47/48 MiB boundaries.
Healthy complete-terminal prune or full authorized reconstruction removes a
key. Overflow cannot clear through timeout, prune or restart. A single malformed or
dropped census record (including a duplicate key) creates sticky decode-loss
overflow until a derivation-bump rebuild. `safety_incomplete_overflow_cause`
reports `decode_loss`, `key_cap` or `malformed_marker`; the first cause persists
with the marker. Old overflow markers without a cause report `malformed_marker`.

Record-local `x` holds acquisition, loss, bounded content pairs and capability
metadata. `sb` holds retired-only safety hashes using the existing base64 u64
codec. Existing fields, derivation, money getters and activation gates retain
their contracts. Ambiguous record keys never become last-wins evidence. This applies with phase B
OFF too: both duplicate census entries are dropped, whereas main used last-wins.
MONEY accepts this corruption-only difference subject to durable counting and
next-pass reconstruction. `decode_duplicate_keys_dropped` is cumulative and
persists as root shadow `a`; it is present in the census line with OFF too.
Both persisted decoder paths retain ambiguous key identities across normalization
and grant that key's transcript one `Parse(Rearmed)` read. The grant lives in
the rebuild guard and the load's transient set only: the indexed source
fingerprint is never written. Save/restart preserves the debt (the guard), and
the next ordinary transcript scan rebuilds the record. A successful rebuild
clears the key's ambiguity, while the corruption count and sticky safety marker
retain history.

That rearm is bounded per key: at most two rebuilds per rolling seven days
(`claude_request_census/rebuild_bound.rs`, shadow `n`). The daemon saves each
grant stamp before its scan can read, so restarts and crashes count; a future
stamp counts as recent. Past the bound the key is not re-read, its record stays
absent, its duplicate stays counted, and `census_duplicate_rebuild_exhausted`
plus a rate-limited `key_hash8`/`cause` alarm make it visible. It clears when
the key's record next decodes clean; the window passing allows only a new
counted attempt. A read that starts spends its grant even if the failed pass is
never saved. A grant authorizes a read only within
`N3_GRANT_MAX_LOAD_TO_READ` (12 h) of its stamp, checked when candidate
selection admits the read, not only at load (MONEY 724h P2; the longest
observed full traversal is about 90 min). Past that it is spent, never moved
forward: the key is skipped (an earlier checkpoint's marked empty is held),
counted as exhausted with cause `grant_read_span_expired`, and read only
through a new counted attempt from the same budget, saved before its scan. A
stamp counts for one window plus that span, so any rolling seven days hold at
most two actual reads, whenever each load ran. Stamps are used exactly as
persisted (MONEY 724h condition 3): a wall clock that goes backward never
clamps or expires one early, and behind the guard's latest stamp no grant is
made or reused, no new key admitted and no read admitted
(`grant_clock_regressed`, counted as exhausted) until the clock passes it; a
grant found spent stays spent in its process (in the same working index
too), and nothing on backward time lowers a persisted stamp (a refusal, a
lost guard's reconstruction (including a present guard with missing state),
which keeps its saved witness, or an identity
revoke, which keeps the removed key's latest stamp; every closure starts no
earlier than the saved witness, of any admitted copy of a duplicated shadow,
even beside a resource-refused copy), a grant
the census terminal finds spent is spent too, and an alarm's retry time is
never before
the clock passes the latest stamp. The process's spent-grant cache is bounded
too: it never evicts a refusal to admit work; after overflow an unrecorded
grant requires proof of a newly saved counted attempt. At most 512 keys are tracked, one compact line each in the saved
index; past that new keys are refused for one window. Only well-formed
fingerprints (64 lowercase hex) are rearmed.

Identity rearms always win (SI-724-B1). The contract-5 latch, family proof
corrections, stale-family uncarries and committable subsets clear the same
fingerprint independently. Because the bound never writes it, they stay visible
to their own consumers, are saved as they are, and are re-offered after any
reload; the bound never restores, overwrites or holds them, whether its grant
for that key is outstanding or exhausted. Whatever erases the guard (a
downgrade, an older binary's save, corruption) erases only the rearm: the entry
keeps its real fingerprint and is not re-read (MONEY P1a).

Identity work also revokes an earlier checkpoint's hold (SI-724-B1b). Every
fingerprint clear goes through `rearm_source_fingerprint`; a unit test
enumerates the call sites. An identity arming (contract-5 or family proof
re-arm, family correction, legacy witness, owned start, stale-family uncarry,
cancel, rewind or stale-pending re-arm) takes a held earlier-form key out of
the bound: the key leaves `n`, and a 16-hex token of the arming's evidence
stays in `n.r` for one window. Every consumed token is kept (at most three
per key; past that a re-entered hold stays held, failing closed). The revoke happens once per key per arming and is
counted in `census_duplicate_rebuild_identity_revoked`. It is durable before
the key is selected (MONEY 724g P1): the daemon applies the revokes made while
its scan is built to the cycle's committed state and saves it before the scan
selects anything (the working index takes the saved generation); a revoke made
later in the cycle is saved by the cycle's own save. Until saved, the key stays
held. A crash before that save loses the revoke and nothing was read, so the
re-derived arming only revokes again and re-offers the key once saved; after
it, a crash or discarded working index finds the token consumed. The key is
then re-offered on the next selection and never held, restored or revoked
again for that arming.
Missing or oversized evidence, or an absent or closed-ambiguous guard, revokes
nothing. Repairs of damaged state, recovery re-reads and carried re-parse debt
never revoke.

A lost or ambiguous guard never replenishes the allowance (SI-724-B3, MONEY
724f P1): a malformed `n`, a repeated `n` or key id, a malformed or duplicated
shadow state, a saved prior whose key the guard no longer holds (an orphan,
`cause=orphaned_rearm`), or a missing `n` with evidence of earlier activity
(the shadow's window witness `nw`, the guard's latest stamp saved beside it,
still inside the window, a priors field present, or the "N3 initialized"
marker present; `cause=guard_lost`) closes
admission for one window (`cause=guard_state_closed`). Orphans and lost guards
count in `census_duplicate_rebuild_orphaned`. Only a checkpoint with no such
evidence starts a fresh guard; main's own save drops `n` and `nw` together,
and main has no duplicate-key rearm. The marker is the root field
`claude_census_rebuild_initialized` (SI-724-B3b), decoded in isolation. It is
written when the guard first holds state, a grant included, and retires only
with an empty guard, which equals a fresh one. A marker with a missing `n` or
root shadow, or a malformed marker, is a lost guard.

Earlier checkpoints of this branch saved a rearm as an empty fingerprint (its
prior in the root field `claude_census_rebuild_priors` or inside the guard).
The current form flags every key whose fingerprint it has seen intact, so the
guard positively records an earlier checkpoint's rearm: a pending key without
that flag. Its empty fingerprint is the bound's own (SI B2 condition 2, MONEY
P1a), with or without its prior: it is held (candidate selection skips it,
`cause=legacy_rearm_held`, counted as exhausted) and read only through a
counted attempt the daemon saves before its scan, at most two per window; it
is never restored. An empty fingerprint of a current-form key, or of a key the
guard does not hold, takes the ordinary path and is re-offered. The priors
field is decoded in isolation, by the index reader and
by the field's own lenient decoder on a plain Serde path. A malformed,
truncated or wrong-type value never fails the index decode: every
entry, binding, ACK and latch is kept, the priors are dropped (marking never
depends on them), admission closes for one window, and `census_rebuild_priors_decode_refused` counts it
(`cause=priors_decode_refused`). A duplicated priors or marker field name is a
root-level defect: like any duplicated index field it refuses the index (kept,
source paused), never quarantined or defaulted. Both lenient and bounded CAS
reads apply census recovery and the bound once, after the whole index is
assembled, carrying the normalizer's decode state. All of these counters and
alarms are count-only.

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

The synthetic receipts include full serialized pressure for active admission
and retired-core metadata growth, plus optional numeric-overflow isolation and
peer provenance for the closed old/inert/retired/alias difference reasons.
Production peak counters explicitly mark measurement unavailable; the CI
allocator receipt measures requested overlap separately from RSS, including
retained old/new state and pretty-checkpoint decode. Workspace refusals remain
in the healthy-terminal denominator.

Required safety coverage includes indexed empty files, retained records, walked keys and residue keys. Unindexed keys require a current-terminal record; absent records close D2, and every covered unindexed member participates in family settlement vetoes. The workspace reservation conservatively prices the full union before allocation.


Round 3 gates phase-B-only work behind `OTTTO_CLAUDE_D2_SHADOW=1`, sampled once
at process start; the unset/default mode is OFF. This is a diagnostic switch,
never a D2 decision or money activation switch. OFF creates no optional safety
fields or retired buffer and uses main's in-place MONEY retirement. OFF retains
main's D1 join, `request_census` counts line and persisted `o`/`f` updates. It
skips D2 joins, digests, owner-pair work and optional serialization.
Previously persisted safety still receives safe reclamation/marker handling.
Old retired or lossy records without required safety remain migration debt when shadow diagnostics are enabled.

Retired safety is a persistent chain of immutable 256-hash chunks. Reclaim
advances the head, copies no retained hash, and preserves old checkpoint clones.
Physical accounting includes the partially consumed first chunk (at most255
unused slots per buffer); serialization and hash budget use its logical suffix.
A streamed codec preserves the existing `sb` wire format. Counting its serialized
size uses the exact base64 length without encoding the remaining buffer.

A view never returns a cached settled boolean. Consumption supplies the current
terminal completeness and window; the view checks generation, a unique evidence
mutation stamp, current indexed fingerprints, the incomplete marker and drift,
then checks each current family member. Removed/invalidated records or downgraded
completeness cannot reuse a prior true. Holder certificates stay independent.

Test-only frozen main admission and record encoding provide independent hash
and byte boundary controls, both with and without reclaim, including full scoped
MONEY-debt byte comparisons. The OFF fixture uses12,400 files/700,000 hashes and
prints actual retained bytes, census save delta, inline record-layout delta and
CPU delta against frozen main maintenance including the D1 join, counts and
`o`/`f` updates in both timing arms. CPU measurements are observations, not timing assertions.
The128/64 MiB synthetic overlap assertions are retained and require an executed
CI receipt; their existence alone is not evidence that a limit was met.

The original12,400-file refusal control remains unchanged. A second admitted
scale control uses1,024 files/700,000 hashes, including retirement buffers,
and requires a completed join, view digests, per-family legacy comparison and
post-save equality. Its overlap includes checkpoint serialization/decode plus
the original shadow heap and checkpoint delta beyond main; it asserts the same
128/64 MiB limits. The test-only allocator pointer inventory accommodates the
full overlap, with a control above its former65,536-pointer capacity. This does
not change any runtime cap or production measurement availability.

The OFF receipt uses the native calling-thread CPU clock, reports wall time
separately and checks complete checkpoint bytes as well as the independent
census field. A boxed retirement-buffer descriptor keeps OFF record slots small;
the descriptor and chunk storage are allocated only when safety is retained and
are included in physical accounting. Inline growth is explicitly reported.

OFF with already persisted incomplete safety still reports the cheap marker
counters and N10/age alarms alongside main's D1 join, without D2 joins or digests. A legacy missing marker
with no retained safety does not trigger this exception. The OFF existing-state
control verifies full-budget main admission, incremental reclaim, persistence,
alarm and healthy prune; clean OFF state continues emitting the existing D1 line.

Ordinary tests use production-OFF defaults; shadow-specific controls opt in on
their own thread. This keeps canonical scan/debt comparisons free of diagnostic
views and elapsed-time observations. Missing legacy marker state stays absent
on save when no new safety exists (and remains closed in memory); empty legacy
indexes do not acquire new metadata. The OFF stamp fast path avoids a global
atomic when no view has ever existed. CPU receipts retain the first-terminal
sample (separate record maps) and add 15 ABAB-interleaved steady-state samples
per arm. The steady main arm runs the frozen main reference on the OFF arm's own
record map, swapped in outside the clock, so both arms walk the same nodes, keys
and hash buffers. The reference counts bytes with main's unchanged
`serialized_len`. Receipts report the median and minimum per arm, both deltas,
the median of back-to-back paired deltas, and every raw sample. A diagnostic
arm repeats the older method, with main on its separately cloned map, to expose
allocation-layout bias. The 0.5% OFF target is reported, never asserted,
because shared CI runners are too noisy for it.


Round 4 moves `x`/`sb` into an optional census side map. The shared MONEY record
returns to main's inline layout. Compiled layout and frozen main load-charge /
resident-bound assertions accompany the existing M4-scale ledger save/load
fixture. No side map exists in ordinary OFF operation. OFF terminals run main's
core prune/recount/retirement and D1 diagnostics directly; safety accounting,
mutation digests, legacy diffs and D2 counters require the diagnostic switch or
retained safety. Pricing borrows the core record and counts optional fields separately;
it never clones ledger facts or a retained hash buffer.

Under byte pressure, retiree `x`/`sb` is stripped oldest-first before active `x`
(oldest window first). Active request hashes and facts remain untouched. The
bounded root marker is separate from the 48 MiB record budget: 4,096 fixed
64-character key ids plus scalar fields fit below its 512 KiB decode envelope.
`safety_metadata_reclaimed_active` counts active metadata losses. Native
selected restore may invalidate the admitted key to a birth stub; the tested
fallback preserves peer truncation and its marker through save/restart, keeping
the strong comparison closed.

`ac` describes bytes consumed for the bound candidate revision. A later growth
is a new revision; `unread_due_to_growth` counts those observations without
turning a consumed bound into global unread debt. Dirty old-window evidence
cannot cover a walked-but-unparsed key. Unread alarms identify only a SHA-256
key hash prefix (eight hex digits) and acquisition cause. At most eight key
alarms are emitted per complete terminal; `unread_alarm_emitted_keys` reports
emissions while age/terminal counters still count every affected key. Stale-window pending
is uncomparable and does not enter invalid/other difference counters.
`dirty_unparsed_keys_known` and `shadow_decision_taps_known` remain false until
their taps exist; zero decision counters are phase-B construction, not observed
activation evidence. MONEY census hash/byte counters keep their original core
meaning; separate safety counters describe retained physical overhead.

`safety_compact_decode_recovered` counts accepted compact inventories whose
main-style pretty core census exceeds the old raw decode envelope. This
MONEY-accepted format boundary expansion is intentional. An old-binary round
trip loses `x`, `sb` and `s`: reclaimed retired records then become migration
debt, and an Exact record loses an `ac=false` restriction. Such downgrade round
trips remain outside the safety guarantee; no schema or derivation bump is used.

Executed Round-5 CI at 9740394c (run 40050786469) passed all four checks:
service 4,338 passed / zero failed / 32 ignored; admitted 1,024 files / 700,000
hashes used 50,642,185 additional overlap bytes and 985,782 workspace bytes,
with saved qualification. The 12,400-file / 2,097,152-hash control used
133,530,703 additional overlap bytes and refused its one attempt; it is an
early-refusal receipt, not admitted coverage. One-slot reclaim allocated zero
bytes. The 128/64 MiB assertions remain unchanged.

Round-5 OFF CPU timing omitted main's D1 work from both arms. Round 6 restores
that work in production OFF and in both timing arms. The frozen-main parity
control compares complete D1 counters, serialized counts lines, `o`/`f` flips
and whole checkpoint bytes. Legacy decoder/CAS/prune guards run OFF and ON.
The same 15-sample paired alternating receipt reports medians, minima, paired
median and raw samples. A shared runner cannot resolve the 0.5% target reliably;
post-release OFF daemon CPU versus the prior release remains a separate check.
Exact-head Round-6 receipts are recorded in the PR after CI completes. Activation
remains OFF; no runtime corpus, seven-day shadow or release evidence is claimed.


Resource admission now assesses the join/view workspace and an additional-peak
estimate before allocating the D2 join. The peak model reserves three serialized
inventory equivalents (checkpoint, normalized decode and decoded evidence) plus
the independently computed workspace layout bound. Old/working copies share
immutable hash buffers; those are not separately encoded inventory copies.
Both estimates are multiplied by `1 + error allowance`, with checked integer
ceil rounding; unavailable/overflowed estimates refuse. The caps stay 128 MiB
additional peak and 64 MiB workspace.

The applied error allowance is a conservative 50% calibration ceiling, not a
claimed measurement. The admitted 1,024-file/700,000-hash reference measures
absolute relative error against its allocator's complete born-in-scope peak;
CI requires that measured error to fit the applied allowance and the adjusted
peak to fit 128 MiB. Its pre-existing shadow-layout/checkpoint charges remain
separate in `additional_overlap_bytes`, with the original 128 MiB assertion.
Both scale receipts print estimate, actual allocator peak, measured reference
error, applied allowance, effective bound and workspace estimate. The full
receipt additionally names `refused_by`, `limit` and `requested`; its allocator
observation under 128 MiB cannot override a refused workspace admission bound.
The full-scale row remains an early-refusal control, not admitted coverage.
The phase-E real-M4/headroom decision is outside this phase-B change.
