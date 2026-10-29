# Terminal census containment

This emergency cut closes whole-cohort Claude sidecar loading and
completion-triggered whole-index replay while preserving ordinary page uploads.

Terminal admission counts the union of attachment session/parent/root keys,
usage roots and retained pending/witness/legacy-owner keys. Limits: 64 keys,
16 MiB aggregate API+trace stat bytes and a 512 MiB decoded-memory estimate
(32 times input plus 8 KiB per key). The estimate is a heuristic, not a heap
certificate. Limits sit below the existing 1 GiB history-upgrade page budget.
Unknown/nonregular metadata refuses admission; missing sidecars retain the
existing absence semantics. Root refusal skips all stats; unknown byte fields
use u64::MAX with stat_skipped=true.

Stat admission is followed by one shared allowance inside the API and trace
readers. It charges actual bytes across files, strict rereads and prepared-read
fallbacks and never reads beyond 16 MiB. Exhaustion conservatively refuses
completion, including exact-limit reads whose EOF cannot be established within
the allowance. Trace growth cannot extend an unbounded lines() walk. Once all
required reads/fallbacks stay within the allowance, the owned readset is frozen
and consumed without more I/O. Content-health failures retain their existing
family scope. A refused terminal attempt ends its allowance before ordinary
current-page enrichment resumes under the existing page rules. Existing speculative paid preparation retains its separate
resource admission; it cannot bypass terminal fallbacks.

Raw-terminal effects are staged in memory until the bounded attempt succeeds:
watcher removal, missing-file reconciliation, disposition prune, absence
retirement, tombstone-fence draining and request-census prune. A late refusal
drops the plan and leaves the existing traversal parked. No cloned index or new
durable cursor is used for rollback. In-budget effects commit before folds, preserving any later effective-completion
veto from the caller.

A refused terminal becomes an ordinary incomplete page with scan_cap_hit=true.
Current-page evidence, finalization, upload, ACK settlement and index save
continue. Completion-only folds, retirement, ACK carry, upload-context adoption
and source-wide manifests stay off. Unread pending/body/ACK/hold witnesses stay
owed. The parked traversal re-offers its terminal without a restart/re-arm;
ordinary watcher hints can keep supplying changed bodies. Partial saves retain
unsettled changed-file demand on EVERY partial page (including pages before a
terminal refusal) in the existing traversal queue; no fresh walk or fingerprint
clear is needed. Refused removals likewise retain exact path revalidation demand;
all staged removals are re-probed before raw effects or a manifest can commit. Native-comparison selected fallback still withholds
and queues dependent bodies; deferral revokes eligibility without dropping it.

Local terminal_fold_deferred diagnostics report roots and estimated/stat bytes,
label cause=preflight or cause=read_allowance, and alarm. A process-local terminal_fold_deferred_consecutive counter alarms at
three consecutive deferred TERMINAL OFFERS; ordinary pages neither increment nor
reset it. It is process-global, including across multi-page metadata sweeps;
process restart resets this diagnostic.

On the measured M4 cohort (thousands of retained roots), 100% of terminal offers
will defer against the 64-key cap until the separate PAGED terminal fold lands.
Uploads continue as ordinary pages; completion and its folds can stall forever.
That follow-up must land before census fix (A) reaches M4. Account correction
pacing, Codex state-only paging, durable deferral honoured by older binaries,
and starvation ordering are outside this cut. Codex state-only burst behaviour
remains as on 0.1.202, with current main's coverage fixes preserved.

Completion-triggered whole-index replay is intentionally disabled. A due corpus
replay reports rearm_full_suppressed and alarms. Re-enabling requires Ron's typed
approval plus a byte estimate. Suppression never opens a fence, proves ownership,
settles first proof or spends a live identity latch. Fixtures distinguish the
conservative latch veto from legitimate clearing after a spent cutover.

Existing family-scoped corrections run uncapped, with no new queue. Global
identity/fence latches require family-specific need where necessary to avoid
another blanket replay. Traversal-start stale-pending and carry invalidations
are pre-existing, outside this completion-triggered containment and owned by R2
restart/restore. No new accounting is claimed for them. No rearm_scoped cap,
scoped_rearm_pending, persisted scheduling debt or deferral counter ships.

SOURCE: persisted-field changes = none. Read allowance, effect plan, readset
freeze and consecutive counter are process-local; parking uses the existing
traversal. No index/wire/body-witness schema change. Downgrade can lose transient
containment; downgrade-aware durable blocking is the explicit follow-up.

Money rule: deferral never treats unread evidence as absent or zero usage.
Fixtures cover ordinary upload/ACK/settlement across parked passes, root/stat
refusal, growth after preflight and during trace reads, witness retention,
admitted completion, disabled full replay and conservative latch clearing.
Tests run in CI; local validation uses the serialized package Clippy wrapper.

Parked discovery recovers on daemon restart, watcher overflow/loss and a
60-second process-local cadence while parked. Each metadata pass visits at most
512 directory entries and eight directories (including resumed readers). New or
changed native files enter ordinary selection. Matching durable size/mtime/birth
metadata queues no read of an unchanged transcript. `parked_rewalk{dirs,new_files,
entries}` counts this work. Existing pending_directories is the durable worklist;
its census_member=false marker identifies metadata work, and reconciliation_after
holds a NUL-prefixed tuple of entry offset and prior index-reconciliation cursor
while that work is active. A metadata sweep restores the paid reconciliation
prefix rather than resetting it. Cached iterators rebind to the durable cursor
after failed checkpoints; changed directory identity restarts only that directory.
Unreadable entries retain their position and keep discovery incomplete. The prefix sorts
before absolute file keys for conservative old-reader reconciliation. No new
persisted field. A known-identity retry rehydrates its iterator offset in bounded chunks. A
process restart with unknown directory identity conservatively replays the current
directory and owes a full metadata sweep before terminal credit; inserts
before an offset are revisited by the next periodic sweep. The metadata iterator
cache holds at most 64 process-local contexts. Discovery adds no ownership proof.

A same-context, exhausted non-window carry (or its metadata re-walk) may drop its
obsolete process certificate across restart without clearing fingerprints or
restarting the traversal. Existing missing/mismatched provenance, full-window,
capped and replay safety conditions remain. The underlying traversal-start/carry
clear loops remain pre-existing R2 paths; this narrow parked-restore guard is part
of the hotfix and needs core/edge review.

Frozen terminal evidence preserves the baseline permissive page-cohort error
boundary on incomplete offers. Retained strict reads fail per family. Changed or
unknown API/trace generations become incomplete before raw commit and stay
incomplete through frozen consumption; healthy decoded rows cannot override a
failed generation validation. The same actual-byte allowance covers all reads.

AccountReproof's pre-existing nonterminal fingerprint-version repair is not a
completion-only clear. The deferral early return bypasses it on refused M4 offers;
row 6's legacy membership/newly proven family corrections also require the census
completion gates. Scoped corrections remain uncapped.

Removal revalidation preserves the original reason: live activity-window
exclusions re-check the age/audit predicate; actual disappearances re-check
NotFound and the parent fence. A present, newly changed file is requeued rather
than erased or treated as absent.

Directory identity is rechecked even after an iterator was discarded for error
retry. A replacement restarts that directory's metadata at zero rather than
applying the removed directory's offset to unknown files. Test-only restart epochs
are thread-isolated and page-limit overrides unwind safely.

The existing durable index generation acknowledges cached metadata progress. If
it has not advanced since the prior metadata page, cached directory identity and
iterator progress are discarded and replay debt is re-established. A rejected
checkpoint cannot turn newly learned identity into permission to skip an older
cursor. No persisted acknowledgement or generation field is added.

Immediately after loading the index, before ANY preparatory claim, retirement
or adoption write, compare its generation to the previous metadata scan's issue
generation and invalidate unacknowledged cached replay. No observation member is
needed. Preparatory saves, including a save followed by a preparation error,
cannot acknowledge rejected replay debt. Fixtures execute a real terminal-contract
retry-claim save both with and without a subsequent preparation abort.
