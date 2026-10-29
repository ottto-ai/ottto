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
durable cursor is used for rollback. In-budget effects commit before folds.

A refused terminal becomes an ordinary incomplete page with scan_cap_hit=true.
Current-page evidence, finalization, upload, ACK settlement and index save
continue. Completion-only folds, retirement, ACK carry, upload-context adoption
and source-wide manifests stay off. Unread pending/body/ACK/hold witnesses stay
owed. The parked traversal re-offers its terminal without a restart/re-arm;
ordinary watcher hints can keep supplying changed bodies. Partial saves retain
unsettled changed-file demand in the existing traversal queue; no fresh walk or
fingerprint clear is needed. Native-comparison selected fallback still withholds
and queues dependent bodies; deferral revokes eligibility without dropping it.

Local terminal_fold_deferred diagnostics report roots and estimated/stat bytes
and alarm. A process-local terminal_fold_deferred_consecutive counter alarms at
three consecutive deferred passes; process restart resets this diagnostic.

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
