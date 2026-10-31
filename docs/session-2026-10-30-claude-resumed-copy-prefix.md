# Claude resumed-file copied-prefix accounting

Resumed main transcripts written by older Claude Code versions use the existing
earlier-file request census to decide their copied prefix. Their own turns stay
outside the removal range. Certified 2.1.309/2.1.310 transcripts keep their
existing timestamp/twin decision.

A proven removal is saved on the resumed file as local request hashes grouped by
the earlier holder. While that holder remains indexed, retirement or loss of its
census hashes does not restore a recorded removal. A positive id hit in a Lossy
holder remains proof. Absence in a Lossy holder is unknown and never invalidates
a recorded removal; only an answering loss-free record can disprove it.
Recorded removals also survive census-walk deadlines while the holder still
contains the request; retry expiry applies only to unresolved copies.
Account-marker decisions follow the exact removed or held requests. Such
markers cannot lend identity to retained usage. Emitted prefix markers and
later own markers keep their scope; both identified and id-less inherited
grains wait for this decision before account reconciliation.
Marker adjudication follows the first nonzero response that established copy
status, even across intervening zero-usage records. Zero-usage responses have
no counted prefix grain and never enter identity repartition.

Storage shares a global 4 MiB charged bound: 40 bytes per file, 32 per holder
group, and 8 per request hash. A file with prefix retry debt and no removals
costs 40 bytes. Existing removals are never evicted for capacity. A full store
still removes newly proven copies without recording them, counted by
`copy_removed_unrecorded` and `copy_removal_store_overflow`, with a local alarm.
If proof later disappears, those unrecorded decisions cannot be recovered and
the prefix emits flagged. Own turns never wait for storage capacity.
Disproven old removals are deleted even when new proof cannot fit; capacity
refusal cannot preserve a decision invalidated by an answering holder.
Holder updates use sorted lookups and consume current proof once, avoiding
pairwise scans across large valid holder-group sets.

A transient proof wait (unscanned or changed holder, walk deadline) holds only
the unresolved copied prefix. Own turns emit. Retry debt remains in the index
through ACK, semantic no-op, and restart and reselects the unchanged file. The
third decision pass emits any still-unproven prefix flagged and clears the debt,
counted by `copy_prefix_hold_expired`. If debt cannot fit, it expires immediately.
`copy_prefix_held_requests` and `copy_prefix_held_files` disclose pending holds.
An intervening page cannot prune retry debt merely because a new whole-body
held file is absent from the settled index. Confirmed source removal clears it.
Conclusive reads that no longer need holder proof, including confirmed empty
or policy-suppressed parses, clear retry attempts while preserving saved
removals. Disabled E2 does not select files solely for this retry debt.

The local CCR2 encoding accepts CCR1 removal records. Absent, damaged or
downgraded metadata is uncertainty. The read already happening re-derives any
available proof; without proof, the prefix emits flagged and increments
`copy_removal_metadata_lost`. Recovery never requests an additional holder read.
A parent link alone does not prove an older-writer resumed prefix.

The daemon sends `copy_unproven: true` only on unproven-prefix usage rows and
`copy_unproven_counts: {rows, requests}` on the body, counting bucket rows once.
The exact provisional activity hint `copy_unproven_contract: "copy_unproven:v1"`
is required; absent, null or unknown capability stays OFF. With the gate off,
fields are omitted and existing row grouping, wire bytes and semantic hashes
are preserved. Backend admission and capability advertisement must precede
activation; the provisional token/field name still needs backend confirmation.

When enabled, marked and ordinary requests keep distinct money grains even if
hour, model and account coincide. The mark changes no identity classification,
tokens or costs. It participates in the semantic hash. A capability change
uses existing upload-context adoption to prevent stale marked retry pages from
crossing a downgrade; the OFF context is byte-identical to the released one.
The capability-qualified context stays a 64-hex fingerprint so partial ACK
progress survives restart through the ordinary progress loader.
No request ids, digests, paths, file keys or source-session links are added.

`copy_prefix_unproven_rows` counts emitted marked bucket rows. Existing local
request/file diagnostics continue while wire emission is OFF. Reported flagged
dollars cover only requests matched to priced local telemetry;
`copy_prefix_unproven_priced_requests` states that partial coverage. Server-side
pricing covers the remainder. Unknown usage stays counted as today and is
separately disclosed; server-side exclusion requires a later evidence-based
rule. No production re-read, money-rule revision bump or release is included.

Synthetic pipeline fixtures cover older-writer families, retirement, missing and
damaged metadata, Lossy positive and negative evidence, capacity refusal, and
three-pass prefix expiry with own-turn ACK and restart; capability-off byte/hash
identity and capability-on mixed-grain flags/counts (Full and sampled/cache),
partial-ACK restart and deletion of disproven removals at capacity. Tests run
in Linux CI, never locally. Marker exclusion covers full/partial proof,
restored prefix markers and id-less usage; retry debt covers intervening page
pruning and restart. Before release, measure local files, holder groups, copied
requests, longest resume chain and charged bytes; occupancy above 50% needs
review before release.

## Default-off release switch

The complete resumed-prefix behavior above ships OFF. The one local process
setting is `OTTTO_CLAUDE_RESUMED_PREFIX_DEDUPE=1`; only the exact value `1`
enables it. Unset, `0`, invalid or non-Unicode values keep released behavior.
This controls resumed dedupe, saved-removal use/writes, prefix retry selection
and expiry, metadata recovery, marker re-derivation and prefix flags/counters.
Existing all-copy and certified-writer decisions retain their released path
when OFF. A frozen pre-change native builder from main `d0dcfbc72` pins actual
upload bytes, hashes and ACK witnesses for a six-file old-writer demo family
in full and sampled scans. Existing resumed-prefix fixtures explicitly opt in.

For a later authorized local enable, set that environment key in the daemon's
launch environment (for a manual launch, prefix the existing daemon command
with `OTTTO_CLAUDE_RESUMED_PREFIX_DEDUPE=1`). Exporting it in another shell does
not change an already-running daemon; the operator must arrange the next
launch using the existing service management procedure. This task does not
set the environment, restart the daemon or inspect private source data.
Enabling first requires the operator's typed authorization and a money PLAN
with expected removed requests/dollars and expected own-turn requests for the
same measurement cohort. Default-ON needs a later release and money review.

The independent wire capability remains OFF unless the backend advertises
`copy_unproven:v1`, and cannot bypass local OFF. ON qualifies the upload
context separately from that capability, so retry bodies cannot cross a local
mode change. OFF preserves the released context. Stored removal decisions are
retained but ignored while OFF, ready for a later authorized ON launch.

For the post-enable counts-only check, use existing schema-2
`native_collection_page` records with `source: "claude_code"` and `counts.money`:
`copy_skipped` (removed request decisions), `copy_prefix_removed_priced_requests`,
`copy_prefix_removed_cost_micros`, `copy_prefix_unproven_requests`,
`copy_prefix_unproven_priced_requests`, `copy_prefix_unproven_cost_micros`,
`copy_prefix_held_requests`, `copy_prefix_held_files`, `copy_prefix_hold_expired`,
and `copy_prefix_own_requests`. Costs are microdollars with partial local
telemetry coverage. Removed pricing excludes files with a partly held prefix,
conflicting/invalid telemetry and ambiguous requests; never price a hold as a
removal. COST must supply the unpriced remainder before comparing total dollars
to PLAN. Own-turn counts exclude side calls and copied-prefix requests.
These are decision events, including rereads, not unique requests or gauges.
An isolated bounded cohort/pass is required; raw sums across retries or other
families cannot prove PLAN agreement. Use an operator-provided, already
counts-only export; never export transcript rows, paths, keys or ids.

A separate counts-only local-state measurement still needs files, holder
groups, saved copied requests, longest resume chain and charged bytes. The
4 MiB bound and 2 MiB escalation threshold remain. No such measurement has
been performed by this implementation task.

## Scoped re-read and counts-only estimate

`ottto-service claude-copy-prefix-reread --scope SCOPE.json --index INDEX --support-dir SUPPORT --window-days DAYS --estimate`
(`--dry-run` is an alias) accepts a private JSON array of absolute affected
Claude main-file paths, including their earlier proof holders. The money owner
supplies that cohort from its PLAN. INDEX names the exact destination-scoped
native Claude scan index: filenames alone cannot reveal twins in other projects
or registered roots. The tool reads index metadata through the read-only
representation reader, without the daemon loader, checkpoint lock, repair,
network or state writes. It stats closure members, refuses symlink paths,
requires creation-time metadata, and never opens transcript bodies.

Apply publishes the FULL estimated closure. A listed path twin forces its
complete native root family: all main twins and all subagents. Affected
families with an authority quarantine also expand. Families with neither twins
nor an authority force retain their listed members. One shared
`claude_read_closure` function supplies estimate/apply/preparation and native
forced-family selection. Preparation rejects changed closure membership before
any re-owe; it never silently expands a previously published request.

Output contains numeric counts/durations only: `listed_files`/`listed_bytes`,
`closure_files`/`closure_bytes`, `added_by_twins_files`/`added_by_twins_bytes`,
blocked/runnable files/bytes, pages and pacing seconds. Runnable groups exclude
oversized or out-of-window members and twins whose combined bytes exceed the
native page budget. Any blocked member means apply refuses the whole request.
The existing Claude 512 MiB per-file limit applies independently of the 1 GiB
page limit. Required `--window-days` is the ordinary daemon scan window, bounded
by existing `BACKFILL_WINDOW_DAYS` policy; it never widens scanning. Both scope
and closure remain bounded by the existing 10,000-file scan limit and the 4 MiB
local request envelope. Estimate creates no support directory and changes no
state or upload.

After the change is merged and installed, money sign-off and a same-cohort
PLAN are prerequisites for the authorized operator to replace `--estimate`
with `--apply`. Apply publishes one private create-new request under
`snapshots/claude-copy-prefix-reread.json`; it does not enable the local switch,
restart the service, read transcript bodies or upload. Existing intent is never
overwritten. Only the ordinary daemon, with the existing local switch ON,
processes it under its sync lock. No helper or implementing agent runs apply,
enables the switch or starts this re-read.

The daemon rechecks the same closure and validates every member remains indexed, lies inside the
configured Claude roots and has the same size, creation time and modification
time. Any mismatch refuses the whole request, with a counts-only refusal.
It uses `re_owe_effective_upload_body_witness_revision(key, 2)` to lower only
those files, without clearing a fingerprint, census record, ACK or global
replay generation. A local bit in the existing per-file money-mark byte
records that this one-shot request already re-owed the file; ordinary money
restamps preserve it. Completed revision-3 entries are never re-owed again by
that request, across restart. Removing an indexed file clears its marks as
before. An index rebuild is not authorized by this tool.

Files are offered in `(min(stored effective birth, physical birth), path)`
order, earlier first, ahead of ordinary census/audits within the same selection
limit. The native history gate still owns admission, protected lists, fences,
byte/file budgets and ACK settlement. There is no new worker, continuation,
pace, rate, cap increase or first-file byte exception. The estimate packs
closure metadata sizes in earliest group creation-time order, next-fit,
reserving path twins together as the native gate does, using the existing
`HISTORY_UPGRADE_FILES_PER_PAGE = 2000` and
`HISTORY_UPGRADE_BYTES_PER_PAGE = 1 GiB`. Runtime stored move-history births can
refine that order; estimates are metadata-based capacity forecasts rather than
a guarantee of exact page boundaries under other ordinary work or holds.

For `P` forecast pages, pacing-only duration is `(P - 1) * 300` seconds at the
existing `SNAPSHOT_SYNC_INTERVAL` floor, and `(P - 1) * 1800` seconds at the
existing `MAX_CYCLE_INTERVAL` cold ceiling. Zero or one page has zero inter-page
wait. Actual expected wall duration adds scan/enrichment/upload/ACK time and
initial scheduling delay; list/fence/metadata/transport holds can extend it
indefinitely. No measured throughput is invented. These are the existing
ordinary-cycle constants, not a new timer. Lead B must pair the counts with
current daemon readiness and measured page work when scheduling the operation.

`copy_prefix_families_corrected` is an additional sparse diagnostic count on
`native_collection_page.counts.money`: distinct families on that page whose
successfully rebuilt native body removed a proven copied request from an
uncertified resumed file that local OFF would have emitted. Certified skips,
all-copy files, unresolved holds and unproven emitted prefixes add zero.
This is a per-page decision event, not a process-wide unique-family ledger;
repeated reads can count a family again. Add the sum of this field to the
same bounded cohort/pass evidence query alongside removed requests/dollars,
unproven residuals, held/expired counts and unchanged own-turn counts.

## Scoped context adoption

Turning the local switch ON alone must not reacquire unchanged unrelated
transcripts. Retry pages, quarantine witnesses and ACK candidates retain the
source-wide mode-qualified context, so stale bodies and ACKs cannot cross a
local-mode or wire-capability change. Acquisition receipts use a separate
expected context: the exact closure members, marked by the one-shot bit, use
the qualified context; every unrequested file uses the original base context.
Unchanged unrelated receipts survive ON, capability ON and OFF transitions.
Already settled legacy entries without per-file receipts recognize only mode
variants of the same base. A real privacy-policy, destination or attribution
context change still uses ordinary context adoption. Planning never creates
an ACK receipt or accepted-upload credit.

The estimate's expanded closure is the exact set offered to that narrowed
acquisition path. Preparation also requires its size and nanosecond mtime to
match the indexed extent, so a changed file cannot enter this historical
cohort under the guise of an unchanged scoped read. The existing native
history gate may defer listed, fenced or over-budget members; estimate counts
the requested workload, not guaranteed completions. Actual native scans in
synthetic regressions open exactly the estimated closure, with equal file/byte
counts and zero unaffected body reads. Coverage includes one listed twin
expanding to two mains and a non-twin subagent, unchanged no-twin behavior,
closure growth refused before re-owe, and existing per-file and page-byte caps.

Release disclosure: missing or expired proof, lost removal metadata and later
expiry of unrecorded removals can preserve the original overcount. These
residuals are counted and disclosed; unknown usage is never silently zeroed.
Removed and unproven dollars include only priced telemetry and are partial.
The local switch remains default OFF, and the separate wire capability is OFF
without the exact advertised token. Money-owner sign-off, an installed merged
build and a same-cohort PLAN still precede any authorized operator enable or
application of a re-read request. Implementation and review do not perform
those runtime actions.

The request binds that window. Runtime validation uses the SAME effective
window and scan clock as ordinary candidate selection, before any re-owe. A
changed window or a member aging past its cutoff refuses the whole cohort
without changing debt. The money owner must obtain the current effective
scan-window day count alongside PLAN, use it for estimate/apply, and
re-estimate if it changes. An out-of-window proof holder is reported blocked;
it is never silently accepted as runnable. No unrelated window is widened.
