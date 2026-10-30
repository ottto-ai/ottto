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
