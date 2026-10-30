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

Storage shares a global 4 MiB charged bound: 40 bytes per file, 32 per holder
group, and 8 per request hash. A file with prefix retry debt and no removals
costs 40 bytes. Existing removals are never evicted for capacity. A full store
still removes newly proven copies without recording them, counted by
`copy_removed_unrecorded` and `copy_removal_store_overflow`, with a local alarm.
If proof later disappears, those unrecorded decisions cannot be recovered and
the prefix emits flagged. Own turns never wait for storage capacity.

A transient proof wait (unscanned or changed holder, walk deadline) holds only
the unresolved copied prefix. Own turns emit. Retry debt remains in the index
through ACK, semantic no-op, and restart and reselects the unchanged file. The
third decision pass emits any still-unproven prefix flagged and clears the debt,
counted by `copy_prefix_hold_expired`. If debt cannot fit, it expires immediately.
`copy_prefix_held_requests` and `copy_prefix_held_files` disclose pending holds.

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
identity and capability-on mixed-grain flags/counts (Full and sampled/cache). Tests run in Linux CI,
never locally. Before release, measure local files, holder groups, copied
requests, longest resume chain and charged bytes; occupancy above 50% needs
review before release.
