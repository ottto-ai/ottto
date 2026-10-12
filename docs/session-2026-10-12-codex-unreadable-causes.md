# Codex unreadable branch attribution

The aggregate `unreadable` counter includes both filesystem failures and
structural replacement/ownership obstructions. It is an event count, not a
count of distinct files or a diagnosis of corruption. Census schema
`local_fenced_codex_census:v3` adds a fixed `unreadable_causes` projection to the
existing `snapshots/codex-fenced-census-v1.json` publication. Its process/start,
attempt, clock, generation, gates and working-before-delivery scope are unchanged.

`counts` always has eight saturated u64 entries in this order:

| Index | Category | Original branch |
|---|---|---|
|0|metadata|root, candidate or directory-entry metadata/resolution failure|
|1|directory|directory enumeration or entry retrieval failure|
|2|open_read|bounded candidate/group open or parser read failure, including failed object revalidation open|
|3|scope_object|sampled reduction scope mismatch or changed reopened object|
|4|reduction|launch/acquisition preparation, retained reduction or parser finalization failure|
|5|alias_parser|alias inventory/owner/member guard, joined replay/parse incompleteness or applied-tier/receipt bound failure|
|6|protected_absence|newly absent protected rollout group at exhausted discovery|
|7|legacy_hold|post-scan legacy output reproduction hold|

These are branch stages; a category must not be translated into a permission,
corruption, parser-migration or permanent-fault claim. Compound alias guards
stay compound. Existing narrower public disappeared, malformed, UTF-8, oversized
and over-line counters retain their meanings and are not counted again here.

`unattributed` is the existing aggregate minus the checked sum of known
categories. Old persisted traversals lack the additive histogram: their losses
remain an explicit unknown remainder, including after new attributed events.
`consistent=false` and `unattributed=null` mean the sum overflowed or exceeded
the aggregate; refuse conservation/completeness claims. Zero known counts with a
nonzero remainder is not clean. Histograms persist alongside existing traversal
counts and merge exactly once with the existing page-count merge. There is no
parser, scan-context or historical replay version change or forced reread.

`losses` adds the existing zero-snapshot-usage count and the exact terminal
counterparts for ownership, zero-snapshot usage, recognized/dropped usage and
over-line loss. They remain subsets, not newly admitted usage. No classifier,
health, retry, owner fence, omission rule or backfill completion rule changes.
Terminal ownership residue stays unsettled beside any retryable obstruction.

Publication remains at the existing pre-delivery destination fence. A later
legacy hold augments only the existing durable traversal; its category appears
when a later normal attempt projects that traversal. This change adds no second
publication or disk write to catch later events. The last-non-success sidecar
remains `local_fenced_codex_census_outcome:v1`: an outer rejection retains the
old census, while existing inner invalidation behavior is unchanged. It carries
no fabricated histogram for an attempt whose scan was unavailable.

The histogram owns 64 inline bytes and no heap. All growth is fixed scalar
metadata; optional scan overlap admission accounts for it through the existing
exhaustive layout inventory. The census still uses the 8 KiB stack encoder and
the sidecar stays at 1 KiB. No paths, source IDs, raw text, credentials or error
strings; no extra filesystem/provider/authority reads, lock, thread, scheduler,
store, fsync or healthy-path write/unlink. Existing writes gain bounded fields.

A future witness is at most the fixed census 8 KiB plus the sidecar 1 KiB.
A v3 consumer must validate its schema, eight-entry shape and conservation,
then use the existing exact process/start/image, freshness and attempt join.
Older v1/v2 census evidence lacks cause attribution; absence is unknown. A v2
consumer must refuse v3 unless explicitly upgraded; never reinterpret missing
fields as zero. Last persisted is not latest executed, health, delivery or ACK.
No live observation, installed acceptance or incident repair is implied.
