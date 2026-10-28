# H527 producer R4, offline diagnostic only

Draft #592 never merges or ships. The hidden producer has no upload or
admission authority. Its packet keeps all 18 members held. B2 chooses counting
allocation only; parsed, rebuilt and serialized bodies must remain untagged.
Output directory permissions remain 0700; files remain 0600 and create-new.

Input remains `h527_producer_input:v2`, with optional `census_index_path` naming
an existing daemon scan-index JSON file. There is no discovery, state creation,
index loader/save call, ledger read or state mutation. The ordinary full peer
walk remains in place. The census is used only for peers that disappear after
metadata planning and before their initial open.

## Read-only census and concurrent daemon

The producer copies at most 256 MiB of the explicitly named index into memory
once, deserializing only `generation` and `claude_request_census`; other fields
are ignored. It binds the copy to file length, modification time, device/inode,
generation and SHA-256. Nonregular paths, oversized/invalid snapshots and a
metadata change during copying refuse the run. After all target rebuilds, a
second bounded read verifies the digest and metadata. Any generation/content
change or atomic replacement during that interval refuses publication entirely.
There is no automatic retry and no daemon stop/restart. A daemon may keep running,
but a concurrent index publication is not accepted. The operator must disclose
this rule before the separately authorized corpus run.

A complete census record has the current derivation, is verified, not a path twin, not retired or
over budget, and has an Exact/Empty shape. Its request hash prefixes count as
present. Matching target IDs are excluded and the peer is classified
`vanished_census_used`. Prefix collisions have negligible probability but can undercount money;
these are not newly recovered exact IDs, line counts, ACKs or dollar proof.
Available positive IDs from incomplete records are still used; their unknown remainder additionally uses the lineage hold. Twin/retired/over-budget/stale-derivation records have no usable IDs and use the no-census fallback. A same-session target replica is the target's own counter, so its IDs stay in B2, as for a live replica. Census prefixes absent from that owner's current request set trigger the existing divergent-replica owner hold, preventing its smaller body from replacing counted history. The snapshot records historical observed IDs, not necessarily the vanished file's latest revision.

With no usable record the producer re-stats the peer once, at the end of the
run after target rebuilds. A still-absent peer holds only related targets, disclosed as
`vanished_no_census { peers, held_targets }`. Related means the existing path
family root, the same project-directory identity across named roots, or a
transitive closure over project, family, copy/fork edges and native-ID shared-target links read from existing target/peer data. An unclassifiable
path conservatively relates to every target. A reappeared peer or refused
re-stat refuses publication of the entire run. Other unknown/cap/creator
gates are preserved.

## Missing native request IDs

The producer reuses the ordinary parser's buffered response resolver, including
progressive-record deduplication, without another transcript read. Id-less
usage stays counted and is reconciled in all eight token/count dimensions.
`missing_evidence_counted { lines, totals, usd: null }` reports resolved counted
usage responses, rather than repeated physical content-block lines. Dollar
valuation is explicitly deferred to admission's catalog. A go request must
supply those dollars; null never means zero.

An exact provider timestamp, model and full eight-dimension usage tuple already
seen in a same-lineage peer proves a copy, disclosed as
`missing_evidence_matched_by_tuple { lines, totals }`. Missing timestamp/model
never matches. Same-session replicas never count as an independent peer. Matching uses hashes of typed tuples in RAM. For progressive
responses, the whole matched response is removed by the ordinary dedup key;
rebuilding must still reconcile exactly. Target-to-target residual copies use
the existing first-ACK/session-key order, preserving one keeper. A native-ID
response takes precedence over a target's matching id-less residual.

## Diagnostic v3 consumer handoff

Output is now `h527_producer_diagnostic:v3`. Input v2 and held-packet contracts
are retained. A v2-only consumer must refuse v3 until deliberately updated.
Changes the consumer must understand:

- Manifest counters: `vanished_census_used`, `vanished_no_census` and optional
  `census_snapshot { generation, sha256 }`.
- Peer rows may carry vanished classification instead of content bytes/hash.
  Census witnesses have `peer_line_count: null` and
  `evidence_basis: vanished_census_used`; no transcript-line count is fabricated.
- Each target declares `lineage_coverage_complete`. Global coverage is complete
  only if all global gates and all target lineage gates pass. A related hold
  cannot disqualify an unrelated target whose own coverage is complete.
- Native request-set fingerprints still describe native IDs only. Original,
  kept and excluded token/count totals include reconciled id-less usage.
  The two missing-evidence records account for the difference. Their `lines`
  count canonical resolved responses. Tuple exclusions have no native-ID
  witness and require separate admission valuation.
- If tuple exclusions exist, the optional native-ID catalog exclusion estimate
  is unavailable, rather than falsely pricing only part of the exclusion.

The second corpus run requires a new explicit operator go. This change does
not authorize that run, installation, daemon state changes or admission.

## Census-only limits and final matching implementation

SOURCE's vanished-census rule reuses the owned request-ID prefixes the daemon
already saved. Those records do not contain inherited fork lines or the vanished
file's fork edges. The producer cannot reconstruct that missing evidence or
apply absent-source exclusions to unseen copied lines. This is a disclosed
limit of the approved census reuse, not strict conservation proof; SOURCE/SI
and admission must retain this limit when reviewing the unqualified diagnostic.
A complete local-coverage flag follows that approved census policy and does
not certify reconstruction of every historical inherited line. No new transcript
reads or blanket hold of all census-backed peers are added.

Observed peer session IDs are connected to their filename-derived path families,
so renamed copies retain project/fork lineage. Id-less responses in same-session
replicas are resolved with the ordinary response resolver in memory during the
same streaming read. Extra, unresolved or over-cap replica responses hold their
owner; identical progressive replicas keep the owner's count. A native-to-idless
identity change conservatively holds the owner. Only owned id-less replica
responses are buffered, bounded by the existing ordinary response-record cap.

Tuple membership indexes are built once from the already-resolved targets. A
native-only target corpus performs no tuple hashes; per-peer matching uses
indexed lookups and never re-hashes a target's full native occurrence collection.
