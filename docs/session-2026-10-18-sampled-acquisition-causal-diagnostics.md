# Sampled acquisition causal diagnostics

Large full reads can have different causes. `state_missing` means that the
acquisition planner received no usable retained reduction; it does not prove
durable data loss or distinguish expiry, eviction, cache clearing, an absent
entry, lock failure, or eligibility refusal.

The existing `native_collection_page` record now includes fixed page totals
under `sampled_acquisition.acquisition_admission`. Each boolean has `assessed`
and `matched` counts. Known false is `assessed - matched`; unassessed is
`attempts - assessed`. A short-circuited dependency or eligibility branch stays
unassessed, rather than becoming false. Counts may overlap and are not a
partition of full-read reasons. A null `sampled_acquisition` still means this
instrumentation was not attached; it does not establish zero native reads.

`cache_lookup_miss_unknown_origin` counts actual lookups returning no retained
entry. Historical causes are unavailable at that seam and are not inferred.
Other totals describe the already-evaluated header, census, dependency, durable
entry, audit, protection, forced-family and comparison gates. A retained entry
rejected by eligibility is counted separately. No cache take/drop order,
eligibility predicate, retry, rearm, audit schedule or retention policy changes.
There are no per-file identifiers, tombstones, new reads or retained histories.
The fixed inline counters are included in the existing Context layout charge;
no heap limit is raised. The worst-width collection log fixture remains below
4 KiB; other diagnostic records retain their existing bounds.

The existing sampled full-audit text point becomes the structured
`sampled_audit_comparison` point in the same best-effort local log, under the
same verified-audit condition. `body_comparison_available` and
`effective_body_changed` retain their additive-witness meanings.
`semantic_comparison_available` and `semantic_changed` independently compare
the already-computed semantic entity-set fingerprints before index overwrite.
Availability means a previous witness exists. A changed flag can be true when
comparison is unavailable, so interpret it with its availability flag. No raw
witness, file path or session identity is logged, and no additional fingerprint,
body copy, resource probe or I/O is computed for these fields.

An audit comparison alone does not prove the audit found a hidden rewrite:
new suffixes or policy output can also change a witness. Installed scan savings,
audit policy changes, acquisition reuse and ownership currency remain separate
questions. Existing traversal-transition records can bind the page to an actual
start/retry reason only when the containing build is installed.

Regression coverage exercises a real semantic-only finalization change with
unchanged additive evidence and control index/body parity, plus actual cold
acquisition and census-blocked branches with unknown gates and full-reader body
parity. These diagnostics do not establish supported-layout tail execution.

Pi uses the shared sampled reader and a separate durable store slot. Its
response-id ledger persists only domain-separated SHA-256 keys and occurrence
digests. More than 65,536 response-id keys or an encoded record above 8 MiB
refuses persistence without truncation, so a missing retained copy reads Full.
`retained_refused_pi_ledger_cap` counts those refusals in the content-free
`durable_tail source=pi` summary. The resident store-map bound is 96 KiB:
one slot per source, three sources.
