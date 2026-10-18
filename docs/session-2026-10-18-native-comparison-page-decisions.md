# Native comparison page decisions

`native_comparison_decision` is one fixed, content-free point in the existing
local resource log per comparison preparation lease. It is emitted when that
lease finishes, is abandoned, or returns untouched for a cadence wait. When the
comparison path is disabled before a lease can begin, a single
`disabled_before_lease` point records that fact instead. No resource sample,
request, scan, persisted state, wire field or policy decision is added. Panic
unwinding emits no point; absence is not evidence of no work.

The point contains no root, path, account, body, request id, proof or context
digest. `lease_generation` binds process-local ordering; `fold_index_generation`
is present only when the actual authority fold was reached. Existing traversal
transition records describe stale-pending invalidation at a new traversal's
start. That invalidation precedes optional native comparison. Its counts are
not duplicated or attributed to terminal suppression here. Existing acquisition
admission records continue to describe cache and sampling gates independently.

| Field | Actual observation seam |
|---|---|
| `layout_supported` | Compiled layout gate on this binary; no inferred compiler claim |
| `allowed_at_bind` | Result of the existing previous-permit/same-scope/generation binding |
| `controller_created` | Actual successful paid controller construction |
| `controller_current_at_finish` | Existing final controller/lease/frozen-root check |
| `bootstrap` | Actual native census complete, coverage complete, census valid, fence open, pending occurrences present, transcript ownership complete, scan census complete and not withheld |
| `selected_save` | Existing post-save lease settlement callback reached |
| `upload_fully_settled` | Existing post-save upload result; unknown before that point |
| `clean_at_finish`, `retained_permit` | Actual finish predicate and selected lifecycle state update; neither an offer nor a candidate grant |
| `revoke_calls`, `admission_refusal_calls` | Existing revoke/refusal calls; overlap because refusal itself revokes |
| `hit_policy_calls` | Completed decisions at the genuine-hit family-policy seam, not all possible-owner lookups or distinct families |
| `deferred_decisions`, `latched_base_decisions`, `other_base_decisions` | That decision's result and pre-existing latch state; failed decisions can remain unknown |
| `terminal_rearm.negative_keys` | Qualified keys returned to the real terminal fold |
| `terminal_rearm.proof_candidates` | Members with the ordinary terminal proof-rearm predicate before negative filtering |
| `terminal_rearm.suppressed` | Proof candidate had a qualified negative and no rearm disjunct cleared it |
| `terminal_rearm.other_rearm_matches` | Existing full-rearm, invalidated-witness or changed-owner/request disjunct matched; overlaps proof candidates |
| `terminal_rearm.clear_calls` | Actual source-fingerprint clear calls, including already-empty entries; not bytes or unique rereads |
| `correction_mint` | Post-selected-save stable-proof receipt seam: window available, candidates, insertions and receipt count after that seam, before later staging/retirement |

Nested objects and boolean outcomes that were not reached stay null. Zero in an
observed count is not a historical claim about earlier leases or another
process. A cadence wait has no fold or bootstrap observation. A completed
native conjunction still needs a fully settled selected save and clean finish
before a permit is retained. The policy status snapshot remains separate from
per-preparation event counts and unknown intervals.

Zero deferrals can coexist with successful negative suppression. Conversely,
supported layout alone does not establish bootstrap, qualifying roots,
suppression, or savings. Invalid census and unrelated rearm disjuncts remain
authoritative. No envelope becomes ownership, coverage, tags, settled state or
an ACK witness.

The counters are fixed inline scalars included in the existing lease layout
charge. No heap cap is raised. JSON uses the existing best-effort stderr sink;
the maximum-width record fixture is bounded below4KiB. Regressions distinguish
unreached/abandoned boundaries from an actual saved and retained lifecycle,
including a zero-deferral retained permit. The lifecycle fixture is logical;
it does not claim supported native-path execution or installed CPU/RSS savings.
