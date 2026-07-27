# Attribution wire budget 4,096 → 8,192 bytes

The client-side attribution payload budget now equals the backend's, at 8,192
bytes. Nothing else changes: the daemon emits the same facts, keys sessions the
same way, and parses transcripts the same way. The only difference is how many
of the facts it already computed survive to the wire.

## Why the daemon was the binding constraint

The budget is a shared contract enforced on both sides. The daemon trims a
session's fact list to fit *before* upload; the backend rejects any batch whose
attribution payload exceeds its own limit. Two numbers, one contract — and while
they disagree, the smaller one decides.

The backend was raised to 8,192 and deployed. The daemon stayed at its previous
value, so it became the smaller number and began trimming facts the backend
would have accepted. That trim is not an error path: it is the documented
tail-drop, it logs, and the batch uploads successfully without the dropped
facts. Silent-by-design at the product surface, which is what made it worth
fixing.

Observed shape of the loss, from the service error log of a daemon still running
the retired 2 KiB budget:

* ~86,600 client-side drop events.
* ~64,900 dropped `template_group_id` on its own, degrading Codex template
  grouping.
* ~16,900 dropped `spawn_depth` and `template_group_id` together.
* ~3,300 dropped `skill_id` and `template_group_id` together.

`spawn_depth` is ordered last precisely so it is the first thing sacrificed, so
a Claude workflow subagent served `spawn_depth: null`. The session tree still
rendered — nesting is recoverable from `parent_session_ref` — but the depth
itself was gone.

## Why 8,192 and not "enough"

A budget *below* the backend's silently discards good facts. A budget *above*
the backend's is worse: the trim that used to lose one field becomes a rejection
of the entire batch. Matching exactly is the only value with neither failure
mode, so the daemon adopts the backend's number rather than picking its own
headroom.

**Release ordering still is not optional.** The backend must accept the wider
budget before a daemon carrying it reaches an installed base. That ordering is
satisfied here: the backend reached 8,192 first and is deployed.

## The count cap is now what binds

An attribution fact carries a mandatory `sha256:` evidence reference and costs
roughly 290 bytes, so a full 24-fact list lands near 7 KiB. At 8 KiB the 24-fact
count cap binds first and the byte budget only stops values crowding the
128-byte per-value ceiling. That is the intended ordering — a byte budget should
be a backstop against pathological values, not the everyday limit — and it is
pinned by its own test so a later change cannot quietly reverse it.

The count cap itself is unchanged at 24.

Concretely: the single fact layout that carries every field — a Claude *workflow*
subagent, with `origin_kind`, `provider_surface`, `parent_session_ref`,
`root_session_ref`, `agent_kind`, `agent_ref`, `workflow_ref` and `spawn_depth` —
serializes to 2,240 bytes. It did not fit the retired 2 KiB budget, which is
exactly why `spawn_depth` was lost. It now uses just over a quarter of the
budget, leaving the rest for the grouping facts appended behind it.

## No parser or scan-identity version bump

Neither `parser_version` nor the scan identity moves. This changes what the
daemon emits, not how transcripts are keyed or parsed, and both versions are
inputs to change detection: bumping either would force a full re-walk of every
transcript on upgrade for no gain. Sessions trimmed under the old budget will
pick up their missing facts on their next natural rescan.

## Fixtures and tests

`fixtures/snapshot-audit/attribution-budget-golden.json` moves to
`attribution_budget_golden:v2` and carries four payloads instead of three:

* `over_retired_budget_case` — over the retired 2 KiB budget.
* `over_previous_budget_case` — over the superseded 4 KiB budget; the band this
  raise newly admits.
* `near_limit_case` — the largest payload the current budget accepts.
* `over_current_budget_case` — one fact past it, which must be refused locally
  rather than by the backend.

The boundary cases now use values at the 128-byte per-value ceiling, because
ordinary facts can no longer reach the byte budget inside the 24-fact cap. Each
case records acceptance under all three budgets, so the other implementation can
replay the payloads rather than reconstruct a guess at them. Fact values are
synthetic. Regenerate with
`UPDATE_ATTRIBUTION_BUDGET_GOLDEN=1 cargo test -p ottto-service --lib attribution_budget_corpus`.
