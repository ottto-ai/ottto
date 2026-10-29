# Durable v1 custody completion (hard-pair second half)

Completes the audit-safe bootstrap core. Both halves ship in the same release;
this half never ships without the core and lands immediately after it.

Restored parameterized stored-representation scope binding: the store's
`scope_digest_for(format, …)`, the runtime `DurableRecord.format`, and the
adapter's `expected(…, representation)` / `replay_scope_for` plumbing for
restore, write and GC. New writes still bind the compiled representation, so
writer bytes and the four full v1 literals are unchanged.

Grouped Codex missing-carrier recovery. At group job start every member,
aliases included, passes the existing T14-aware full hold, which now also
returns the core's validated same-live-context deadline clamped once to
min(envelope due, now). The deadline is kept per member on the running group
job (runtime-only, sized at boot, heap-accounted), so a paused paged job
carries it; a deferred group has not captured yet and recaptures at its later
start. Settlement handles each member's own native-created entry: an
unverified publication stages the existing unverified-source marker; a
source-verified group Full retires recovered and marked members through the
existing `audits_completed` counter, which has no `audits_started` counterpart
for groups. If a fresh index loaded while a paged group or singleton job was
parked, a member or file with no captured deadline and no index entry
re-probes the same live-context, clamped handoff at settlement before it is
recorded; the parked job keeps its progress. The re-probe is a read-only header
classification with no hold, T14, breaker or RAM side effect; a re-probed
singleton retired by a verified Full counts `audits_completed` once. `ineligible.audit_carrier` and
`ineligible.audit_carrier_staged_unverified` advance once per settled member.
Preflight hold checks and pauses neither capture nor count. No store, map,
persisted field, Full cause or schedule is added; membership is never inferred
from a record.

Fixtures: reset + debt-bearing non-live alias and live member + complete join
inventory + incomplete sidecar census, paged and unpaged: publication, a marker
per member with its own deadline, save/post-save GC/restart, selection past the
window and verified retirement. A grouped control proves a foreign-context
alias contributes nothing and a future live-member deadline clamps once.
A paged group and a paged singleton parked across a fresh index load each
stage the marker from the record at settlement.
Exact-head CI and native qualification remain required.
