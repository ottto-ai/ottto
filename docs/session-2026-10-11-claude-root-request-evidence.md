# Top-level Claude own-request account qualification

Top-level Claude Code sessions now use the same own-request account qualifier
as children. A canonical root UUID is the API/trace namespace; a child retains
its original root namespace and own agent identity. Every counted transcript
request must have one checked API-v2 account record, a valid canonical evidence
fingerprint and an exact trace/client-request owner for this session. A trace
that assigns a request to a child cannot certify that request for the root.
Other requests in the namespace, including children and auxiliary requests, do
not supply the root's login. Missing, duplicated, conflicting or partial proof
remains Unknown.

A single login must agree with every local subscription aggregate and hourly
row. Every counted request, including zero-token requests, still needs its own
original provider usage-event clock, with exact per-hour count and min/max.
Observed-time fallback cannot certify Complete. Clock refusal preserves any
independently proved account and factual usage/money. The original Desktop
creator remains separate: conflict stays conflict, and a complete creator
contradicted by the root login refuses qualification. No request organization
is emitted or used to select among several subscriptions.

The genuinely qualified mixed-root path retains first precedence and its
existing reported-accounting, original creator, exact body and retained-owner
capability checks. A single-login proof never creates that capability. Existing
CAS, predecessor, body-witness ACK, retry and recovery mechanics are unchanged.
No acceptance is inferred from qualification.

The existing Complete/Unknown collectors and conditional attribution hash leaf
are reused, with no new wire field, hash epoch, persistent proof store, timer or
provider query. No parser revision or history replay is requested: this changes
scan-local qualification of normally collected evidence. A marker-only or
proofless reconstructed body cannot qualify. Folder identity does not supply
payer evidence; older sessions with no request evidence remain unproved.

The compatible receiver must accept this same top-level Complete body under the
existing missing-original, exactly-one scoped subscription rule. Its exact
receiver contract and deployed web AND worker callback must precede changed
producer emission. Prior child-only compatibility does not satisfy that gate.
Containing release and ordinary installed emission/ACK acceptance are separate
owner steps; synthetic source validation does not complete them.

Qualification reuses the scan's checked request and trace indexes. The existing
local evidence stage now records its duration and bounded numeric Complete/
Unknown root counts, without session or account identifiers. Synthetic fixtures
cover root/child login separation, exact request ownership, missing/partial and
duplicate evidence, clocks before hourly folding, creator conflicts and genuine
mixed-root precedence. Full snapshot/sync regressions cover unchanged settlement.
