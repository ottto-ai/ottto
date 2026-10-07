# Claude subagent own-request account qualification

Claude reports subagent API requests under the root session ID. Requiring one
account across that root's entire history prevents an otherwise single-account
child from carrying its own observed account. Family accounting and account
coverage are separate proofs.

The existing scan now qualifies each Claude subagent using its own complete
transcript request-ID set, checked canonical API records and matching canonical
trace owners/client request IDs. Root transcript presence, root account
unanimity and a complete family census are unnecessary for this account proof.
Nested children use their original root namespace and their own agent identity.
No new source reads, provider calls, credential access, scheduler or persisted
coverage index are introduced. Borrowed request indexes are built once per scan.

The existing `provenance.collector` carrier has two closed values:

| Value | Meaning |
| --- | --- |
| `claude_code_jsonl:own_request_account:v1` | Every counted request is exactly covered by checked, canonical, single-account API evidence and its own trace owner. The same account is present in every aggregate and hourly row. |
| `claude_code_jsonl:own_request_account_unknown:v1` | The scan evaluated this subagent but could not establish that complete own-request account proof. Existing independently known row hashes, usage and reported money are retained. |

These values describe observed account coverage, not a subscription, paid route
or provider entitlement. A bare legacy row hash, Desktop mapping or durable
binding does not qualify. Typed request identity, when present, must use
`provider-sha256:v1` with a complete consistent account observation. Checked
legacy API-v2 records may supply their existing account hash; unchecked records
cannot. Missing organization evidence is never invented or emitted.

Missing/unreadable evidence, incomplete or duplicated own IDs, conflicting
accounts, mismatched trace ownership/client IDs, malformed hashes and conflicting
known row identity remain unknown. Independent API/cloud destinations retain
all their facts and money without acquiring subscription identity. Unrelated
root requests cannot veto a completely covered child. A lost proof withdraws the
qualifier; a later genuine proof can restore it. Original creator evidence is
never rewritten, including genuine missing/conflict/complete evaluations.

Imported sessions and registered-home sessions follow the same exact request
proof. Without matching local evidence, they remain unknown. A directory name,
slot login, parent subscription or arbitrary OTEL environment is not a fallback.
Home discovery and copied-transcript deduplication remain separate operations.

Parser v37 revisits ordinary cached parses through existing invalidation. Scan
identity, usage-accounting authority, cached-owner refusal, body witness, CAS,
ACK, retry and correction mechanisms are unchanged. The qualifier is covered by
the existing attribution component as `request_account_coverage`, with its
exact closed collector value. Legacy collectors omit that component leaf.
This changes the semantic fingerprint and revision-v2 material so local no-op
suppression cannot lose a proof change; it does not change the policy-neutral
content hash or original identity body witness. Admission must require that exact revision and accepted
body when settling a qualifier change; content-hash equality alone cannot settle
proof loss or restoration. No history reset, demo-data repair or forced resend
is part of this change.

## Backend and release dependency

Before an installed producer emits these qualifiers, the backend must reproduce
that exact conditional attribution component leaf, accept the exact
complete/unknown contract, check aggregate/hour account agreement,
and resolve only one eligible logical subscription in the authenticated
organization/user/source/Mac at supported session time. Complete own-request
coverage is separate from original creator identity and does not authorize a
conflicting or contradictory original pair. SOURCE must use explicit
`request_login` provenance/material in existing session and paired control
settlement, and return honest Unknown on absence or ambiguity. Successful ACK
requires the normal exact body/predecessor settlement.

Existing retained hourly authority remains protected. Attribution refinement
or a changed account is not automatically a monotone extension of previously
accepted grains. Only the existing supported correction authority may admit
such a change; no manufactured proven contract or erased account grain is used.
Forward operation and fresh-user historical import are the delivery targets;
there is no special migration to repair previously stored demo data.

Containing backend compatibility/deployment, then ordinary installed collection
and served subscription membership, are separate acceptance steps. An independent
release that omits this producer change is unaffected. Mixed-login root-session
accounting and request-level organization emission remain separate scopes.
