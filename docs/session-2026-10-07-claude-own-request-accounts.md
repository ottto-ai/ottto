# Claude own-request accounts and qualified mixed-session delivery

Claude reports subagent API requests under the root session ID. The scan joins
each child's own complete request-ID set to canonical checked API records and
exact trace owners/client IDs. Root account unanimity, root transcript presence
and a complete family census are unnecessary for that independent child proof.
Nested children keep their original root namespace and own agent identity.
Borrowed API/trace indexes are built once per scan; no new provider read,
credential access, scheduler, source or persisted coverage index is introduced.

The existing `provenance.collector` has three closed values:

| Value | Meaning |
| --- | --- |
| `claude_code_jsonl:own_request_account:v1` | Every counted child request has complete, checked, canonical, single-account API/trace coverage AND its own original provider usage-event clock. That one account names every aggregate and hourly row. |
| `claude_code_jsonl:own_request_account_unknown:v1` | The child was evaluated but account coverage or original event-clock coverage is incomplete. Independently proved account hashes, creator, usage and money remain factual. |
| `claude_code_jsonl:own_request_account_mixed:v1` | A root has genuine complete reported accounting, a complete original Desktop creator, complete own-request API/trace coverage across at least two accounts including that creator, and naturally NULL accounts on every local subscription aggregate/hourly row. This marker certifies account coverage, not event clocks. |

D1 complete checks original clocks before response folding can hide missing or
malformed timestamps. Every counted request must reproduce the complete
original min/max and count in every represented hour. Session activity fallback,
OTLP observer time, auxiliary-only requests and an unstamped progressive partial
cannot certify this clock proof. Counted zero-token rows are included. Valid
lifecycle timestamps use UTC spelling while retaining their original instants.
A bucket-wide minimum may conservatively precede a destination's own first
request; terminal usage-event time does not prove request initiation or an
entitlement interval. Missing time proof withdraws complete without deleting an
independently proved account. Legacy persisted API-v2 evidence cannot recover
event-versus-observer clock provenance.

D2 uses an opaque scan-local capability bound to the freshly qualified semantic
fingerprint and additive creator/body witness. Only that capability may release
the old root account-switch upload veto, with the retained owner matching the
original creator. A raw collector string, cached index or marker-only import
cannot restore it. Original creator/owner, factual rows and whole reported money
stay unchanged; no hash is cleared to manufacture a mixed body, no accounting
contract is fabricated, and no money is split by login. Missing/invalid API or
trace evidence, conflicting creator, known-row accounts, independent API/cloud
routes, incomplete accounting and changed candidate bodies keep the existing
refusal. A restart must reconstruct the genuine proof before release.

Each recognized collector adds its exact value as `request_account_coverage`
in the existing attribution component. Legacy collectors omit that leaf. A
marker change therefore changes semantic fingerprint/revision-v2 material;
marker-only changes leave policy-neutral content and creator/body witness
unchanged. UTC spelling uses the existing component algorithms. Parser v38
revisits ordinary cached parses; scan identity and hash epochs remain unchanged.
Qualification still precedes privacy policy stripping, and the qualifier
survives disabled attribution labels with matching canonical bytes.

## Backend compatibility and delivery

The compatible receiver must reproduce the exact conditional attribution leaf
in both raw and post-policy admission. D1 request-login resolution requires the
complete qualifier, aggregate/hour account agreement, one scoped logical
subscription and a supported original usage-time observation bound. Legacy or
Unknown account rows cannot acquire that binding. Missing/ambiguous evidence is
terminal Unknown; original creator evidence is a separate fact.

A qualified mixed root settles current subscription membership Unresolved through
the existing paired controls. Its whole reported money replaces the prior
version once, preserving creator and factual rows. The receiver clears current
membership and prevents legacy/backfill healing; no request-level allocation or
new stored grain is introduced.

Temporary SOURCE unreadiness returns retryable503 after its observation commit.
The existing uploader retains the same candidate and retries it through normal
checkpoint/recovery.503 never means acceptance or terminal Unknown. Lost ACK,
restart and repeat keep semantic/body identity and preserve retained ownership;
only an exact validated body/paired settlement ACK advances acceptance. Existing
predecessor/CAS, correction authority, hourly/priced floors and refusal guards
remain in force. No new timer, outbox, replay, history reset or forced resend is
introduced. RD45 stays inactive until its separate durable cutoff and first
canonical-admission proof exist; absence of a resident row is not freshness.

Backend web AND worker compatibility/deployment must precede a containing
producer release or emission. Native synthetic tests and receiver
canonicalization checks do not establish deployed paired settlement or installed
acceptance. Ordinary collection/status/served membership remains a separate
acceptance step. Real roots with missing request witnesses remain unqualified.

## Validation scope

Focused native cases cover original time versus fallback, pre-fold missing
clocks, UTC/historical hours, every bucket, counted auxiliary zero-token events,
proof loss/recovery, mixed-root exact-body eligibility/refusals, retained owner,
503/lostACK/restart and settled no-op. Generated bodies are checked against the
compatible receiver with privacy labels enabled and disabled. Existing native
snapshot/synchronization checks, generated parser-dependent fixtures, export
manifest/contracts, formatting, Clippy and strict review complete source
validation; deployment and installed behavior are reported separately.
