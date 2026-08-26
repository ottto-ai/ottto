# Local Session Context Curves

## Scope

Added the public local-collector producer for `session_context_curve:v1`.
Backend admission must deploy before any daemon release. No release or deploy
was performed in this worktree.

Claude Code curves are built only after complete local request-id ownership
reconciliation. Copied predecessor prefixes are excluded only with exact local
proof; missing ids, unresolved duplicates, and multi-iteration responses that
cannot be expanded into stable request identities fail closed. A root user row,
matching file/session id, and nearby file birth time are not ownership proof:
Claude can create a copied continuation within milliseconds. Ordinary
transcript-only Claude roots therefore remain `ownership_unresolved` until a
versioned local/provider start marker can distinguish them. Codex curves use
owned stable token-count occurrences only. Trusted Codex Desktop
`agent_created_thread` lineage participates in ownership before any rollout
record is counted: an exact current parent ledger suppresses a copied prefix,
while a zero-length mismatch, copied suffix, older parent version, or missing,
stale, conflicting, or incomplete parent evidence fails closed unless a native
ordinal/history-base boundary proves the local start. Unsigned records at the
copied-prefix boundary are never replayed as child activity or compactions.
Capability-off parsing keeps the prior session behavior and emits no curve, so
the collector merge is inert until exact backend admission. Claude effective input is uncached
input plus cache read plus both cache-creation TTL buckets. Codex
`input_tokens` already includes cached input and is never added twice.

## Wire and bounds

- optional `context_curve`; omission means the producer cannot speak v1;
- explicit coverage: `complete`, `sampled`, `ownership_unresolved`,
  `parser_unsupported`, `pre_capture`, or `payload_budget_exceeded`;
- at most 256 points, 64 boundaries, 16 model-window records, and 64 KiB;
- deterministic retention of requests 1/2/5/10/20, every retained compaction
  adjacency, peak, tail, then even-gap fill;
- content-free model/window evidence and parser/ownership/sampling revisions;
- curve excluded from semantic component hashes and content identity.

The whole 128 KiB snapshot-item budget is authoritative. Post-policy fitting
removes fill-only points and compacts unused model-window records first. If
mandatory curve evidence still cannot fit, it becomes explicit zero-data
`payload_budget_exceeded`. Only that explicit clear may use a narrow 129 KiB
item reserve when the same item without the curve fits the ordinary 128 KiB
cap. Populated curves keep the 128 KiB cap and the 4 MiB batch cap is unchanged.

The scan index and resumable-upload checkpoint instead retain a local
hash-neutral body witness. This makes absent-to-present and A-to-B-to-A curve
or tool-evidence corrections upload once without changing the stable entity
fingerprint. A corrected body also bypasses quarantine for the rejected old
body. Curve-bearing accepted/unchanged entities settle only when the backend
echoes the exact durable v5/v6 witness; legacy, rollback, or routing-off ACKs
remain pending.

## Historical replay

The activity hint must advertise exact `session_context_curve:v1` durable-log
admission before the daemon derives, emits, or replays curves. Missing/null/
unknown capability is inert and preserves normal usage sync. Capability enable
triggers one bounded full replay; partial pages do not complete it, and an
enabled-to-disabled-to-enabled epoch replays files changed while admission was
off. The replay key includes the exact curve parser, ownership, sampling, and
model-window evidence revisions, so any derivation correction rearms exactly
one replay. Sessions remain reconstructible only while their local transcripts
are readable and inside the daemon's reviewed historical scan bounds. Deleted,
unreadable, or no-longer-retained request evidence is permanently unavailable;
state-only Codex records emit `pre_capture` and cannot claim an available
curve.

## Cross-language fixtures

- `fixtures/snapshot-audit/context-curve-v1-golden.json`
- `fixtures/snapshot-audit/context-curve-v1-max-fractional.json`
- `fixtures/snapshot-audit/context-curve-v1-manifest.json`

The fixture is canonical compact RFC 8785 integers-only UTF-8 JSON plus exactly
one trailing LF. The manifest SHA is over canonical bytes without that LF and
records the exact caps, retention bits, and revision ids.
