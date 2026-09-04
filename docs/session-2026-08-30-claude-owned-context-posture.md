# Claude-owned context posture

## Problem

Claude Code can write legacy Fable/takeover transcripts whose leading provider
responses were copied from a predecessor without `forkedFrom`. The complete
local ownership census already excluded that exact prefix from billed usage and
`session_context_curve:v1`, but the session-level context scalars were still
computed from the raw file. A successor could therefore report its
predecessor's near-1M first/peak prompt and copied compactions.

## Ownership rule

Claude context posture now follows the same local, content-free ownership proof
as reported usage:

- explicit provider `forkedFrom` records remain suppressed by the streaming
  parser before any session metric is recorded;
- a legacy unmarked prefix is removed only when the complete local transcript,
  API-request, and trace-ownership evidence assigns the exact leading request
  ids to another root;
- a persisted family witness remains usable only while current local evidence
  revalidates its occurrence fingerprints and external owners;
- missing/deleted/out-of-window predecessor evidence is not treated as a fresh
  session. First/peak/last context and compaction scalars are omitted until
  ownership is proven.
- cross-session provider request duplicates remain fail-closed across bounded
  census pages. The local scan index retains only domain-separated session-id
  hashes keyed by request-id hash, caps that owner set at 250,000, and forces a
  full corrective census instead of persisting partial authority on overflow.
  Any invalid or occurrence-cap-crossing family fences posture globally because
  its discarded request hashes could duplicate another family; only a later
  complete, fully valid below-cap census may clear that fence.
  On every valid complete census, persisted owners are first intersected with
  the current indexed family members, so deletion, retention expiry, or root
  removal re-arms a surviving owner once instead of tombstoning it forever.
  A changed owner reconciles the witness and re-arms every affected transcript
  once; an unchanged witness does not create a replay loop.

For a proven legacy successor, first/peak/last effective input context is folded
only from owned response occurrences. Compaction count, timestamps, and metric
totals are folded only from boundaries after the copied prefix. Claude effective
input remains uncached input + cache read + cache creation.

Session duration and time-to-first-token aggregates are intentionally unchanged.
The owned response occurrence currently has no latency/TTFT evidence, so resetting
those fields would erase an existing non-Context-Posture metric without a truthful
replacement. A regression proves context and compaction can fail closed while the
independent duration aggregate remains intact.

## Replay and compatibility

`CLAUDE_CODE_SCAN_IDENTITY_VERSION` advances from `claude_code_jsonl:v27` to
`claude_code_jsonl:v28` so retained transcripts are revisited once. Parser and
curve contract revisions remain `claude_code_jsonl:v33` and
`session_context_curve:v1`; no wire field, cap, schema version, body-witness
version, prompt content, or provider identity is added.

The backend SESSION fold shipped in coding-agents-observability #5165 and is
deployed. It scopes peak context and compaction values to the newest scan
identity, accepts explicit NULL tombstones, and suppresses stale heads. That
closes the collector merge dependency: v28 is now the only scan-identity
claimant, while v27 behavior and fixture digests remain unchanged.

The macOS stable release remains a separate operational step. Releasing v28
triggers a one-time re-scan of retained Claude transcripts, so it is sequenced
after the forced COST window (September 6, 2026 or later), not during it.

The machine-local Context Posture cache treats a re-parsed session with all
posture evidence cleared as a tombstone. That removes any older cached peak or
compaction row immediately instead of leaving disproven values visible for the
14-day cache retention window.

Curve body witnesses use internal semantic-envelope revisions 11/12 while the
released backend ACK contract intentionally exposes public revisions 5/6. The
collector's current ACK boundary (landed independently in #385) maps only the
two curve revisions to released v5/v6, then requires that exact version plus
the unchanged digest for settlement. It does not accept internal v11/v12
aliases from the server. This repair does not replace that runtime mapping; its
canonical source fixture records the complete semantic-envelope/public-version
vocabulary for private byte-hash parity.

## Verification

Regressions cover a legacy copied ~895K prefix with copied and owned compaction
boundaries, missing-predecessor fail-closed behavior, cross-page duplicate
discovery through its corrective pass, stable-witness no-op behavior, duplicate
removal, bounded overflow recovery, old-index defaults, deterministic witness
ordering, revalidated child-only correction, explicit-fork preservation,
v11->v5 and v12->v6 request/response proof, lost-response retry, and durable
no-op checkpointing. The complete `ottto-service` unit lane and public
export/manifest checks are required before readiness.

Rebasing onto public main composed the bounded duplicate-owner witness with the
newer durable usage-authority quarantine. A stale pending family from a prior
census is ignored by duplicate validation only while its quarantine is bounded
and bound to the exact retained witness. Current-window invalid evidence,
unbound stale state, and witness-cap overflow still fence all Claude posture.
This prevents a valid retrying family from globally suppressing unrelated
sessions without weakening the fail-closed boundary. Duplicate reconciliation
also re-arms every current member containing a changed request hash, including
a new singleton owner after both previously recorded owners disappear, so a
conservative tombstone cannot become permanent when ownership moves.
