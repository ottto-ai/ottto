# Claude posture member waiver

## Problem

The Claude duplicate-request census fences context posture for every Claude
session while any family's request evidence is hidden: a current-window invalid
family, unbound stale pending, or the persisted fence flag. On a large local
corpus that state is routine. Live sessions re-observed in one window, API-error
records without a request id, and the Mac-wide 250,000 pending-occurrence cap
each invalidate some family on most passes. Every Claude session then uploaded
empty first/peak/last context and compaction scalars, including sessions whose
own Claude Code telemetry proves each counted request.

## Rule

The strict rule is unchanged: owned start proven (explicit fork boundary, exact
legacy prefix, or `session_exclusive_reported_usage:v1`) and no unresolved
duplicate. While the global fence is closed, an item the strict rule withholds
keeps its scalar tuple only when all of these hold:

- this fold set `session_exclusive_reported_usage:v1` from a proven or
  reconstructed family with healthy reports, so every transcript request of
  this member is assigned to it by its root's API rows and trace agent ids;
- the member has no legacy excluded prefix (that path stays fenced);
- request identity is complete: every resolved response has one unique request
  id, and request ids and occurrences correspond one to one;
- the member's own family pending is valid in the current census window and
  holds exactly this item's request set;
- no request is a persisted duplicate, held by another (root, member) owner in
  any retained non-invalid family pending (`visible_dupes`), or reported under
  another root in the loaded API or trace evidence (`foreign_otel`). Both are
  new fold-local, read-only values; the persisted duplicate witness is not
  touched.

Uniqueness is never proof. A hidden family can only hide negative evidence, and
the waiver depends on none: a copier cannot hold telemetry for requests another
session made, so it has no contract and stays cleared. Identity-invalid families
are unknown, never unique; a shared hash visible to the fold keeps every peer
that holds it fail closed.

## Limits

The visible refusals are defense in depth and only see this fold's evidence:
retained non-invalid pending, and API or trace rows of the roots loaded for
this page. While the fence is closed the durable duplicate witness is cleared
and an invalid census retires ordinary pending, so a copy first seen on a later
page or window cannot retract scalars an earlier page already admitted. That
order dependence does not move tokens to the wrong session while each member's
telemetry proof holds. Closing it needs revision-bound per-member request
evidence or a persisted veto on the fence side; this change does not alter
that machinery.

Admitted items rebuild first/peak/last from all owned occurrences. Compaction
count, timestamps and totals use the copied-prefix boundary rule with the first
owned response as the boundary, so a compaction recorded before any owned
response is never counted. `session_start` keeps only `client_version`.
Cache observations and the context curve still read the strict ownership result,
so the curve stays `ownership_unresolved` while the fence is closed.

Fence state, its persistence, coverage, re-arm, caps, scan identity and parser
versions are unchanged. No wire field is added.

## Resource bounds

The waiver evidence is built only while the fence is closed, once per fold
(one scan page). Candidates are this page's items with the v1 contract, complete
identity, no legacy exclusion and their own current, valid family pending.
Before any allocation the fold sums the candidates' request ids and refuses the
evidence above the existing Mac-wide 250,000 pending-occurrence cap; candidates
already sit inside that capped pending, so the refusal guards the invariant, and
a refused fold keeps the strict rule (cleared scalars) for every candidate. No
cap changes.

Within the bound the evidence holds one borrowed request id and one hash per
candidate request, at most one owner per candidate hash (collapsed to "shared"
at the second owner), and one borrowed reporting root per reported candidate
request. Worst case per page is therefore linear in the page's candidate
requests, never in the pending or report maps. Each closed-fence fold walks the
retained pending member hashes and occurrence keys once and the loaded API and
trace rows once; nothing is cloned from those maps. The admission reason is an
in-memory value used for branching; tests record it, release folds do not.

Local audit counts by admission reason (waived sessions, each refusal, and a
non-zero foreign-telemetry count as a signal) are deliberately not part of this
change. They need a snapshot-audit schema change, which is proposed separately
with that schema's owner.

## Verification

Synthetic regressions cover an unrelated cap-invalid family, an own invalid
family with a reconstructed witness, a stale unrelated family on an incomplete
pass, a copied-prefix successor without a contract, a legacy-excluded successor,
a visible duplicate in a valid peer family, a request reported under another
root, incomplete identity, owned-boundary compaction filtering, the open-fence
strict rule, family-level-only trace attribution, a persisted duplicate owner
under the closed fence, a stale valid peer holding the request, and a request
traced under another root. Compaction fixtures pin the
`response_count_before > first_owned_sequence` rule (0-based ordinals) for a
non-zero, non-contiguous first owned ordinal, provider-stamped copied responses
and boundaries before, between and after owned responses, and an own boundary
with no owned response (count stays null). One regression checks that the waived
upload body differs from the withheld body only in the context scalar tuple and
the derived semantic fingerprint; account, attribution and identity fields are
identical. A copier whose requests are reported under another root stays
cleared, and the evidence refuses past its allocation bound. The existing hidden-copy
regression now records that the curve stays fenced while the provider-owned
child keeps its scalars and the hidden copy is cleared.
