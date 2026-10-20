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
  any retained non-invalid family pending, or reported under another root in the
  loaded API or trace evidence.

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

## Audit

`snapshot-audit` reports `local_snapshot_audit:v5`. Each session row adds the
four posture integers (or null) and `posture_admission`: `strict`,
`member_waiver`, `withheld_no_contract`, `withheld_global_census`,
`withheld_own_family`, `withheld_duplicate` or `withheld_identity`. The report
adds per-rule counts, sessions with peak above 1,000,000 and incoherent tuples
(first or last above peak). Admission is recorded only when Claude support
evidence runs the ownership fold. Blinded keys move to the v5 domain; the
golden oracle is `fixtures/snapshot-audit/v5-golden-keys.json`.

## Verification

Synthetic regressions cover an unrelated cap-invalid family, an own invalid
family with a reconstructed witness, a stale unrelated family on an incomplete
pass, a copied-prefix successor without a contract, a legacy-excluded successor,
a visible duplicate in a valid peer family, a request reported under another
root, incomplete identity, owned-boundary compaction filtering, the open-fence
strict rule, and family-level-only trace attribution. The existing hidden-copy
regression now records that the curve stays fenced while the provider-owned
child keeps its scalars and the hidden copy is cleared.
