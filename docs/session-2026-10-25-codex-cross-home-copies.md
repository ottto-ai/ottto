# Codex usage across copied homes

Codex metadata and rollouts can outlive the home that first wrote them. A copied
thread may have a different absolute rollout path, a later update time and a
higher cumulative usage total. Treating every difference as an identity
collision withholds otherwise countable sessions and prevents census completion.

The collector now reconciles compatible metadata while retaining exact
creation/path/projection evidence per home. Compatibility requires the same UUID,
root-relative rollout locator, title, model and archive state, subsecond creation
precision agreement, and update/token progress that does not regress. Every copy
is compared with every earlier copy, so timestamp tolerances cannot chain. Real
collisions remain scoped, and cannot reappear as total-only fallback snapshots.

Cross-home rollouts additionally require identical native headers and complete
byte-prefix agreement. The collector parses the longest complete rollout once,
then uses its existing alias acknowledgement boundary for every physical copy.
Divergent copies, changed files, incomplete records and un-replayed saved tier
authority remain withheld. Capture validation covers every contributing home.
No metadata maximum substitutes for parsed usage, and no subscription identity
is inferred merely from registration of a transcript root.

Prefix comparison yields after bounded chunks and charges the existing read
budget. Proof that cannot fit that budget stays strict; this change does not
increase scan caps or relax unreadable/retry gates. Reduction and alias-parser
failures must still clear in a genuinely clean traversal before census can finish.

Synthetic crate regressions cover five homes, 46 threads with copied progress,
26 creation-clock differences, identity/refusal boundaries, common alias
acknowledgement and a clean follow-up census. Validation receipts are recorded
in the pull request. No installed-runtime or production convergence is claimed
by this source change.
