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

The measured failure has stale state/projection metadata in several homes and a
single remaining rollout per logical thread. Its file keeps the existing native
parser and upload acknowledgement path. Multiple physical rollouts for one owner
in different homes retain the existing strict alias guard; metadata compatibility
alone cannot prove their content, pricing authority or subscription ownership.

No scan cap, wire format or retry gate changes. Reduction and alias-parser errors
must still clear in a genuinely clean traversal before census can finish.

Synthetic crate regressions cover five homes, 46 threads with copied progress,
26 creation-clock differences, identity/refusal boundaries, upload
acknowledgement and a clean follow-up census. Validation receipts are recorded
in the pull request. No installed-runtime or production convergence is claimed
by this source change.
