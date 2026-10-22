# Composition session identity and opening ownership

The incremental composition reader uses the snapshot reader's session identity:
Claude subagents use the parent from the transcript path and the agent file
stem, and Codex UUIDs use the snapshot reader's case normalization. Identity is
fixed when the file's first checkpoint is created. Session upload rows retain
the hash alongside `source_session_id` and add
`top_kind_tokens_entered_est`, the tokens assigned to the row's `top_kind`.

The snapshot upload client records session-start verdict changes from final
accepted or unchanged wire items. Rejected, conflicted, disabled and malformed
acknowledgments do not publish verdicts. This happens after ownership folding
and payload trimming, so a final clear replaces an earlier measured verdict.

The worker reads `composition-start-verdicts.jsonl` once per run. The log stores
destination/source/session hashes, a boolean and a timestamp, with an 8 MiB / 50,000-session
cap and 92-day retention. Unchanged verdicts append zero bytes. Pruning occurs
on the next snapshot upload after expiry or reaching a cap. The snapshot client
logs appended and compacted bytes; transcript contents and source session ids are absent
from the log. Relay authority, endpoint and machine changes select a different
namespace. Missing, expired or invalid entries supply no verdict.

Before first classifying an opening, a file born less than six hours before
scan start waits if its verdict is absent. A bounded identity-head read checks
the verdict, but no composition lines are processed and no pin or checkpoint
is created. The metrics line counts it as `verdict_deferred`. The saved
discovery boundary stays at the earliest deferred birth, so the next daily run
reads the whole file forward from zero as new bytes, without a repair grant.
At six hours or older, a missing verdict is `NotMeasured`; the wait is bounded
by birth time and cannot renew indefinitely. Unknown or future birth times do
not authorize this wait. Explicit measured and unmeasured verdicts do not wait.
Late days are resent by changed-days uploads when that path is enabled.

Verdict transitions do not reconcile previously classified contributions.
The reader remains forward-only: it does not reread old transcript bytes to
remove an opening after a later measured verdict or restore an opening after
a later clear.

For a measured start, composition skips opening input until the first response.
For an unmeasured start, including a missing entry, it counts that input under
`automatic_additions/start_not_measured`. Later prompts and reloads continue
to count normally. Claude subagents follow the same snapshot verdict.

Claude compaction markers use the snapshot pairing helper. Pairing state,
including an attachment-chain tip, survives checkpoints, so a boundary and its
later linked summary clear residency once. File session counts still fold
subagents into their parent. The changed-days reader switch remains off.
