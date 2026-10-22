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
namespace. Missing, expired or invalid entries are unmeasured.

For a measured start, composition skips opening input until the first response.
For an unmeasured start, including a missing entry, it counts that input under
`automatic_additions/start_not_measured`. Later prompts and reloads continue
to count normally. Claude subagents follow the same snapshot verdict.

Claude compaction markers use the snapshot pairing helper. Pairing state,
including an attachment-chain tip, survives checkpoints, so a boundary and its
later linked summary clear residency once. File session counts still fold
subagents into their parent. The changed-days reader switch remains off.
