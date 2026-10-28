# Feature readers count Codex archives they skip (2026-10-28)

Codex compresses an idle rollout to `.jsonl.zst`. The feature readers never
decode an archive: only the main read may, once. Each one now counts the
archives it skips, under the same cause names as the main read's archive
work, so a query can join them. Counts only; no path or content is logged.

- Composition (`context_composition_v2_metrics`): `archived_unpinned` counts
  archives found with no plain copy and no pin. Either the rollout was never
  read while it was plain, or it was read and its pin was forgotten after the
  missing-file window. Cause: `CompressedCompositionUnsupported`. The existing
  `archived` field still counts an archive that finishes a known pin.
- Codex session start (`codex_session_start_harvest_metrics`):
  `compressed_skipped` counts recent archives the shared recent-file collector
  passed over. Cause: `CompressedPreludeUnsupported`.
- MCP inventory: when the newest Codex rollout of the newest day is an
  archive, the harvest logs
  `mcp_harvest codex_version=unavailable reason=CompressedClientVersionUnavailable`.
  The reported version is unchanged: the newest plain log, or unknown.

Nothing reads, opens or decodes an archive; detection uses file names and
directory metadata only. These causes stay on each feature's own line and are
not added to the main read's archive counters.
