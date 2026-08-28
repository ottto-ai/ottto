# 2026-08-28 — Codex created-thread ownership, v36 fix-forward

## Outcome

Parser `codex_jsonl:v36` closes the independent created-thread `history_base`
authorization bypass and strengthens the v35 native witness with corroboration
outside the rollout bytes. Replay revision
`codex_session_exclusive_usage:v6` deliberately revisits settled Codex history;
v34/v4 and v35/v5 are not active proofs.

For `thread_source=agent_created_thread`, neither `history_base` nor
`subagent_history_start_ordinal` can transition directly to `AllLocal` or the
ordinary ordinal boundary. A created-thread file carrying either field is
admitted only through the complete native witness. If that witness is absent or
invalid, the shape becomes ownership-incomplete and cannot fall through to the
legacy copied-prefix state machine or inclusive SQLite usage.

## Native witness and external corroboration

The native witness requires all of the following:

- a complete Codex state-sidecar census with an exact, non-conflicting
  child-to-parent edge and a parseable child creation time;
- physical record zero is `session_meta` at ordinal zero, binds both `id` and
  `session_id` to the rollout filename's child id, declares
  `thread_source=agent_created_thread`, and uses paginated history;
- the first record timestamp is not before the sidecar creation time and is no
  more than five seconds after it; the embedded session-meta timestamp lies in
  the same spawn-to-first-record interval;
- physical record one is `event_msg/task_started` with a UUID-like turn id,
  32-hex trace id, and `started_at` inside the spawn-to-record interval;
- the first `turn_context` binds that turn before any usage;
- every record through opened-file EOF has the exact next ordinal and a
  parseable, non-retrograde timestamp at or after the header; and
- when the Codex-owned artifacts expose them, the opened file matches
  `state_5.sqlite.threads.rollout_path`, the path resolves to the same opened
  filesystem object, file birth/mtime are within five seconds of the sidecar
  creation/update times, file size equals
  `thread_history_1.sqlite.thread_history_projection_state.next_rollout_byte_offset`,
  and final ordinal equals `next_rollout_ordinal`.

The filesystem checks are optional only when the corresponding provider field
or projection database does not exist. When present, a mismatch fails closed.
The projected byte/ordinal extent and rollout path participate in the
per-session sidecar fingerprint, so a later projection update reselects the
file. Usage remains tentative until whole-file finalization.

Read-only schema inspection found no provider-held rollout digest, signature,
first-turn commitment, or immutable content id. `state_5.sqlite.threads`
provides path and timestamps but no general size/hash; the migration-skip table
has size/mtime only for skipped migrations and cannot authenticate ordinary
rollouts. `session_index.jsonl` contains only `id`, `thread_name`, and
`updated_at`. The thread-history projection supplies byte-offset/ordinal extent,
not a content hash. Those are real corroborating facts and are used only for
what they prove.

The five affected real rollouts satisfy the strengthened evidence:

| Child id | Physical records | Positive checkpoints | First positive ordinal | First record after sidecar |
| --- | ---: | ---: | ---: | ---: |
| `01a03e97-49cf-7460-9fd7-f7dbfd2f05e4` | 6,015 | 958 | 18 | 606 ms |
| `01a03eee-dd5b-7851-a3c6-18caedfc2dfb` | 704 | 106 | 17 | 1,351 ms |
| `01a03eee-dd5b-7851-a3c6-18e36157f193` | 722 | 115 | 17 | 1,479 ms |
| `01a03eee-dd5b-7851-a3c6-190c38e68ce8` | 387 | 59 | 16 | 1,284 ms |
| `01a03f0e-a60a-76e3-9d2b-e612b4488dd8` | 872 | 139 | 17 | 833 ms |

Their projected byte offsets equal file sizes `44,429,566`, `8,178,205`,
`6,401,656`, `5,073,982`, and `8,732,561`; projected next ordinals equal
record counts. State-row update times equal file mtimes at millisecond
precision, and birth times are within the five-second creation tolerance.

## Attack matrix

| Shape | v36 outcome | Signal or compatibility reason |
| --- | --- | --- |
| R1 copied parent suffix | Fails closed; no child snapshot | Exact usage-record drops plus one ownership-incomplete file |
| R2 copied suffix with optional `model` omitted | Fails closed; no child snapshot | Optional representation is not an ownership gate |
| Clean newline-truncated parent with omitted suffix in child | Fails closed at parent-ledger EOF | Scan-complete EOF is not provider-final extent |
| Created-thread `history_base` with missing native ordinals/task structure and retrograde copied usage | Fails closed; no child snapshot | One dropped usage record plus one ownership-incomplete file |
| Native stream with ordinal gap/restart | Whole file fails closed | Final native validation suppresses tentative usage |
| Native stream with retrograde timestamp | Whole file fails closed | Final native validation suppresses tentative usage |
| Native first-turn mismatch | Whole file fails closed | Final native validation suppresses tentative usage |
| First record more than five seconds after sidecar creation | Fails closed before native admission | Bounded external chronology mismatch |
| Sidecar rollout path/object, mtime/birthtime, byte extent, or final ordinal mismatch | Fails closed when that evidence exists | External witness mismatch |
| Malformed partial final JSON record / crash mid-write | Whole file remains retryable and unhealthy | Parser incompleteness; never confirmed empty |
| Ordinary resume/compaction/pagination | Does not enter created-thread native admission solely for being paginated | Existing ordinary ownership paths remain separate |
| Adjacent equal timestamps | Accepted as non-retrograde | All five real files contain equal pairs; equality cannot honestly be rejected |
| Five native corpus shapes, including valid native `history_base` | Each admitted exactly once | 1,377 checkpoints; zero loss counters |

## Trust model

This is a local-evidence integrity boundary, not a cryptographic provenance
boundary. Natural truncation and partial-copy shapes fail closed: the R1 copied
suffix, R2 optional-field variant, clean parent-EOF omission, invalid
`history_base`, ordinal gap/restart, retrograde chronology, task/first-turn
mismatch, projected extent mismatch, and malformed crash tail all suppress the
child and retain explicit retry/loss evidence. Ordinary resume and compaction
do not acquire created-thread ownership merely from pagination. Equal
timestamps are the one enumerated compatibility case, not a failure signal:
they occur naturally in all five target files (22, 4, 4, 6, and 7 adjacent
equal pairs), so the honest chronology rule is non-retrograde rather than
strictly increasing.

The remaining open case is DELIBERATE whole-file self-forgery against the
machine operator's own billing telemetry. An operator who can rewrite the
rollout can also choose an in-window first timestamp, preserve/pad byte size and
ordinals, restore the forgeable mtime, replace the local thread-history
projection, or edit the local state sidecar itself. Path, inode, birthtime,
mtime, byte-offset, and ordinal checks raise replacement cost and catch natural
damage; none authenticates content against that operator. The current Codex
schemas expose no signature or provider-held digest that could close this gap.

This matches existing daemon precedent rather than creating a stronger claim:
`docs/privacy.md` documents bounded local launch-event files under the user's
home and owner-only local Claude OTLP sidecars as accepted attribution/usage
evidence. Those artifacts are validated and fail closed but are not signed
against the machine owner. This PR applies the same local trust boundary to
Codex sidecars and rollout metadata.

OWNER DECISION REQUIRED: accept this documented boundary or fund a
cryptographic provenance mechanism (Codex-side signing) as future work.

## Version and validation decision

The derivation changed after v35/v5: a formerly admitted `history_base` branch
now fails closed, and new sidecar/file/extent evidence participates in native
admission and candidate selection. Therefore keeping v35/v5 would be false
provenance. The compiled versions are `codex_jsonl:v36` and
`codex_session_exclusive_usage:v6`.

Focused regressions cover the history-base reproduction, valid native
history-base compatibility, the five-second spawn window, path/mtime/byte
extent checks, projected final-ordinal mismatch, the prior R1/R2/truncated-parent
matrix, native ordinal/chronology/turn failures, and the five corpus shapes.
