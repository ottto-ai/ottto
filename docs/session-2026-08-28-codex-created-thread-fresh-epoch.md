# 2026-08-28 — Codex created-thread ownership, v36 fix-forward

## Outcome

Parser `codex_jsonl:v36` closes the independent created-thread `history_base`,
capability-off, and legacy parent-prefix authorization bypasses and strengthens
the v35 native witness with corroboration outside the rollout bytes. Replay revision
`codex_session_exclusive_usage:v6` deliberately revisits settled Codex history;
v34/v4 and v35/v5 are not active proofs.

For `thread_source=agent_created_thread`, neither context-curve capability,
`history_base`, `subagent_history_start_ordinal`, nor a legacy parent ledger can
transition directly to `AllLocal`, the ordinary ordinal boundary, or the legacy
copied-prefix machine. Every created-thread shape is admitted only through the
complete native witness. If that witness is absent or invalid, the shape becomes
ownership-incomplete and cannot fall through to inclusive SQLite usage. Backend
capability controls what optional curve payload the daemon emits, never what it
requires to attribute usage ownership.

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

## Exhaustive created-thread admission branches

The first authoritative `session_meta` fixes the ownership state once. For a
file declaring `thread_source=agent_created_thread`, the complete set of
admission/fallback branches is:

| Candidate branch | Gate for a created thread | Result |
| --- | --- | --- |
| Native JSONL usage, curve capability present | Trusted sidecar child/parent edge, complete native header/task/turn witness, gap-free non-retrograde stream through projected EOF, complete/lossless parse | Usage admitted; curve emitted |
| Native JSONL usage, curve capability absent | Identical ownership gates to capability-present | Usage admitted; curve omitted |
| `history_base` marker | Cannot authorize `AllLocal`; must independently satisfy the complete native witness | Native admission or `AmbiguousFork` |
| `subagent_history_start_ordinal` marker | Cannot authorize `Ordinal`; the native header rejects this marker | `AmbiguousFork` |
| No pagination marker with a complete parent ledger | Legacy `AwaitingParentPrefix` is unreachable; must independently satisfy the complete native witness | Native admission or `AmbiguousFork` |
| Transcript `forked_from_id` | Must agree with the trusted sidecar parent and still satisfy the complete native witness | Native admission or `AmbiguousFork` |
| Missing/conflicting sidecar, invalid header, task/turn mismatch, ordinal/time/extent failure, or incomplete parse | No alternative positive gate | Whole file suppressed, ownership/loss or parser-health evidence retained, retry remains pending |
| Inclusive `state_5.sqlite.tokens_used` fallback | Blocked by the created-thread/fork session id and independently excluded by sidecar family membership | Never admitted for the ambiguous file |
| Confirmed-empty/index skip | Incomplete ownership or parsing never records the file as confirmed empty; sidecar evidence participates in the candidate fingerprint | Never converts ambiguity into a positive witness |

There is therefore one positive admission branch for this shape:
`NativeCreatedThread` followed by whole-file finalization. `AllLocal`, `Ordinal`,
`AwaitingLegacyTrigger`, and `AwaitingParentPrefix` remain compatibility states
only for explicitly non-created-thread legacy sources.

## Attack matrix

| Shape | Capability present / absent | v36 outcome | Signal or compatibility reason |
| --- | --- | --- | --- |
| R1 copied parent suffix | Identical fail-closed result | Fails closed; no child snapshot | Exact usage-record drops plus one ownership-incomplete file |
| R2 copied suffix with optional `model` omitted | Identical fail-closed result | Fails closed; no child snapshot | Optional representation is not an ownership gate |
| Clean newline-truncated parent with omitted suffix in child | Identical fail-closed result | Fails closed without consulting legacy prefix admission | Scan-complete EOF is not provider-final extent |
| No-marker child with matched parent A, omitted parent B, then copied parent C | Identical fail-closed result | Legacy parent-prefix machine is unreachable | One copied usage drop plus one ownership-incomplete file |
| Created-thread `history_base` with missing native ordinals/task structure and retrograde copied usage | Identical fail-closed result | Fails closed; no child snapshot | One dropped usage record plus one ownership-incomplete file |
| Native stream with ordinal gap/restart | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| Native stream with retrograde timestamp | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| Native first-turn mismatch | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| First record more than five seconds after sidecar creation | Identical fail-closed result | Fails closed before native admission | Bounded external chronology mismatch |
| Sidecar rollout path/object, mtime/birthtime, byte extent, or final ordinal mismatch | Identical fail-closed result | Fails closed when that evidence exists | External witness mismatch |
| Malformed partial final JSON record / crash mid-write | Identical uncommittable result | Whole file remains retryable and unhealthy | Parser incompleteness; never confirmed empty |
| Ordinary resume/compaction/pagination | Identical legacy classification | Does not enter created-thread native admission solely for being paginated | Existing ordinary ownership paths remain separate |
| Adjacent equal timestamps | Identical compatibility result | Accepted as non-retrograde | All five real files contain equal pairs; equality cannot honestly be rejected |
| Five native corpus shapes, including valid native `history_base` | Same ownership totals; curve only present when advertised | Each admitted exactly once | 1,377 checkpoints per capability mode; zero loss counters |

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

Owner decision: ACCEPTED for this PR.

## Version and validation decision

The derivation changed after v35/v5: formerly admitted `history_base`,
capability-off, and no-marker parent-prefix branches now fail closed, and new
sidecar/file/extent evidence participates in native admission and candidate
selection. Therefore keeping v35/v5 would be false provenance. The compiled
versions remain `codex_jsonl:v36` and `codex_session_exclusive_usage:v6` because
all of these corrections are fix-forwards within the same unmerged DRAFT v36/v6
release unit; no released v36/v6 completion exists to distinguish with another
revision.

Focused regressions run the full matrix with the curve capability present and
absent, including `history_base`, the no-marker internal parent omission, valid
native compatibility, the five-second spawn window, path/mtime/byte extent
checks, projected final-ordinal mismatch, R1/R2/truncated-parent shapes, native
ordinal/chronology/turn failures, malformed crash tails, ordinary pagination
non-acquisition, and the five corpus shapes. Durable production replay state is
also exercised from recorded v2, v3, v4, and v5 through persisted v6 completion.
