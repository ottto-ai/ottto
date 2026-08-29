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

Created-thread classification is the OR of two independently retained inputs:
the trusted state-row declaration and the rollout declaration. A trusted state
declaration cannot be withdrawn by the rollout it governs. The complete input
product is below. One resolver owns every state, thread-history, spawn-edge,
rollout-path/header, blocker, ownership-map, ledger, membership-set, and
fingerprint boundary: an exactly 36-byte, ASCII-hex, hyphenated UUID becomes
lowercase ASCII, while every other identifier remains byte-exact (including
Unicode and leading/trailing whitespace). The path ingress parses the provider
grammar `rollout-<timestamp>-<identity>.jsonl` (and legacy
`rollout-<identity>.jsonl`) without guessing between them. If the legacy
identity itself begins `YYYY-MM-DDTHH-MM-SS-`, ingress preserves both the full
legacy remainder and the possible modern remainder until trusted state/census
evidence or the first authoritative header selects exactly one. Both candidates,
or no supported candidate when created-thread evidence is present, is
`AmbiguousFork`; every unresolved candidate is also retained in the inclusive
state-fallback blocker. The parser never strips a UUID-looking suffix from a
larger identifier. Distinct sidecar rows that collapse to one UUID key make that
key ambiguous. The key remains in a durable in-memory blocker set while
non-colliding state classifications remain available.

An existing `state_5.sqlite` is a complete created-thread classification source
only when `threads` contains all required columns: `id`, `thread_source`, and
`first_user_message`, and the fixed classification query and every selected row
decode successfully. A missing table/column and a query/read/decode failure are
the same unscoped incomplete result and block every Codex rollout. Unknown extra
columns are additive and accepted. An incomplete title/state-detail/history
census blocks identities already classified as created, but does not change an
unrelated ordinary rollout's compatibility classification.

| Trusted state row | Rollout `thread_source` | Classification / admission result |
| --- | --- | --- |
| Declares created thread | Declares `agent_created_thread` | Created thread; only the complete native witness can admit it |
| Declares created thread | Omitted | Created thread plus classification conflict; `AmbiguousFork` |
| Declares created thread | Other string | Created thread plus classification conflict; `AmbiguousFork` |
| Declares created thread | Malformed/non-string | Created thread plus classification conflict; `AmbiguousFork` |
| Semantically matching created row whose raw UUID casing differs from the rollout key | Any rollout value | Canonicalized to the same state-created identity, then handled exactly as the corresponding state-declares-created row above |
| Matching created row and rollout use the same non-UUID/near-UUID bytes | Any rollout value | Byte-exactly resolves to the same key, then follows the corresponding state-declares-created row above; no UUID suffix alias exists |
| State/sidecar rows contain distinct raw UUID aliases for this resolved key | Any rollout value | Key-scoped census ambiguity; `AmbiguousFork`, with no generic branch evaluated |
| Readable state DB is missing `threads`, `id`, `thread_source`, or `first_user_message`, or a classification row cannot decode | Any rollout value | Source-wide identity ambiguity; `AmbiguousFork`. This closes the reproduced former `history_base -> AllLocal` admission of exact `30/8/12/1/1` usage |
| Complete required state schema also has unknown future columns | Any rollout value | Additive columns do not make the census incomplete; classification follows the matching ordinary/created row normally |
| Legacy filename identity starts with the modern timestamp grammar and exactly the full legacy candidate has trusted evidence | Any rollout value | The full byte-exact legacy identity is selected. This closes the reproduced former shortened-key `history_base -> AllLocal` admission of exact `30/8/12/1/1` usage |
| Both filename grammar candidates have trusted evidence and either is created/conflicted, or no candidate can be selected while created classification is incomplete | Any rollout value | Multi-key identity ambiguity; `AmbiguousFork`, and inclusive state fallback is blocked for every candidate |
| Created-thread classification census fails without an identity scope | Any rollout value | Source-wide identity ambiguity; `AmbiguousFork`, with no generic branch evaluated |
| Title/state-detail/history census is incomplete, but created classification is complete | Any rollout value | State-created identity is `AmbiguousFork`; unrelated ordinary identity retains its ordinary compatibility result |
| Rollout path cannot resolve while trusted created-thread suspects exist | Any rollout value | Identity ambiguity; `AmbiguousFork`, with no generic branch evaluated |
| Does not declare this session | Declares `agent_created_thread` | Created thread from rollout evidence; native admission still requires an independent trusted matching child/parent edge and the complete witness |
| Does not declare this session | Omitted, malformed, or another value | Not classified as created; ordinary compatibility branches apply |
| Ordinary non-created state/header/path all use the same non-UUID bytes | Omitted, malformed, or another non-created value | Ordinary compatibility branches apply unchanged; byte-exact identity alone does not manufacture created ownership |

The state declaration is bound by the rollout path's provider session id;
created rows for unrelated session ids and generic `thread_spawn_edges` never
set it. After that classification, the first authoritative `session_meta`
fixes the ownership state once. The complete admission/fallback enumeration is:

| Candidate branch | Gate for a created thread | Result |
| --- | --- | --- |
| Native JSONL usage, curve capability present | Rollout declares created thread, any state declaration agrees, and the trusted sidecar child/parent edge plus complete native header/task/turn witness, gap-free non-retrograde stream through projected EOF, and complete/lossless parse all hold | Usage admitted; curve emitted |
| Native JSONL usage, curve capability absent | Identical ownership gates to capability-present | Usage admitted; curve omitted |
| State/rollout classification disagreement | State declaration wins classification, while an omitted, malformed, or different rollout marker proves conflict | `AmbiguousFork`; no generic branch is evaluated |
| Census incomplete from a known UUID-alias collision | The collided resolved key is retained as a blocker; non-colliding map/set entries remain classified | Collided file is `AmbiguousFork`; unrelated ordinary compatibility and trusted created classification remain unchanged |
| Created-thread classification census incomplete without a trustworthy key scope | No identity can prove it is outside the missing classification census | Every Codex file is `AmbiguousFork` until a complete classification census is available |
| Title/state-detail/history census incomplete with complete classification | Missing corroboration can weaken only an already-classified created candidate | Created identity is `AmbiguousFork`; unrelated ordinary identity remains ordinary |
| Non-UUID/near-UUID path identity | Complete filename identity remainder and raw header/state bytes resolve through the same byte-exact key | Matching state-created suspect follows native-only admission or `AmbiguousFork`; matching ordinary file remains ordinary |
| Timestamp-shaped legacy/current filename overlap | Both complete candidate identities survive parsing; state/census and the first authoritative header must support exactly one whenever either candidate is created/conflicted | Unique candidate follows its normal classification; otherwise `AmbiguousFork`, with every candidate blocked from state fallback |
| Unresolvable/ambiguous path identity with created-thread suspects | No trustworthy state-to-file join exists | `AmbiguousFork`; header-controlled generic admission is unreachable |
| `history_base` or `subagent_history_start_ordinal` marker | Cannot authorize `AllLocal` or `Ordinal`; the latter is also rejected by the native header | Native admission or `AmbiguousFork` |
| No pagination marker with a complete parent ledger | `AwaitingParentPrefix` / `AwaitingLegacyTrigger` are unreachable; must independently satisfy the complete native witness | Native admission or `AmbiguousFork` |
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
| State-proven created thread with rollout marker absent | Identical fail-closed result | State classification prevents `history_base -> AllLocal` | One copied usage drop plus one ownership-incomplete file |
| State-proven created thread with conflicting/malformed rollout marker | Identical fail-closed result | Classification conflict is `AmbiguousFork` | One copied usage drop plus one ownership-incomplete file |
| Readable state DB missing a required created-thread classification table/column, or carrying an undecodable row | Identical fail-closed result | Source-wide census incompleteness is `AmbiguousFork`; empty is never inferred | Exact probe: zero snapshots, one usage drop, one ownership-incomplete file, one dropped record |
| Required state schema plus an unknown future column | Identical compatibility result | Additive schema growth remains complete | Ordinary control emits exact `30/8/12/1/1` usage with zero loss counters |
| Legacy identity begins `YYYY-MM-DDTHH-MM-SS-` | Identical fail-closed result for the state-created probe | Full and shortened candidates are retained; the full state/header match wins | Legacy probe suppressed with one/one/one counters; modern timestamped ordinary control remains admitted |
| Live lower/uppercase UUID-alias collision for the rollout key, marker absent, `history_base` present | Identical fail-closed result | Key-scoped census ambiguity is `AmbiguousFork`; no snapshot or upload work item | One copied usage drop plus one ownership-incomplete file; non-colliding sessions retain classification |
| Collided identity named as parent by N direct created children | Identical fail-closed result | Each direct child loses its trusted parent edge; unrelated files and a grandchild with its own unambiguous direct edge are not identity aliases | N usage drops, N ownership-incomplete files, and N dropped records; the production regression proves N=3 |
| Matching state/path/header identity is 35/37 characters, unhyphenated, braced, `urn:uuid:`, whitespace-suffixed, Unicode, or plain non-UUID | Identical fail-closed result for state-created suspects | Complete filename remainder and raw header/state bytes join byte-exactly; no generic admission | One copied usage drop plus one ownership-incomplete file |
| Same near-/non-UUID corpus with an ordinary non-created state row | Identical compatibility result | Ordinary `history_base` behavior is unchanged | One ordinary snapshot with exact `30/8/12/1/1` usage |
| Created-thread `history_base` with missing native ordinals/task structure and retrograde copied usage | Identical fail-closed result | Fails closed; no child snapshot | One dropped usage record plus one ownership-incomplete file |
| Native stream with ordinal gap/restart | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| Native stream with retrograde timestamp | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| Native first-turn mismatch | Identical fail-closed result | Whole file fails closed | Final native validation suppresses tentative usage |
| First record more than five seconds after sidecar creation | Identical fail-closed result | Fails closed before native admission | Bounded external chronology mismatch |
| Sidecar rollout path/object, mtime/birthtime, byte extent, or final ordinal mismatch | Identical fail-closed result | Fails closed when that evidence exists | External witness mismatch |
| Malformed partial final JSON record / crash mid-write | Identical uncommittable result | Whole file remains retryable and unhealthy | Parser incompleteness; never confirmed empty |
| Ordinary resume/compaction/pagination with generic edge and unrelated created row | Identical legacy classification | Does not enter created-thread native admission | Generic edges and unrelated state rows cannot set created identity |
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

A parent-key collision has a bounded identity scope but an unbounded direct-edge
availability cost: every direct created child whose edge names that key is
ambiguous. There is no safe tighter bound in the available data because the
parent bytes are the child's required independent lineage witness. The loader
does not cap the number of such rows, so the logical bound is N direct children.
It does not reclassify unrelated sessions or alias a grandchild's independently
unambiguous direct edge. Each affected child is parsed and contributes its own
usage-drop, ownership-incomplete-file, and dropped-record counter, making the
loss visible in census health rather than silently hiding it.

One naming residual is accepted rather than guessed away. When a rollout name is
grammar ambiguous, carries no `session_meta` identity at all, and neither
candidate has any trusted state/census evidence, no evidence exists to select
between the two readings. Such a file keeps the shared last-resort file-stem
session id instead of silently adopting the shortened candidate. This cannot
admit a created thread — that path requires created evidence, whose presence
makes the same file `AmbiguousFork` — and the stem cannot alias any state row,
so it cannot double-count against the inclusive state fallback. It costs
attribution continuity for a file that carries no identity evidence anywhere.

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
capability-off, no-marker parent-prefix, and state-proven/rollout-marker-dodge
branches now fail closed, and new sidecar/file/extent/classification evidence
participates in native admission and candidate selection. Therefore keeping
v35/v5 would be false provenance. The compiled versions remain
`codex_jsonl:v36` and `codex_session_exclusive_usage:v6` because all of these
corrections are fix-forwards within the same unmerged DRAFT v36/v6 release
unit; no released daemon ever ran v36/v6 and no released v36/v6 completion
exists to distinguish with another revision. UUID-key canonicalization does not
justify another parser/replay revision: shipped Codex state, rollout, and
thread-history identifiers are consistently lowercase already, so no real
shipped corpus shape changes admission. A read-only live check on 2026-08-29
found 1,883 `state_5.sqlite` thread ids and 716 thread-history projection ids
(a point-in-time read of a live growing store; earlier samples saw 1,868/701
and 1,871/704). Both sources had zero non-lowercase ids, zero
non-exact-UUID-shaped ids, and zero timestamp-prefixed identities; the live
`threads` table contained all three required classification columns. A sweep of
the 1,848 live `rollout-*.jsonl` names found zero whose identity remainder
itself begins with a second timestamp shape, so no real file is grammar
ambiguous. Thus the missing-schema and ambiguous
legacy-grammar fixes change only adversarial/damaged shapes in this unreleased
DRAFT, while the real-corpus justification for keeping v36/v6 remains intact.
The case-alias outcome likewise remains part of the same unreleased derivation.

Focused regressions run the full matrix with the curve capability present and
absent, including `history_base`, the no-marker internal parent omission, valid
native compatibility, the five-second spawn window, path/mtime/byte extent
checks, projected final-ordinal mismatch, R1/R2/truncated-parent shapes, native
ordinal/chronology/turn failures, malformed crash tails, ordinary pagination
non-acquisition, state-loaded absent/conflicting/malformed rollout markers,
UUID case aliases in both state-to-rollout directions, canonical-key collision
failure through the production scanner, every requested near-/non-UUID shape
through the production join, exact-length right-hyphen/non-hex and
timestamp-prefixed legacy families in the generated path/state/header property,
missing-table/column/row-decode failures, additive future-column growth,
ordinary byte-exact negative controls, upload-unreachability for a suppressed
collision file, generic-edge/unrelated-row non-acquisition, and the five corpus
shapes. The collision probes also prove non-colliding created and ordinary rows
retain their respective classifications and that three direct children produce
three independent loss-counter increments in both modes. Durable production
replay state is also exercised from recorded v2, v3, v4, and v5 through
persisted v6 completion.
