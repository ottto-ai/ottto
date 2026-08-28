# 2026-08-28 — Codex created-thread fresh-epoch ownership, v35 fix-forward

## Outcome

The v34 fresh-epoch rule must not ship as an active ownership proof. Equality
between cumulative and last-response usage is repeatable, while absence from a
parent signature ledger was representation-sensitive. Omitting an optional
`model` field from copied parent content could therefore turn the parent's
final restarted response into an apparently novel child response and count it
twice.

Parser `codex_jsonl:v35` removes equality-plus-absence completely. It admits a
fresh physical child only when the rollout carries Codex's native creation
envelope and the entire opened stream validates. Replay revision
`codex_session_exclusive_usage:v5` makes this derivation change one-shot for
already settled machines; v4 is not the active proof.

## Native physical witness

The witness is the conjunction of provider-written structure, not a usage
value:

- the state sidecar contains the exact trusted child-to-parent edge and the
  child's creation time;
- physical record zero is `session_meta`, has ordinal zero, binds both `id`
  and `session_id` to the child rollout id, declares
  `thread_source=agent_created_thread`, and uses paginated history;
- both session-meta timestamps are at or after the sidecar creation time;
- record one is the child's `task_started` event with a fresh turn id and trace
  id, and the first `turn_context` binds the same turn before any usage;
- every physical record has the next exact ordinal and a parseable,
  non-retrograde timestamp at or after the child header; and
- the complete opened file satisfies the witness. Any late structural failure
  suppresses all tentatively parsed usage from that file.

This boundary cannot be manufactured by changing optional fields in copied
usage content. It binds ownership to the rollout identity, provider creation
edge, creation time, physical zero, child task preamble, and complete ordinal
stream that Codex itself writes when creating the file.

The five affected real rollouts provide the same native shape:

| Child id | File SHA-256 | Physical records | Positive checkpoints | First positive ordinal | Header after sidecar |
| --- | --- | ---: | ---: | ---: | ---: |
| `01a03e97-49cf-7460-9fd7-f7dbfd2f05e4` | `48e5ff75ee19f135c9974f931f5d8b63ccbbe9305bc852dba9e3d5d428bf1080` | 6,015 | 958 | 18 | 606 ms |
| `01a03eee-dd5b-7851-a3c6-18caedfc2dfb` | `37d8395b303553a9d617a18b697f9860636172109cfd24df17d036ea256c1fa2` | 704 | 106 | 17 | 1,351 ms |
| `01a03eee-dd5b-7851-a3c6-18e36157f193` | `256013f7e4e77fa57b21c43f2c0ad6231a0680e9507910a7f2f54cac01e3b5eb` | 722 | 115 | 17 | 1,479 ms |
| `01a03eee-dd5b-7851-a3c6-190c38e68ce8` | `fd94886522c474fbaa2ee7eefd683b059da1d20e7a2ad9cc3d7d7840d6c318cb` | 387 | 59 | 16 | 1,284 ms |
| `01a03f0e-a60a-76e3-9d2b-e612b4488dd8` | `0edad137aa8b98ec88cced4ad0dd92aaace54e8886464b7813a25407485da7dd` | 872 | 139 | 17 | 833 ms |

Every physical stream starts at ordinal 0 and remains exactly gap-free. No
record timestamp precedes the header or moves backward. All five begin with
`task_started` at ordinal 1 and bind its turn in the first `turn_context`.
Together they contain 1,377 positive checkpoints: 958 + 106 + 115 + 59 + 139.

Ordinary, resumed, and compacted rollouts can also have a gap-free ordinal
stream, so ordinals alone are not the witness. The trusted created-thread edge,
in-file child identity/source, provider creation chronology, task binding, and
complete physical stream are all required. The R1/R2 fixtures lack this
envelope: they have no ordinal stream, no in-file `session_id`, no native task
preamble, and copied records whose timestamps precede the child header.

## Legacy copied-prefix boundary

A syntactically complete scan is not proof of provider-final history. A parent
file cleanly truncated at a newline is indistinguishable from a genuinely
finished file at EOF. The parent ledger field is therefore named
`scan_complete`, and ledger exhaustion never establishes child ownership.

The legacy copied-prefix path may cross to child-owned data only after matching
a non-empty parent prefix when a later parent signature is already present in
the opened ledger. The divergent child signature is then distinct from that
observed later parent record. Divergence at ledger EOF fails closed.

Ownership signatures are semantic and versioned independently of optional
representation: turn identity and cumulative token totals are retained, while
optional `model`, effort, and last-response presentation are excluded. Optional
field edits therefore cannot create a false absence.

## Attack matrix

| Reproduction | v35 outcome | Loss signal |
| --- | --- | --- |
| R1 copied parent suffix | Fails closed; no snapshot | One ownership-incomplete file plus exact dropped usage records |
| R2 copy with optional `model` omitted | Fails closed; no snapshot | One ownership-incomplete file plus exact dropped usage records |
| Clean newline-truncated parent ledger with omitted suffix in child | Fails closed at parent-ledger EOF | One ownership-incomplete file plus exact dropped usage records |
| Native created-thread stream with a gap, bad chronology, or task mismatch | Whole file fails closed | One ownership-incomplete file plus exact dropped usage records |
| Five native corpus shapes | Admitted exactly once | 1,377 checkpoints; zero loss signals |

## Honest loss decomposition

Ownership/file sentinels are not usage records. v35 reports them separately as
`ownership_incomplete_file_count`. `recognized_usage_drop_count` and
`dropped_usage_record_count` contain only recognized usage records. The former
1,201 aggregate is thus expressed honestly as 1,196 dropped usage records and
5 ownership-incomplete files for the original failing census shape.

## Residual risk

The native path intentionally depends on the matching local sidecar state row.
If that row, its creation timestamp, the provider header, or any ordinal record
is missing or malformed, a legitimate fresh child is withheld rather than
guessed. No operator-attestation escape hatch is needed for the verified
corpus. Future provider layout changes must ship as another versioned parser
proof with corpus evidence.
