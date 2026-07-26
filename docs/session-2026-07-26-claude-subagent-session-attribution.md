# 2026-07-26 — Claude Code subagent session attribution (`claude_code_jsonl:v20`)

## Outcome

Claude Code workflow-subagent transcripts no longer upload snapshots that claim
to be their parent human session. Every subagent transcript is keyed from its
path, the Workflow tool's bookkeeping journal is excluded from snapshot
emission, and subagent sessions now carry their position in the agent tree as
attribution facts.

## The four on-disk layouts

Claude Code writes exactly four JSONL shapes under `~/.claude/projects`:

| # | Path | What it is |
| - | ---- | ---------- |
| 1 | `<projectDir>/<sessionId>.jsonl` | top-level human session |
| 2 | `<projectDir>/<sessionId>/subagents/agent-<agentId>.jsonl` | Task-tool subagent |
| 3 | `<projectDir>/<sessionId>/subagents/workflows/<wfId>/agent-<agentId>.jsonl` | Workflow-tool subagent |
| 4 | `<projectDir>/<sessionId>/subagents/workflows/<wfId>/journal.jsonl` | Workflow bookkeeping |

Every line of layouts 2-4 carries the **parent's** `sessionId`, never the
agent's own. The path, not the file contents, is the authority on which session
a transcript belongs to.

## Bug

`claude_code_jsonl:v13` introduced the subagent re-key but recognised a subagent
transcript only when its **immediate** parent directory was `subagents`. That is
true for layout 2 and false for layouts 3 and 4, whose immediate parent is a
`wf_*` directory. Layout 3 therefore kept the in-file `sessionId` and uploaded
under the parent's id.

Backend `is_latest` promotion is last-writer-wins per destination scope, so one
arbitrary workflow agent's slice overwrote the real orchestrator session: wrong
model, wrong totals, `initiator` flipped human to `ai_agent`, a poisoned context
watermark, and `used_workflow_orchestration=false` on a session that had in fact
run the Workflow tool.

Layout 4 never produced a snapshot (no `message.usage` rows), but it was still
walked and indexed, and its `journal` file stem is **not** unique within a parent
session — a session with two workflow directories has two `journal.jsonl` files
that would both re-key to `<parentSessionId>_journal`.

## Fix

- The subagent test is now "**any** ancestor directory is `subagents`".
- `root_session_id` comes from the directory whose child is `subagents`. The
  in-file `sessionId` is corroboration only and is never used to build the id.
- The `<parentSessionId>_<fileStem>` id scheme is unchanged, so ids already
  minted for layout 2 keep resolving to the same backend session.
- `journal.jsonl` inside a `subagents` tree is dropped at collection time and
  refused by the parser, so `<parentSessionId>_journal` can never exist.
- The desktop-title lookup and the scan sidecar fingerprint use the same
  ancestor-aware test, so a workflow agent cannot inherit its parent's title.

## Wire contract

A Claude subagent snapshot now carries these attribution facts. The names are
fixed and shared with the backend session-attribution reader.

| Field | Value | Source |
| ----- | ----- | ------ |
| `parent_session_ref` | direct parent: the raw parent UUID at depth 1, or `<parentUUID>_agent-<parentAgentId>` when the sidecar records a spawning agent | path + sidecar |
| `root_session_ref` | the top-level human session UUID — the rollup key | path |
| `agent_kind` | `agentType`, e.g. `workflow-subagent`, `Explore`, `general-purpose` | `*.meta.json` |
| `agent_ref` | provider agent id (file stem with `agent-` stripped) | path |
| `spawn_depth` | `spawnDepth`, stringified | `*.meta.json` |
| `workflow_ref` | the `wf_*` directory name, absent outside `workflows/` | path |

`parent_session_ref` rides the existing `SnapshotOrigin::parent_session_ref`
path already used by Codex; it stays `#[serde(skip)]` and never widens the v6
`origin` wire object.

The sidecar read is bounded (64 KiB, streamed, never slurped) and every failure
mode — absent file, oversized file, unreadable bytes, invalid JSON, wrong value
type, unsafe characters — degrades to an absent fact. A malformed sidecar can
never drop the session it describes. `description`, `worktreePath`, and
`worktreeBranch` are deliberately not read: they carry prompt material and local
filesystem paths. Values pass a conservative `[A-Za-z0-9._:-]` allowlist and are
dropped, not sanitized, when they fail it.

## Payload budget

The 24-fact and 2 KiB attribution-payload limits still apply. At roughly 269
bytes per fact only seven fit, and a workflow agent produces eight
(`origin_kind`, `provider_surface`, `parent_session_ref`, `root_session_ref`,
`agent_kind`, `agent_ref`, `workflow_ref`, `spawn_depth`). `spawn_depth` is
ordered last and is the one trimmed, which is lossless in this layout: every
observed workflow agent is depth 1, which `parent_session_ref ==
root_session_ref` already states. Task-tool agents — the layout that actually
nests, to depth 2 and 3 — carry no `workflow_ref`, so their `spawn_depth` fits.
Raising the shared budget to ~2.4 KiB would let all eight through.

## Version bump

Both `CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` and
`CLAUDE_CODE_SCAN_IDENTITY_VERSION` advance to `claude_code_jsonl:v20`.

The scan-identity bump is required, not incidental. Since local semantic sync,
the incremental scan skips a transcript whose bytes and mtime are unchanged and
keys that decision on the scan identity version, not the parser version. A
parser-version bump alone would leave every already-indexed workflow-agent file
permanently skipped and the fix inert on existing installs. The derivation that
changed is which **session** a file maps to, which is scan identity. The
one-time revisit stays cheap: an unchanged session re-parses to the same
semantic fingerprint and is suppressed as a semantic no-op.

The revisit re-emits every mis-keyed subagent under its own id and stops the
overwrites, but it does **not** re-emit the parent sessions, which are semantic
no-ops. Healing an already-overwritten parent row is a backend re-promotion, or
an explicit full replay via `current_historical_replay`.

## Verification

A read-only audit (`claude_real_tree_rekey_audit`, `#[ignore]`d, opens no
daemon and uploads nothing) over a real 3,224-file tree:

```
layout 1 (top-level session):  1939
layout 2 (task subagent):       752
layout 3 (workflow subagent):   461
layout 4 (workflow journal):     72 (all excluded)
re-keyed subagent sessions:    1213   (all with a readable meta.json + agentType)
  nested (parentAgentId):        23
v19 mis-keyed onto a parent:    461   across 22 distinct parent sessions
re-keyed id collisions:           0
re-key vs top-level id clash:     0
```

## Release implication

Deploy the backend field-name allowlist, storage, and the mirrored semantic
envelope golden **before** publishing a macOS build that carries
`claude_code_jsonl:v20`. The backend rejects unknown attribution field names and
one rejected fact fails the whole upload batch.
