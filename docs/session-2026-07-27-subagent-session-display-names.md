# Subagent sessions get real display names (`agent_label`)

Re-keyed Claude Code subagent sessions (`<parentSessionId>_agent-<agentId>`,
Task tool and Workflow tool alike) uploaded with no usable display name and all
rendered as the same workspace fallback. The Workflow tool's human-readable
per-agent labels were sitting on disk the whole time; this change reads them.

## Where the naming material durably lives

| Priority | Location | Field |
| -------- | -------- | ----- |
| 1 | `<sessionDir>/workflows/wf_*.json` run manifest | `workflowProgress[]` rows `{type:"workflow_agent", agentId, label}`, e.g. `probe:data-model` |
| 2 | `<transcript>.meta.json` sidecar | `description` — the Task tool's 3-8 word task summary |
| 3 | same sidecar | `agentType` (`workflow-subagent`, `Explore`, ...) |

Two non-findings that shaped the design: the workflow agent's own sidecar does
NOT carry the label (only `agentType`/`spawnDepth`), so the run manifest is the
sole durable label record; and the "spawned by X - Y" titles seen on
desktop-spawned sessions are authored by the Claude desktop app into its
per-session store — the daemon merely relays them as `desktop_title`.

## What the daemon now emits

The resolved label rides the ordinary title path as
`session_display_name_source=agent_label`, composed as
"spawned by \<parent title\> - \<label\>" when the parent's desktop-store title
is known, mirroring the desktop app's own naming. The parent fragment
truncates to keep the whole title within the 120-char display ceiling; the
label itself is never truncated by composition. Upload-policy title stripping
(`session_titles_enabled`) applies unchanged.

## Titles yes, content no

This deliberately revisits part of the original sidecar policy: `description`
is now read as title material, while prompt bodies and local paths stay out.
`safe_claude_agent_display_label` enforces the shape — whitespace collapse, a
printable-ASCII allowlist, rejection of path-bearing values (`/Users/`,
`/home/`, backslashes, the backend's forbidden fragments), and a hard 80-char
truncation — so a pathological description cannot smuggle prompt content. Only
`label` is extracted from the manifest; the prompt/result previews on the same
rows never survive the parse. `worktreePath` remains unread.

Consistently, the first-prompt TITLE fallback is suppressed for subagent
transcripts: their "first user prompt" is the injected Task prompt body, not a
human-authored title. First-prompt MATERIAL still feeds attribution grouping.

## Late-arriving names re-emit

The subagent slot of the scan fingerprint (previously empty) now folds in stat
tokens for the meta sidecar and the workflow manifest plus the parent's
desktop-title candidate, so a label or parent title that lands after the
transcript was indexed still re-selects the unchanged transcript. Stat-only on
the enumeration path — no content reads per cycle.

## Version bump

`CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` and `CLAUDE_CODE_SCAN_IDENTITY_VERSION`
advance to `claude_code_jsonl:v21`. The scan-identity move is required, not
incidental: semantic sync skips unchanged files by scan identity, and the new
fingerprint components only guard future changes, so without the bump every
already-indexed agent transcript would keep its generic fallback name forever.
The one-time revisit re-emits a title and is otherwise a semantic
no-op-sized upload.

## Release ordering

The backend's `DisplayNameSource` wire literal must accept `agent_label`
before a build carrying v21 reaches an installed base; the batch validator
rejects unknown sources per entity. The backend change ships first.
