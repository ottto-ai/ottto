# 2026-10-18 — Skill evidence from the tool walk (capability marker v2)

## What changed

- **One shared SKILL.md path extractor** (`for_each_skill_md_reference`,
  `snapshots.rs`) replaces `skill_names_from_material`. It checks every
  `SKILL.md` occurrence on its own and takes the immediate parent directory as
  the skill name, so any root works: `.agents/skills/x`, `.claude/skills/x`,
  plugin caches (`…/skills/review`), `skills/.system/imagegen`, synced buckets,
  relative and custom roots. Filename boundaries reject `SKILL.md.backup` and
  `SKILL.mdx`. A reference that cannot be named (`cat SKILL.md`,
  `skills/*/SKILL.md`, `"$D/SKILL.md"`, `../SKILL.md`) marks the session's skill
  detector incomplete. It is a delimiter scan, not a shell parser; no file is
  opened and no path is uploaded.
- **Codex** uses it through the existing activity material walk
  (`note_activity_tools` + `note_activity_skills`, split from
  `note_activity_material`).
- **Claude** gets skill evidence in the existing tool-use loop
  (`note_claude_skill_signal`):
  - `Skill` tool input → provider skill (invocation, `provider_native`), the same
    set as the `attributionSkill` marker, so both dedupe;
  - `Read.file_path` and `Bash.command` → the shared extractor (reference,
    `provider_artifact`). Claude never runs the Codex nested-tool counter, so its
    tool totals are unchanged. Edit/Write/Grep of a SKILL.md are authoring or
    search, not a load, and are not counted.
- **Capability marker v2.** `activity_summary.capability_collection_version` is
  `agent_capability_usage:v2` for Claude and Codex when every SKILL.md reference
  was named, else `agent_capability_usage:v1`. v2 keeps v1's capability counts;
  it only adds "the skill detector saw everything it could name". No new wire
  field. The backend must admit v2 before this ships.
- **Bounded memory.** Activity skills stop at 33 (wire cap 32 + 1, so the backend
  still sees truncation); provider skills stop at 9 (fact cap 8 + 1).
  `MAX_SKILL_FACTS` names the shared 8-fact cap in `session_attribution.rs`.
- **Versions.** Claude parser v38→v39, scan identity v29→v30; Codex parser
  v38→v39, scan identity v33→v34. The marker lives in the semantic
  `activity_summary`, so every retained Claude and Codex session republishes
  once, then converges as a semantic no-op. Session id, content hash, usage and
  money are unchanged. `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE` is untouched.
- Generated fixtures refreshed (versions, marker, revision and body-witness
  digests; content hashes unchanged). The Codex cache fixture test now writes
  `OTTTO_CACHE_FIXTURE_OUT` before asserting, like the Claude one, so it can be
  regenerated.

## Tests

- `skill_md_references_name_every_layout_and_flag_unnamed_ones`: extractor table.
- `claude_skill_evidence_separates_invocations_from_references`: Skill + marker
  dedupe, plugin/relative paths, `.backup` lookalike, Edit ignored, no tool
  counts, no path upload, unnamed → v1, 33/9 bounds, wire cap 32.
- `codex_unnamed_skill_reference_keeps_capability_marker_v1`, and the existing
  Codex activity test now covers `.system` and asserts v2.
- `skill_detector_upgrade_republishes_retained_claude_history_once`: an index
  left by the previous scan identity with a v1 body republishes both sessions
  (one with a skill, one empty) once with the same content hash and usage, then
  settles; labels-off policy still strips skill names.

## Measured cost (debug test build, same frozen local corpus, 3 runs each)

Corpus: 581 Claude files (1.47 GB, 227 sessions), 68 Codex files (1.47 GB,
61 sessions). Whole-process CPU of the parse, main vs this change:

| | main (s) | change (s) | delta |
|---|---|---|---|
| Claude, all files | 68.9 / 71.2 / 69.9 | 69.6 / 68.3 / 69.4 | −1.2% (noise) |
| Codex, all files | 35.1 / 36.1 / 34.8 | 34.8 / 35.2 / 34.9 | −1.0% (noise) |
| Claude largest file (185 MB) | 11.0 / 11.8 / 11.3 | 10.8 / 10.9 / 10.7 | noise |
| Codex largest file (514 MB) | 8.4 / 8.9 / 8.5 | 8.5 / 8.4 / 8.6 | noise |

- Peak RSS of the run: 128.9 MB main, 127.4 MB change (no increase).
- Serialized `activity_summary`: Claude +6.3 KB over 227 sessions (~28 B each),
  Codex +0.2 KB. Sessions with skills: Claude 0 → 88, Codex 14 → 19.
- Marker: Claude 208/227 v2, Codex 58/61 v2; the rest saw an unnamed reference.
- No new files or background work; the scan index keeps its row count.
- One-time: every retained session republishes once after upgrade.
