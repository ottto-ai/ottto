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
- **One spelling per skill.** The backend turns uploaded
  `activity_summary.skills` names into `skill_id` facts by hashing their exact
  bytes and skipping hashes it already has. So the summary uploads, for a
  reference to an invoked skill, the invocation's lowercased spelling (the one
  its fact hashes), and a second casing of a referenced skill (`Foo/SKILL.md`
  after `foo/SKILL.md`) is not stored; the first spelling wins. Admission then
  keeps one fact per skill without a backend change.
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
  dedupe, plugin/relative paths, `.backup` lookalike, Edit ignored, casing
  variants upload one spelling (the invocation's for an invoked skill), no tool
  counts, no path upload, unnamed → v1, 33/9 bounds, wire cap 32.
- `codex_unnamed_skill_reference_keeps_capability_marker_v1`, and the existing
  Codex activity test now covers `.system` and asserts v2.
- `skill_detector_upgrade_republishes_retained_claude_history_once`: an index
  left by the previous scan identity with a v1 body republishes both sessions
  (one with a skill, one empty) once with the same content hash and usage, then
  settles; labels-off policy still strips skill names.

## Measured cost (release builds, `ottto-service snapshot-audit`)

One release build of main and one of this change, run through the existing
`snapshot-audit` command (production scanner, isolated audit state directory,
no upload). Frozen local corpus: 626 Claude files (1.50 GB, 258 sessions) and
75 Codex files (1.50 GB, 67 sessions). For the measurement only, both builds
got the same uncommitted two-line audit tweak: allow the private upload payload
for Claude, and an env switch that turns attribution, labels and titles on so
skill facts and names reach the payload. Default policy (all off) unless noted.
User CPU from `/usr/bin/time -l`; runs alternate main/change to remove drift.

| # | what | main | change | delta |
|---|---|---|---|---|
| M1 | Claude full scan, user CPU (6 runs) | 10.31 s | 10.25 s | −0.6% |
| M1 | Codex full scan, user CPU (4 runs) | 7.93 s | 7.78 s | −1.9% |
| M1 | scanner-stage peak RSS, median (Claude / Codex) | 145.7 / 62.4 MB | 146.2 / 63.1 MB | +0.5 / +0.7 MB |
| M2 | append one record to the largest Claude file (186 MB), rescan, user CPU (8 runs) | 1.212 s | 1.234 s | +1.8% (one run-to-run stdev is ~0.04 s) |
| M2 | same, largest Codex file (521 MB) (6 runs) | 4.02 s | 3.98 s | −1.0% |
| M4 | audit state directory after scans (Claude / Codex) | 536,632 / 86,264 B | 536,632 / 86,264 B | 0 B, no new files |

The rescan after an append re-reads the whole changed file (1 Claude file; 5
Codex files, of which 4 are ownership-incomplete residue re-derived every
generation in both builds).

**M3, one-time upgrade.** First scan of the change over main's settled state:

| | Claude | Codex |
|---|---|---|
| files parsed (all, 1.50 GB each) | 622 / 622 | 75 / 75 |
| sessions republished | 258 / 258 | 67 / 67 |
| upload JSON, policy off | 3,649,398 B (gzip 322,582) | 1,451,989 B (gzip 158,240) |
| upload JSON, attribution + labels on | 4,143,445 B (gzip 451,214) | 1,559,148 B (gzip 184,991) |
| second scan: files parsed / sessions published | 0 / 0 | 4 residue / 0 |

Every retained session republishes once (the parser version is in the revision
hash, so this includes sessions whose marker stays v1), then the next scan is a
no-op. Against a fresh main scan, the change adds 0 B of upload JSON with the
policy off (marker string has the same length) and +99,102 B for Claude
(+384 B per session, +2.5%) / +4,499 B for Codex with attribution and labels on.

Signal with attribution and labels on: Claude `skill_id` facts 21 → 258
(15 → 97 sessions), summary names 0 → 264 (94 sessions); Codex facts 81 → 92.
Marker v2: Claude 237/258, Codex 64/67; the rest saw an unnamed reference.
Replaying backend admission's promotion on the change's payloads (same HMAC,
same caps) adds 0 new skill facts in both sources, and no session holds two
casings of one skill.

The scan index keeps its size and file count; no background work is added.
