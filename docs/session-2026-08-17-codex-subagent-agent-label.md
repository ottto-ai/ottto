# Codex subagent agent labels

Codex rollout headers record a content-free logical `agent_path` for spawned
agents. The daemon now converts only the final validated task-name segment into
an attribution display label on the existing `agent_kind=codex_subagent` fact.
It never uploads the raw path, agent nickname, prompt, parent title, command, or
tool output.

The label is useful even when the mutable Codex SQLite family graph is absent.
The rollout itself proves subagent identity and supplies the label; SQLite may
still add root-session and spawn-depth facts when available. Parent provenance
continues to travel in its existing, separate fact.

The parser and scan-identity versions both move to `codex_jsonl:v31`, causing a
bounded revisit of historical rollouts. Upload policy removes the display label
when session-title or attribution-label consent is disabled. A backend must
admit the additive `agent_label` display-label source before any daemon release
containing v31 is published.

Validation covers sanitization, operation without SQLite lineage, privacy-policy
stripping, semantic-envelope golden regeneration, Codex-focused tests, clippy,
and public-export manifest integrity.
