# Active Session Surfaces

Ottto's local status contract can identify which provider client ran a recently
changed coding-agent session. When direct provider metadata is available,
`active_session_reconciliation.sessions[].provider_surface` contains one of:

- `codex_desktop`, `codex_cli`, or `codex_exec`
- `claude_desktop`, `claude_cli`, or `claude_sdk`
- `pi_cli`

The field is optional for compatibility with older transcripts and daemons.
Consumers must leave the surface unknown when the field is absent rather than
guessing from transport metadata.

For Codex, provider-native `originator` metadata is authoritative. In
particular, the raw `source: "vscode"` transport does not prove an IDE session:
Codex Desktop currently emits that transport value too. Ottto recognizes the
provider's Desktop, TUI/CLI, and exec originator markers first, then uses an
explicit `cli` or `exec` source only when no stronger originator marker exists.

This surface says where the session ran. It is separate from account login
probing: `codex app-server` proves a usable CLI identity, not that the Codex
macOS app is currently open.

## Account attribution

`active_session_reconciliation.sessions[]` attributes a recent session to an
account only from privacy-safe, conflict-checked evidence. Precedence is:

1. an exact session plan observation;
2. the exact account hash already carried by the snapshot's model-usage rows;
3. a high/medium-confidence plan observation on a directly evidenced parent or
   root session (`parent_session_ref` / `root_session_ref`);
4. a compatible current login at reconciliation time.

Exact observation/snapshot disagreement, missing or conflicting account hashes
across aggregate and bucket model-usage rows, or conflicting parent/root
accounts fail closed and leave the session unattributed; weaker fallbacks are
not considered after a conflict. The lineage fallback therefore covers
Task/Workflow subagents without turning repository, timing, title, or provider
similarity into an account guess.
