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
