# Session account binding

The collector now keeps a hash-only owner record for each machine, source, and
session in its local scan index. For running CLI sessions, it discovers the
transcript home from the rollout file held open by that exact Codex process.
This identifies the home used for session files even when the process has a
separate `CODEX_SQLITE_HOME`. It scans that root and derives identity through
the existing validated hashing path for the same home. It records both hashes
only when the transcript row explicitly proves OAuth and the auth file timestamp
predates the session. A later login switch cannot rewrite that record. A row
without OAuth evidence carries no account hash even when an owner was recorded.

Claude records an exact session account hash from its Desktop or request
evidence. If a later revision lacks that evidence or conflicts, the collector
holds that revision for another scan and retains the verified owner.

Current account status remains separate from historical session ownership.
Codex managed homes join the transcript scan roots; CLI and Desktop status
observations retain their own evidence methods and auth modes. Unregistered
process homes do not add current status observations. Backend upload copies
remove account email and raw account or organization labels; only the existing
identity hashes leave the machine. Backend stored data is unchanged by this
collector update. Existing wrong bindings need a separately authorized repair
after owner proof.

An independently configured SQLite home is never treated as account proof by
itself. If no process-owned rollout or other exact home evidence exists, the
collector sends no newly inferred account hash.
