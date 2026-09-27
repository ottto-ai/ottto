# Session account binding

The collector now keeps a hash-only owner record for each machine, source, and
session in its local scan index. Codex records the account and workspace from
the exact transcript home only when its existing validated identity and the
auth file timestamp predate the session. A later login switch cannot rewrite
that record. Sessions without this proof carry no new account hash.

Claude records an exact session account hash from its Desktop or request
evidence. If a later revision lacks that evidence or conflicts, the collector
holds that revision for another scan and retains the verified owner.

Current account status remains separate from historical session ownership.
Codex managed homes join the transcript scan roots; CLI and Desktop status
observations retain their own evidence methods and auth modes. Backend stored
data is unchanged by this collector update. Existing wrong bindings need a
separately authorized repair after owner proof.

An independently configured SQLite home is scanned but does not supply owner
proof unless it is also the authenticated Codex home.
