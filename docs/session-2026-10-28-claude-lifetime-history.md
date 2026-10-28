# Claude lifetime login history preparation

The daemon now records bounded hash-only observations of known Claude folders,
including existing card reads and collection cadence. It initializes under the
existing held state-directory lock before producers start. A durable intent
precedes each read/mutation, and both state and intent writes sync their parent
directory. Interrupted observations conservatively retire their folder proofs;
malformed intent makes the complete history uncertain. Already committed pins
remain immutable; uncertain tentative pins roll back on recovery.

This preparation emits no account identities and changes no usage/money rows.
The existing sole-login emission gate stays unchanged. Watcher qualification
is deferred, so all unobserved periods remain gaps. Activation requires a later
reviewed change that implements the full age, wait, healthy-window, forward-only
and stronger-evidence rules.

State caps: 128 folder tombstones, 16,384 sessions, 64 merged gaps per folder,
and 4 MiB encoded/read limit. No raw path, UUID, account name or email persists.
An unresolved intent retains a permanent conservative folder veto, even after
a fresh read; an unparseable intent retains a history-wide uncertainty latch.
Reset state alone supplies no eligible pair and starts a later enable boundary.
