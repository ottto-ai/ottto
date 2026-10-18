# Context composition reads registered transcript roots

Context composition discovered workspaces only under `~/.claude/projects` and
`~/.codex/sessions`. The session sink also reads registered Claude config
folders, Codex `archived_sessions`, and accepted Codex slot homes
(`snapshot_roots::scan_roots`). Sessions kept there had no composition data.

Composition now asks `snapshot_roots::registered_scan_roots` for its roots.
Claude roots are the default folder plus registered config folders, as in the
sink. Codex roots are `sessions` and `archived_sessions` under the default
home and under each accepted slot home, read from slot registrations without
credentials. Running-process Codex homes are not probed: composition runs
daily and has no status collection. If a registry or an accepted slot home
cannot be read, composition skips that source for the cycle and keeps its
last good aggregates, because a partial root list would replace them with
smaller ones.

One transcript can sit in two roots (a copied account folder, or a rollout in
both `sessions` and `archived_sessions`). Discovery counts each transcript
once and keeps the newest copy. The key is the file name, plus the parent
session for Claude subagent files, whose ids repeat across sessions.

Unchanged: wire fields, cadence, the 12-workspace and 5-minute cycle caps, the
50 MiB per-file bound, cache layout and parser version. Workspaces whose file
set grows rescan once through the existing file signature.

Resource effect, measured read-only on one heavy Mac (bytes, not CPU):
discovery opens 6,379 instead of 2,872 Claude files and 1,012 instead of 686
Codex files, reading only up to the first cwd. When every top-12 workspace
rebuilds, Claude parsing grows from 3.3 GB to 7.1 GB and Codex from 3 MB to
958 MB, because that Mac's main repository keeps most sessions in slot
folders. Unchanged workspaces still parse nothing. The cycle caps bound the
worst case.

Validation: `cargo check -p ottto-service --tests`; focused tests run in CI.
