# Composition V1 harvest deleted (2026-10-28)

The kinds_version 1 composition harvest, discovery loop, cache and uploader
are deleted, along with the compiled changed-days switch and its debug
override. The daemon now always delegates composition collection to the V2
reader, preserving the HOME preflight and existing worker behavior.

Rollback now requires a source revert and release. This supersedes the
flip-the-constant rollback recipe in
[the October 23 switch-on note](session-2026-10-23-composition-changed-days-switch-on.md).

The user and organization opt-outs remain: the
`OTTTO_CONTEXT_COMPOSITION_HARVEST_DISABLED` environment variable,
`<support>/context_composition/disabled`, destination-fenced organization
markers, and the `context_footprint_harvest_enabled` cascade.

The V1 parsers, accumulator and fixtures remain test-only oracles for V2
comparisons. The scale harness's `v1` phase is removed; its V2 phases remain.
The wire counter source stays `context_composition_v1`.

Two V1-only pieces outside the module also go: the footprint module's
first-cwd discovery reader and file-metadata witness (V1 discovery and cache
were their only callers), and the JSON-body composition uploader that V1 used
(V2 uploads through the serialized-body call). `Kind::ALL` and `Kind::index`,
which served only the V1 payload and accumulator, are now test-only.

Orphaned V1 cache JSON files are intentionally left on disk. V2 uses its own
state subdirectory and does not load these sibling files; this deletion adds
no cleanup or migration path.
