# Exact context-footprint file counts

Claude Code's `/context` counts loaded tokens. The six-hour footprint collector now
also measures resolvable memory/instruction files, bounded to 1 MiB each. It sends
`file_bytes`, `file_lines`, `file_chars` (UTF-16 units), and a device-salted
`content_hash`. AutoMem MEMORY.md adds `loaded_lines` and `truncated_by_limit`, using
200 lines or 25,000 UTF-16 units, whichever comes first, at a whole-line boundary.
A final newline is not an extra file line. Unreadable, non-UTF-8, nonregular and
over-cap files omit measurements rather than reporting partial sizes.

Measurements describe the current disk file, not the historical text of any
particular session. All fields participate in upload change detection, including
edits beyond Claude's loaded prefix. Original paths remain local and file content
is never uploaded. Hashes use a private random 32-byte salt in the support
directory (`context-footprint/content-hash-salt-v1`, mode 0600 on Unix), plus the
domain `ottto-context-file-v1\0`. Only within-device hashes are comparable;
cross-device comparisons can use file bytes but equal sizes do not prove equality.

Backend admission must precede runtime release. Collection approval and release
remain pending; this change is prepared as a draft. Limits belong to Claude Code
and should be reverified when its memory loader changes. The generated synthetic
fixture is `fixtures/context-footprint/file-counts-v1.json` and is consumed by the
backend contract tests. No real account or memory text is used in these tests.
