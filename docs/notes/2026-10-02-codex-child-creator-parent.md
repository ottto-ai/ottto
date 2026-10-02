# Codex child original creator capture

A first physical native subagent header can identify its own child with `id`
while using optional `session_id` for the parent explicitly declared by
`source.subagent.thread_spawn.parent_thread_id`. Creator capture and existing
filename ownership resolution now recognize that declared relationship using
one normalized identity predicate. They retain the child's own complete
provider creator pair and source creation time.

Unrelated aliases, copied headers, conflicting later headers, malformed pairs
and clocks, and ordinary fork exclusions retain their existing behavior.
Usage ownership and wire witness versions are unchanged. The correction applies
to normal future collection and changed or newly imported source files; it does
not trigger historical replay or increment a broad projection revision.

Focused tests exercise three native-parent spellings, refusal and legacy
shapes, and the actual parser, privacy policy, and batch serializer. The native
parent positive fails on the preceding implementation through the normal file
parser and passes with both existing ownership checks corrected.
