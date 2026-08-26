# Codex Desktop created-task lineage

Codex Desktop's current create-task path can persist a real parent/child task
relationship without adding a row to `thread_spawn_edges`. The child instead
has `thread_source=agent_created_thread`, and its machine-generated
`codex_delegation` wrapper carries the source thread id. Ottto previously read
only the spawn-edge table and older rollout-native subagent object, leaving
these children disconnected in the Sessions list, session Family sections,
and Agent Lineage explorer.

The snapshot sidecar loader now imports this provider-native shape into the
existing `spawn_parents` graph. It reads only rows with the exact provider-owned
thread source, accepts only the exact wrapper shape and one UUID-like parent,
rejects self-links, and never retains or uploads the delegated prompt body.
Explicit `thread_spawn_edges` remain authoritative when both sources exist.

No backend, API, schema, or frontend change is required. The existing direct
`parent_session_ref`, `root_session_ref`, `spawn_depth`, and
`agent_kind=codex_subagent` facts already project into the GOLD `sessions`
model and power every family surface.

The parser provenance moves to `codex_jsonl:v32`. Scan identity stays at v31:
the already-versioned per-session sidecar fingerprint includes family
position, so only affected immutable rollouts are selected and re-uploaded;
unrelated sessions remain semantic no-ops.

Regression coverage uses the production-observed parent and child ids and
proves end-to-end fact emission from a temporary Codex state database with no
spawn-edge table. Negative coverage rejects ordinary prompt prefixes,
malformed ids, self-links, and trailing content. The test also proves the new
family position changes that child's sidecar fingerprint.
