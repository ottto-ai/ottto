# Process-local re-arm Full attribution

Traversal-start stale-pending re-arms and carry invalidations retain a closed
clear-cause enum in RAM, keyed only by existing index files. The next sampled
Full selection adds `rearm_cleared{<start_reason>}` (or
`rearm_cleared{carry_invalidation}`) to local resources diagnostics at
`counts.sampled_acquisition.page_events.full_cause`, with `count` and
`completed_native_bytes`. Existing acquisition `full_reasons` retain their
meaning. Native bytes are completed reader bytes, not physical disk traffic.

Tags survive ordinary index reloads within the process. Completion or re-proof
consumes them; pruning removes keys absent from the current index. Restarting
loses all tags, so outstanding pre-restart clears remain unattributed. There is
no persisted field and no upload field. Fixed page aggregates live outside scan
state and are removed when the diagnostics probe drops, including early exits;
scan/index layouts and acquisition memory admission bounds stay unchanged.

Synthetic fixtures cover start-reason mapping, carry causes, completed byte
attribution, unlabelled other Fulls, process-local loss, tag consumption, page
cleanup, and identical selections, index serialization and upload bodies with
and without tagging. Local clippy compiles fixtures; tests remain CI-only.

Codex terminal state-only append calls also log a nonzero-only
`codex_state_only` traversal record with `{scanned, emitted, noops}`.
`scanned` and `noops` preserve the append function's existing return counts;
`emitted` is its output-vector length increase. These are provisional append
entities, before later policy filtering or semantic no-op suppression, not
network attempts or accepted uploads. A synthetic terminal fixture checks
0, 1 and 3 uncovered state threads plus a filtered zero-token thread.
