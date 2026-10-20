# Claude subagent launch lookup demand

The native Claude scan prepares launch-event lookup for up to 512 worker ids at
a time. Each completed sweep validates every retained launch event. A file
whose id is outside the prepared batch discards it and starts another full
sweep.

## Cause

Claude subagent and Workflow agent transcripts carry their parent's
`sessionId`. At finish time the scan, the parser's finish gate, and the
synchronous reader all demanded that parsed parent id. When the parent's
top-level transcript was not in the current batch, each such file discarded the
batch and forced a sweep for one id. The next top-level candidate then rebuilt
the batch with another sweep.

That demand never fed a fact. `into_items` re-keys a subagent from its path to
`<root>_<stem>` before it reads launch facts. Launch workers are UUID-only, so
the re-keyed id never matches one. The path-derived demand has the same
problem: a subagent file whose stem looks like a UUID still asked for that stem.

## Fix

Launch demand now uses the same predicate as the re-key
(`claude_subagent_identity`). A Claude subagent path demands nothing, both from
its path and from its parsed id. All three finish sites share one helper, so
they cannot drift apart. These are unchanged:

- Codex demand (header owner or resolved id)
- Pi demand (parsed id, else file stem)
- Top-level Claude demand
- Trust fences: TTL, directory stamps, ambiguity withholding, the demand cap

## Behavior change

- A subagent no longer stays owed when launch lookup fails or is still in
  progress. No launch fact can exist for it.
- Top-level workers still stay owed until a complete, fresh sweep proves their
  evidence.
- One edge case: a subagent with a UUID stem that also names a retained launch
  worker loses its launch witness from the local file fingerprint. That witness
  never reached any fact. Snapshot bodies do not change.

## Tests

`snapshots/launch_demand_tests.rs` covers:

- A real native scan where subagents have unbatched parents, including a
  Workflow agent and a UUID-stem subagent. Lookup steps stay within a bounded
  sweep budget instead of growing per subagent. The
  top-level worker keeps its launcher edge. Subagents never get the controller,
  and their canonical fingerprints match a run with no launch store.
- A failed lookup. The top-level worker is held, and the unbatched-parent
  subagents complete.
- The synchronous reader keeps a prepared batch across subagent parses.
- The finish gate on stale evidence. It rejects the top-level file and accepts
  subagents.

Existing tests in `launch_events.rs` and `snapshots/launcher_recognition_tests.rs`
cover ambiguity, same-name edits, TTL expiry, and incomplete or unreadable
evidence for top-level workers.

## Not measured

No production sweep rate was measured. This is a source-level correction, not
an installed CPU or memory result. Launch lookup holds at most 512 entries and
small per-file buffers, so it does not explain a peak of hundreds of megabytes.
A count-only per-page sweep counter and an allocation witness are left to
separate performance work.
