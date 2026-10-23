# Composition changed-days reader switched on (2026-10-23)

The new-lines context composition reader (kinds_version 2) is now on. The
compile-time switch `CHANGED_DAYS_UPLOAD_ENABLED` in
`crates/ottto-service/src/context_composition/v2/mod.rs` is `true`.

## What turns on

- The daemon starts the new-lines reader instead of the kinds_version 1
  harvest loop. The kinds_version 1 harvest no longer runs.
- The reader wakes hourly and runs at most once per UTC day, after the daemon
  has been up 15 minutes, in a separate worker process at utility priority,
  with a 30-minute wall cap.
- First run is forward-only: each transcript starts at its current size,
  except files modified within the last day, which are read once from their
  start within the 1 GB/day repair budget. No history is read.
- Later runs read only the lines added since each file's checkpoint. A daily
  audit re-reads at most 100 MB (32 files) already counted.

## What the Mac now sends

- `POST /api/v1/context-composition/snapshot` with `kinds_version: 2` and
  `upload_mode: "changed_days"`: daily rows by kind for the days that changed,
  `retention_floor`, and 30-day and all-history totals for parts, top tools,
  top files and top sessions. A scope uploads only when one of its
  checkpoints moved, or after 7 days without an upload.
- `POST /api/v1/context-composition/run-health`: one post per agent per daily
  run with the run's counts (files checked, bytes read, CPU, duration, audit
  differences, backlog, quarantines, resets, worker timeouts and failures).
  Health is never inside the composition payload.

The server must accept `upload_mode: "changed_days"` and the run-health route
before a release with this switch ships; until then it refuses those uploads.

## How to turn it off again

One-line revert: set

```rust
const CHANGED_DAYS_UPLOAD_ENABLED: bool = false;
```

and release. The daemon goes back to the kinds_version 1 harvest. The
reader's local state stays on disk unread; turning the switch on later
continues from the saved checkpoints (no re-read of old bytes).

## Tests

- `changed_days_reader_runs_in_this_build`: the build runs the reader.
- `changed_days_switch_rules`: with the switch on the reader runs in every
  build; with it off the kinds_version 1 harvest runs, and only a debug build
  with a truthy `OTTTO_CONTEXT_COMPOSITION_CHANGED_DAYS` turns the reader on.
- No existing test assumed the switch was off: the reader tests call the
  reader directly, and the kinds_version 1 tests call the kinds_version 1
  harvest directly. Both sets are unchanged.
