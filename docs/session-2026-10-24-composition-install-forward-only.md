# Context composition: the first run reads nothing from before the install

Owner decision: no backfills, keep the reader light. Until now the first run
read each transcript modified within 24 hours of the install from offset zero,
within the 1 GiB/day repair budget, newest first. On a busy Mac that budget ran
out on day one and left a backlog of several GB, which took days to drain. In
effect that backlog was a backfill of those files' earlier content.

## New rule

- First run (and an agent reset, which already worked this way): every
  transcript found, including one still being written, starts at its current
  size. Nothing written before the install is read. Each such file is counted
  in the new local metric `install_forward_only` (a subset of
  `dormant_found`).
- A transcript born after the install record's cutoff (the last saved scan
  start) is still new and is read from offset zero as new bytes, outside the
  repair budget. This is unchanged.
  A file born after the install's start but found by that same first walk
  is still pinned at its end, so its first seconds are not read; this fits
  "no backfill".
- An install made by an earlier build keeps its saved state. Pins waiting for a
  full read still drain within the repair budget, newest first, until none are
  left. No backlog is dropped.
- The repair budget now only covers files rewritten in place, that remaining
  backlog, and reads after a state fallback.

No persisted format, wire field or hash changes. The run-health payload is
unchanged; `install_forward_only` appears only in the local metrics log line.

## Tests

The shared test fixture now installs both agents on an empty transcript folder
first. Files that a test writes are then born after the install and read as new
bytes, which is how sessions reach the reader under the new rule.
`Env::uninstalled` keeps the tests whose first run is the install. Tests that
needed a waiting full read now build the state that an earlier build's install
left behind. New tests cover: an install with sessions in flight reads 0 bytes
from them on day 1, a file created after the install is read from 0, an earlier
build's backlog keeps draining, an agent reset starts in-flight files at
their end, and a crash during an install before its index is saved resets
on the next run and reads 0 bytes from existing files.
