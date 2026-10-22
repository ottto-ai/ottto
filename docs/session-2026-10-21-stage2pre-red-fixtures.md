# Stage2-pre red fixtures: Codex append during an in-page Tail

A sampled in-page Codex `Tail` sets no extent limit (only cursor jobs do).
If Codex appends while the Tail reads, the reader passes the length frozen at
open and fails with "acquisition exceeds stable source". The page records one
`OpenRead` unreadable and drops the retained copy it took, so the next read is
`Full(StateMissing)`.

This change adds red-first fixtures for the reviewed fix (a reader-relative
extent limit, an in-page E1 for a quiescent unterminated row, and a grown-Tail
sealed-prefix commit). It changes no production behavior.

## What was added

- `snapshots/transcript_acquisition_tests/stage2pre_in_page_tail_tests.rs`,
  registered with one line in `transcript_acquisition_tests.rs`.
- One `#[cfg(test)]` seam in `snapshots.rs`: `with_after_reader_eof` runs a
  hook once the active file's reader reports EOF and before its completion
  (E1, tier gate, revalidation, commit). It is the only window a test cannot
  reach between `OwnedSourceScan::step` calls.
- The append right after the open step (after prepare, before the first reader
  step) needs no seam: the open step returns `Pending`, so the test changes the
  file between two steps.

## Rows

RED (fail on main for the stated reason):

- SP-1, SP-2a, SP-2c, SP-6a, SP-6b, SP-8a: the reader fails D1, recorded as
  `OpenRead`, where the fix commits `[0, frozen)` (or the last newline below it).
- SP-3b, SP-5a', SP-7b: main records `OpenRead` (D1) where the fix refuses as
  `ScopeObject`.
- SP-8b: main records `OpenRead` where the fix refuses `AuditDue` as
  `Reduction`.
- SP-5 residual: main refuses at revalidation; the fix accepts a rewrite that
  preserves both sample windows. This is a disclosed residual, not mutation
  detection.

PARITY (pass on main, and must keep passing): SP-2b, the SP-2c negative
control, SP-3a, SP-4, SP-5a, SP-5b, SP-5c, SP-7a, SP-8c, SP-8d, SP-9, SP-10 and
SP-11.

SP-1 runs the ordinary next page through directory discovery, with no
`release_path` and no watcher hint. It asserts a `Tail` from frozen that reads
exactly the appended bytes.

## Not covered

- SP-12 (a Codex file crossing 2 GiB) needs the bounded revalidation that is
  not on main yet.
- The cursor-only N2 counter is private to `codex_cursor`. The unmodified
  cursor tests cover it.
- Unchanged-mode growth (SP-10) keeps main's behavior.

Tests ran only in CI; no local build or test was run.

## FE: the Claude twin (2026-10-22)

FE caps Claude in-page `Full` and `Tail` reads at the frozen length and
publishes the sealed prefix `[0, s)` as a certificate only: no checkpoint,
copy, cache insert or audit credit; the prepared debt is re-staged and the
index keeps the opened stamp. SOURCE gave a qualified YES; c22's ACK of the
production seam is pending, so this round is test-only.

- New child module
  `stage2pre_in_page_tail_tests/fe_claude_in_page_read_tests.rs`, registered
  with one line at the end of `stage2pre_in_page_tail_tests.rs`. Every test is
  prefixed `fe_claude_`. The Codex rows are unchanged.
- No new seam: the rows reuse `with_after_reader_eof`.
- RED: SP-1c, SP-1c', SP-2a-c, SP-2c-c, SP-D2c (Full and Tail), the Claude
  SP-5 residual (SOURCE FE2), SP-8c-c, and the SOURCE and census rows
  (prefix D1 record unverified and replaced, no v1 or witness from a prefix,
  prefix in pending, in-window re-read gives `member_changed`, proof fails
  closed while API rows exceed the prefix).
- GREEN: SP-2b-c (Tail and Full), SP-3a/4/5a/5b/5c-c, SP-7a/7b-c, SP-11-c
  (Codex Full, Pi), `s` below the last committed size publishes nothing, a D1
  record control, a proof control, and one diagnostic of main.
- Diagnostic finding: main's authority fold accepts trace-owned API rows the
  transcript lacks as auxiliary calls (`transcript ⊆ assigned`), so a body
  missing requests still mints v1. FE's "proof fails closed" cannot rest on
  unequal request sets; the SOURCE rows need an explicit guard.
- Stage2-pre's `sp11_claude_in_page_tail_with_append_keeps_main_failure` pins
  the Claude D1 failure FE replaces; the FE production change must update it.
