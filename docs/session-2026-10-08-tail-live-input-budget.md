# Exclude live source inputs from optional tail-copy accounting

A small, ownership-complete Codex session could fail to retain an optional
checkpoint when its source scan held large unrelated trace or parent-ledger
maps. The active-copy budget traversed those shared inputs, although retained
copies already excluded them. Exhausting that traversal returned a zero copy
budget and made the next append require a missing-checkpoint full read.

Active-copy accounting, retained-copy accounting and retained-copy construction
now share one narrow detach/restore operation for those two existing baseline
inputs. Their source-scan lifetime and current-cycle reuse checks stay native.
All active owned parser, acquisition, path, alias and receipt state remains
charged. Immutable retained reductions still refuse frozen accounting while
either live input is present. No retained allocation is exempted.

The same scanner mechanism serves Claude Code and Codex; these two inputs are
Codex-specific. Entry, aggregate memory, traversal and scratch limits, compiler
gates, byte guards, hourly audits, source ownership, account scope, upload and
acknowledgement behavior are unchanged. No persistent cursor, scheduler or new
provider read is introduced.

Synthetic native regressions cover 5,000 unrelated trace entries, 5,000 unrelated
parent entries and both together. Each warm append must use a tail, read fewer
bytes including guards, and match an independent native full-reader body.
Separate checks verify live pointers survive successful and refused retained
charges and that retained copies do not hold them. Original code fails on the
trace-only missing-checkpoint case. These source fixtures establish a defect
and its repair, not the cause of every installed full read or average computer
load. Installed effectiveness still requires a containing release and ordinary
eligible warm observations.

Rust 1.95 native validation passed 78 affected checks, including both-provider
parity, historical scan pressure, acquisition guards, bounded retry/rotation
and the serial allocation probe. Each new Codex graph case reads 291 native
suffix bytes plus 8,192 guard bytes versus a 66,237-byte full fixture. These are
logical synthetic reads and exclude discovery, sidecars and independent
identity work; they are not physical disk, elapsed-time or installed savings.
