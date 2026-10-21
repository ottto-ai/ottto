# Paged Claude S0: oversized-transcript red baselines

Test-only. A Claude Code transcript over the per-file cap
(`max_jsonl_file_bytes`, 256 MiB) is counted oversized at discovery and never
read. This change adds baselines for that state before any fix lands. No
production behavior changes.

## The test hook

`with_test_claude_file_cap(limit, run)` is a `#[cfg(test)]` thread-local
override of `max_jsonl_file_bytes(ClaudeCode)`. Discovery, revalidation, open
and the finish identity read that one function, so a 4 KiB cap moves all of
them together and fixtures stay KiB-sized. It applies on the calling thread
only, nests, and restores the enclosing value. Codex and Pi caps ignore it.

No new test writes cap-sized bytes. The real 256 MiB cap stays pinned by the
existing sparse-file test `scan_policy_skips_oversized_non_codex_transcript_files`.

## Tests

All live in `snapshots/paged_claude_s0_baseline_tests.rs`. `RED` tests assert
the behavior a later slice must produce and fail on main. `CHARACTERIZATION`
tests assert today's behavior and pass on main; the assertions a fix inverts
are marked `FLIPS`.

| Test | Kind | On main |
|---|---|---|
| hook guard | guard | green |
| RB-1: an over-cap transcript is read on a sampled scan | RED until paged reads | fails: counted oversized, no snapshot |
| RB-2: the red census surfaces only generic owed work | CHARACTERIZATION | green: `scan_cap_hit` true, `skipped_file_count_due_to_limit` 0, no owed-bytes field |
| RB-3: growth during an in-page read fails publication | CHARACTERIZATION | green: refused at finish (`Reduction`), oversized on the next retry; growth under the cap fails the same way |
| RB-5: a red-census retry re-parses pending families | RED until the census settles oversized files | fails: each due restart re-parses the unchanged sibling |
| RB-6: an audit-pending oversized entry counts past the window | CHARACTERIZATION | green: counted forever; without the marker it ages out |
| RB-7: the duplicate fence stays closed over an unread request | RED until the census settles with a fence pin | fails: no complete generation |
| RB-8: a healthy sibling family folds beside an oversized file | RED until the census settles oversized files | fails: census incomplete, no family proof; the control arm folds |

## Note for the census slice

If the fence pin is implemented by marking the duplicate census invalid while
an oversized member is in the window, the closed fence schedules a full re-arm
of every indexed Claude member (1 h doubling to 24 h). RB-5 then stays red.
The pin should keep the fence closed without that re-arm, because re-reading
cannot cure an oversized member.

Tests ran only in CI; no local build or test was run.
