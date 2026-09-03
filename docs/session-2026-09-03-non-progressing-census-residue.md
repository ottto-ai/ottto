# A census held red by loss no retry can change

## Problem

The local snapshot census decides whether a source's historical backfill is
done, whether the terminal manifest may publish, and - since ottto#397 -
whether the legacy settlement sweep may arm a page or re-open an unproven
ledger. All of those wait on `census_complete`, and `census_complete` waits on
`ScanTraversalCounts::has_errors()` being false once discovery has finished.

`has_errors()` treated four counters as errors with no terminal escape:

- `ownership_incomplete_file_count` - a Codex rollout whose exclusive-usage
  boundary cannot be determined and whose parent resolution is not pending;
- `zero_snapshot_usage_evidence_count` - a file with usage evidence the parser
  could not turn into an entity;
- `recognized_usage_drop_count` and `dropped_usage_record_count` beyond the
  over-line-cap share that already carried a terminal disposition.

A file in any of those classes is never checkpointed, so every generation
parses it again from the same bytes, under the same sidecar and parent
evidence, and reaches the same counts. Retrying the traversal cannot change
them; only new input can. Yet the census treated them like an unreadable
directory: it stayed incomplete, the bounded unhealthy-retry latch re-armed
after every walk, and every gate downstream stayed shut - for as long as the
file existed.

On an upgraded machine that is exactly the shape ottto#397 needs to reach. A
ledger sealed at the unproven version sits behind a Codex census that a single
archived rollout keeps incomplete with nothing pending, so the re-open is never
asked for. A pre-ledger index mid-sweep behind the same residue never arms its
next page. The population the fix targets is the population the gate blocks.

Two smaller defects sat beside it. The unhealthy-retry attempt counter grew
without bound (one persisted witness had reached 46), and a persisted witness
with no deadline at all was never due. And `RuntimeIdentityV1.started_at` was
stamped from the status query clock, so every machine reported a daemon that
had started the instant it was asked.

## Change

### Non-progressing residue settles once discovery is done

`ScanTraversalCounts` now separates the two kinds of loss:

- `has_retryable_problems()` - a directory the walk could not enter or finish,
  an object it could not open or read, a root that vanished, a line the parser
  rejected, or over-line-cap loss not yet terminal. These keep their retry
  semantics unchanged: the census stays red and the latch re-walks.
- `has_unsettled_residue()` - the four counters above, beyond what the
  generation has already settled as terminal.

`has_errors()` is the disjunction, so nothing that was red before is green now
except through the one new path: when discovery has finished (`pending
directories` and `pending candidates` both empty) and no retryable problem
remains, `settle_non_progressing_residue` promotes the residue to terminal for
that generation. Two new counters, `terminal_ownership_incomplete_file_count`
and `terminal_zero_snapshot_usage_evidence_count`, sit beside the existing
`terminal_*` trio; the promotion is an assignment from the counts the
generation actually re-derived, never an accumulation.

A retryable problem vetoes the settlement. A walk that could not enter a
directory or open an object may simply not have seen the file that would
resolve a fork, so its residue is not yet known to be non-progressing.

The residue files themselves are not checkpointed. They stay outside `files`,
the next generation parses them again, and any change to their bytes, their
sidecar or their parent evidence is picked up the way it always was. What
changes is only the verdict: the census completes with the loss named. The
public counters (`ownership_incomplete_file_count`,
`zero_snapshot_usage_evidence_count`, `dropped_usage_record_count`) are
unchanged and still travel with every status report.

### The residue is recorded, not folded into totals

Each traversal generation records the local index keys of its residue files
and the Codex session ids those files hold out of the inclusive state-only
fallback. When a generation completes, `ScanIndex::scan_residue_witness` is
written from those counts and keys (or cleared when the census was clean), and
one line is printed per change - never per cycle - naming the counts, how many
residue rollouts sit under an archived root, and how many Codex sessions stay
held out of the fallback.

The blocked session ids are deliberately not pruned by settling. The block
records what the rollout's content proved about its ownership; releasing it
would publish inclusive `tokens_used` for a thread whose exclusive usage is
exactly what could not be determined. A rollout under an archived root is
handled the same way as one under the active root: both roots are configured
scan roots, so both files are parsed, and the only distinction the witness
draws is where the residue sits.

### The unhealthy-retry latch is bounded and cannot be fenced

- The attempt counter saturates at `UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS = 7`,
  the attempt whose delay already reaches the one-hour ceiling. A persisted
  witness above the cap is clamped when it is carried into the next walk.
- A deadline that is past, absurdly far ahead, or missing altogether (an index
  persisted before the deadline existed) is due now. The retry depends on the
  clock alone, never on new input arriving.
- What clears it is unchanged and now stated: a generation that completes drops
  the traversal, and a changed scan context starts a fresh one; both begin at
  attempt zero.
- One line is printed when the cap is reached.

Because residue no longer counts as unhealthy once settled, the latch engages
only for genuine retryable problems, which is what it was for.

### `started_at` is the process start

`DaemonState` records the instant the daemon was constructed and the runtime
projection reports it as `started_at`; `last_seen_at` remains the query time.
A re-projection of an already projected status carries the recorded start
forward rather than restarting the clock.

## What an upgraded machine does

On the first source cycle after upgrade, a Codex census that was held red by
residue settles and completes; its check-in carries `last_census_complete:
true` with the residue counters unchanged. That cycle marks the destination's
historical backfill done. The next cycle finds no replay pending: an unproven
ledger is re-opened once and its first page armed, and a pre-ledger sweep with
a persisted cursor arms its next page. From there the bounded sweep proceeds
as ottto#397 describes, one page of fifty per source cycle.

The check-in still reports `last_error_code: parse_error` for a census that
completed with dropped usage, as it did before this change; that mapping is
unchanged here and is a separate question for consumers that require a fully
clean check-in.

## Compatibility

New index fields all default: an index written by an older daemon loads
unchanged, and an older daemon reading a newer index ignores the fields it
does not know. No wire field changed shape.

## Tests

`crates/ottto-service/src/snapshots.rs`:

- `non_progressing_residue_settles_only_without_retryable_problems` -
  every retryable class vetoes settlement; settling is idempotent; the
  over-line-cap share is excluded from the settled residue.
- `unproven_ledger_behind_non_progressing_codex_residue_completes_and_reopens_once`
  - the upgraded shape: v1 ledger, every revision accepted, no cursor, one
  ownership-incomplete archived rollout, nothing pending. The census completes
  with the residue named, the backfill clears, the next cycle re-opens the
  ledger exactly once (version key dropped, cursor set), and a further cycle
  re-opens nothing.
- `pre_ledger_sweep_behind_non_progressing_codex_residue_resumes` - the
  mid-sweep shape arms its next page from the persisted cursor and keeps its
  re-earned acceptances.
- `residue_is_not_settled_while_candidates_are_still_pending` - settling
  waits for discovery.
- `retryable_problem_keeps_the_census_red_and_the_latch_bounded` - a symlink
  beside the residue keeps the census red and the residue unsettled; the latch
  re-arms on 1, 2, 4, ... minutes, saturates at attempt 7 and one hour, and
  the generation completes once the problem is removed.
- `unhealthy_retry_latch_saturates_at_its_cap_and_a_missing_deadline_is_due_now`
  - attempt 46 with a fifteen-hour-stale deadline is retried now and clamped;
  a witness with no deadline is due now; the latch clears with the problem.
- `residue_rollouts_under_archived_and_active_roots_stay_blocked_while_the_fallback_resumes`
  - both residue sessions stay blocked, the witness names them and counts the
  archived one, the state-only fallback resumes for an unblocked thread, and
  new sidecar input clears the witness.

`crates/ottto-service/src/lib.rs`:

- `runtime_started_at_is_the_process_start_instant_not_the_status_query_time`.

Existing tests that asserted the old verdict for residue classes were inverted
on that one assertion only, with their fixtures untouched; each is named in
the pull request.
