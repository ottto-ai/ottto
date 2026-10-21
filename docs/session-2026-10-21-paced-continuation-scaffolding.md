# Paced cursor continuation scaffolding (inert)

A Codex file larger than one cursor page is read 64 MiB per page, and only one
page runs per ordinary sync cycle. Almost all of a multi-hour read is the fixed
five-minute post-cycle wait. This change adds the sync-loop side of paced
continuation pages, compiled in but switched off: `continuation::ENABLED` is
`false`.

## What is added

**Cadence (`adaptive_collector.rs`).**
- `SourceCadence` gains a continuation request: `request_continuation`, `clear_continuation`, `continuation_due` and `continuation_work`.
- It also gains `ordinary_interval`. This is the existing tier/directive arithmetic moved out of `next_scan_after`, unchanged.
- A continuation is due at `max(server minimum, failure backoff if failing, max(30 s, 9 × measured work))` after the later of the asking page and the last ordinary scan.
- It replaces only the Hot/Warm/Idle floor. A continuation that would not run before the ordinary scan is dropped rather than clamped, so slow pages keep the 10 % wall-duty bound.
- All arithmetic is checked, and overflow refuses the continuation.
- A continuation never moves `last_scan_at` or the tier, so `next_scan_after` and the ordinary eligibility clock are unchanged.

**Dedicated entry point (`snapshot_sync/continuation.rs`).** `run_page` is not `sync_once`. In order, it:
1. takes the ticket;
2. refuses on Failing, upload backoff, not-due, or a power state other than `Allowed`;
3. takes `SNAPSHOT_SYNC_LOCK` with `try_lock`, so a busy lock is a contention skip;
4. rechecks the destination digest from local credentials;
5. enters background QoS;
6. asks the cursor side whether the ticket is ready;
7. runs one page.

Only these makes network calls:
- **EOF page:** the existing completion upload, attempted once, after the upload backoff and the destination have been rechecked. If either recheck fails, the obligation goes to the owed path instead.
- **Every other page:** none. That includes relay tokens, activity hints, receipts, status and health.

The lock is released before `run_page` returns, so it is never held while waiting between pages. Measured work runs from entry to after the lock is released.

Only a `Paused` page whose work is at most 20 s leaves a ticket behind. Every other ending clears the ticket and the cadence request, and the next page is ordinary:
- Deferred, Cancelled or Failed;
- any EOF outcome;
- a page over 20 s;
- any refusal.

**Loop.**
- While disabled, the sync loop runs today's single `collect_file_activity_for(SNAPSHOT_SYNC_INTERVAL, …)` call, unchanged. The delivery-wake closure moved into `delivery_wake`, with the same body.
- While enabled, `wait_for_ordinary_cycle` runs continuation pages inside the ordinary interval:
  - The ordinary deadline is fixed when the wait starts.
  - A page is offered only if, judged by the asking page's work, it ends before that deadline.
  - An account switch still ends the wait at once. `collect_file_activity_for` now returns whether it did.
- `SnapshotCycleOwner` records the Codex preparation start and hands the ordinary page's ticket over after a successful finish, but only while enabled.

## Interfaces left for the cursor owner

The cursor side is `CursorContinuation`. The production stub `NoCursorContinuation` never mints a ticket and is never ready. It has these methods:

| Method | Role |
|---|---|
| `ticket_for` | Mint the ticket at the single pause site. |
| `ready` | `cursor_continuation_ready`. |
| `page` | One resume-only page: load, C14 continuation pass, scan, C15 mark, save, note. |
| `complete_eof` | The existing completion upload through the unchanged `finish_sync_source`. |
| `defer_eof` | The owed path. |

Two more pieces are left open:
- `CursorTicket` and `EofCompletion` are sealed placeholders for the cursor owner's fields.
- `ordinary_equivalent` returns the ordinary-equivalent gap for guard and E2 accounting: the applicable ordinary interval, clamped between the loop interval and its 30-minute ceiling. It is a lower bound because it excludes cycle duration.

## Platform gates

`PlatformGates` covers power and Low Power Mode plus background QoS. The service has no such call today, so the production `NoPlatformSignals` answers `Unknown`, and an unknown or refused state falls back to the ordinary cadence. The proposed macOS calls are held for review, not implemented. They are:
- `pthread_set_qos_class_self_np`, from `libc`, which is already a dependency;
- IOKit power-source type;
- `NSProcessInfo.isLowPowerModeEnabled`.

## Bounds (models, not measurements)

- **Duty.** With pages of 3–5 s, the gap is 30–45 s. That bounds the wall-clock duty of one thread at 10 %. It is not a bound on process CPU, IO or foreground impact.
- **Unchanged.** Ordinary cycles keep today's start times, request volume and per-source cadence.
- **Added network.** The only new requests are one completion upload per completed job.
- **Overrun.** A page longer than the one before it can delay the next ordinary cycle by the difference.
- **Ordinary page after a continuation.** It can follow a continuation page by less than a server directive. The continuation page made no request, and the ordinary schedule is unchanged by design.

## Validation

CI only. The new tests are in `adaptive_collector.rs` and `snapshot_sync/continuation_tests.rs`. They cover:
- directive and failure backoff over the continuation;
- the duty bound with slow pages;
- zero network calls until EOF;
- EOF success, refusal, rechecks, cancellation and failed save;
- refusal, unknown and busy inputs;
- ordinary-cycle cadence parity with and without continuation pages;
- the inert default.
