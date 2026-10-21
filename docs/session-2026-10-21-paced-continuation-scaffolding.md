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
- `ordinary_clock` and `restore_ordinary_clock` save and put back the part of the cadence an ordinary scan moves (tier, last scan and activity, failure count, full-sweep marker). An EOF completion uses them; see below.
- `request_continuation` returns whether the request stands; a disabled source takes none.

**Dedicated entry point (`snapshot_sync/continuation.rs`).** `run_page` is not `sync_once`. In order, it:
1. returns at once when there is no ticket;
2. refuses on Failing, upload backoff, not-due, or a power state other than `Allowed`;
3. takes `SNAPSHOT_SYNC_LOCK` with `try_lock`, so a busy lock is a contention skip;
4. under the lock, rechecks the current cadence, due time, failing state and upload backoff before taking the current ticket. A future due time preserves both ticket and request;
5. rechecks the scan authority: the same device id, machine id, Codex grant, API endpoint and account witness that `ensure_snapshot_scan_authority` checks at every ordinary prepare and finish. The ticket carries them as one SHA-256 digest;
6. rechecks the destination digest from local credentials;
7. enters background QoS, restored by a drop guard as soon as the page returns;
8. asks the cursor side whether the ticket is ready;
9. runs one page, which must stop at the next record boundary after the earlier of the ordinary deadline and 20 s;
10. settles the page and writes any new ticket and cadence request, still under the lock.

Only these make network calls:
- **EOF page:** the existing completion upload, attempted once, after the scan authority, the upload backoff and the destination have been rechecked. If a recheck fails, the obligation stays owed to the next ordinary pass and nothing is saved.
- **Every other page:** none. That includes relay tokens, activity hints, receipts, status and health.

**EOF completion (StateMissing side).** `SnapshotCycleOwner::finish_completed` is the census fence over the authority and destination rechecks, then the unchanged `finish_sync_source`. An ordinary finish and a continuation EOF both call it; `complete_continuation_eof` builds the owner from the same local inputs `sync_once_with_retry` reads, with no cycle-start receipt or health upload. Because `finish_sync_source` records its cadence as an ordinary scan, `run_page` saves the ordinary Codex clock before the completion and restores it after. **An EOF completion therefore leaves the ordinary Codex cadence exactly where it was**: the next ordinary Codex scan, its tier and its full sweep happen when they would have without the continuation. If the clock cannot be saved, the completion is deferred instead. The EOF transport outcome does not feed the cycle streak.

**Ticket writes.** A new ticket is written only while `SNAPSHOT_SYNC_LOCK` is held, as an ordinary Codex finish writes its own, so a page can never overwrite a newer ordinary decision with an older ticket. Clearing needs no lock, because it can only lose a continuation. A cycle that ends `Err`, including before rotation, or that runs without the Codex grant clears the ticket before the lock is released (`CycleSettlement`).

The lock is released before `run_page` returns, so it is never held while waiting between pages. Measured work runs from entry to just before the lock is released.

Only a byte-budget-exhausted `Paused` page whose work is at most 20 s, and whose cadence took the request, leaves a ticket behind. Every other ending clears the ticket and the cadence request, and the next page is ordinary:
- Deferred, Cancelled or Failed;
- any EOF outcome;
- a deadline/contention pause (`PageEnd::PausedContended`), even if it took less than 20 s;
- a byte-budget pause over 20 s (`paused_contended`);
- a page whose cadence took no request (`paused_without_request`);
- any refusal.

**Loop.**
- While disabled, the sync loop runs today's single `collect_file_activity_for(SNAPSHOT_SYNC_INTERVAL, …)` call, unchanged. The delivery-wake closure moved into `delivery_wake`, with the same body.
- While enabled, `wait_for_ordinary_cycle` runs continuation pages inside the ordinary interval:
  - The ordinary deadline is fixed when the wait starts.
  - A page is offered only if, judged by the asking page's work, it ends before that deadline.
  - An account switch still ends the wait at once. `collect_file_activity_for` now returns whether it did.
- `SnapshotCycleOwner` records the Codex preparation start and hands the ordinary page's ticket over after a successful finish, bound to the destination and scan authority it ran under, but only while enabled.

## Interfaces left for the cursor owner

The cursor side is `CursorContinuation`. The production stub `NoCursorContinuation` never mints a ticket and is never ready. None of its methods makes a network call:

| Method | Role |
|---|---|
| `ticket_for` | Mint the ticket at the single pause site. |
| `ready` | `cursor_continuation_ready`. |
| `page(ticket, deadline)` | One resume-only page: load, C14 continuation pass, scan, C15 mark, save, note. Past `deadline`, stop at the next record boundary, save and return `PausedContended`, without a ticket or request. Only byte-budget exhaustion returns `Paused(ticket)`. |

Two more pieces are left open:
- `CursorTicket` is a sealed placeholder for the cursor owner's fields. The cursor side returns an EOF page as `EofCompletion::new(preparation, index, scan)`; StateMissing completes or defers it.
- `production_ordinary_equivalent` always returns `None`: the scaffold cannot establish ordinary coverage for same-revision guard/E2 admission. Historical tick/cycle maxima do not bound a later cycle or lock wait, and directives/backoff may change during the attempt. The guard must refuse acceleration on `None`, even after accelerated pages finish; it must not substitute a historical estimate. A future implementation needs an actual ordinary eligibility/coverage witness carried through final admission. The unused loop-history machinery has been removed.

## Platform gates

`PlatformGates` covers power and Low Power Mode plus background QoS. The service has no such call today, so the production `NoPlatformSignals` answers `Unknown`, and an unknown or refused state falls back to the ordinary cadence. The proposed macOS calls are held for review, not implemented. They are:
- `pthread_set_qos_class_self_np`, from `libc`, which is already a dependency;
- IOKit power-source type;
- `NSProcessInfo.isLowPowerModeEnabled`.

## Bounds (models, not measurements)

- **Duty.** With pages of 3–5 s, the gap is 30–45 s. That bounds the wall-clock duty of one thread at 10 %. It is not a bound on process CPU, IO or foreground impact.
- **Ordinary schedule.** The ordinary wait and per-source cadence are unchanged. A running continuation can overrun the next cycle as described below.
- **Added network.** The only new requests are one completion upload per completed job.
- **Overrun.** A page is given the ordinary deadline. It can still delay the next ordinary cycle by the record it was reading when the deadline passed, required local finalization and scheduling, plus any EOF completion upload. This cooperative deadline establishes no hard elapsed-time bound.
- **EOF cadence.** An EOF completion leaves the ordinary Codex cadence unchanged; it is not counted as an ordinary scan.
- **Ordinary page after a continuation.** It can follow a continuation page by less than a server directive. The continuation page made no request, and the ordinary schedule is unchanged by design.

## Validation

CI only. The new tests are in `adaptive_collector.rs` and `snapshot_sync/continuation_tests.rs`. They cover:
- directive and failure backoff over the continuation;
- the duty bound with slow pages, and pages cut at their deadline;
- zero network calls until EOF, plus a structural control that this module names no network client and reaches the network only through the one EOF completion call;
- EOF success, refusal, authority/backoff/destination rechecks, cancellation and failed save;
- an EOF completion leaving the ordinary Codex cadence unchanged, through the real `record_finished_snapshot_cadence`;
- refusal, unknown and busy inputs, a revoked Codex grant and a changed account;
- a failed cycle or a lost grant clearing the ticket, tickets taken and written only under the sync lock, and a replacement ticket plus request between precheck and lock obeying its new due time;
- the authority digest agreeing with `validate_snapshot_scan_authority` field by field;
- the slow-later-cycle counterexample to historical coverage, and final same-revision admission refusing unknown coverage after directive/backoff changes (a consumer model; c22's real guard is not present);
- ordinary-cycle cadence parity with and without continuation pages;
- the inert default's constant gate and stubs.

**Inert parity** rests on the constant gate and on review: while `ENABLED` is false, the loop takes today's path before it reaches the continuation module, and every other hook is gated on the same constant. The inert test covers the gate and the stubs, not the loop. The non-gated changes are moves without a behaviour change: the cycle's client construction into `snapshot_cycle_client`, and the ordinary finish's closure body into `SnapshotCycleOwner::finish_completed`.

**Not covered.** A real-boundary network probe of the cursor page waits for the cursor owner's page; until then zero-network is shown with fakes and the structural control.
