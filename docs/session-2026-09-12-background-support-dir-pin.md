# A library test run could refresh the developer's own Claude credentials

2026-09-12. On a Mac with three registered Claude credential slots, all three
slots refreshed their OAuth access tokens three seconds apart, in slot-id sort
order, and `claude-background-upkeep-state.json` gained three `refreshed`
witnesses. The running daemon could not have done it: it had been up for a day
without a restart, on a build whose spawn gate rejected every annotated
descriptor. What was finishing at that moment was
`cargo test -p ottto-service --lib`.

## What was wrong

`spawn_claude_agent_status_refresh` detaches a thread and never joins it. The
thread body then resolves `default_support_dir()` — many times, at its own pace:
to load the Claude slot registry, to write collection state, to decide whether
consented upkeep may run `claude doctor`.

Nothing binds those resolutions to the moment of the spawn. In a test, the
staging `OTTTO_LOCAL_PLATFORM_SUPPORT_DIR` guard belongs to the test function;
it drops when the test returns. The worker outlives it, finds the variable
unset, falls back to `$HOME/Library/Application Support/Ottto`, and reads the
developer's real installation.

From there every downstream step is correct behaviour applied to the wrong
accounts:

1. `collect_claude_status_snapshots` reads the real registry: consent granted,
   three real slots, sorted by slot id.
2. Each slot's access token is past expiry with a live refresh grant, so
   `observe_registered_slot_upkeep` queues production upkeep for it.
3. The queue worker re-resolves the support directory the same ambient way,
   reaches `ProductionFinalSpawnGate`, finds real consent and real
   registration, and runs the real `claude doctor` against each real config
   directory in turn.
4. `claim_attempt`/`complete_attempt` write the three `refreshed` witnesses into
   the real support directory, and `upload_agent_status_snapshots` uploads the
   resulting snapshots.

`control::tests` are what start that thread: every Claude registry mutation
calls `spawn_claude_agent_status_refresh("registry_mutation")`.

Instrumenting `write_owner_only_file_atomic` to record writes under the real
support directory during a full `--test-threads=1` lib run found exactly one
offending thread and three files:

```
thread=ottto-claude-refresh-registry_mutation target=.../claude-code-oauth-usage-cache.json
thread=ottto-claude-refresh-registry_mutation target=.../claude-config-slot-collection-state.json
thread=ottto-claude-refresh-registry_mutation target=.../claude-oauth-usage-breaker.json
```

The credential refresh needs one more condition than those writes do — real
access tokens past expiry — which is why it reproduces only on the days the
operator's own tokens happen to be stale.

## The change

- `ottto_core::pin_support_dir` binds the calling thread to one support
  directory until its guard drops; `default_support_dir()` consults that pin
  before the environment. Production never sets the variable twice, so the pin
  is inert there and decisive everywhere else.
- `support_dir_scope::spawn_pinned` captures the support directory in the
  spawning thread and installs it as the new thread's first act. Every detached
  worker in `snapshot_sync` and `claude_browser_auth` goes through it, so a
  worker keeps the installation it was started for.
- The production upkeep queue stores the support directory each slot was queued
  against (`QueuedUpkeep`) and the worker pins it for the whole attempt, rather
  than asking the process again at dequeue.
- `ProductionFinalSpawnGate` refuses — `ProbeFailed`, no spawn — when the live
  support directory is not the one the attempt staged. The gate consults the
  registry, network switch, and stop file ambiently while the claim that
  authorised the attempt was taken against a specific directory; a disagreement
  means those are two different installations.
- The Claude refresh claim is keyed by support directory. A worker is now bound
  to one installation for its whole life, so the old process-global
  running/pending pair would let a trigger for one installation be absorbed as
  a trailing run the other worker spends on its own directory. A daemon has one
  installation, so the map holds at most one entry in production.
- `SupportDirPin` is `!Send`. It restores a thread-local, so moving the guard to
  another thread and dropping it there would restore that thread's pin and
  leave the pinned thread bound for the rest of its life.

## Evidence

- `a_pinned_worker_keeps_the_support_dir_its_spawner_staged` stages a directory,
  spawns a worker that blocks on a channel, drops the staging guard, points the
  environment elsewhere, and only then releases the worker. Without the pin the
  worker reports the later directory.
- `a_queued_attempt_stays_on_the_installation_that_queued_it` holds the upkeep
  state lock so the environment provably moves mid-attempt, then asserts the
  durable witness lands in the staged installation and that nothing reaches the
  other one. The test installs the decoy directory *before* the staging guard
  so the variable is never momentarily unset — unset is what resolves to the
  developer's own installation.
- `the_production_gate_refuses_a_support_dir_the_attempt_never_staged` drives
  the real gate against a fully willing registry — consent granted, slot
  registered, no stop file — and asserts zero doctor invocations on a mismatch,
  then asserts the same gate proceeds when the staged directory is the one it
  reads.
- All three fail on this branch with their fix removed.
- `claude_refresh_claims_are_scoped_per_installation` asserts a second
  installation gets its own claim and that its trailing run is not spent on the
  first. It fails when the claim ignores the support directory.
- A `compile_fail` doctest on `pin_support_dir` proves the guard cannot cross
  threads; it fails when the non-`Send` marker is relaxed to `PhantomData<()>`.
- A full lib run with the write instrumentation reapplied on top of the fix
  reports no writes under the real support directory.
- `cargo test --workspace --locked` and
  `cargo test -p ottto-service --lib --locked -- --test-threads=1`: 1729 passed,
  2 ignored.

## Scope

This closes the write and vendor-spawn path. A full run still *reads* the real
support directory from tests that never staged one — device path, token store
secret directory, detected uses. Those are same-thread reads in tests that set
no guard at all, not background drift, and they are untouched here.
